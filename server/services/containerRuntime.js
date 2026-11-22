// Which OCI runtime an app container runs under: runc (Docker's default, the
// host kernel) or runsc (gVisor, a user-space kernel between the app and the
// host). Migration 250 holds the per-app overrides; settings key
// container_runtime_default holds the platform default.
//
// Who may change what:
//   - the platform default: platform admin only;
//   - an app's override: an owner or app admin may only RAISE isolation (set
//     runsc, or clear an override when that does not lower the result); a
//     runc override, or any change that lowers the result, is platform admin
//     only, and a runc override needs a reason (it stays an exception when the
//     platform default is later raised to runsc);
//   - an app's plan (services/plans/runtimeFloor.js) may set a floor of runsc
//     that nothing goes below: not the owner, not the platform default, and
//     not a platform admin's override (a runc override is refused while the
//     floor is runsc, and an older one is outranked by the floor).
//
// Fail closed: a start that needs runsc on a host whose dockerd has no runsc
// runtime is refused before the running container is touched. It is never
// started on runc instead. A runc start adds no flag, so the argv of every app
// that stays on runc is unchanged to the byte.
//
// AppCrane's own helper containers (egress anchor and relay, builders,
// scanners, root helpers, managed databases) are not covered: the egress
// anchor in particular MUST stay on runc, because it removes the default route
// from the host network namespace the app then joins; under runsc that change
// would land in gVisor's own network stack and the app would keep its route.

import { execFile } from 'child_process';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { logAudit } from '../middleware/audit.js';
import { planRuntimeFloor } from './plans/runtimeFloor.js';

export const RUNTIMES = ['runc', 'runsc'];
const RANK = { runc: 0, runsc: 1 };
const SETTING = 'container_runtime_default';
const MIN_REASON = 8;

const defaultDocker = (args, timeout = 15_000) => new Promise((res, rej) => {
  execFile('docker', args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => (err
    ? rej(new Error(String(stderr || '').trim() || err.message))
    : res(String(stdout).trim())));
});
let docker = defaultDocker;
/** Test seam. */
export function _setDockerForTests(fn) { docker = fn || defaultDocker; hostCache = null; }
let floorOf = planRuntimeFloor;
/** Test seam for the plan floor. */
export function _setPlanFloorForTests(fn) { floorOf = fn || planRuntimeFloor; }

function planFloor(app, db) {
  const f = app ? floorOf(db, app) : null;
  return f === 'runsc' ? 'runsc' : null;
}

export function platformDefault(db = getDb()) {
  const v = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTING)?.value;
  return RUNTIMES.includes(v) ? v : 'runc';
}

export function appOverride(appId, db = getDb()) {
  return db.prepare('SELECT runtime, reason, updated_by, updated_at FROM app_container_runtime WHERE app_id = ?').get(appId) || null;
}

function resolve(platform, override, floor = null) {
  const chosen = override?.runtime || platform;
  const raisedByPlan = floor && RANK[floor] > RANK[chosen];
  const runtime = raisedByPlan ? floor : chosen;
  return {
    runtime,
    source: raisedByPlan ? 'plan' : override ? 'app' : 'platform',
    platform_default: platform,
    plan_floor: floor,
    override: override ? { runtime: override.runtime, reason: override.reason || null, updated_at: override.updated_at } : null,
    below_platform_default: RANK[runtime] < RANK[platform],
  };
}

export function effectiveRuntime(app, db = getDb()) {
  return resolve(platformDefault(db), appOverride(app.id, db), planFloor(app, db));
}

let hostCache = null;
const HOST_TTL_MS = 30_000;

/**
 * The runtimes dockerd has registered, read from `docker info`. `fresh` skips
 * the cache; the start path always reads fresh so a runtime removed from
 * daemon.json is noticed at the very next start.
 */
export async function hostRuntimes({ fresh = false } = {}) {
  if (!fresh && hostCache && Date.now() - hostCache.at < HOST_TTL_MS) return hostCache.value;
  let value;
  try {
    const out = await docker(['info', '--format', '{{json .Runtimes}}']);
    const parsed = JSON.parse(out);
    const runtimes = Object.keys(parsed && typeof parsed === 'object' ? parsed : {}).sort();
    value = { runtimes, runsc: runtimes.includes('runsc'), error: null };
  } catch (e) {
    value = { runtimes: [], runsc: false, error: `docker info failed: ${e.message}` };
  }
  hostCache = { at: Date.now(), value };
  return value;
}

function unavailable(what, host) {
  return new AppError(
    `${what} requires the gVisor runtime (runsc), and this host's Docker daemon does not have it registered` +
    ` (runtimes: ${host.runtimes.join(', ') || 'none readable'}${host.error ? `; ${host.error}` : ''}).` +
    ' AppCrane does not fall back to runc. Install runsc on the host (scripts/install-gvisor.sh) or have a platform' +
    ' admin change the runtime policy.',
    409, 'RUNTIME_UNAVAILABLE',
  );
}

/**
 * The `docker run` flags for an app container start, or a thrown 409. An app
 * row that cannot be found (a caller starting a container by slug for an app
 * not in the database) gets the platform default.
 */
export async function runtimeRunArgs(slug, db = getDb()) {
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  const eff = app ? effectiveRuntime(app, db) : resolve(platformDefault(db), null);
  if (eff.runtime === 'runc') return [];
  const host = await hostRuntimes({ fresh: true });
  if (!host.runsc) throw unavailable(`App '${slug}'`, host);
  return ['--runtime=runsc'];
}

/** HostConfig.Runtime of a running container, or null when it cannot be read. */
export async function appliedRuntime(containerName) {
  try {
    const out = await docker(['inspect', '--format', '{{.HostConfig.Runtime}}', containerName], 5_000);
    return out || null;
  } catch (_) {
    return null;
  }
}

export async function runtimeStatus(app, containerName, db = getDb()) {
  const eff = effectiveRuntime(app, db);
  const applied = await appliedRuntime(containerName);
  const appliedRank = applied === 'runsc' ? 1 : applied ? 0 : null;
  return {
    desired: eff.runtime,
    source: eff.source,
    applied,
    drift: applied != null && appliedRank !== RANK[eff.runtime],
    ...(applied != null && appliedRank < RANK[eff.runtime]
      ? { notice: `This container runs under ${applied}; the policy now requires ${eff.runtime}. It applies when the container is recreated (deploy, or POST /api/apps/${app.slug}/restart/<env>).` }
      : {}),
  };
}

export async function setPlatformDefault(runtime, user, db = getDb()) {
  if (!RUNTIMES.includes(runtime)) throw new AppError(`runtime must be one of ${RUNTIMES.join(', ')}`, 400, 'VALIDATION');
  if (runtime === 'runsc') {
    const host = await hostRuntimes({ fresh: true });
    if (!host.runsc) throw unavailable('A platform default of runsc', host);
  }
  const before = platformDefault(db);
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`).run(SETTING, runtime, user.id);
  logAudit(user.id, null, 'container-runtime-default', { from: before, to: runtime });
  return runtime;
}

/**
 * Set (runtime 'runc' | 'runsc') or clear (null) one app's override.
 * `isPlatformAdmin` is the caller's platform role; the route has already
 * checked the caller is an owner or admin of the app otherwise.
 */
export async function setAppOverride(app, runtime, user, { isPlatformAdmin, reason } = {}, db = getDb()) {
  if (runtime !== null && !RUNTIMES.includes(runtime)) {
    throw new AppError(`runtime must be one of ${RUNTIMES.join(', ')}, or null to use the platform default`, 400, 'VALIDATION');
  }
  const platform = platformDefault(db);
  const floor = planFloor(app, db);
  if (floor === 'runsc' && runtime === 'runc') {
    throw new AppError("This app's plan requires gVisor (runsc); no override can set it to runc.", 409, 'PLAN_RUNTIME_FLOOR');
  }
  const before = resolve(platform, appOverride(app.id, db), floor);
  const after = resolve(platform, runtime ? { runtime } : null, floor);
  const lowers = RANK[after.runtime] < RANK[before.runtime];
  if (!isPlatformAdmin && (runtime === 'runc' || lowers)) {
    throw new AppError(
      runtime === 'runc'
        ? 'Only a platform admin can set an app to runc: it is an exception below gVisor isolation.'
        : `Clearing this override would lower the app from ${before.runtime} to ${after.runtime}; only a platform admin can lower isolation.`,
      403, 'FORBIDDEN',
    );
  }
  const why = typeof reason === 'string' ? reason.trim() : '';
  if (runtime === 'runc' && why.length < MIN_REASON) {
    throw new AppError(`A runc override needs a reason of at least ${MIN_REASON} characters; it is recorded in the audit log.`, 400, 'VALIDATION');
  }
  if (runtime === 'runsc') {
    const host = await hostRuntimes({ fresh: true });
    if (!host.runsc) throw unavailable(`App '${app.slug}'`, host);
  }
  if (runtime === null) {
    db.prepare('DELETE FROM app_container_runtime WHERE app_id = ?').run(app.id);
  } else {
    db.prepare(`INSERT INTO app_container_runtime (app_id, runtime, reason, updated_by, updated_at) VALUES (?, ?, ?, ?, datetime('now'))
      ON CONFLICT(app_id) DO UPDATE SET runtime = excluded.runtime, reason = excluded.reason, updated_by = excluded.updated_by, updated_at = datetime('now')`)
      .run(app.id, runtime, why || null, user.id);
  }
  logAudit(user.id, app.id, 'container-runtime-app', { from: before.runtime, to: after.runtime, override: runtime, ...(why ? { reason: why } : {}) });
  return effectiveRuntime(app, db);
}

/** Apps whose override is below the current platform default. */
export function exceptions(db = getDb()) {
  const platform = platformDefault(db);
  return db.prepare(`SELECT a.slug, r.runtime, r.reason, r.updated_at FROM app_container_runtime r JOIN apps a ON a.id = r.app_id ORDER BY a.slug`)
    .all().filter((r) => RANK[r.runtime] < RANK[platform]);
}
