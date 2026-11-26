import { execFile } from 'child_process';
import { promisify } from 'util';
import net from 'net';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { sleepRow, setSleepState } from './envSleepState.js';
import { toSqlTime } from './envActivity.js';
import { withDbAccessDuringStart } from './hostFirewall/dbChain.js';

// Putting an environment to sleep and waking it.
//
// Sleep is `docker stop` WITHOUT `rm`, and wake is `docker start` of that same
// container: same image, env, mounts and limits, the way a database restore
// stops and starts an app (managedDbRestoreGuard.js). --restart=on-failure:2
// does not restart a container stopped this way, Docker restart included.
//
// One operation per env at a time: every caller of wakeEnv while a wake is in
// flight gets the same promise, so twenty requests arriving together cause one
// `docker start`. A sleep never runs while a wake or sleep is in flight.

const execFileAsync = promisify(execFile);
const ops = new Map();

export const WAKE_HEALTH_WAIT_MS = 90_000;
const POLL_MS = 400;

const keyOf = (appId, env) => `${appId}:${env}`;
export const containerNameOf = (slug, env) => `appcrane-${slug}-${env}`;

async function dockerCmd(args, timeout = 30_000) {
  try {
    const { stdout } = await execFileAsync('docker', args, { timeout });
    return stdout;
  } catch (e) {
    throw new Error(e.stderr?.toString().trim() || e.message);
  }
}

function probeTcp(port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const s = net.createConnection({ host: '127.0.0.1', port });
    const done = (ok) => { s.destroy(); resolve(ok); };
    s.setTimeout(timeoutMs);
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
  });
}

/** Serving means the app answered its health path below 500 (tcp: accepted a connection). */
export async function probeServing(db, app, env) {
  const { getPortsForSlot } = await import('./portAllocator.js');
  const ports = getPortsForSlot(app.slot);
  const port = env === 'production' ? ports.prod_be : ports.sand_be;
  const { getIngressForApp } = await import('./tcpIngress.js');
  if (getIngressForApp(db, app.id).ingress_type === 'tcp') return probeTcp(port);
  const hc = db.prepare('SELECT endpoint FROM health_configs WHERE app_id = ? AND env = ?').get(app.id, env);
  const path = (!hc?.endpoint || hc.endpoint === '/api/health') && app.health_path ? app.health_path : (hc?.endpoint || '/api/health');
  const { fetchAppProbe } = await import('./appProbeFetch.js');
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 3000);
  try {
    const res = await fetchAppProbe(`http://localhost:${port}${path}`, { signal: ctl.signal });
    await res.body?.cancel().catch(() => {});
    return res.status > 0 && res.status < 500;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

async function defaultAdmit(app, env) {
  const { admitAppStart } = await import('./deployer.js');
  await admitAppStart({ app, env, automatic: true, what: 'wake', onWarn: 'silent' });
}

async function defaultVerifyTrust(app, env) {
  const name = containerNameOf(app.slug, env);
  const running = await (await import('./imageTrust/dockerImage.js')).containerImageId(name);
  if (!running.error) {
    await (await import('./imageTrust/verify.js')).enforceImageTrust({ slug: app.slug, env, image: running.ref, imageId: running.id, what: 'wake' });
  }
}

async function defaultAudit(appId, action, detail, userId = null) {
  const { logAudit } = await import('../middleware/audit.js');
  logAudit(userId, appId, action, detail, userId ? null : 'system');
}

async function invalidateDockerCaches() {
  const d = await import('./docker.js');
  d.invalidatePublishedPortsCache();
  d.invalidateResourcesCache();
}

export async function notifyInactiveSleep(db, app, env, sleptAt, days) {
  const { enqueueEmail } = await import('./emailQueue.js');
  const { appOwners } = await import('./memoryAdmissionMail.js');
  const seen = new Set();
  for (const u of appOwners(db, app.id)) {
    const k = u.email.trim().toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    try {
      enqueueEmail({
        appId: app.id, env, to: u.email, source: 'env-sleep',
        subject: `[AppCrane] ${app.slug} (${env}) is asleep after ${days} days without use`,
        text: `Hi${u.name ? ` ${u.name}` : ''},\n\n${app.name || app.slug} (${env}) had no requests and no deploys for ${days} days, ` +
          `so AppCrane stopped its container to free memory on the server. Nothing was deleted.\n\n` +
          `It wakes on the next visit: the first request starts it again and waits until it answers. ` +
          `A deploy also wakes it.\n\nYou get this because you own ${app.slug}.\n`,
        idempotencyKey: `env-sleep:${app.id}:${env}:${sleptAt}:${k}`,
      });
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[env-sleep] mail to ${u.email} skipped: ${e.message}`);
    }
  }
}

function defaultDeps() {
  return {
    db: getDb(),
    docker: dockerCmd,
    probe: probeServing,
    admit: defaultAdmit,
    verifyTrust: defaultVerifyTrust,
    audit: defaultAudit,
    recoverSoon: async () => (await import('./containerRecovery.js')).recoverSoon(),
    notifyInactive: notifyInactiveSleep,
    invalidate: invalidateDockerCaches,
    now: () => Date.now(),
    sleep: (ms) => new Promise(r => setTimeout(r, ms)),
    healthWaitMs: WAKE_HEALTH_WAIT_MS,
  };
}

let depsOverride = null;
export function _setWakeDepsForTests(d) { depsOverride = d; }
const deps = () => ({ ...defaultDeps(), ...(depsOverride || {}) });

export function opInFlight(appId, env) {
  return ops.has(keyOf(appId, env));
}

/**
 * Stop `app`'s `env` container and record it sleeping. The state is written
 * BEFORE the stop, so the health checker and container recovery already leave
 * it alone while Docker is stopping it. Returns { ok, error? }.
 */
export async function sleepEnv(app, env, reason, detail = {}) {
  const key = keyOf(app.id, env);
  if (ops.has(key)) return { ok: false, error: 'another sleep or wake is in progress' };
  const d = deps();
  const run = (async () => {
    const sleptAt = toSqlTime(d.now());
    setSleepState(d.db, app.id, env, { state: 'sleeping', reason, slept_at: sleptAt, last_error: null });
    try {
      await d.docker(['stop', containerNameOf(app.slug, env)], 60_000);
    } catch (e) {
      setSleepState(d.db, app.id, env, { state: 'awake', last_error: `could not stop: ${String(e.message).slice(0, 300)}` });
      log.warn(`[env-sleep] ${app.slug} ${env}: stop failed, left awake: ${e.message}`);
      return { ok: false, error: e.message };
    }
    await d.invalidate().catch(() => {});
    d.db.prepare('UPDATE health_state SET consecutive_fails = 0, is_down = 0 WHERE app_id = ? AND env = ?').run(app.id, env);
    await d.audit(app.id, 'env-sleep', { env, reason, ...detail });
    log.info(`[env-sleep] ${app.slug} ${env} is asleep (${reason})`);
    if (reason === 'inactive') {
      try { await d.notifyInactive(d.db, app, env, sleptAt, detail.inactive_days); } catch (e) { log.warn(`[env-sleep] owner mail failed: ${e.message}`); }
    }
    return { ok: true, slept_at: sleptAt };
  })();
  const entry = { kind: 'sleep', promise: run };
  ops.set(key, entry);
  try { return await run; } finally { if (ops.get(key) === entry) ops.delete(key); }
}

/**
 * Wake `app`'s `env` if it sleeps, and wait (bounded) until it serves. Concurrent
 * callers share one wake. Returns { ok, healthy?, already?, code?, error? }.
 */
export async function wakeEnv(app, env, { reason = 'request', userId = null } = {}) {
  const key = keyOf(app.id, env);
  const inflight = ops.get(key);
  if (inflight?.kind === 'wake') return inflight.promise;
  if (inflight) await inflight.promise.catch(() => {});
  const again = ops.get(key);
  if (again?.kind === 'wake') return again.promise;

  const d = deps();
  const row = sleepRow(d.db, app.id, env);
  if (!row || row.state === 'awake') return { ok: true, already: true };

  const promise = (async () => {
    const started = d.now();
    setSleepState(d.db, app.id, env, { state: 'waking', last_error: null });
    try {
      await d.admit(app, env);
      await d.verifyTrust(app, env);
    } catch (e) {
      setSleepState(d.db, app.id, env, { state: 'sleeping', last_error: String(e.message).slice(0, 500) });
      log.warn(`[env-wake] ${app.slug} ${env} not woken: ${e.message}`);
      return { ok: false, code: e.code || 'WAKE_REFUSED', error: e.message };
    }
    let recovering = false;
    try {
      // APPCRANE-DB: `docker start` can hand the container a new address, so
      // its database ports are held open until that address is on the list.
      const name = containerNameOf(app.slug, env);
      await withDbAccessDuringStart(name, () => d.docker(['start', name], 60_000));
    } catch (e) {
      if (!/no such (object|container)/i.test(e.message)) {
        setSleepState(d.db, app.id, env, { state: 'sleeping', last_error: `could not start: ${String(e.message).slice(0, 300)}` });
        log.warn(`[env-wake] ${app.slug} ${env}: start failed: ${e.message}`);
        return { ok: false, code: 'WAKE_FAILED', error: e.message };
      }
      // The container went while it slept (a prune, a host rebuild): container
      // recovery runs the live release again, as it does for any lost container.
      recovering = true;
      setSleepState(d.db, app.id, env, { state: 'awake', woke_at: toSqlTime(d.now()), wake_reason: `${reason} (recreated)` });
      await d.recoverSoon();
    }
    await d.invalidate().catch(() => {});
    let healthy = false;
    while (d.now() - started < d.healthWaitMs) {
      if (await d.probe(d.db, app, env)) { healthy = true; break; }
      await d.sleep(POLL_MS);
    }
    if (!recovering) setSleepState(d.db, app.id, env, { state: 'awake', woke_at: toSqlTime(d.now()), wake_reason: reason });
    await d.audit(app.id, 'env-wake', { env, reason, healthy, ms: d.now() - started, recreated: recovering }, userId);
    log.info(`[env-wake] ${app.slug} ${env} woke (${reason}) in ${d.now() - started} ms${healthy ? '' : ', not serving yet'}`);
    return { ok: true, healthy, ms: d.now() - started };
  })();
  const entry = { kind: 'wake', promise };
  ops.set(key, entry);
  try { return await promise; } finally { if (ops.get(key) === entry) ops.delete(key); }
}

/** For tools that need the container running (docker exec): wake it, or say why not. */
export async function ensureAwake(app, env, opts = {}) {
  const row = sleepRow(getDb(), app.id, env);
  if (!row || row.state === 'awake') return { ok: true, already: true };
  const r = await wakeEnv(app, env, opts);
  if (!r.ok) throw new Error(`${app.slug} (${env}) is asleep and could not be woken: ${r.error}`);
  return r;
}
