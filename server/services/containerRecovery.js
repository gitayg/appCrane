// Container recovery: an app environment with a live release but no container
// that is up gets its live release run again.
//
// Why this exists. App containers run with --restart=on-failure:2
// (docker.js runAppContainer). Docker can restart a container it still has; it
// cannot bring back one that was removed, and it gives up on one that exited
// cleanly or failed twice. After a host reboot plus a full disk, one app's
// containers were simply gone in both environments for two days while its
// release was still live.
//
// This replaces the boot-only "Auto-heal" block that lived in index.js. That
// block had the right idea and four gaps, each of which can explain the outage:
//   1. It only considered an env whose NEWEST deployment row was live. Its own
//      heal inserts a row, so one failed heal (a full disk fails every build)
//      left a failed row on top and locked that env out on every later boot.
//      Here the target is the newest LIVE row, whatever came after it.
//   2. It ran once per boot. A container removed while AppCrane stayed up was
//      never noticed. Here a sweep also runs every 10 minutes.
//   3. It gave Docker 5 s at boot and skipped everything otherwise. Here boot
//      waits up to 2 minutes, and the periodic sweep covers a slower Docker.
//   4. It rebuilt from source (a clone at the live commit, or the branch head
//      when no commit was recorded). Here the live release's own directory is
//      run again, as rollbackApp does, so deployApp reuses the cached image when
//      it is still there and a missing git source does not matter.
//
// What is never touched: an env under a managed-database restore (stopped on
// purpose), an env with a deploy in flight, and a container Docker is still
// handling or someone paused. Memory admission is deployApp's own, so a refusal
// is a failed attempt and backs off like any other.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

const execFileAsync = promisify(execFile);

const SWEEP_MS = 10 * 60 * 1000;
// Same grace the old auto-heal had: a deploy that finished moments ago may
// still be settling, and its own health check owns that window.
export const GRACE_SECONDS = 300;
const BACKOFF_BASE_MS = 10 * 60 * 1000;
export const BACKOFF_CAP_MS = 6 * 60 * 60 * 1000;
const DOCKER_WAIT_MS = 2 * 60 * 1000;
const DOCKER_POLL_MS = 5000;
export const MAIL_SOURCE = 'container-recovery';
export const DEPLOY_LOG_PREFIX = 'auto-heal:';

// States where Docker still has the container in hand, or a person paused it.
// Everything else Docker reports (exited, created, dead) will not come back on
// its own under on-failure:2.
const LEAVE_ALONE = new Set(['running', 'restarting', 'paused', 'removing']);

const COMMIT_RE = /^[0-9a-f]{7,40}$/i;

// Per-env attempt state, keyed `${appId}:${env}`: { failures, nextAt, lastError }.
// In memory on purpose: a reboot is exactly when every env deserves a fresh try.
const attempts = new Map();
let running = false;
let rerun = false;
let timer = null;

export const keyOf = (appId, env) => `${appId}:${env}`;

export function backoffMs(failures) {
  return Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, failures - 1), BACKOFF_CAP_MS);
}

/** The newest live deployment per app and env, past the grace window. */
export function liveTargets(db) {
  return db.prepare(`
    SELECT d.app_id, d.env, d.id AS live_id, d.version, d.commit_hash, d.commit_sha,
           d.release_path, d.tree_sha256, d.image_ref, a.slug, a.source_type
    FROM deployments d JOIN apps a ON a.id = d.app_id
    WHERE d.status = 'live'
      AND d.id = (SELECT MAX(id) FROM deployments WHERE app_id = d.app_id AND env = d.env AND status = 'live')
      AND (strftime('%s', 'now') - strftime('%s', COALESCE(d.finished_at, d.started_at))) > ?
    ORDER BY d.app_id, d.env
  `).all(GRACE_SECONDS);
}

/**
 * Which targets need recovering now. Pure: `containers` is Map<name, state>
 * from one `docker ps -a`, `restoring(slug, env)` is the restore guard, and
 * `attemptState` the backoff map.
 */
export function findMissing({ targets, containers, restoring, attemptState, now }) {
  const missing = [];
  const skipped = [];
  for (const t of targets) {
    const name = `appcrane-${t.slug}-${t.env}`;
    const state = containers.get(name) || 'absent';
    if (LEAVE_ALONE.has(state)) continue;
    if (restoring(t.slug, t.env)) { skipped.push({ name, why: 'restore in progress' }); continue; }
    const a = attemptState.get(keyOf(t.app_id, t.env));
    if (a && a.nextAt > now) { skipped.push({ name, why: `backing off until ${new Date(a.nextAt).toISOString()}` }); continue; }
    missing.push({ ...t, name, state });
  }
  return { missing, skipped };
}

/**
 * How to run the live release again, or why it cannot be. Mirrors
 * rollbackApp's opts, without its rollback bookkeeping: nothing is being rolled
 * back, so the live row is not marked rolled_back. The release check is skipped
 * because these are the bytes that already passed it.
 */
export function restorePlan(t, { fileExists = existsSync } = {}) {
  const liveCommit = [t.commit_sha, t.commit_hash].find(c => COMMIT_RE.test(String(c || '')));
  if (t.source_type === 'image') {
    if (!t.image_ref) return { error: `deployment #${t.live_id} has no image_ref recorded, so there is no digest to restart` };
    return { mode: 'image', opts: { imageRef: t.image_ref, commitHash: t.commit_hash, releaseCheck: 'skip', rollback: true } };
  }
  if (t.release_path && fileExists(t.release_path)) {
    return {
      mode: 'release',
      opts: { preExtractedDir: t.release_path, commitHash: t.commit_hash, expectTreeSha: t.tree_sha256 || null, releaseCheck: 'skip' },
    };
  }
  // The release directory went with the disk. A rebuild pinned to the live
  // commit is still the live release; a build of whatever the branch holds now
  // would be a new release nobody asked for, so that is refused.
  if (liveCommit) return { mode: 'rebuild', opts: { targetCommit: liveCommit, releaseCheck: 'skip' } };
  return { error: `the release directory of deployment #${t.live_id} is gone and no commit is recorded to rebuild it from` };
}

/** Map<name, state> of every AppCrane container. Throws when Docker does not answer. */
export async function listContainers() {
  const { stdout } = await execFileAsync('docker',
    ['ps', '-a', '--filter', 'label=appcrane=true', '--format', '{{.Names}}|{{.State}}'],
    { timeout: 15000 });
  const map = new Map();
  for (const line of stdout.trim().split('\n')) {
    if (!line) continue;
    const [name, state] = line.split('|');
    map.set(name, state);
  }
  return map;
}

/**
 * True only when Docker says the container does not exist. Anything unclear is
 * false, so the health checker keeps doing what it did before.
 */
export async function containerMissing(slug, env) {
  try {
    await execFileAsync('docker', ['inspect', '-f', '{{.State.Status}}', `appcrane-${slug}-${env}`], { timeout: 10000 });
    return false;
  } catch (e) {
    return /no such (object|container)/i.test(String(e.stderr || e.message || ''));
  }
}

async function defaultDeps() {
  const deployer = await import('./deployer.js');
  const { getPortsForSlot } = await import('./portAllocator.js');
  const { restoreInProgress } = await import('./managedDbRestoreGuard.js');
  const { imageExists, imageTagFor } = await import('./docker.js');
  const { logAudit } = await import('../middleware/audit.js');
  return {
    db: getDb(),
    listContainers,
    restoring: restoreInProgress,
    assertNoInflightDeploy: deployer.assertNoInflightDeploy,
    deployApp: deployer.deployApp,
    getPortsForSlot,
    imageCached: async (slug, env, commitHash) =>
      (commitHash && commitHash !== 'unknown') ? imageExists(imageTagFor(slug, env, commitHash)) : false,
    fileExists: existsSync,
    logAudit,
    notify: notifyRecovery,
    now: () => Date.now(),
  };
}

/** Recover one env. Returns { outcome: 'recovered' | 'failed' | 'skipped', ... }. */
export async function recoverOne(t, deps) {
  const { db } = deps;
  try {
    deps.assertNoInflightDeploy(db, t.app_id, t.env, t.slug);
  } catch (e) {
    if (e.code === 'DEPLOY_IN_PROGRESS') return { outcome: 'skipped', why: 'deploy in flight' };
    throw e;
  }

  const plan = restorePlan(t, { fileExists: deps.fileExists });
  const detail = {
    env: t.env, container_state: t.state, live_deployment_id: t.live_id, version: t.version || null,
    mode: plan.mode || null,
  };
  if (plan.mode === 'release') {
    detail.image_cached = await deps.imageCached(t.slug, t.env, t.commit_hash);
    // deployApp's disk-headroom guard lets a rollback through because it builds
    // nothing. A re-run of the live release with its image still cached is the
    // same case; one that has to rebuild is not, and takes the guard.
    if (detail.image_cached) plan.opts.rollback = true;
  }

  let error = plan.error || null;
  let deploymentId = null;
  if (!error) {
    // Copied from the live row so the restored deployment carries the same
    // version, commit and artifact identity as the one it stands in for.
    const ins = db.prepare(`
      INSERT INTO deployments (app_id, env, version, status, commit_hash, commit_sha, release_path, image_ref,
                               artifact_sha256, artifact_bytes, artifact_filename, declared_commit_sha, log)
      SELECT app_id, env, version, 'pending', commit_hash, commit_sha, release_path, image_ref,
             artifact_sha256, artifact_bytes, artifact_filename, declared_commit_sha, ?
      FROM deployments WHERE id = ?
    `).run(`${DEPLOY_LOG_PREFIX} container ${t.state}; re-running live deployment #${t.live_id}`, t.live_id);
    deploymentId = Number(ins.lastInsertRowid);
    detail.deployment_id = deploymentId;
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(t.app_id);
    try {
      await deps.deployApp(deploymentId, app, t.env, deps.getPortsForSlot(app.slot), plan.opts);
    } catch (e) {
      error = e.message;
      // deployApp marks its row failed for anything thrown inside its pipeline,
      // but not for what throws before it (directory setup). A row left pending
      // would read as a deploy in flight and block this env for 30 minutes.
      db.prepare(`UPDATE deployments SET status = 'failed', finished_at = datetime('now'), failure_reason = ?
                  WHERE id = ? AND status IN ('pending', 'building', 'deploying')`)
        .run(`Container recovery failed: ${String(error).slice(0, 500)}`, deploymentId);
    }
  }

  const key = keyOf(t.app_id, t.env);
  if (error) {
    const failures = (attempts.get(key)?.failures || 0) + 1;
    const nextAt = deps.now() + backoffMs(failures);
    attempts.set(key, { failures, nextAt, lastError: error });
    detail.error = String(error).slice(0, 500);
    detail.failures = failures;
    detail.next_attempt_at = new Date(nextAt).toISOString();
    log.error(`[container-recovery] ${t.name} not recovered (attempt ${failures}, next ${detail.next_attempt_at}): ${error}`);
  } else {
    attempts.delete(key);
    log.info(`[container-recovery] ${t.name} recovered from live deployment #${t.live_id} as #${deploymentId}`);
  }
  const outcome = error ? 'failed' : 'recovered';
  deps.logAudit(null, t.app_id, error ? 'container-recovery-failed' : 'container-recovered', detail, 'system');
  try { await deps.notify(db, t, outcome, detail); } catch (e) { log.warn(`[container-recovery] mail for ${t.name} skipped: ${e.message}`); }
  return { outcome, detail };
}

/** One sweep, one recovery at a time. */
export async function sweep(deps) {
  const d = deps || await defaultDeps();
  let containers;
  try {
    containers = await d.listContainers();
  } catch (e) {
    // Never read "Docker did not answer" as "every container is gone".
    log.warn(`[container-recovery] sweep skipped, Docker did not answer: ${e.message}`);
    return { results: [], skipped: [], dockerDown: true };
  }
  const { missing, skipped } = findMissing({
    targets: liveTargets(d.db), containers, restoring: d.restoring, attemptState: attempts, now: d.now(),
  });
  if (missing.length) log.info(`[container-recovery] ${missing.length} live env(s) have no container up: ${missing.map(m => `${m.name} (${m.state})`).join(', ')}`);
  const results = [];
  for (const t of missing) {
    try {
      results.push({ name: t.name, ...(await recoverOne(t, d)) });
    } catch (e) {
      log.error(`[container-recovery] ${t.name}: ${e.message}`);
      results.push({ name: t.name, outcome: 'error', error: e.message });
    }
  }
  return { results, skipped, dockerDown: false };
}

/** Run a sweep unless one is running; a request during a sweep queues one more. */
export async function runSweep(deps) {
  if (running) { rerun = true; return null; }
  running = true;
  try {
    let out;
    do {
      rerun = false;
      out = await sweep(deps);
    } while (rerun);
    return out;
  } finally {
    running = false;
  }
}

/** For the health checker: an env just turned out to have no container. */
export function recoverSoon() {
  runSweep().catch(e => log.error(`[container-recovery] sweep failed: ${e.message}`));
}

async function waitForDocker(dockerAvailable, waitMs = DOCKER_WAIT_MS) {
  const until = Date.now() + waitMs;
  while (Date.now() < until) {
    if (await dockerAvailable()) return true;
    await new Promise(r => setTimeout(r, DOCKER_POLL_MS));
  }
  return false;
}

export function startContainerRecovery() {
  if (timer) return;
  timer = setInterval(recoverSoon, SWEEP_MS);
  timer.unref();
  (async () => {
    const { dockerAvailable } = await import('./docker.js');
    if (!(await waitForDocker(dockerAvailable))) {
      log.warn(`[container-recovery] Docker did not answer within ${DOCKER_WAIT_MS / 1000}s of boot; the ${SWEEP_MS / 60000}-minute sweep will retry`);
      return;
    }
    await runSweep();
  })().catch(e => log.error(`[container-recovery] boot sweep failed: ${e.message}`));
}

export function stopContainerRecovery() {
  if (timer) clearInterval(timer);
  timer = null;
}

/** One mail per outage: keyed on the live deployment the outage started from. */
export async function notifyRecovery(db, t, outcome, detail) {
  const { enqueueEmail } = await import('./emailQueue.js');
  const { appOwners, platformAdmins } = await import('./memoryAdmissionMail.js');
  const seen = new Set();
  const people = [...appOwners(db, t.app_id), ...platformAdmins(db)].filter(u => {
    const k = u.email.trim().toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const what = outcome === 'recovered'
    ? `AppCrane found no running container for ${t.slug} (${t.env}, container ${t.state}) and started live deployment #${t.live_id} again as deployment #${detail.deployment_id}.`
    : `AppCrane found no running container for ${t.slug} (${t.env}, container ${t.state}) and could not start live deployment #${t.live_id} again: ${detail.error}. It will try again after ${detail.next_attempt_at}, backing off up to every ${BACKOFF_CAP_MS / 3600000} hours.`;
  for (const u of people) {
    try {
      enqueueEmail({
        appId: t.app_id, env: t.env, to: u.email, source: MAIL_SOURCE,
        subject: `[AppCrane] ${t.slug} (${t.env}): container ${outcome === 'recovered' ? 'recovered' : 'down, recovery failed'}`,
        text: `Hi${u.name ? ` ${u.name}` : ''},\n\n${what}\n\nYou get this because you own ${t.slug} or administer this AppCrane.\n`,
        idempotencyKey: `${MAIL_SOURCE}:${t.env}:${t.live_id}:${u.email.trim().toLowerCase()}`,
      });
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[container-recovery] mail to ${u.email} skipped: ${e.message}`);
    }
  }
}

export const __testables = { attempts, waitForDocker };
