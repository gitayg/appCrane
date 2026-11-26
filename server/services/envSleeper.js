import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import { effectivePolicy, inSchedule, sleepBlockers, OUT_OF_WINDOW_IDLE_MIN } from './sleepPolicy.js';
import { activityOf, ensureTracking, flushActivity, fromSqlTime } from './envActivity.js';
import { sleepRow } from './envSleepState.js';
import { sleepEnv, wakeEnv, opInFlight } from './envWake.js';
import { automaticRecreateInFlight } from './containerRecreate.js';

// The env-sleeper job (Job Health: 'env-sleeper'), once a minute:
//   - sandbox idle: asleep after sandbox_idle_minutes with no request;
//   - sandbox schedule: asleep outside the window once idle for
//     OUT_OF_WINDOW_IDLE_MIN, and woken when the window opens if the schedule
//     is what put it to sleep;
//   - inactive (any env, production included): asleep after inactive_days with
//     no request AND no deploy.
// Production never takes the minutes-scale idle or the schedule.
//
// Idle is measured from the newest of: the last request, the last deploy of
// that env (any outcome; days rule only), the last wake, and when AppCrane
// started tracking the env, so a fresh upgrade never reads as a long silence.
// The minutes rules also count from this process's start, which covers the
// requests a restart lost before they were flushed; the days rule does not, or
// a box that restarts weekly would never reach seven days.

const TICK_MS = 60_000;
const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const PROCESS_START = Date.now();
let timer = null;
let running = false;

/** Map<name, state> of AppCrane containers, as container recovery reads it. */
async function defaultListContainers() {
  const { listContainers } = await import('./containerRecovery.js');
  return listContainers();
}

function liveEnvs(db) {
  return db.prepare(`
    SELECT DISTINCT a.*, d.env AS live_env FROM deployments d JOIN apps a ON a.id = d.app_id
    WHERE d.status = 'live' ORDER BY a.id, d.env`).all();
}

function lastDeployAt(db, appId, env) {
  const r = db.prepare('SELECT MAX(COALESCE(finished_at, started_at)) AS at FROM deployments WHERE app_id = ? AND env = ?').get(appId, env);
  return fromSqlTime(r?.at);
}

export function deployInFlight(db, appId, env) {
  return !!db.prepare("SELECT 1 FROM deployments WHERE app_id = ? AND env = ? AND status IN ('pending','building','deploying') LIMIT 1").get(appId, env);
}

function idleBaseline(db, app, env, row) {
  const act = activityOf(db, app.id, env);
  return Math.max(act.lastRequestAt || 0, act.trackingSince || 0, fromSqlTime(row?.woke_at) || 0);
}

/**
 * When the days rule would put one env to sleep, by the same clock decide()
 * reads: { inactive_days, state, blockers, idle_since, sleeps_at } (ms or null).
 * sleeps_at is null when the rule is off, the env is not eligible or not awake.
 */
export function inactivityForecast(db, app, env) {
  const days = effectivePolicy(db, app.id).inactive_days;
  const row = sleepRow(db, app.id, env);
  const state = row?.state || 'awake';
  const blockers = sleepBlockers(db, app, env);
  const idleSince = Math.max(idleBaseline(db, app, env, row), lastDeployAt(db, app.id, env) || 0) || null;
  const sleepsAt = days && !blockers.length && state === 'awake' && idleSince ? idleSince + days * DAY : null;
  return { inactive_days: days, state, blockers, idle_since: idleSince, sleeps_at: sleepsAt };
}

/**
 * What should happen to one env now: { action: 'sleep'|'wake'|'none', reason, why }.
 * Pure apart from reading the database.
 */
export function decide(db, app, env, now, { processStart = PROCESS_START } = {}) {
  const policy = effectivePolicy(db, app.id);
  const row = sleepRow(db, app.id, env);
  const state = row?.state || 'awake';
  const sandbox = env === 'sandbox';
  const schedule = sandbox ? policy.sandbox_schedule : null;
  const idleMin = sandbox ? policy.sandbox_idle_minutes : 0;
  const days = policy.inactive_days;
  if (!schedule && !idleMin && !days) return { action: 'none', why: 'off' };

  if (state === 'sleeping') {
    if (schedule && row.reason === 'schedule' && inSchedule(schedule, now)) return { action: 'wake', reason: 'schedule', why: 'the schedule window opened' };
    return { action: 'none', why: 'asleep' };
  }
  if (state !== 'awake') return { action: 'none', why: state };

  const blockers = sleepBlockers(db, app, env);
  if (blockers.length) return { action: 'none', why: `not eligible: ${blockers.join('; ')}` };

  const baseline = idleBaseline(db, app, env, row);
  const sinceRequest = now - Math.max(baseline, processStart);
  const sinceUseOrDeploy = now - Math.max(baseline, lastDeployAt(db, app.id, env) || 0);

  if (days && sinceUseOrDeploy >= days * DAY) return { action: 'sleep', reason: 'inactive', why: `${days} days without requests or deploys`, detail: { inactive_days: days } };
  if (schedule && !inSchedule(schedule, now) && sinceRequest >= OUT_OF_WINDOW_IDLE_MIN * MIN) {
    return { action: 'sleep', reason: 'schedule', why: 'outside the schedule window', detail: { schedule } };
  }
  if (idleMin && sinceRequest >= idleMin * MIN) return { action: 'sleep', reason: 'idle', why: `${idleMin} minutes without requests`, detail: { idle_minutes: idleMin } };
  return { action: 'none', why: 'active' };
}

/** One pass. deps: { db, now, listContainers, processStart } for tests. */
export async function runSleeper(deps = {}) {
  const db = deps.db || getDb();
  const now = (deps.now || Date.now)();
  const listContainers = deps.listContainers || defaultListContainers;
  flushActivity(db);
  const targets = liveEnvs(db);
  if (!targets.length) return { slept: [], woken: [], skipped: [] };
  let containers;
  try {
    containers = await listContainers();
  } catch (e) {
    log.warn(`[env-sleeper] skipped, Docker did not answer: ${e.message}`);
    throw new Error(`Docker did not answer: ${e.message}`);
  }
  const { restoreInProgress } = await import('./managedDbRestoreGuard.js');
  const slept = [], woken = [], skipped = [], failed = [];
  for (const t of targets) {
    const env = t.live_env;
    const app = { ...t };
    delete app.live_env;
    ensureTracking(db, app.id, env, now);
    const d = decide(db, app, env, now, { processStart: deps.processStart ?? PROCESS_START });
    if (d.action === 'none') continue;
    const name = `appcrane-${app.slug}-${env}`;
    if (opInFlight(app.id, env) || deployInFlight(db, app.id, env) || restoreInProgress(app.slug, env) || automaticRecreateInFlight(app.id, env)) {
      skipped.push({ name, why: 'busy' });
      continue;
    }
    if (d.action === 'sleep') {
      if (containers.get(name) !== 'running') { skipped.push({ name, why: `container ${containers.get(name) || 'absent'}` }); continue; }
      const r = await sleepEnv(app, env, d.reason, d.detail);
      (r.ok ? slept : failed).push({ name, reason: d.reason, error: r.error });
    } else {
      const r = await wakeEnv(app, env, { reason: d.reason });
      (r.ok ? woken : failed).push({ name, reason: d.reason, error: r.error });
    }
  }
  setJobDetail('env-sleeper', { slept: slept.length, woken: woken.length, failed: failed.length, at: new Date(now).toISOString() });
  if (failed.length) log.warn(`[env-sleeper] ${failed.length} failed: ${failed.map(f => `${f.name}: ${f.error}`).join('; ')}`);
  return { slept, woken, skipped, failed };
}

export function startEnvSleeper() {
  if (timer) return;
  jobStarted('env-sleeper', { cadenceMs: TICK_MS });
  const tick = async () => {
    if (running) return;
    running = true;
    try { await trackJob('env-sleeper', () => runSleeper()); }
    catch (e) { log.error(`[env-sleeper] pass failed: ${e.message}`); }
    finally { running = false; }
  };
  timer = setInterval(tick, TICK_MS);
  timer.unref?.();
}

export function stopEnvSleeper() {
  if (timer) { clearInterval(timer); timer = null; }
}
