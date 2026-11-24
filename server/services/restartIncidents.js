// Restart incidents and restart-loop detection.
//
// Every restart, stop or death of an app container is one restart_incidents
// row (migration 270), whoever caused it:
//   health    the health checker restarted it (healthChecker.js), or skipped a
//             restart because the env is in a restart loop
//   crash     the container exited on its own (Docker's on-failure policy may
//             then restart it; restartWatcher.js sees it in `docker events`)
//   oom       the kernel OOM-killed it (same)
//   recovery  container recovery started the live release again
//   manual / deploy / sleep / restore / stop
//             a planned stop, attributed by restartWatcher.js
//   restart_refused
//             image trust (enforce) refused the health checker's restart; the
//             container was not touched, so it is not counted as a restart
//
// Loop detection counts the UNPLANNED ones (health, crash, oom, recovery).
// After N in a window (platform settings, defaults below) the env is marked
// unstable: the health checker then restarts it only after an exponential
// backoff, the trip is audited, and the app's owners (platform admins when it
// has none) get one mail per episode. A deploy, a manual restart, or a quiet
// period with the env healthy clears it.

import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { scrubSummary, scrubText } from './eventScrub.js';

export const TRIGGERS = ['health', 'crash', 'oom', 'recovery', 'manual', 'deploy', 'sleep', 'restore', 'stop', 'restart_refused'];
export const UNPLANNED = ['health', 'crash', 'oom', 'recovery'];
export const PLANNED = ['manual', 'deploy', 'sleep', 'restore', 'stop'];
export const COUNTED_ACTIONS = ['restarted', 'observed', 'recovered', 'failed'];
export const MEMORY_RATIO = 0.95;

export const LOOP_DEFAULTS = Object.freeze({
  restart_loop_short_count: 3,
  restart_loop_short_minutes: 10,
  restart_loop_long_count: 6,
  restart_loop_long_minutes: 60,
  restart_loop_quiet_minutes: 60,
  restart_backoff_base_minutes: 5,
  restart_backoff_max_minutes: 360,
});
export const RETENTION_DAYS_DEFAULT = 90;
export const RETENTION_KEY = 'restart_incident_retention_days';
export const PER_ENV_CAP = 500;

const MiB = 1024 * 1024;
const DAY = 86_400_000;

export function sqlTime(ms) {
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
}
export function fromSql(s) {
  return s ? Date.parse(String(s).replace(' ', 'T') + 'Z') : null;
}

function setting(db, key) {
  try { return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null; } catch (_) { return null; }
}

/** The loop rules in force. An unset or invalid value falls back to its default. */
export function loopSettings(db = getDb()) {
  const out = {};
  for (const [k, def] of Object.entries(LOOP_DEFAULTS)) {
    const n = Number(setting(db, k));
    out[k] = Number.isInteger(n) && n > 0 && n <= 100_000 ? n : def;
  }
  return out;
}

const fmtMb = (b) => `${Math.round(b / MiB)} MB`;

/**
 * What the capture says caused it. Returns { kind, summary }.
 * kind: memory | exit | health | recovery | planned | unknown
 */
export function classify({ trigger, action, capture = {}, detail = {} }) {
  const m = capture.memory;
  const st = capture.state;

  const ratio = m && m.current != null && m.max ? m.current / m.max : null;
  const oomKilled = trigger === 'oom' || !!(st?.oom_killed && st.status !== 'running');
  const innerOom = !!(st?.oom_killed && st.status === 'running');
  let mem = null;
  if ((ratio != null && ratio >= MEMORY_RATIO) || m?.oom_kill > 0 || oomKilled || innerOom) {
    const bits = [ratio != null ? `memory ${Math.min(100, Math.floor(ratio * 100))}% of ${fmtMb(m.max)}`
      : st?.limit_bytes ? `memory limit ${fmtMb(st.limit_bytes)}` : 'memory'];
    if (oomKilled) bits.push('OOM-killed');
    else if (m?.oom_kill > 0) bits.push(`${m.oom_kill} OOM kill${m.oom_kill === 1 ? '' : 's'} inside the container`);
    else if (innerOom) bits.push('a process inside was OOM-killed');
    mem = bits.join(', ');
  }

  let kind;
  let text;
  if (trigger === 'health') {
    const why = detail.probe_error ? `: ${detail.probe_error}` : detail.last_status ? `: HTTP ${detail.last_status}` : '';
    const h = `health check failed ${detail.consecutive_fails ?? '?'} times${why}`;
    kind = mem ? 'memory' : 'health';
    text = mem ? `${mem} (${h})` : h;
  } else if (trigger === 'crash' || trigger === 'oom') {
    const code = detail.exit_code ?? st?.exit_code;
    const exit = code == null ? 'exited' : `exited with code ${code}`;
    kind = mem ? 'memory' : 'exit';
    text = mem ? (code != null && Number(code) !== 137 ? `${mem}, ${exit}` : mem) : exit;
  } else if (trigger === 'restart_refused') {
    kind = 'refused';
    text = `auto-restart refused by image trust: ${String(detail.error || 'image not trusted').replace(/^IMAGE_UNTRUSTED:\s*/, '').split('. Image trust is in enforce mode')[0]}`;
  } else if (trigger === 'recovery') {
    kind = 'recovery';
    text = action === 'failed'
      ? `container ${detail.container_state || 'missing'}; recovery failed${detail.error ? `: ${detail.error}` : ''}`
      : `container ${detail.container_state || 'missing'}; live release started again`;
  } else {
    kind = 'planned';
    const label = { manual: 'manual restart', deploy: 'deploy', sleep: 'put to sleep', restore: 'database restore', stop: 'stopped outside AppCrane' }[trigger];
    text = mem ? `${label} (${mem})` : label;
  }
  if (action === 'skipped') text = `auto-restart skipped (restart loop): ${text}`;
  if (action === 'observed' && detail.docker_restarts) text += ', restarted by Docker';
  return { kind, summary: scrubSummary(text) };
}

function rowOut(r, { withLogs }) {
  if (!r) return null;
  const parse = (s) => { try { return s ? JSON.parse(s) : null; } catch { return null; } };
  const out = {
    id: r.id, env: r.env, trigger: r.trigger, action: r.action, kind: r.kind, summary: r.summary,
    created_at: r.created_at,
    memory: r.memory_current != null || r.memory_max != null
      ? { current: r.memory_current, max: r.memory_max, source: r.memory_source, oom_kill: r.oom_kill_events }
      : null,
    exit_state: parse(r.exit_state),
    detail: parse(r.detail),
    not_captured: parse(r.not_captured) || [],
  };
  if (withLogs) out.log_tail = parse(r.log_tail) || [];
  return out;
}

/**
 * Write one incident and re-evaluate the loop rules. Returns the row (with logs).
 * Never throws: a recording failure must not get in the way of a restart.
 */
export async function recordIncident({ appId, env, trigger, action, capture = {}, detail = {}, db = getDb(), now = Date.now() }) {
  try {
    if (!TRIGGERS.includes(trigger)) throw new Error(`unknown trigger ${trigger}`);
    const { kind, summary } = classify({ trigger, action, capture, detail });
    const cleanDetail = {};
    for (const [k, v] of Object.entries(detail || {})) cleanDetail[k] = typeof v === 'string' ? scrubText(v).slice(0, 500) : v;
    const m = capture.memory || {};
    const id = Number(db.prepare(`INSERT INTO restart_incidents
        (app_id, env, trigger, action, kind, summary, detail, memory_current, memory_max, memory_source, oom_kill_events,
         exit_state, log_tail, not_captured, container_id, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      appId, env, trigger, action, kind, summary, JSON.stringify(cleanDetail),
      m.current ?? null, m.max ?? null, m.source ?? null, m.oom_kill ?? null,
      capture.state ? JSON.stringify(capture.state) : null,
      capture.log_tail ? JSON.stringify(capture.log_tail) : null,
      capture.not_captured?.length ? JSON.stringify(capture.not_captured) : null,
      capture.container_id || null, sqlTime(now),
    ).lastInsertRowid);
    log.info(`[restart-incident] app ${appId} ${env} ${trigger}/${action}: ${summary}`);
    if (UNPLANNED.includes(trigger) && action !== 'skipped') await evaluateLoop({ appId, env, db, now, incidentId: id });
    return rowOut(db.prepare('SELECT * FROM restart_incidents WHERE id = ?').get(id), { withLogs: true });
  } catch (e) {
    log.error(`[restart-incident] could not record ${trigger} for app ${appId} ${env}: ${e.message}`);
    return null;
  }
}

function stabilityRow(db, appId, env) {
  return db.prepare('SELECT * FROM restart_stability WHERE app_id = ? AND env = ?').get(appId, env) || null;
}

function upsertStability(db, appId, env, fields, now) {
  db.prepare(`INSERT INTO restart_stability (app_id, env, updated_at) VALUES (?, ?, ?)
              ON CONFLICT(app_id, env) DO NOTHING`).run(appId, env, sqlTime(now));
  const keys = Object.keys(fields);
  db.prepare(`UPDATE restart_stability SET ${keys.map(k => `${k} = ?`).join(', ')}, updated_at = ? WHERE app_id = ? AND env = ?`)
    .run(...keys.map(k => fields[k]), sqlTime(now), appId, env);
}

function countSince(db, appId, env, sinceMs) {
  return db.prepare(`SELECT COUNT(*) AS n FROM restart_incidents WHERE app_id = ? AND env = ? AND created_at >= ?
      AND trigger IN (${UNPLANNED.map(() => '?').join(',')}) AND action IN (${COUNTED_ACTIONS.map(() => '?').join(',')})`)
    .get(appId, env, sqlTime(sinceMs), ...UNPLANNED, ...COUNTED_ACTIONS).n;
}

/** Which rule (if any) the recent unplanned restarts trip. */
export function trippedRule(db, appId, env, now, s = loopSettings(db)) {
  for (const [count, minutes] of [[s.restart_loop_short_count, s.restart_loop_short_minutes], [s.restart_loop_long_count, s.restart_loop_long_minutes]]) {
    const n = countSince(db, appId, env, now - minutes * 60_000);
    if (n >= count) return { rule: `${count} restarts in ${minutes} min`, count: n };
  }
  return null;
}

export function backoffMinutes(level, s) {
  return Math.min(s.restart_backoff_base_minutes * 2 ** Math.max(0, level - 1), s.restart_backoff_max_minutes);
}

async function evaluateLoop({ appId, env, db, now, incidentId }) {
  const s = loopSettings(db);
  const cur = getStability({ appId, env, db, now });
  if (cur.unstable) {
    upsertStability(db, appId, env, { last_incident_id: incidentId }, now);
    return;
  }
  const hit = trippedRule(db, appId, env, now, s);
  if (!hit) return;
  const episode = (stabilityRow(db, appId, env)?.episode || 0) + 1;
  const next = now + backoffMinutes(1, s) * 60_000;
  upsertStability(db, appId, env, {
    unstable: 1, unstable_since: sqlTime(now), episode, tripped_rule: hit.rule, backoff_level: 1,
    next_restart_at: sqlTime(next), last_incident_id: incidentId, cleared_at: null, cleared_reason: null,
  }, now);
  const incident = db.prepare('SELECT * FROM restart_incidents WHERE id = ?').get(incidentId);
  log.warn(`[restart-loop] app ${appId} ${env} is unstable: ${hit.rule}; auto-restart backs off until ${sqlTime(next)} UTC`);
  try {
    const { logAudit } = await import('../middleware/audit.js');
    logAudit(null, appId, 'restart-loop-detected', { env, rule: hit.rule, restarts: hit.count, episode, last_incident: incident?.summary, next_restart_at: sqlTime(next) }, 'system');
  } catch (e) { log.warn(`[restart-loop] audit failed: ${e.message}`); }
  try {
    const { notifyRestartLoop } = await import('./emailService.js');
    await notifyRestartLoop({ db, appId, env, episode, rule: hit.rule, restarts: hit.count, lastSummary: incident?.summary, lastAt: incident?.created_at, nextRestartAt: sqlTime(next) });
  } catch (e) { log.warn(`[restart-loop] owner mail failed: ${e.message}`); }
}

function clearUnstable(db, appId, env, reason, now) {
  upsertStability(db, appId, env, { unstable: 0, backoff_level: 0, next_restart_at: null, cleared_at: sqlTime(now), cleared_reason: reason }, now);
  log.info(`[restart-loop] app ${appId} ${env} is stable again (${reason})`);
  import('../middleware/audit.js')
    .then(({ logAudit }) => logAudit(null, appId, 'restart-loop-cleared', { env, reason }, 'system'))
    .catch(e => log.warn(`[restart-loop] audit failed: ${e.message}`));
}

/**
 * The env's loop state, clearing it first when a deploy finished, someone
 * restarted it by hand, or it has been healthy with no unplanned restart for
 * the quiet period since it was marked.
 */
export function getStability({ appId, env, db = getDb(), now = Date.now() }) {
  const row = stabilityRow(db, appId, env);
  if (!row?.unstable) return { unstable: false, episode: row?.episode || 0, cleared_at: row?.cleared_at || null, cleared_reason: row?.cleared_reason || null };
  const since = row.unstable_since;
  const deployed = db.prepare(`SELECT id FROM deployments WHERE app_id = ? AND env = ? AND status = 'live' AND finished_at > ? LIMIT 1`)
    .get(appId, env, since);
  if (deployed) { clearUnstable(db, appId, env, `deployment #${deployed.id}`, now); return getStability({ appId, env, db, now }); }
  const manual = db.prepare(`SELECT id FROM audit_log WHERE app_id = ? AND action = 'restart' AND created_at > ? AND detail LIKE ? LIMIT 1`)
    .get(appId, since, `%"env":"${env}"%`);
  if (manual) { clearUnstable(db, appId, env, 'manual restart', now); return getStability({ appId, env, db, now }); }
  const s = loopSettings(db);
  const quietSince = now - s.restart_loop_quiet_minutes * 60_000;
  const healthy = db.prepare('SELECT consecutive_fails FROM health_state WHERE app_id = ? AND env = ?').get(appId, env);
  if (fromSql(since) < quietSince && healthy && healthy.consecutive_fails === 0 && countSince(db, appId, env, quietSince) === 0) {
    clearUnstable(db, appId, env, `quiet for ${s.restart_loop_quiet_minutes} min`, now);
    return getStability({ appId, env, db, now });
  }
  return {
    unstable: true, since, episode: row.episode, rule: row.tripped_rule, backoff_level: row.backoff_level,
    next_restart_at: row.next_restart_at,
  };
}

/**
 * For the health checker: may it restart this env now? Stable envs always may.
 * An unstable env may once next_restart_at has passed, and each restart doubles
 * the wait (up to restart_backoff_max_minutes).
 */
export function restartDecision({ appId, env, db = getDb(), now = Date.now() }) {
  const st = getStability({ appId, env, db, now });
  if (!st.unstable) return { allowed: true, unstable: false };
  if (fromSql(st.next_restart_at) > now) {
    return { allowed: false, unstable: true, reason: `restart loop (${st.rule}); next automatic restart after ${st.next_restart_at} UTC`, next_restart_at: st.next_restart_at };
  }
  return { allowed: true, unstable: true, backoff_level: st.backoff_level };
}

/** Called after a backoff restart went ahead: push the next one out. */
export function noteBackoffRestart({ appId, env, db = getDb(), now = Date.now() }) {
  const row = stabilityRow(db, appId, env);
  if (!row?.unstable) return;
  const s = loopSettings(db);
  const level = (row.backoff_level || 1) + 1;
  upsertStability(db, appId, env, { backoff_level: level, next_restart_at: sqlTime(now + backoffMinutes(level, s) * 60_000) }, now);
}

export function listIncidents({ appId, env = null, limit = 50, withLogs = false, db = getDb() }) {
  const rows = env
    ? db.prepare('SELECT * FROM restart_incidents WHERE app_id = ? AND env = ? ORDER BY created_at DESC, id DESC LIMIT ?').all(appId, env, limit)
    : db.prepare('SELECT * FROM restart_incidents WHERE app_id = ? ORDER BY created_at DESC, id DESC LIMIT ?').all(appId, limit);
  return rows.map(r => rowOut(r, { withLogs }));
}

/** { summary, created_at, trigger, action, kind } of the newest incident, or null. */
export function lastIncident({ appId, env, db = getDb() }) {
  const r = db.prepare('SELECT id, trigger, action, kind, summary, created_at FROM restart_incidents WHERE app_id = ? AND env = ? ORDER BY created_at DESC, id DESC LIMIT 1')
    .get(appId, env);
  return r ? { id: r.id, summary: r.summary, created_at: r.created_at, trigger: r.trigger, action: r.action, kind: r.kind } : null;
}

/** Counts per trigger since `sinceMs`, unplanned and planned. */
export function incidentCounts({ appId, env, sinceMs, db = getDb() }) {
  const rows = db.prepare(`SELECT trigger, COUNT(*) AS n FROM restart_incidents WHERE app_id = ? AND env = ? AND created_at >= ?
      AND action != 'skipped' GROUP BY trigger`).all(appId, env, sqlTime(sinceMs));
  const by = Object.fromEntries(rows.map(r => [r.trigger, r.n]));
  const sum = (list) => list.reduce((a, t) => a + (by[t] || 0), 0);
  return { by_trigger: by, unplanned: sum(UNPLANNED), planned: sum(PLANNED), refused: by.restart_refused || 0 };
}

/** Did anything record an incident for this env within `ms`? (The watcher uses it to avoid doubles.) */
export function recentIncident({ appId, env, ms, triggers = TRIGGERS, db = getDb(), now = Date.now() }) {
  return db.prepare(`SELECT id, trigger FROM restart_incidents WHERE app_id = ? AND env = ? AND created_at >= ?
      AND trigger IN (${triggers.map(() => '?').join(',')}) ORDER BY id DESC LIMIT 1`)
    .get(appId, env, sqlTime(now - ms), ...triggers) || null;
}

export function retentionDays(db = getDb()) {
  const n = Number(setting(db, RETENTION_KEY));
  return Number.isInteger(n) && n >= 1 && n <= 3650 ? n : RETENTION_DAYS_DEFAULT;
}

/** Drop incidents past the retention window, and keep at most PER_ENV_CAP per env. */
export function pruneIncidents({ db = getDb(), now = Date.now(), cap = PER_ENV_CAP } = {}) {
  const aged = db.prepare('DELETE FROM restart_incidents WHERE created_at < ?').run(sqlTime(now - retentionDays(db) * DAY)).changes;
  let capped = 0;
  for (const { app_id, env } of db.prepare('SELECT app_id, env FROM restart_incidents GROUP BY app_id, env HAVING COUNT(*) > ?').all(cap)) {
    capped += db.prepare(`DELETE FROM restart_incidents WHERE app_id = ? AND env = ? AND id NOT IN (
        SELECT id FROM restart_incidents WHERE app_id = ? AND env = ? ORDER BY created_at DESC, id DESC LIMIT ?)`)
      .run(app_id, env, app_id, env, cap).changes;
  }
  if (aged + capped) log.info(`[restart-incident] retention removed ${aged + capped} incident(s)`);
  return { aged, capped };
}

let timers = [];
export function startIncidentRetention() {
  if (timers.length) return;
  const go = () => { try { pruneIncidents(); } catch (e) { log.warn(`[restart-incident] retention failed: ${e.message}`); } };
  const first = setTimeout(go, 15 * 60_000);
  const daily = setInterval(go, DAY);
  first.unref?.(); daily.unref?.();
  timers = [first, daily];
}
export function stopIncidentRetention() {
  for (const t of timers) { clearTimeout(t); clearInterval(t); }
  timers = [];
}

// An AppCrane path about to stop or restart a container it records itself
// (health, recovery) says so here first, so restartWatcher.js does not record
// the same stop a second time as unattributed.
const expected = new Map();
export const EXPECT_MS = 90_000;
export function expectPlanned(appId, env, trigger, now = Date.now()) {
  expected.set(`${appId}:${env}`, { trigger, until: now + EXPECT_MS });
}
export function takeExpected(appId, env, now = Date.now()) {
  const k = `${appId}:${env}`;
  const e = expected.get(k);
  if (!e) return null;
  if (e.until < now) { expected.delete(k); return null; }
  return e.trigger;
}
