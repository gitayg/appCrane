import { randomBytes } from 'crypto';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { parseBypassPaths } from '../utils/authBypassPaths.js';
import { getIngressForApp } from './tcpIngress.js';

// Who sleeps, and when.
//
//   sandbox_idle_minutes  sandbox only: stop after this many minutes with no
//                         request (10-1440, 0 off).
//   sandbox_schedule      sandbox only: {days, start, end, tz}. Outside the
//                         window the sandbox is stopped; a request still wakes
//                         it, and it goes back to sleep after OUT_OF_WINDOW_IDLE_MIN.
//   inactive_days         either environment, production included: stop after
//                         this many days with no request and no deploy (7-365, 0 off).
//
// Platform defaults are all off. An app value of NULL inherits the platform's.

export const IDLE_MIN = 10;
export const IDLE_MAX = 1440;
export const INACTIVE_MIN = 7;
export const INACTIVE_MAX = 365;
export const OUT_OF_WINDOW_IDLE_MIN = 10;

const DAY_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const HHMM = /^([01]\d|2[0-3]):([0-5]\d)$/;

function bounded(name, v, min, max) {
  if (v === null) return null;
  const n = Number(v);
  if (!Number.isInteger(n) || (n !== 0 && (n < min || n > max))) {
    throw new AppError(`${name} must be 0 (off) or a whole number from ${min} to ${max}`, 400, 'VALIDATION');
  }
  return n;
}

export function validTimeZone(tz) {
  if (typeof tz !== 'string' || !tz || tz.length > 64) return false;
  try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); return true; } catch { return false; }
}

/** A schedule from the API: null (inherit), 'off', or {days, start, end, tz}. Throws 400. */
export function parseSchedule(v) {
  if (v === null || v === undefined) return null;
  if (v === 'off' || v === false) return 'off';
  if (typeof v !== 'object' || Array.isArray(v)) throw new AppError("schedule must be null, 'off' or {days, start, end, tz}", 400, 'VALIDATION');
  const days = Array.isArray(v.days) ? v.days : null;
  if (!days || !days.length || days.length > 7) throw new AppError('schedule.days must list 1 to 7 days (0 = Sunday … 6 = Saturday)', 400, 'VALIDATION');
  const set = new Set();
  for (const d of days) {
    const n = typeof d === 'string' ? DAY_NAMES.indexOf(d.toLowerCase().slice(0, 3)) : d;
    if (!Number.isInteger(n) || n < 0 || n > 6) throw new AppError(`schedule.days has an invalid day: ${JSON.stringify(d)}`, 400, 'VALIDATION');
    set.add(n);
  }
  if (!HHMM.test(String(v.start)) || !HHMM.test(String(v.end))) throw new AppError('schedule.start and schedule.end must be HH:MM (24-hour)', 400, 'VALIDATION');
  if (v.start === v.end) throw new AppError('schedule.start and schedule.end must differ', 400, 'VALIDATION');
  if (!validTimeZone(v.tz)) throw new AppError('schedule.tz must be an IANA time zone, e.g. Europe/London', 400, 'VALIDATION');
  return { days: [...set].sort(), start: v.start, end: v.end, tz: v.tz };
}

function readSchedule(raw) {
  if (raw == null) return null;
  if (raw === 'off') return 'off';
  try { return parseSchedule(JSON.parse(raw)); } catch { return 'off'; }
}
const writeSchedule = (s) => (s == null ? null : s === 'off' ? 'off' : JSON.stringify(s));

const minutes = (hhmm) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3));

function localParts(ms, tz) {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .formatToParts(new Date(ms));
  const get = (t) => parts.find(p => p.type === t)?.value;
  return { day: DAY_NAMES.indexOf(get('weekday').toLowerCase()), minute: Number(get('hour')) * 60 + Number(get('minute')) };
}

/** Is `ms` inside the schedule's window? An end before the start runs past midnight. */
export function inSchedule(schedule, ms) {
  if (!schedule || schedule === 'off') return true;
  const { day, minute } = localParts(ms, schedule.tz);
  const days = new Set(schedule.days);
  const s = minutes(schedule.start), e = minutes(schedule.end);
  if (s < e) return days.has(day) && minute >= s && minute < e;
  return (days.has(day) && minute >= s) || (days.has((day + 6) % 7) && minute < e);
}

export function getPlatformPolicy(db = getDb()) {
  const r = db.prepare('SELECT * FROM sleep_platform WHERE id = 1').get() || {};
  return {
    sandbox_idle_minutes: r.sandbox_idle_minutes || 0,
    sandbox_schedule: readSchedule(r.sandbox_schedule) || 'off',
    inactive_days: r.inactive_days || 0,
    updated_at: r.updated_at || null,
  };
}

export function getAppPolicy(db, appId) {
  const r = db.prepare('SELECT * FROM app_sleep_policy WHERE app_id = ?').get(appId) || {};
  return {
    sandbox_idle_minutes: r.sandbox_idle_minutes ?? null,
    sandbox_schedule: readSchedule(r.sandbox_schedule ?? null),
    inactive_days: r.inactive_days ?? null,
    updated_at: r.updated_at || null,
  };
}

/** The values that apply to the app: each override, else the platform's. */
export function effectivePolicy(db, appId) {
  const p = getPlatformPolicy(db), a = getAppPolicy(db, appId);
  const schedule = a.sandbox_schedule ?? p.sandbox_schedule;
  return {
    sandbox_idle_minutes: a.sandbox_idle_minutes ?? p.sandbox_idle_minutes,
    sandbox_schedule: schedule === 'off' ? null : schedule,
    inactive_days: a.inactive_days ?? p.inactive_days,
  };
}

/** Parse a PUT body into stored values. Keys left out keep their value. */
export function parsePolicyBody(body, { allowNull }) {
  const out = {};
  if ('sandbox_idle_minutes' in body) {
    if (body.sandbox_idle_minutes === null && !allowNull) throw new AppError('sandbox_idle_minutes cannot be null here', 400, 'VALIDATION');
    out.sandbox_idle_minutes = bounded('sandbox_idle_minutes', body.sandbox_idle_minutes, IDLE_MIN, IDLE_MAX);
  }
  if ('sandbox_schedule' in body) {
    if (body.sandbox_schedule === null && !allowNull) throw new AppError("sandbox_schedule cannot be null here; use 'off'", 400, 'VALIDATION');
    out.sandbox_schedule = parseSchedule(body.sandbox_schedule);
  }
  if ('inactive_days' in body) {
    if (body.inactive_days === null && !allowNull) throw new AppError('inactive_days cannot be null here', 400, 'VALIDATION');
    out.inactive_days = bounded('inactive_days', body.inactive_days, INACTIVE_MIN, INACTIVE_MAX);
  }
  if (!Object.keys(out).length) throw new AppError('Nothing to change: send sandbox_idle_minutes, sandbox_schedule or inactive_days', 400, 'VALIDATION');
  return out;
}

export function setPlatformPolicy(db, values, userId) {
  const cur = db.prepare('SELECT * FROM sleep_platform WHERE id = 1').get();
  const next = {
    sandbox_idle_minutes: values.sandbox_idle_minutes ?? cur.sandbox_idle_minutes,
    sandbox_schedule: 'sandbox_schedule' in values ? writeSchedule(values.sandbox_schedule) : cur.sandbox_schedule,
    inactive_days: values.inactive_days ?? cur.inactive_days,
  };
  db.prepare(`UPDATE sleep_platform SET sandbox_idle_minutes = ?, sandbox_schedule = ?, inactive_days = ?,
              updated_at = datetime('now'), updated_by = ? WHERE id = 1`)
    .run(next.sandbox_idle_minutes, next.sandbox_schedule, next.inactive_days, userId ?? null);
}

export function setAppPolicy(db, appId, values, userId) {
  const cur = db.prepare('SELECT * FROM app_sleep_policy WHERE app_id = ?').get(appId) || {};
  const pick = (k) => (k in values ? values[k] : (cur[k] ?? null));
  db.prepare(`INSERT INTO app_sleep_policy (app_id, sandbox_idle_minutes, sandbox_schedule, inactive_days, updated_at, updated_by)
              VALUES (?, ?, ?, ?, datetime('now'), ?)
              ON CONFLICT(app_id) DO UPDATE SET sandbox_idle_minutes = excluded.sandbox_idle_minutes,
                sandbox_schedule = excluded.sandbox_schedule, inactive_days = excluded.inactive_days,
                updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(appId, pick('sandbox_idle_minutes'),
      'sandbox_schedule' in values ? writeSchedule(values.sandbox_schedule) : (cur.sandbox_schedule ?? null),
      pick('inactive_days'), userId ?? null);
}

/** Does any app (or the platform default) put anything to sleep? Gates the Caddy wake header. */
export function sleepEnabledAnywhere(db = getDb()) {
  let p;
  try { p = db.prepare('SELECT * FROM sleep_platform WHERE id = 1').get(); } catch { return false; }
  if (!p) return false;
  if (p.sandbox_idle_minutes > 0 || p.inactive_days > 0 || (p.sandbox_schedule && p.sandbox_schedule !== 'off')) return true;
  return !!db.prepare(`SELECT 1 FROM app_sleep_policy WHERE sandbox_idle_minutes > 0 OR inactive_days > 0
                       OR (sandbox_schedule IS NOT NULL AND sandbox_schedule != 'off') LIMIT 1`).get();
}

/** The token Caddy's crash-page rewrite carries (created on first use). */
export function wakeToken(db = getDb()) {
  const row = db.prepare('SELECT wake_token FROM sleep_platform WHERE id = 1').get();
  if (row?.wake_token) return row.wake_token;
  const token = randomBytes(32).toString('base64url');
  db.prepare('UPDATE sleep_platform SET wake_token = COALESCE(wake_token, ?) WHERE id = 1').run(token);
  return db.prepare('SELECT wake_token FROM sleep_platform WHERE id = 1').get().wake_token;
}

/**
 * Can AppCrane see every request this env gets? Only then may it decide the
 * env is idle. Requests are counted at forward_auth, so anything that reaches
 * the container without it would look like silence:
 *   - a headless app (no forward_auth at all) and auth-bypass paths;
 *   - a tcp or dual ingress, whose public port goes straight to the container;
 *   - production on a custom domain (no forward_auth unless custom_domain_auth,
 *     and no crash-page rewrite to wake it from either way);
 *   - production with enabled cron jobs: their work is the app's use, and they
 *     cannot run while it sleeps.
 */
export function sleepBlockers(db, app, env) {
  const reasons = [];
  if (app.auth_mode === 'headless') reasons.push('the app is headless, so AppCrane does not see its requests');
  if (app.auth_mode !== 'headless' && parseBypassPaths(app.auth_bypass_paths, () => {}).length) {
    reasons.push('the app has auth-bypass paths, whose requests AppCrane does not see');
  }
  if (getIngressForApp(db, app.id).ingress_type !== 'http') reasons.push('the app publishes a raw TCP port that bypasses AppCrane');
  if (env === 'production') {
    if ((app.domain || '').trim()) reasons.push('production is served on a custom domain, which AppCrane cannot wake it from');
    if (db.prepare("SELECT 1 FROM app_cron_jobs WHERE app_id = ? AND env = 'production' AND enabled = 1 LIMIT 1").get(app.id)) {
      reasons.push('production has enabled cron jobs, which cannot run while it sleeps');
    }
  }
  return reasons;
}
