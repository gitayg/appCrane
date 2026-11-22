import { AppError } from '../utils/errors.js';
import { RETENTION_DAYS, activityOf, flushActivity } from './envActivity.js';
import { usageCoverage } from './usageCoverage.js';
import { inactivityForecast } from './envSleeper.js';
import { effectivePolicy } from './sleepPolicy.js';

// Usage analytics over env_activity_daily (requests per app/env/day) and
// env_activity_users (signed-in users per app/env/day, with their requests).
// All days are UTC.
//
//   DAU(d)   distinct users active on d
//   WAU(d)   distinct users active on any day in [d-6, d]
//   MAU(d)   distinct users active on any day in [d-29, d] (a union of user
//            sets, never a sum of DAUs)
//   stickiness(d)  DAU(d) / MAU(d); the summary is mean DAU over the 30 days
//            ending `to`, divided by MAU(to)
//   new user in week W  first day on record for the app (env filter applied,
//            within retention) falls in W; returning = active in W and not new
//   funnel   granted (active users with a role other than 'none' in app_user_roles)
//            -> signed in at least once (any activity row, or app_visits)
//            -> active on >= 3 distinct days of the 30 ending `to`
//            -> active in the 7 days ending `to`
//            Every stage is a subset of the one before it.

const DAY = 86_400_000;
export const MAX_RANGE_DAYS = 366;
export const DEFAULT_RANGE_DAYS = 90;
export const TOP_USERS = 20;
const ENVS = { sandbox: ['sandbox'], production: ['production'], all: ['sandbox', 'production'] };

let clock = () => Date.now();
export function _setUsageClockForTests(fn) { clock = fn || (() => Date.now()); }
export const usageNow = () => clock();

const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
const dayMs = (day) => Date.parse(`${day}T00:00:00Z`);
const addDays = (day, n) => dayOf(dayMs(day) + n * DAY);
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const round4 = (x) => Math.round(x * 10000) / 10000;

function parseDay(name, v) {
  if (v === undefined || v === '') return null;
  if (typeof v !== 'string' || !DAY_RE.test(v) || !Number.isFinite(dayMs(v)) || dayOf(dayMs(v)) !== v) {
    throw new AppError(`${name} must be a date, YYYY-MM-DD`, 400, 'VALIDATION');
  }
  return v;
}

/** { env, envs, from, to, clamped } from query params. Throws 400. */
export function parseUsageQuery(q, now = usageNow()) {
  const env = q.env === undefined || q.env === '' ? 'production' : String(q.env);
  if (!ENVS[env]) throw new AppError('env must be sandbox, production or all', 400, 'VALIDATION');
  const today = dayOf(now);
  let to = parseDay('to', q.to) || today;
  if (to > today) to = today;
  let from = parseDay('from', q.from) || addDays(to, -(DEFAULT_RANGE_DAYS - 1));
  if (from > to) throw new AppError('from must not be after to', 400, 'VALIDATION');
  if ((dayMs(to) - dayMs(from)) / DAY + 1 > MAX_RANGE_DAYS) {
    throw new AppError(`The range can be at most ${MAX_RANGE_DAYS} days`, 400, 'VALIDATION');
  }
  // MAU on `from` reads 29 days before it; nothing older than retention exists.
  const oldest = addDays(today, -(RETENTION_DAYS - 1) + 29);
  let clamped = false;
  if (from < oldest) { from = oldest; clamped = true; }
  if (from > to) from = to;
  return { env, envs: ENVS[env], from, to, clamped };
}

function daysBetween(from, to) {
  const out = [];
  for (let d = from; d <= to; d = addDays(d, 1)) out.push(d);
  return out;
}

const mondayOf = (day) => addDays(day, -((new Date(dayMs(day)).getUTCDay() + 6) % 7));

export function aggregatesOnly(db, appId) {
  return !!db.prepare('SELECT aggregates_only FROM app_usage_settings WHERE app_id = ?').get(appId)?.aggregates_only;
}

export function setAggregatesOnly(db, appId, on, userId) {
  db.prepare(`INSERT INTO app_usage_settings (app_id, aggregates_only, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
              ON CONFLICT(app_id) DO UPDATE SET aggregates_only = excluded.aggregates_only,
                updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(appId, on ? 1 : 0, userId ?? null);
}

/**
 * Usage of one app. opts: { env, envs, from, to, clamped } from parseUsageQuery,
 * perUser (false leaves top_users null), now.
 */
export function appUsage(db, app, opts) {
  const { env, envs, from, to, perUser, now = usageNow() } = opts;
  flushActivity(db, now);
  const inEnv = envs.map(() => '?').join(',');
  const lookback = addDays(from, -29);
  const allDays = daysBetween(lookback, to);
  const index = new Map(allDays.map((d, i) => [d, i]));

  const requestsByDay = new Map(db.prepare(`
    SELECT day, SUM(requests) AS n FROM env_activity_daily
    WHERE app_id = ? AND env IN (${inEnv}) AND day BETWEEN ? AND ? GROUP BY day`)
    .all(app.id, ...envs, from, to).map(r => [r.day, r.n]));

  const userDays = db.prepare(`
    SELECT DISTINCT day, user_id FROM env_activity_users
    WHERE app_id = ? AND env IN (${inEnv}) AND day BETWEEN ? AND ?`).all(app.id, ...envs, lookback, to);
  const activeOn = allDays.map(() => []);
  for (const r of userDays) activeOn[index.get(r.day)].push(r.user_id);

  const last = new Map();
  const daily = [];
  const fromIdx = index.get(from);
  for (let i = 0; i < allDays.length; i++) {
    for (const u of activeOn[i]) last.set(u, i);
    if (i < fromIdx) continue;
    let wau = 0, mau = 0;
    for (const l of last.values()) { if (l >= i - 29) { mau++; if (l >= i - 6) wau++; } }
    const dau = activeOn[i].length;
    daily.push({ day: allDays[i], requests: requestsByDay.get(allDays[i]) || 0, dau, wau, mau, stickiness: mau ? round4(dau / mau) : null });
  }
  const end = daily[daily.length - 1];
  const toIdx = index.get(to);
  let dauSum = 0;
  for (let i = toIdx - 29; i <= toIdx; i++) dauSum += activeOn[i].length;

  const firstSeen = new Map(db.prepare(`
    SELECT user_id, MIN(day) AS d FROM env_activity_users WHERE app_id = ? AND env IN (${inEnv}) AND day <= ? GROUP BY user_id`)
    .all(app.id, ...envs, to).map(r => [r.user_id, r.d]));
  const cov = usageCoverage(db, app, envs, from);

  const weeks = [];
  for (let ws = mondayOf(from); ws <= to; ws = addDays(ws, 7)) {
    const we = addDays(ws, 6);
    const lo = ws < from ? from : ws, hi = we > to ? to : we;
    const active = new Set();
    for (let i = index.get(lo); i <= index.get(hi); i++) for (const u of activeOn[i]) active.add(u);
    let fresh = 0;
    for (const u of active) { const f = firstSeen.get(u); if (f >= ws && f <= we) fresh++; }
    weeks.push({
      week_start: ws, active: active.size, new: fresh, returning: active.size - fresh,
      partial_week: lo !== ws || hi !== we,
      first_tracked_week: !!cov.tracking_since && ws <= cov.tracking_since,
    });
  }

  const granted = new Set(db.prepare(`
    SELECT r.user_id FROM app_user_roles r JOIN users u ON u.id = r.user_id
    WHERE r.app_id = ? AND r.app_role <> 'none' AND u.active = 1`).all(app.id).map(r => r.user_id));
  const everVisited = new Set(db.prepare('SELECT DISTINCT user_id FROM app_visits WHERE app_id = ? AND day <= ?').all(app.id, to).map(r => r.user_id));
  const daysIn30 = new Map(), in7 = new Set();
  for (let i = toIdx - 29; i <= toIdx; i++) {
    for (const u of activeOn[i]) {
      daysIn30.set(u, (daysIn30.get(u) || 0) + 1);
      if (i >= toIdx - 6) in7.add(u);
    }
  }
  const signedIn = [...granted].filter(u => firstSeen.has(u) || everVisited.has(u));
  const engaged = signedIn.filter(u => (daysIn30.get(u) || 0) >= 3);
  const thisWeek = engaged.filter(u => in7.has(u));
  const funnel = {
    granted: granted.size,
    signed_in: signedIn.length,
    active_3_days_in_30: engaged.length,
    active_this_week: thisWeek.length,
    active_without_grant: [...daysIn30.keys()].filter(u => !granted.has(u)).length,
  };

  let topUsers = null;
  if (perUser) {
    topUsers = db.prepare(`
      SELECT a.user_id, u.name, u.email, SUM(a.requests) AS requests, COUNT(DISTINCT a.day) AS active_days, MAX(a.day) AS last_seen
      FROM env_activity_users a JOIN users u ON u.id = a.user_id
      WHERE a.app_id = ? AND a.env IN (${inEnv}) AND a.day BETWEEN ? AND ?
      GROUP BY a.user_id ORDER BY requests DESC, active_days DESC, last_seen DESC, a.user_id LIMIT ?`)
      .all(app.id, ...envs, from, to, TOP_USERS);
  }

  return {
    app: app.slug,
    env,
    range: { from, to, clamped: !!opts.clamped, retention_days: RETENTION_DAYS },
    ...cov,
    summary: {
      requests: daily.reduce((n, d) => n + d.requests, 0),
      dau: end.dau, wau: end.wau, mau: end.mau,
      stickiness: end.mau ? round4(dauSum / 30 / end.mau) : null,
    },
    daily,
    weeks,
    funnel,
    top_users: topUsers,
    per_user_hidden: perUser ? null : 'aggregates_only',
  };
}

/**
 * Every app, least used first, with what the inactivity sleep would do to each
 * live environment and when.
 */
export function leastUsedApps(db, now = usageNow()) {
  flushActivity(db, now);
  const today = dayOf(now), since = addDays(today, -29);
  const users30 = new Map(db.prepare(`
    SELECT app_id, COUNT(DISTINCT user_id) AS n FROM env_activity_users WHERE day BETWEEN ? AND ? GROUP BY app_id`)
    .all(since, today).map(r => [r.app_id, r.n]));
  const req30 = new Map(db.prepare(`
    SELECT app_id, SUM(requests) AS n FROM env_activity_daily WHERE day BETWEEN ? AND ? GROUP BY app_id`)
    .all(since, today).map(r => [r.app_id, r.n]));
  const live = db.prepare("SELECT DISTINCT app_id, env FROM deployments WHERE status = 'live'").all();
  const liveBy = new Map();
  for (const r of live) liveBy.set(r.app_id, [...(liveBy.get(r.app_id) || []), r.env]);
  const iso = (ms) => (ms ? new Date(ms).toISOString() : null);

  const apps = db.prepare('SELECT * FROM apps ORDER BY slug').all().map(app => {
    let lastUse = null;
    for (const env of ['sandbox', 'production']) {
      const t = activityOf(db, app.id, env).lastRequestAt;
      if (t && (lastUse == null || t > lastUse)) lastUse = t;
    }
    const envs = (liveBy.get(app.id) || []).sort().map(env => {
      const f = inactivityForecast(db, app, env);
      return {
        env, state: f.state, inactive_days: f.inactive_days, not_eligible: f.blockers,
        idle_since: iso(f.idle_since), sleeps_at: iso(f.sleeps_at),
        due: f.sleeps_at != null && f.sleeps_at <= now,
      };
    });
    const cov = usageCoverage(db, app, ['sandbox', 'production'], since);
    return {
      slug: app.slug, name: app.name,
      last_use_at: iso(lastUse),
      active_users_30d: users30.get(app.id) || 0,
      requests_30d: req30.get(app.id) || 0,
      coverage: cov.coverage, coverage_reasons: cov.coverage_reasons, tracking_since: cov.tracking_since,
      inactive_days: effectivePolicy(db, app.id).inactive_days,
      envs,
    };
  });
  apps.sort((a, b) => a.active_users_30d - b.active_users_30d
    || (a.last_use_at || '').localeCompare(b.last_use_at || '') || a.slug.localeCompare(b.slug));
  return { now: iso(now), window_days: 30, apps };
}
