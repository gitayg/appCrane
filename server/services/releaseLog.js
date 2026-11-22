import { AppError } from '../utils/errors.js';
import { fromSqlTime, flushActivity } from './envActivity.js';
import { usageNow } from './usageAnalytics.js';

// The release log (routes/releases.js, appcrane_list_app_releases): every
// deployment of an app per environment, with a status derived from the columns
// the deployer already writes and what the app saw while each release was live.
//
// Derived status:
//   live           deployments.status 'live'
//   replaced       'rolled_back' and the next release that went live was a deploy
//   rolled back    'rolled_back' and the next release that went live was a rollback
//                  (its log starts "Rollback to deployment #N", deployer.js rollbackApp)
//   auto-reverted  'failed' and the log says the deployer restored the previous image
//   failed         'failed' otherwise
//   in progress    pending / building / deploying
// A production release whose log starts "Promote from sandbox #N" / "Promoted from
// sandbox deployment #N" (deployer.js promoteApp) is kind 'promote' and names its
// sandbox source; that sandbox release lists it in promoted_to.
//
// Metrics while live, [live_from, live_until or now):
//   requests       env_activity_daily, each UTC day pro-rated by how much of it
//                  (up to now) the release was live
//   active_users   distinct users in env_activity_users on the days it was live
//                  (day granularity, not pro-rated)
//   restarts       audit_log 'restart' rows for that env (dashboard and API
//                  restarts; a container's own crash restarts are not recorded)
//   error_rate, p95_ms  null: the activity counters store neither the response
//                  status nor its timing (envActivity.js noteRequest), so there
//                  is nothing to compute them from.

export const LABEL_RE = /^[A-Za-z0-9._=-]{1,40}$/;
export const LABEL_RULE = 'label must be 1-40 characters of letters, digits and . _ = -';
export const METRICS_UNAVAILABLE = {
  error_rate: 'Not recorded: request counting at forward_auth keeps no response status.',
  p95_ms: 'Not recorded: request counting at forward_auth keeps no response timing.',
};
const DAY = 86_400_000;
const ENVS = ['production', 'sandbox'];
const MAX_ROWS = 200;
const ROLLBACK_RE = /^Rollback to deployment #(\d+)/;
const PROMOTE_RE = /^Promote(?:d)? from sandbox (?:deployment )?#(\d+)/;
const REVERT_MARK = 'Reverting to previous image';

/** null for absent or empty; the label otherwise. Throws 400 on anything else. */
export function parseLabel(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw !== 'string' || !LABEL_RE.test(raw)) throw new AppError(LABEL_RULE, 400, 'VALIDATION');
  return raw;
}

export function parseReleaseQuery(q) {
  const env = q.env || null;
  if (env && !ENVS.includes(env)) throw new AppError('env must be production or sandbox', 400, 'VALIDATION');
  return { env, label: parseLabel(q.label) };
}

export function setReleaseLabel(db, app, id, raw) {
  const label = parseLabel(raw);
  const row = db.prepare('SELECT id FROM deployments WHERE id = ? AND app_id = ?').get(id, app.id);
  if (!row) throw new AppError('Release not found', 404, 'NOT_FOUND');
  db.prepare('UPDATE deployments SET release_label = ? WHERE id = ?').run(label, id);
  return { id, label };
}

const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
const round = (x, n = 2) => (x == null ? null : Math.round(x * 10 ** n) / 10 ** n);

function metricsFor(db, app, env, from, to, now) {
  if (from == null) return null;
  const end = to ?? now;
  const days = [];
  for (let d = Date.parse(`${dayOf(from)}T00:00:00Z`); d < end; d += DAY) days.push(d);
  if (!days.length) days.push(Date.parse(`${dayOf(from)}T00:00:00Z`));
  const daily = db.prepare('SELECT requests FROM env_activity_daily WHERE app_id = ? AND env = ? AND day = ?');
  const usersOn = db.prepare('SELECT COUNT(*) AS n FROM env_activity_users WHERE app_id = ? AND env = ? AND day = ?');
  let requests = 0;
  let userDays = 0;
  for (const d of days) {
    const dayEnd = Math.min(d + DAY, now);
    const span = dayEnd - d;
    const overlap = Math.min(end, dayEnd) - Math.max(from, d);
    const n = daily.get(app.id, env, dayOf(d))?.requests || 0;
    if (span > 0 && overlap > 0) requests += n * Math.min(1, overlap / span);
    userDays += usersOn.get(app.id, env, dayOf(d)).n;
  }
  const activeUsers = db.prepare(`SELECT COUNT(DISTINCT user_id) AS n FROM env_activity_users
    WHERE app_id = ? AND env = ? AND day BETWEEN ? AND ?`).get(app.id, env, dayOf(days[0]), dayOf(days[days.length - 1])).n;
  const restarts = db.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE app_id = ? AND action = 'restart'
    AND created_at >= ? AND created_at < ? AND detail LIKE ?`)
    .get(app.id, toSql(from), toSql(end), `%"env":"${env}"%`).n;
  const tracking = db.prepare('SELECT tracking_since FROM env_activity_last WHERE app_id = ? AND env = ?').get(app.id, env);
  const since = fromSqlTime(tracking?.tracking_since);
  const coverage = since == null || since >= end ? 'none' : since > from ? 'partial' : 'full';
  const liveDays = (end - from) / DAY;
  const perDay = liveDays >= 1 / 24 ? (x) => round(x / liveDays) : () => null;
  return {
    requests: Math.round(requests),
    active_users: activeUsers,
    restarts,
    requests_per_day: perDay(requests),
    active_users_per_day: round(userDays / days.length),
    restarts_per_day: perDay(restarts),
    error_rate: null,
    p95_ms: null,
    coverage,
  };
}

const toSql = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');

function envReleases(db, app, env, now) {
  const rows = db.prepare(`
    SELECT d.id, d.env, d.version, d.status, d.commit_hash, d.commit_sha, d.commit_message, d.release_label,
           d.started_at, d.finished_at, d.failure_reason, substr(COALESCE(d.log, ''), 1, 120) AS log_head,
           instr(COALESCE(d.log, ''), ?) > 0 AS reverted,
           u.id AS user_id, u.name AS user_name, u.kind AS user_kind
      FROM deployments d LEFT JOIN users u ON u.id = d.deployed_by
     WHERE d.app_id = ? AND d.env = ?
     ORDER BY d.id DESC LIMIT ?`).all(REVERT_MARK, app.id, env, MAX_ROWS).reverse();
  const wentLive = (r) => r.status === 'live' || r.status === 'rolled_back';
  return rows.map((r, i) => {
    const liveFrom = wentLive(r) ? fromSqlTime(r.finished_at || r.started_at) : null;
    const next = rows.slice(i + 1).find(wentLive);
    const after = rows[i + 1];
    let liveUntil = null;
    if (liveFrom != null && r.status !== 'live') {
      liveUntil = next ? fromSqlTime(next.finished_at || next.started_at) : fromSqlTime(after?.finished_at || after?.started_at);
    }
    const rollbackOf = ROLLBACK_RE.exec(r.log_head)?.[1];
    const promotedFrom = env === 'production' ? PROMOTE_RE.exec(r.log_head)?.[1] : undefined;
    let status;
    if (r.status === 'live') status = 'live';
    else if (r.status === 'rolled_back') status = next && ROLLBACK_RE.test(next.log_head) ? 'rolled back' : 'replaced';
    else if (r.status === 'failed') status = r.reverted ? 'auto-reverted' : 'failed';
    else status = 'in progress';
    return {
      id: r.id,
      env,
      version: r.version || null,
      label: r.release_label || null,
      status,
      raw_status: r.status,
      kind: rollbackOf ? 'rollback' : promotedFrom ? 'promote' : 'deploy',
      rollback_of: rollbackOf ? Number(rollbackOf) : null,
      promoted_from: promotedFrom ? Number(promotedFrom) : null,
      promoted_to: [],
      whats_new: r.commit_message || null,
      commit: r.commit_hash || null,
      commit_sha: r.commit_sha || null,
      deployed_by: r.user_id ? { id: r.user_id, name: r.user_name, kind: r.user_kind === 'agent' ? 'agent' : 'person' } : null,
      approver: null,
      started_at: r.started_at,
      finished_at: r.finished_at,
      failure_reason: r.failure_reason || null,
      live_from: liveFrom != null ? new Date(liveFrom).toISOString() : null,
      live_until: liveUntil != null ? new Date(liveUntil).toISOString() : null,
      live_ms: liveFrom != null ? Math.max(0, (liveUntil ?? now) - liveFrom) : null,
      metrics: metricsFor(db, app, env, liveFrom, liveUntil, now),
    };
  });
}

/** { releases (newest first), labels } for one app. */
export function listReleases(db, app, { env = null, label = null, now = usageNow() } = {}) {
  flushActivity(db, now);
  const byEnv = Object.fromEntries(ENVS.map(e => [e, envReleases(db, app, e, now)]));
  const sandboxById = new Map(byEnv.sandbox.map(r => [r.id, r]));
  for (const r of byEnv.production) {
    if (r.promoted_from && sandboxById.has(r.promoted_from)) sandboxById.get(r.promoted_from).promoted_to.push(r.id);
  }
  const labels = [...new Set([...byEnv.production, ...byEnv.sandbox].map(r => r.label).filter(Boolean))].sort();
  const releases = (env ? byEnv[env] : [...byEnv.production, ...byEnv.sandbox])
    .filter(r => !label || r.label === label)
    .sort((a, b) => b.id - a.id);
  return { app: app.slug, env, label, releases, labels, unavailable: METRICS_UNAVAILABLE };
}

const CSV_COLUMNS = [
  ['env', r => r.env], ['id', r => r.id], ['version', r => r.version], ['label', r => r.label],
  ['status', r => r.status], ['kind', r => r.kind], ['live_from', r => r.live_from], ['live_until', r => r.live_until],
  ['hours_live', r => (r.live_ms == null ? null : round(r.live_ms / 3_600_000))],
  ['deployed_by', r => r.deployed_by?.name], ['deployed_by_kind', r => r.deployed_by?.kind],
  ['commit', r => r.commit], ['requests', r => r.metrics?.requests], ['active_users', r => r.metrics?.active_users],
  ['restarts', r => r.metrics?.restarts], ['requests_per_day', r => r.metrics?.requests_per_day],
  ['active_users_per_day', r => r.metrics?.active_users_per_day], ['error_rate', r => r.metrics?.error_rate],
  ['p95_ms', r => r.metrics?.p95_ms], ['whats_new', r => r.whats_new],
];

// A cell a spreadsheet would read as a formula is prefixed with ' so it stays text.
function csvCell(v) {
  if (v == null) return '';
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function releasesCsv(releases) {
  const lines = [CSV_COLUMNS.map(c => c[0]).join(',')];
  for (const r of releases) lines.push(CSV_COLUMNS.map(([, f]) => csvCell(f(r))).join(','));
  return lines.join('\r\n') + '\r\n';
}
