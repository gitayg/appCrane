import { getDb } from '../db.js';
import log from '../utils/logger.js';

// Request activity per app and environment, recorded where Caddy's forward_auth
// asks /api/identity/verify about a request (routes/identity.js). Counted in
// memory and written in batches, so a page with forty assets costs one map
// update per asset and one upsert per flush, not forty writes.
//
// Written: env_activity_last (newest request), env_activity_daily (requests per
// UTC day) and env_activity_users (signed-in users per UTC day). The sleeper
// reads the first; usage analytics can read all three.

const FLUSH_MS = 30_000;
export const RETENTION_DAYS = 400;
const PRUNE_EVERY_MS = 60 * 60_000;
const pending = new Map();
let timer = null;
let lastPruneAt = 0;

const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
export const toSqlTime = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
export function fromSqlTime(s) {
  if (!s) return null;
  const t = Date.parse(String(s).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? '' : 'Z'));
  return Number.isFinite(t) ? t : null;
}

export function noteRequest(appId, env, userId = null, now = Date.now()) {
  if (!appId || (env !== 'sandbox' && env !== 'production')) return;
  const key = `${appId}:${env}:${dayOf(now)}`;
  let p = pending.get(key);
  if (!p) { p = { appId, env, day: dayOf(now), requests: 0, last: 0, users: new Map() }; pending.set(key, p); }
  p.requests++;
  if (now > p.last) p.last = now;
  if (userId != null) p.users.set(Number(userId), (p.users.get(Number(userId)) || 0) + 1);
  if (!timer) {
    timer = setTimeout(() => { timer = null; flushActivity(); }, FLUSH_MS);
    timer.unref?.();
  }
}

/** Write what is pending. Safe to call any time; the sleeper calls it before deciding. */
export function flushActivity(db = getDb(), now = Date.now()) {
  if (now - lastPruneAt >= PRUNE_EVERY_MS) {
    lastPruneAt = now;
    try { pruneActivity(db, now); } catch (e) { log.warn(`[env-activity] prune failed: ${e.message}`); }
  }
  if (!pending.size) return 0;
  const batch = [...pending.values()];
  pending.clear();
  try {
    const last = db.prepare(`
      INSERT INTO env_activity_last (app_id, env, last_request_at, tracking_since) VALUES (?, ?, ?, ?)
      ON CONFLICT(app_id, env) DO UPDATE SET last_request_at = excluded.last_request_at
      WHERE env_activity_last.last_request_at IS NULL OR env_activity_last.last_request_at < excluded.last_request_at`);
    const daily = db.prepare(`
      INSERT INTO env_activity_daily (app_id, env, day, requests) VALUES (?, ?, ?, ?)
      ON CONFLICT(app_id, env, day) DO UPDATE SET requests = requests + excluded.requests`);
    const users = db.prepare(`
      INSERT INTO env_activity_users (app_id, env, day, user_id, requests) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(app_id, env, day, user_id) DO UPDATE SET requests = requests + excluded.requests`);
    db.transaction(() => {
      for (const p of batch) {
        const at = toSqlTime(p.last);
        last.run(p.appId, p.env, at, at);
        daily.run(p.appId, p.env, p.day, p.requests);
        for (const [u, n] of p.users) users.run(p.appId, p.env, p.day, u, n);
      }
    })();
  } catch (e) {
    // An app deleted between the request and the flush fails its foreign key;
    // the rest of the batch is not worth losing for it.
    log.warn(`[env-activity] flush failed: ${e.message}`);
  }
  return batch.length;
}

/** Drop per-day rows older than RETENTION_DAYS. Returns { users, daily } rows deleted. */
export function pruneActivity(db, now = Date.now()) {
  const cutoff = dayOf(now - RETENTION_DAYS * 86_400_000);
  return {
    users: db.prepare('DELETE FROM env_activity_users WHERE day < ?').run(cutoff).changes,
    daily: db.prepare('DELETE FROM env_activity_daily WHERE day < ?').run(cutoff).changes,
  };
}

/** First look at an env: idle is measured from now, not from the epoch. */
export function ensureTracking(db, appId, env, now = Date.now()) {
  db.prepare('INSERT OR IGNORE INTO env_activity_last (app_id, env, last_request_at, tracking_since) VALUES (?, ?, NULL, ?)')
    .run(appId, env, toSqlTime(now));
}

/** { lastRequestAt, trackingSince } in ms (null when unknown), memory included. */
export function activityOf(db, appId, env) {
  const row = db.prepare('SELECT last_request_at, tracking_since FROM env_activity_last WHERE app_id = ? AND env = ?').get(appId, env);
  let last = fromSqlTime(row?.last_request_at);
  for (const p of pending.values()) {
    if (p.appId === appId && p.env === env && (last == null || p.last > last)) last = p.last;
  }
  return { lastRequestAt: last, trackingSince: fromSqlTime(row?.tracking_since) };
}

export function _resetActivityForTests() {
  pending.clear();
  lastPruneAt = 0;
  if (timer) { clearTimeout(timer); timer = null; }
}
