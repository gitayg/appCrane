import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { jobStarted, trackJob } from '../jobHealth.js';
import { readPolicy } from './config.js';
import { KINDS, signal } from './signals.js';
import { pruneLockouts } from './lockout.js';
import { revokeAllGrantsForUser } from '../oauthStore.js';

// Stale accounts: active people with no sign-in for stale_days (never signed
// in counts from created_at). Listed for platform admins; with
// stale_deactivate_days set (0 = off, the default) the daily sweep
// deactivates those past that age. Agents never sign in, so only kind
// 'human' is considered, and the sweep never deactivates the last active
// platform admin: it re-counts before each one.

const DAY = 86_400_000;
const FIRST_RUN_DELAY_MS = 15 * 60_000;
export const JOB_ID = 'signin-stale-sweep';

const STALE_SQL = `SELECT id, name, username, email, role, created_at, last_login_at,
    CAST(julianday('now') - julianday(COALESCE(last_login_at, created_at)) AS INTEGER) AS idle_days
  FROM users
  WHERE active = 1 AND COALESCE(kind, 'human') = 'human'
    AND julianday('now') - julianday(COALESCE(last_login_at, created_at)) >= ?
  ORDER BY COALESCE(last_login_at, created_at) ASC`;

export function listStale(db = getDb(), days = readPolicy(db).stale_days) {
  return db.prepare(STALE_SQL).all(days).map((r) => ({ ...r, never_signed_in: !r.last_login_at }));
}

/**
 * For access reviews: { [userId]: { stale, last_sign_in_at, idle_days } } for
 * the given users, under the current stale_days. Read live, so a review shows
 * today's answer, not the one at campaign start.
 */
export function staleInfoFor(db, userIds) {
  const days = readPolicy(db).stale_days;
  const ids = [...new Set(userIds.filter((n) => Number.isInteger(n)))];
  const out = {};
  if (!ids.length) return out;
  const rows = db.prepare(`SELECT id, last_login_at, COALESCE(kind, 'human') AS kind,
      CAST(julianday('now') - julianday(COALESCE(last_login_at, created_at)) AS INTEGER) AS idle_days
    FROM users WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids);
  for (const r of rows) out[r.id] = { stale: r.kind === 'human' && r.idle_days >= days, last_sign_in_at: r.last_login_at, idle_days: r.idle_days };
  return out;
}

const activeAdmins = (db) => db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'platform_admin' AND active = 1").get().n;

/** Deactivate accounts past stale_deactivate_days. No-op when it is 0. Returns { deactivated: [ids], skipped_last_admin: [ids] }. */
export function runStaleSweep(db = getDb()) {
  pruneLockouts(db);
  db.prepare("DELETE FROM signin_report_links WHERE expires_at <= datetime('now') OR used_at IS NOT NULL").run();
  const policy = readPolicy(db);
  const out = { deactivated: [], skipped_last_admin: [] };
  if (!policy.stale_deactivate_days) return out;
  for (const u of listStale(db, policy.stale_deactivate_days)) {
    db.transaction(() => {
      if (u.role === 'platform_admin' && activeAdmins(db) <= 1) { out.skipped_last_admin.push(u.id); return; }
      const n = db.prepare('UPDATE users SET active = 0 WHERE id = ? AND active = 1').run(u.id).changes;
      if (!n) return;
      db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(u.id);
      out.deactivated.push(u.id);
    })();
    if (out.deactivated.includes(u.id)) {
      try { revokeAllGrantsForUser(u.id); } catch (_) {}
      signal({
        kind: KINDS.staleDeactivated, severity: 'warning', subjectUserId: u.id,
        summary: `Account deactivated after ${u.idle_days} days without a sign-in`,
        data: { idle_days: u.idle_days, last_login_at: u.last_login_at, threshold_days: policy.stale_deactivate_days },
        audit: { actorId: null, action: 'signin-stale-deactivated' },
      });
    }
  }
  if (out.skipped_last_admin.length) log.warn(`[signin-risk] not deactivating the last active platform admin (user ${out.skipped_last_admin.join(', ')})`);
  return out;
}

let timers = [];
export function startStaleSweep() {
  if (timers.length) return;
  jobStarted(JOB_ID);
  const run = () => trackJob(JOB_ID, async () => runStaleSweep())
    .catch((e) => log.warn(`[signin-risk] stale sweep failed: ${e.message}`));
  const first = setTimeout(run, FIRST_RUN_DELAY_MS);
  const daily = setInterval(run, DAY);
  first.unref?.();
  daily.unref?.();
  timers = [first, daily];
}

export function stopStaleSweep() {
  for (const t of timers) { clearTimeout(t); clearInterval(t); }
  timers = [];
}
