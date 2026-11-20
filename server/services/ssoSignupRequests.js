// Sign-up requests from an SSO provider, decided by a platform admin.
// See migrations/173-sso-signup-requests.sql.

import { logAudit } from '../middleware/audit.js';
import { noteSignup, signupLimited } from './ssoSignupRateLimit.js';

// A public provider lets anyone with an account there file a request, so the
// queue is capped; past it, a new identity is refused without being recorded.
export const MAX_PENDING = 500;

/**
 * 'pending' | 'denied' | 'full' | 'limited' for a sign-in that may not create an
 * account by itself. 'limited': `ip` already filed too many new requests.
 */
export function recordSignupRequest(db, { provider = 'oidc', subject, email, name, ip }) {
  const row = db.prepare('SELECT id, status FROM sso_signup_requests WHERE provider = ? AND subject = ?').get(provider, subject);
  if (row) {
    db.prepare("UPDATE sso_signup_requests SET last_seen_at = datetime('now'), email = ?, name = ? WHERE id = ?").run(email, name || null, row.id);
    return row.status === 'denied' ? 'denied' : 'pending';
  }
  if (signupLimited(ip)) return 'limited';
  const { n } = db.prepare("SELECT COUNT(*) n FROM sso_signup_requests WHERE status = 'pending'").get();
  if (n >= MAX_PENDING) return 'full';
  db.prepare('INSERT INTO sso_signup_requests (provider, subject, email, name) VALUES (?, ?, ?, ?)').run(provider, subject, email, name || null);
  noteSignup(ip);
  return 'pending';
}

export function listSignupRequests(db, status = 'pending') {
  return db.prepare(`SELECT id, provider, email, name, status, requested_at, last_seen_at, decided_at,
      (SELECT name FROM users u WHERE u.id = r.decided_by) AS decided_by_name
    FROM sso_signup_requests r WHERE status = ? ORDER BY requested_at DESC LIMIT 500`).all(status);
}

function httpError(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

/**
 * Creates the account. Pending or denied requests can be approved. `email` is
 * the address the admin saw: every sign-in rewrites the row's email, so a
 * request whose email changed since is refused rather than approved unseen.
 */
export function approveSignupRequest(db, id, adminId, { email } = {}) {
  if (typeof email !== 'string' || !email.trim()) throw httpError(400, 'VALIDATION', 'email is required: the address you are approving');
  return db.transaction(() => {
    const r = db.prepare('SELECT * FROM sso_signup_requests WHERE id = ?').get(id);
    if (!r) throw httpError(404, 'NOT_FOUND', 'No such sign-up request');
    if (r.status === 'approved') throw httpError(409, 'ALREADY_APPROVED', 'This request was already approved');
    if (String(r.email || '').toLowerCase() !== email.trim().toLowerCase()) {
      throw httpError(409, 'EMAIL_CHANGED', `This request's email changed to ${r.email} since the list was loaded. Check it and approve again.`);
    }
    const column = r.provider === 'oidc' ? 'sso_sub' : null;
    if (!column) throw httpError(400, 'VALIDATION', 'Unknown provider');
    if (db.prepare(`SELECT 1 FROM users WHERE ${column} = ?`).get(r.subject)) throw httpError(409, 'EXISTS', 'An account already uses this sign-in');
    if (db.prepare('SELECT 1 FROM users WHERE lower(email) = lower(?)').get(r.email)) {
      throw httpError(409, 'EXISTS', `An account with ${r.email} already exists`);
    }
    const userId = Number(db.prepare(`INSERT INTO users (name, email, role, ${column}, created_at) VALUES (?, ?, 'user', ?, datetime('now'))`)
      .run(r.name || r.email, r.email, r.subject).lastInsertRowid);
    db.prepare("UPDATE sso_signup_requests SET status = 'approved', decided_by = ?, decided_at = datetime('now'), user_id = ? WHERE id = ?").run(adminId, userId, id);
    logAudit(adminId, null, 'sso-signup-approved', { request_id: id, email: r.email, user_id: userId });
    return { user_id: userId, email: r.email };
  })();
}

export function denySignupRequest(db, id, adminId) {
  const r = db.prepare('SELECT * FROM sso_signup_requests WHERE id = ?').get(id);
  if (!r) throw httpError(404, 'NOT_FOUND', 'No such sign-up request');
  if (r.status !== 'pending') throw httpError(409, 'NOT_PENDING', `This request is already ${r.status}`);
  db.prepare("UPDATE sso_signup_requests SET status = 'denied', decided_by = ?, decided_at = datetime('now') WHERE id = ?").run(adminId, id);
  logAudit(adminId, null, 'sso-signup-denied', { request_id: id, email: r.email });
  return { email: r.email };
}
