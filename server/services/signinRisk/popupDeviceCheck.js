import { createHash } from 'crypto';
import { getDb } from '../../db.js';
import { readSessionCookie } from '../../utils/sessionCookie.js';
import { noteSuccessfulSignIn } from './devices.js';

// SAML popup sign-in without an AppCrane MFA step. The callback is a
// cross-site POST, so the SameSite=Lax device cookie is not on it, and popup
// mode has no /handoff redeem. The completion page it answers with is an
// AppCrane document that loads /api/auth/popup/complete.js: a same-origin
// subresource request, which carries the Lax device cookie AND the session
// cookie the callback just set. So the callback parks the check here, keyed by
// the SHA-256 of the session token it issued, and complete.js runs it. Only
// the browser holding that session token can redeem it; single use, 2 minutes.

const TTL_MS = 2 * 60_000;
const MAX = 10_000;
const pending = new Map(); // sha256(session token) -> { userId, method, ip, expiresAt }
const h = (t) => createHash('sha256').update(String(t)).digest('hex');

export function parkPopupDeviceCheck(sessionToken, userId, method, nowMs = Date.now()) {
  if (!sessionToken || !userId) return;
  for (const [k, rec] of pending) {
    if (rec.expiresAt > nowMs && pending.size < MAX) break;
    pending.delete(k);
  }
  pending.set(h(sessionToken), { userId, method, expiresAt: nowMs + TTL_MS });
}

/** Run the parked check for this request's session cookie, if any. Returns the device result or null. */
export function runPopupDeviceCheck(req, res, nowMs = Date.now()) {
  const token = readSessionCookie(req);
  if (!token) return null;
  const key = h(token);
  const rec = pending.get(key);
  if (!rec) return null;
  pending.delete(key);
  if (rec.expiresAt <= nowMs) return null;
  const user = getDb().prepare('SELECT * FROM users WHERE id = ? AND active = 1').get(rec.userId);
  if (!user) return null;
  return noteSuccessfulSignIn(req, res, user, { method: rec.method, ip: req.ip });
}
