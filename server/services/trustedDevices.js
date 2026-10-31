import crypto from 'crypto';
import { getDb } from '../db.js';
import { hashApiKey } from './encryption.js';
import { logAudit } from '../middleware/audit.js';
import { recordEvent } from './eventStore.js';
import { parseUtc, sqlUtc } from './sessionPolicy.js';
import { platformCookieSecure, readCookie } from '../utils/sessionCookie.js';
import { userAgentFamily } from '../utils/userAgentFamily.js';

// "Remember this device" for local MFA. After a correct password AND a
// correct code, a browser can be issued a trusted-device cookie; on a later
// password sign-in by the SAME user it stands in for the code. It never stands
// in for the password, and nothing outside POST /api/identity/login reads it
// (SSO sign-ins, API keys and the code checks on /setup, /disable and
// /recovery-codes never call trustedDeviceFor).
//
// Off by default. The admin setting is read on every check, so lowering it or
// turning it off cuts existing devices at once; turning it off also deletes
// the rows so nothing lingers to come back if it is turned on again.

export const REMEMBER_KEY = 'auth_mfa_remember_days';
export const REMEMBER_MAX_DAYS = 30;
const DAY_MS = 86_400_000;

// __Secure- needs the Secure flag, which plain-HTTP dev instances cannot set,
// so they fall back to the bare name. Neither collides with cc_token /
// __Host-cc_token or the app-session cookies.
export const COOKIE_SECURE = '__Secure-cc_mfa_trust';
export const COOKIE_PLAIN = 'cc_mfa_trust';
// Only the password sign-in reads it, so it is sent nowhere else. A Path
// attribute may name a path other than the one that set it (RFC 6265 5.2.4),
// which is how /api/identity/mfa/verify can set it for /api/identity/login.
export const COOKIE_PATH = '/api/identity/login';

// ── setting ───────────────────────────────────────────────────────────────

export function rememberDays(db = getDb()) {
  const n = Number(db.prepare('SELECT value FROM settings WHERE key = ?').get(REMEMBER_KEY)?.value);
  return Number.isInteger(n) && n >= 0 && n <= REMEMBER_MAX_DAYS ? n : 0;
}

/** Validate and store. Turning it off deletes every trusted device. Returns { days, revoked }. */
export function setRememberDays(db, value, actorId) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > REMEMBER_MAX_DAYS) {
    const e = new Error(`remember_device_days must be a whole number from 0 (off) to ${REMEMBER_MAX_DAYS}`);
    e.field = 'remember_device_days';
    throw e;
  }
  db.prepare(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(REMEMBER_KEY, String(n), actorId ?? null);
  const revoked = n === 0 ? db.prepare('DELETE FROM mfa_trusted_devices').run().changes : 0;
  return { days: n, revoked };
}

// ── cookie ────────────────────────────────────────────────────────────────

function cookieName(req) {
  return platformCookieSecure(req) ? COOKIE_SECURE : COOKIE_PLAIN;
}

function readToken(req) {
  return readCookie(req, COOKIE_SECURE) || (platformCookieSecure(req) ? null : readCookie(req, COOKIE_PLAIN));
}

export function clearTrustedDeviceCookie(req, res) {
  res.clearCookie(cookieName(req), { path: COOKIE_PATH, httpOnly: true, secure: platformCookieSecure(req), sameSite: 'strict' });
}

// ── issue / check ─────────────────────────────────────────────────────────

function mfaEnabledAt(db, userId) {
  return db.prepare('SELECT enabled_at FROM user_mfa WHERE user_id = ? AND totp_secret_enc IS NOT NULL').get(userId)?.enabled_at || null;
}

/**
 * Called after a successful second step when the user ticked the box. No-op
 * (returns null) when the setting is off. Sets the cookie on res.
 */
export function trustDevice(db, req, res, user, { ip = null, nowMs = Date.now() } = {}) {
  const days = rememberDays(db);
  if (!days) return null;
  const token = crypto.randomBytes(32).toString('base64url');
  const publicId = crypto.randomBytes(16).toString('base64url');
  const label = userAgentFamily(req.headers['user-agent']);
  db.prepare(`INSERT INTO mfa_trusted_devices (public_id, token_hash, user_id, label, ip, mfa_enabled_at, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(publicId, hashApiKey(token), user.id, label, ip, mfaEnabledAt(db, user.id), sqlUtc(nowMs), sqlUtc(nowMs + days * DAY_MS));
  res.cookie(cookieName(req), token, {
    httpOnly: true,
    secure: platformCookieSecure(req),
    // Strict, not the session cookie's Lax: the session cookie must ride
    // top-level navigations into app hosts, this one only ever rides the
    // login page's own same-origin fetch, so Strict costs nothing.
    sameSite: 'strict',
    path: COOKIE_PATH,
    maxAge: days * DAY_MS,
  });
  audit(user.id, 'mfa-device-trusted', { device_id: publicId, label, days, ip }, user.id, `Device remembered for ${days} day(s)`);
  return { id: publicId, days };
}

/**
 * The live trusted-device row for THIS user from the request's cookie, or
 * null. Lookup is by SHA-256 of the token (no string compare of secrets). A
 * row is live while now < min(expires_at, created_at + current setting) and
 * the user's MFA factor is the one it was issued under.
 */
export function trustedDeviceFor(db, req, user, { nowMs = Date.now() } = {}) {
  const days = rememberDays(db);
  if (!days) return null;
  const token = readToken(req);
  if (!token) return null;
  const row = db.prepare('SELECT * FROM mfa_trusted_devices WHERE token_hash = ? AND user_id = ?').get(hashApiKey(token), user.id);
  if (!row) return null;
  const limit = Math.min(parseUtc(row.expires_at), parseUtc(row.created_at) + days * DAY_MS);
  if (!(nowMs < limit)) return null;
  const enabledAt = mfaEnabledAt(db, user.id);
  if (!enabledAt || enabledAt !== row.mfa_enabled_at) return null;
  db.prepare('UPDATE mfa_trusted_devices SET last_used_at = ? WHERE id = ?').run(sqlUtc(nowMs), row.id);
  return row;
}

/** True when the request carried a trusted-device cookie at all (to clear a dead one). */
export function hasTrustedDeviceCookie(req) {
  return !!readToken(req);
}

export function auditTrustedSkip(user, row, ip) {
  audit(user.id, 'mfa-skipped-trusted-device', { device_id: row.public_id, label: row.label, ip }, user.id,
    'Two-factor step skipped on a remembered device');
}

// ── list / revoke ─────────────────────────────────────────────────────────

export function listDevices(db, userId, { nowMs = Date.now() } = {}) {
  const days = rememberDays(db);
  return db.prepare('SELECT public_id, label, ip, created_at, expires_at, last_used_at FROM mfa_trusted_devices WHERE user_id = ? ORDER BY created_at DESC')
    .all(userId)
    .map((r) => {
      const limit = Math.min(parseUtc(r.expires_at), parseUtc(r.created_at) + days * DAY_MS);
      return {
        id: r.public_id, label: r.label, ip: r.ip, created_at: r.created_at, last_used_at: r.last_used_at,
        expires_at: Number.isFinite(limit) && days ? new Date(limit).toISOString() : null,
        active: !!days && nowMs < limit,
      };
    });
}

/** Revoke one device of userId by its opaque id. Scoped by user_id, so a foreign id is a no-op. */
export function revokeDevice(db, userId, publicId, { actorId = userId, ip = null } = {}) {
  if (typeof publicId !== 'string' || !publicId) return false;
  const n = db.prepare('DELETE FROM mfa_trusted_devices WHERE user_id = ? AND public_id = ?').run(userId, publicId).changes;
  if (n) audit(actorId, 'mfa-devices-revoked', { target_user_id: userId, device_id: publicId, count: n, reason: 'user', ip }, userId, 'Remembered device removed');
  return n > 0;
}

/** Revoke every trusted device of a user. reason names the trigger for the audit row. */
export function revokeAllDevices(db, userId, { actorId = null, reason, ip = null } = {}) {
  const n = db.prepare('DELETE FROM mfa_trusted_devices WHERE user_id = ?').run(userId).changes;
  if (n) audit(actorId ?? userId, 'mfa-devices-revoked', { target_user_id: userId, count: n, reason, ip }, userId,
    `${n} remembered device(s) revoked (${reason})`, 'warning');
  return n;
}

// ── retention ─────────────────────────────────────────────────────────────

/** Delete rows past their own expiry or past the current setting. Returns the count. */
export function purgeExpiredDevices(db = getDb(), nowMs = Date.now()) {
  const days = rememberDays(db);
  if (!days) return db.prepare('DELETE FROM mfa_trusted_devices').run().changes;
  return db.prepare('DELETE FROM mfa_trusted_devices WHERE expires_at <= ? OR created_at <= ?')
    .run(sqlUtc(nowMs), sqlUtc(nowMs - days * DAY_MS)).changes;
}

// ── audit ─────────────────────────────────────────────────────────────────

function audit(actorId, action, detail, subjectUserId, summary, severity = 'info') {
  try { logAudit(actorId, null, action, detail); } catch (_) {}
  try { recordEvent({ kind: 'mfa', severity, userId: actorId, subjectUserId, summary, data: { action, ...detail } }); } catch (_) {}
}
