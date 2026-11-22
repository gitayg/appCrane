import crypto from 'crypto';
import { getDb } from '../../db.js';
import { hashApiKey } from '../encryption.js';
import { platformCookieSecure, readCookie } from '../../utils/sessionCookie.js';
import { userAgentFamily } from '../../utils/userAgentFamily.js';
import { readPolicy } from './config.js';
import { KINDS, signal } from './signals.js';
import { sendNewDeviceMail } from './mail.js';

// Device recognition for AppCrane's own sign-in. A browser gets one random,
// long-lived device cookie (opaque; only its SHA-256 is stored); a user's
// device row is (user, that hash). The cookie authenticates nothing: it only
// says "this browser has signed in as this user before". So it rides every
// request (Path=/, SameSite=Lax) and does not need to be Strict.

export const COOKIE_SECURE = '__Secure-cc_device';
export const COOKIE_PLAIN = 'cc_device';
const MAX_AGE_MS = 400 * 86_400_000; // the longest lifetime browsers honour
const MAX_DEVICES_PER_USER = 50;
const MAX_MAILS_PER_HOUR = 5;

function cookieName(req) {
  return platformCookieSecure(req) ? COOKIE_SECURE : COOKIE_PLAIN;
}

export function readDeviceToken(req) {
  const t = readCookie(req, COOKIE_SECURE) || (platformCookieSecure(req) ? null : readCookie(req, COOKIE_PLAIN));
  return typeof t === 'string' && /^[A-Za-z0-9_-]{32,64}$/.test(t) ? t : null;
}

function setDeviceCookie(req, res, token) {
  res.cookie(cookieName(req), token, {
    httpOnly: true,
    secure: platformCookieSecure(req),
    sameSite: 'lax',
    path: '/',
    maxAge: MAX_AGE_MS,
  });
}

/** The device row for this request's cookie and this user, or null. Read only. */
export function knownDeviceFor(db, req, userId) {
  const token = readDeviceToken(req);
  if (!token || !userId) return null;
  return db.prepare('SELECT * FROM signin_devices WHERE user_id = ? AND token_hash = ?').get(userId, hashApiKey(token)) || null;
}

/**
 * Call once after a sign-in succeeded and a session was issued. Recognises
 * the browser or records it as new (setting the cookie when it had none),
 * and on a NEW device for a user who already has at least one recorded
 * device queues the "new sign-in" e-mail (once per device) and emits the
 * signal. Never throws: a sign-in must not fail over this.
 * Returns { known, deviceId, notified } or null.
 */
export function noteSuccessfulSignIn(req, res, user, { method, ip } = {}) {
  try {
    const db = getDb();
    if (!user?.id) return null;
    let token = readDeviceToken(req);
    if (!token) {
      token = crypto.randomBytes(32).toString('base64url');
      if (res) setDeviceCookie(req, res, token);
    }
    const hash = hashApiKey(token);
    const ua = userAgentFamily(req.headers?.['user-agent']);
    const existing = db.prepare('SELECT * FROM signin_devices WHERE user_id = ? AND token_hash = ?').get(user.id, hash);
    if (existing) {
      db.prepare("UPDATE signin_devices SET last_seen_at = datetime('now'), last_ip = ?, ua_family = ? WHERE id = ?").run(ip ?? null, ua, existing.id);
      return { known: true, deviceId: existing.public_id, notified: false };
    }
    const prior = db.prepare('SELECT COUNT(*) n FROM signin_devices WHERE user_id = ?').get(user.id).n;
    const publicId = crypto.randomBytes(16).toString('base64url');
    db.prepare(`INSERT INTO signin_devices (public_id, user_id, token_hash, ua_family, first_ip, last_ip, first_method)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(publicId, user.id, hash, ua, ip ?? null, ip ?? null, method ?? null);
    if (prior >= MAX_DEVICES_PER_USER) {
      db.prepare(`DELETE FROM signin_devices WHERE id IN (SELECT id FROM signin_devices WHERE user_id = ?
        ORDER BY last_seen_at ASC, id ASC LIMIT ?)`).run(user.id, prior + 1 - MAX_DEVICES_PER_USER);
    }
    // The first device we ever see for an account is its baseline, not news:
    // without this every existing user would get a "new sign-in" mail on
    // their first sign-in after the upgrade.
    if (prior === 0) return { known: false, deviceId: publicId, notified: false, baseline: true };

    const data = { device_id: publicId, ua_family: ua, ip: ip ?? null, method: method ?? null };
    let notified = false;
    const policy = readPolicy(db);
    const recent = db.prepare("SELECT COUNT(*) n FROM signin_devices WHERE user_id = ? AND notified_at >= datetime('now', '-1 hour')").get(user.id).n;
    if (policy.new_device_mail && user.email && recent < MAX_MAILS_PER_HOUR) {
      notified = sendNewDeviceMail(db, user, { devicePublicId: publicId, ua, ip, method });
      if (notified) db.prepare("UPDATE signin_devices SET notified_at = datetime('now') WHERE public_id = ?").run(publicId);
    }
    signal({
      kind: KINDS.newDevice, severity: 'info', userId: user.id, subjectUserId: user.id,
      summary: `New sign-in device: ${ua}${method ? ` (${method})` : ''}`,
      data: { ...data, notified },
      audit: { actorId: user.id, action: 'signin-new-device' },
    });
    return { known: false, deviceId: publicId, notified };
  } catch (_) {
    return null;
  }
}

export function listUserDevices(db, userId) {
  return db.prepare('SELECT public_id AS id, ua_family, first_ip, last_ip, first_method, created_at, last_seen_at, notified_at FROM signin_devices WHERE user_id = ? ORDER BY last_seen_at DESC').all(userId);
}

export function forgetUserDevices(db, userId) {
  return db.prepare('DELETE FROM signin_devices WHERE user_id = ?').run(userId).changes;
}
