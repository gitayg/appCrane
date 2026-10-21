import { getDb } from '../db.js';
import { generateSessionToken, hashApiKey } from './encryption.js';
import { setSessionCookie } from '../utils/sessionCookie.js';

// Session lifetime policy: an absolute lifetime from sign-in and an idle
// timeout, stricter for platform admins. Applied to every new identity_sessions
// row by the migration-145 trigger (whatever route issued it) and slid forward
// by touchSession() on authenticated requests, at most once a minute.
//
// The trigger reads the same settings keys with the same defaults and bounds;
// test/session-policy.test.js holds the two together.

export const DEFAULTS = Object.freeze({
  admin: Object.freeze({ absolute: 480, idle: 30 }),
  user: Object.freeze({ absolute: 1440, idle: 480 }),
});
export const BOUNDS = Object.freeze({
  absolute: Object.freeze({ min: 15, max: 43200 }),
  idle: Object.freeze({ min: 5, max: 1440 }),
});
export const SETTING_KEYS = Object.freeze({
  admin: Object.freeze({ absolute: 'session_admin_absolute_minutes', idle: 'session_admin_idle_minutes' }),
  user: Object.freeze({ absolute: 'session_user_absolute_minutes', idle: 'session_user_idle_minutes' }),
});
export const TOUCH_INTERVAL_MS = 60_000;

const tierOf = (user) => (user?.role === 'platform_admin' ? 'admin' : 'user');

function readMinutes(db, key, kind, fallback) {
  const raw = db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value;
  const n = Number(raw);
  const { min, max } = BOUNDS[kind];
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback;
}

export function readPolicy(db = getDb()) {
  const out = {};
  for (const tier of ['admin', 'user']) {
    out[tier] = {
      absolute: readMinutes(db, SETTING_KEYS[tier].absolute, 'absolute', DEFAULTS[tier].absolute),
      idle: readMinutes(db, SETTING_KEYS[tier].idle, 'idle', DEFAULTS[tier].idle),
    };
  }
  return out;
}

export function policyFor(user, db = getDb()) {
  return readPolicy(db)[tierOf(user)];
}

/** Validate and store a partial policy. Returns the new policy or throws { field } errors. */
export function writePolicy(db, patch, actorId) {
  const current = readPolicy(db);
  const next = { admin: { ...current.admin }, user: { ...current.user } };
  for (const tier of ['admin', 'user']) {
    for (const kind of ['absolute', 'idle']) {
      const v = patch?.[tier]?.[kind];
      if (v === undefined) continue;
      const n = Number(v);
      const { min, max } = BOUNDS[kind];
      if (!Number.isInteger(n) || n < min || n > max) {
        const e = new Error(`${tier} ${kind} must be a whole number of minutes between ${min} and ${max}`);
        e.field = `${tier}.${kind}`;
        throw e;
      }
      next[tier][kind] = n;
    }
    if (next[tier].idle > next[tier].absolute) {
      const e = new Error(`${tier} idle timeout cannot be longer than the absolute lifetime`);
      e.field = `${tier}.idle`;
      throw e;
    }
  }
  const put = db.prepare(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`);
  db.transaction(() => {
    for (const tier of ['admin', 'user']) {
      put.run(SETTING_KEYS[tier].absolute, String(next[tier].absolute), actorId ?? null);
      put.run(SETTING_KEYS[tier].idle, String(next[tier].idle), actorId ?? null);
    }
  })();
  return next;
}

/** 'YYYY-MM-DD HH:MM:SSZ': compares correctly with datetime('now') as text, parses as UTC in JS. */
export function sqlUtc(ms) {
  return new Date(ms).toISOString().slice(0, 19).replace('T', ' ') + 'Z';
}

export function parseUtc(s) {
  if (!s) return NaN;
  const str = String(s);
  const iso = str.includes('T') ? str : str.replace(' ', 'T');
  return Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`);
}

/**
 * Slide a live session's idle deadline. row needs id, last_seen_at,
 * absolute_expires_at; user is the session's (real) user. Writes at most once
 * per TOUCH_INTERVAL_MS per session. Rows issued before migration 145 have no
 * absolute_expires_at and are left alone (they keep their original expiry).
 */
export function touchSession(db, row, user, nowMs = Date.now()) {
  if (!row || !row.absolute_expires_at) return false;
  const last = parseUtc(row.last_seen_at);
  if (Number.isFinite(last) && nowMs - last < TOUCH_INTERVAL_MS) return false;
  const { idle } = policyFor(user, db);
  const absolute = parseUtc(row.absolute_expires_at);
  const expires = Math.min(absolute, nowMs + idle * 60_000);
  const info = db.prepare(`UPDATE identity_sessions SET last_seen_at = ?, expires_at = ?
    WHERE id = ? AND datetime(expires_at) > datetime(?)`).run(sqlUtc(nowMs), sqlUtc(expires), row.id, sqlUtc(nowMs));
  return info.changes > 0;
}

/**
 * Issue a session the way POST /api/identity/login does (row + httpOnly
 * cookie). The trigger applies the lifetime policy; the returned expires_at is
 * the row's real one.
 */
export function issueSession(db, req, res, user, appId = null) {
  const token = generateSessionToken();
  const tokenHash = hashApiKey(token);
  const requested = sqlUtc(Date.now() + BOUNDS.absolute.max * 60_000);
  db.prepare('INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at) VALUES (?, ?, ?, ?)')
    .run(user.id, tokenHash, appId, requested);
  db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(user.id);
  const row = db.prepare('SELECT expires_at, absolute_expires_at FROM identity_sessions WHERE token_hash = ?').get(tokenHash);
  if (res) setSessionCookie(res, token, req);
  return { token, expires_at: row.expires_at, absolute_expires_at: row.absolute_expires_at };
}
