import crypto from 'crypto';
import { getDb } from '../db.js';
import { encrypt, decrypt, deriveSecret, hashApiKey } from './encryption.js';
import { base32Decode, base32Encode, generateSecret, matchStep, normalizeAlgorithm, otpauthUri } from './totp.js';
import { logAudit } from '../middleware/audit.js';
import { recordEvent } from './eventStore.js';
import { rememberDays, revokeAllDevices } from './trustedDevices.js';

// Local MFA for password sign-in: TOTP with single-use recovery codes.
// SSO sign-ins never reach this module (the IdP owns MFA there); API keys are
// not sessions and are unaffected.

export const REQUIRE_KEY = 'auth_mfa_required';
export const REQUIRE_LEVELS = Object.freeze(['off', 'admins', 'everyone']);
export const REQUIRE_DEFAULT = 'admins';
export const RECOVERY_CODE_COUNT = 10;
export const CHALLENGE_TTL_MS = 5 * 60_000;
export const CHALLENGE_MAX_ATTEMPTS = 5;
export const ENROLL_PENDING_TTL_MS = 15 * 60_000;

export const RATE = Object.freeze({
  windowMs: 15 * 60_000,
  perUser: 5,
  perIp: 20,
});

// ── policy ────────────────────────────────────────────────────────────────

export function requiredLevel(db = getDb()) {
  const v = db.prepare('SELECT value FROM settings WHERE key = ?').get(REQUIRE_KEY)?.value;
  return REQUIRE_LEVELS.includes(v) ? v : REQUIRE_DEFAULT;
}

export function setRequiredLevel(db, level, actorId) {
  if (!REQUIRE_LEVELS.includes(level)) {
    const e = new Error(`mfa_required must be one of ${REQUIRE_LEVELS.join(', ')}`);
    e.field = 'mfa_required';
    throw e;
  }
  db.prepare(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(REQUIRE_KEY, level, actorId ?? null);
  return level;
}

export function mfaRequiredFor(user, db = getDb()) {
  const level = requiredLevel(db);
  if (level === 'everyone') return true;
  if (level === 'admins') return user?.role === 'platform_admin';
  return false;
}

// ── state ─────────────────────────────────────────────────────────────────

function mfaRow(db, userId) {
  return db.prepare('SELECT * FROM user_mfa WHERE user_id = ?').get(userId) || null;
}

export function isEnrolled(db, userId) {
  const r = mfaRow(db, userId);
  return !!(r && r.enabled_at && r.totp_secret_enc);
}

export function status(db, user) {
  const r = mfaRow(db, user.id);
  const enrolled = !!(r && r.enabled_at && r.totp_secret_enc);
  const remaining = enrolled
    ? db.prepare('SELECT COUNT(*) AS n FROM user_mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL').get(user.id).n
    : 0;
  return {
    enrolled,
    algorithm: enrolled ? r.algorithm : null,
    enabled_at: enrolled ? r.enabled_at : null,
    recovery_codes_remaining: remaining,
    required: mfaRequiredFor(user, db),
    required_level: requiredLevel(db),
    has_password: !!user.password_hash,
  };
}

// ── enrollment ────────────────────────────────────────────────────────────

/** Start (or restart) enrollment: a pending secret that becomes active only after a correct code. */
export function startEnrollment(db, user, algorithm = 'SHA1') {
  const alg = normalizeAlgorithm(algorithm);
  if (!alg) {
    const e = new Error('algorithm must be SHA1 or SHA256');
    e.field = 'algorithm';
    throw e;
  }
  const secret = generateSecret(alg);
  const secretB32 = base32Encode(secret);
  db.prepare(`INSERT INTO user_mfa (user_id, pending_secret_enc, pending_algorithm, pending_created_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET pending_secret_enc = excluded.pending_secret_enc,
      pending_algorithm = excluded.pending_algorithm, pending_created_at = excluded.pending_created_at`)
    .run(user.id, encrypt(secretB32), alg);
  const account = user.email || user.username || `user-${user.id}`;
  return { secret: secretB32, algorithm: alg, otpauth_uri: otpauthUri({ secretB32, account, algorithm: alg }) };
}

/**
 * Confirm the pending secret with a code from the app. On success the secret
 * becomes active, any earlier factor and recovery codes are replaced, and the
 * new recovery codes are returned (the only time they are shown).
 */
export function activateEnrollment(db, user, code, { nowMs = Date.now(), ip = null } = {}) {
  const r = mfaRow(db, user.id);
  if (!r || !r.pending_secret_enc) return { ok: false, reason: 'no_pending' };
  const created = Date.parse(String(r.pending_created_at).replace(' ', 'T') + 'Z');
  if (Number.isFinite(created) && nowMs - created > ENROLL_PENDING_TTL_MS) return { ok: false, reason: 'pending_expired' };
  const limited = rateLimited(user.id, ip, nowMs);
  if (limited) return { ok: false, reason: 'rate_limited', retry_after_s: limited };
  const step = matchStep(decodeSecret(r.pending_secret_enc), code, { nowMs, algorithm: r.pending_algorithm || 'SHA1' });
  if (step === null) return fail(db, user, ip, nowMs, 'bad_enroll_code');
  const codes = generateRecoveryCodes();
  db.transaction(() => {
    db.prepare(`UPDATE user_mfa SET totp_secret_enc = pending_secret_enc, algorithm = pending_algorithm,
      enabled_at = datetime('now'), last_used_step = ?, pending_secret_enc = NULL, pending_algorithm = NULL,
      pending_created_at = NULL WHERE user_id = ?`).run(step, user.id);
    storeRecoveryCodes(db, user.id, codes);
  })();
  clearFailures(user.id);
  // A new factor means devices remembered under the old one no longer count.
  revokeAllDevices(db, user.id, { actorId: user.id, reason: 'mfa-enroll', ip });
  audit(user.id, 'mfa-enroll', { algorithm: r.pending_algorithm || 'SHA1', ip }, user.id, 'Two-factor sign-in turned on');
  return { ok: true, recovery_codes: codes };
}

export function disable(db, user, { actorId = user.id, ip = null } = {}) {
  db.transaction(() => {
    db.prepare('DELETE FROM user_mfa WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM user_mfa_recovery_codes WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM mfa_challenges WHERE user_id = ?').run(user.id);
  })();
  revokeAllDevices(db, user.id, { actorId, reason: 'mfa-disable', ip });
  audit(actorId, 'mfa-disable', { target_user_id: user.id, ip }, user.id, 'Two-factor sign-in turned off', 'warning');
}

/** Platform-admin reset (lost device). Audited, evented, the user is e-mailed. */
export async function adminReset(db, admin, target, { ip = null, mail = defaultResetMail } = {}) {
  const had = isEnrolled(db, target.id);
  db.transaction(() => {
    db.prepare('DELETE FROM user_mfa WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM user_mfa_recovery_codes WHERE user_id = ?').run(target.id);
    db.prepare('DELETE FROM mfa_challenges WHERE user_id = ?').run(target.id);
  })();
  clearFailures(target.id);
  revokeAllDevices(db, target.id, { actorId: admin.id, reason: 'mfa-reset', ip });
  audit(admin.id, 'mfa-reset', { target_user_id: target.id, was_enrolled: had, ip }, target.id,
    'Two-factor sign-in reset by a platform admin', 'warning');
  let mailed = false;
  try { mailed = !!(await mail(target, admin)); } catch (_) { mailed = false; }
  return { was_enrolled: had, mailed };
}

async function defaultResetMail(target, admin) {
  if (!target.email) return false;
  const { enqueueEmail } = await import('./emailQueue.js');
  const by = admin.name || admin.username || 'A platform admin';
  enqueueEmail({
    appId: null,
    source: 'mfa',
    to: target.email,
    subject: '[AppCrane] Your two-factor sign-in was reset',
    text: `${by} reset two-factor sign-in on your AppCrane account. `
      + 'Your authenticator app and recovery codes no longer work. '
      + 'If your instance requires two-factor sign-in, you will set it up again the next time you sign in with your password. '
      + 'If you did not ask for this, contact your platform admin.',
  });
  return true;
}

// ── verification ──────────────────────────────────────────────────────────

/**
 * Check a TOTP or recovery code for an enrolled user. A TOTP step can be used
 * once (replay refused within and after its window); a recovery code once.
 * Rate limits are applied per user and per IP before any check.
 */
export function verifyCode(db, user, code, { nowMs = Date.now(), ip = null } = {}) {
  const limited = rateLimited(user.id, ip, nowMs);
  if (limited) return { ok: false, reason: 'rate_limited', retry_after_s: limited };
  const r = mfaRow(db, user.id);
  if (!r || !r.enabled_at || !r.totp_secret_enc) return { ok: false, reason: 'not_enrolled' };
  const raw = String(code || '').trim();
  if (/^\d{6}$/.test(raw.replace(/\s/g, ''))) {
    const step = matchStep(decodeSecret(r.totp_secret_enc), raw, { nowMs, algorithm: r.algorithm });
    if (step === null) return fail(db, user, ip, nowMs, 'bad_code');
    const info = db.prepare(`UPDATE user_mfa SET last_used_step = ?
      WHERE user_id = ? AND (last_used_step IS NULL OR last_used_step < ?)`).run(step, user.id, step);
    if (info.changes === 0) return fail(db, user, ip, nowMs, 'replayed');
    clearFailures(user.id);
    return { ok: true, method: 'totp' };
  }
  const norm = normalizeRecoveryCode(raw);
  if (!norm) return fail(db, user, ip, nowMs, 'bad_code');
  const hashes = [recoveryHash(user.id, norm), ...legacyRecoverySecrets(db).map((k) => recoveryHashWith(k, user.id, norm))];
  const info = db.prepare(`UPDATE user_mfa_recovery_codes SET used_at = datetime('now')
    WHERE user_id = ? AND code_hash IN (${hashes.map(() => '?').join(', ')}) AND used_at IS NULL`).run(user.id, ...hashes);
  if (info.changes === 0) return fail(db, user, ip, nowMs, 'bad_recovery_code');
  clearFailures(user.id);
  const left = db.prepare('SELECT COUNT(*) AS n FROM user_mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL').get(user.id).n;
  audit(user.id, 'mfa-recovery-code-used', { remaining: left, ip }, user.id, 'Recovery code used to sign in', 'warning');
  return { ok: true, method: 'recovery_code', recovery_codes_remaining: left };
}

/** New set of recovery codes (old ones stop working). Requires a valid current code from the caller. */
export function regenerateRecoveryCodes(db, user, { ip = null } = {}) {
  const codes = generateRecoveryCodes();
  db.transaction(() => storeRecoveryCodes(db, user.id, codes))();
  audit(user.id, 'mfa-recovery-codes-regenerated', { ip }, user.id, 'Recovery codes replaced');
  return codes;
}

function fail(db, user, ip, nowMs, reason) {
  noteFailure(db, user, ip, reason, nowMs);
  return { ok: false, reason };
}

function decodeSecret(enc) {
  return base32Decode(decrypt(enc));
}

// ── recovery codes ────────────────────────────────────────────────────────

const RC_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generateRecoveryCodes(n = RECOVERY_CODE_COUNT) {
  const out = [];
  for (let i = 0; i < n; i++) {
    let s = '';
    for (const b of crypto.randomBytes(10)) s += RC_ALPHABET[b & 31];
    out.push(`${s.slice(0, 5)}-${s.slice(5)}`);
  }
  return out;
}

export function normalizeRecoveryCode(code) {
  const s = String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  return /^[A-Z0-9]{10}$/.test(s) ? s : null;
}

export const RECOVERY_LABEL = 'mfa-recovery-codes';
// crane rotate-key cannot re-hash recovery codes (only their hashes are kept),
// so it stores the recovery-code secret derived from each previous key here,
// encrypted under the current key; codes issued before a rotation keep working.
export const LEGACY_RECOVERY_SETTING = 'mfa_recovery_legacy_secrets_enc';

function recoveryHashWith(secretHex, userId, normalized) {
  return crypto.createHmac('sha256', secretHex).update(`${userId}:${normalized}`).digest('hex');
}

function recoveryHash(userId, normalized) {
  return recoveryHashWith(deriveSecret(RECOVERY_LABEL), userId, normalized);
}

function legacyRecoverySecrets(db) {
  const enc = db.prepare('SELECT value FROM settings WHERE key = ?').get(LEGACY_RECOVERY_SETTING)?.value;
  if (!enc) return [];
  try {
    const list = JSON.parse(decrypt(enc));
    return Array.isArray(list) ? list.filter((k) => /^[0-9a-f]{64}$/.test(k)) : [];
  } catch { return []; }
}

function storeRecoveryCodes(db, userId, codes) {
  db.prepare('DELETE FROM user_mfa_recovery_codes WHERE user_id = ?').run(userId);
  const ins = db.prepare('INSERT INTO user_mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)');
  for (const c of codes) ins.run(userId, recoveryHash(userId, normalizeRecoveryCode(c)));
}

// ── challenges (password accepted, second step pending) ───────────────────

export function createChallenge(db, user, purpose, appId = null, nowMs = Date.now()) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare("DELETE FROM mfa_challenges WHERE user_id = ? OR datetime(expires_at) < datetime('now')").run(user.id);
  db.prepare('INSERT INTO mfa_challenges (token_hash, user_id, purpose, app_id, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(hashApiKey(token), user.id, purpose, appId, new Date(nowMs + CHALLENGE_TTL_MS).toISOString());
  return token;
}

/** The live challenge and its active user, or null. Counts an attempt. */
export function loadChallenge(db, token, purpose, nowMs = Date.now()) {
  if (!token || typeof token !== 'string') return null;
  const c = db.prepare('SELECT * FROM mfa_challenges WHERE token_hash = ?').get(hashApiKey(token));
  if (!c || c.purpose !== purpose || c.consumed_at) return null;
  if (Date.parse(c.expires_at) <= nowMs || c.attempts >= CHALLENGE_MAX_ATTEMPTS) return null;
  const user = db.prepare('SELECT * FROM users WHERE id = ? AND active = 1').get(c.user_id);
  if (!user) return null;
  db.prepare('UPDATE mfa_challenges SET attempts = attempts + 1 WHERE id = ?').run(c.id);
  return { challenge: c, user };
}

export function consumeChallenge(db, challengeId) {
  return db.prepare("UPDATE mfa_challenges SET consumed_at = datetime('now') WHERE id = ? AND consumed_at IS NULL")
    .run(challengeId).changes > 0;
}

/**
 * Called by POST /api/identity/login after the password is verified and before
 * a session is issued. Returns null (issue the session as before) or the body
 * to answer with instead of a session.
 */
export function passwordLoginMfaStep(db, user, { appId = null } = {}) {
  if (isEnrolled(db, user.id)) {
    return {
      mfa_required: true,
      mfa_token: createChallenge(db, user, 'verify', appId),
      // >0 tells the sign-in page to offer "Remember this device for N days".
      remember_device_days: rememberDays(db),
      error: { code: 'MFA_REQUIRED', message: 'Enter the code from your authenticator app to finish signing in.' },
    };
  }
  if (mfaRequiredFor(user, db)) {
    return {
      mfa_enroll_required: true,
      mfa_token: createChallenge(db, user, 'enroll', appId),
      error: { code: 'MFA_ENROLL_REQUIRED', message: 'Two-factor sign-in is required. Set it up to finish signing in.' },
    };
  }
  return null;
}

// ── rate limiting (in memory, per process) ────────────────────────────────

const _userFails = new Map();
const _ipFails = new Map();

function prune(list, nowMs) {
  while (list.length && nowMs - list[0] > RATE.windowMs) list.shift();
  return list;
}

/** Seconds until the caller may try again, or 0. */
export function rateLimited(userId, ip, nowMs = Date.now()) {
  const u = prune(_userFails.get(userId) || [], nowMs);
  const i = ip ? prune(_ipFails.get(ip) || [], nowMs) : [];
  const waits = [];
  if (u.length >= RATE.perUser) waits.push(RATE.windowMs - (nowMs - u[0]));
  if (i.length >= RATE.perIp) waits.push(RATE.windowMs - (nowMs - i[0]));
  return waits.length ? Math.max(1, Math.ceil(Math.max(...waits) / 1000)) : 0;
}

function noteFailure(db, user, ip, reason, nowMs = Date.now()) {
  const u = _userFails.get(user.id) || [];
  u.push(nowMs);
  _userFails.set(user.id, u);
  if (ip) {
    const i = _ipFails.get(ip) || [];
    i.push(nowMs);
    _ipFails.set(ip, i);
  }
  audit(user.id, 'mfa-failed', { reason, ip }, user.id, `Two-factor code refused: ${reason}`, 'warning');
}

function clearFailures(userId) {
  _userFails.delete(userId);
}

export function _resetMfaRateLimitsForTests() {
  _userFails.clear();
  _ipFails.clear();
}

export function _sweepMfaRateLimits(nowMs = Date.now()) {
  for (const m of [_userFails, _ipFails]) {
    for (const [k, list] of m) if (!prune(list, nowMs).length) m.delete(k);
  }
}
const _sweeper = setInterval(_sweepMfaRateLimits, 5 * 60_000);
_sweeper.unref?.();

// ── audit ─────────────────────────────────────────────────────────────────

function audit(actorId, action, detail, subjectUserId, summary, severity = 'info') {
  try { logAudit(actorId, null, action, detail); } catch (_) {}
  recordEvent({ kind: 'mfa', severity, userId: actorId, subjectUserId, summary, data: { action, ...detail } });
}
