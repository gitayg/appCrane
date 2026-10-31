import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { auditLogin, logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { verifyPassword } from '../services/encryption.js';
import * as mfa from '../services/mfa.js';
import { BOUNDS, DEFAULTS, issueSession, policyFor, readPolicy, writePolicy } from '../services/sessionPolicy.js';
import { REMEMBER_MAX_DAYS, listDevices, rememberDays, revokeAllDevices, revokeDevice, setRememberDays, trustDevice } from '../services/trustedDevices.js';

// Mounted at /api/identity/mfa. Two halves:
//  - the sign-in second step (no session yet; authorised by the short-lived
//    mfa_token POST /api/identity/login returned after a correct password)
//  - self-service and admin management (requireAuth)
// Wrong codes answer 400, never 401, so the SPA's expired-session handler does
// not sign a signed-in user out over a typo.

const router = Router();

const ipOf = (req) => req.ip || req.socket?.remoteAddress || 'unknown';
const WARN_BEFORE_S = 120;

function codeError(result) {
  if (result.reason === 'rate_limited') {
    return new AppError(`Too many wrong codes. Try again in ${Math.ceil(result.retry_after_s / 60)} minute(s).`, 429, 'RATE_LIMITED');
  }
  if (result.reason === 'replayed') return new AppError('That code was already used. Wait for the next one.', 400, 'CODE_REPLAYED');
  if (result.reason === 'pending_expired' || result.reason === 'no_pending') {
    return new AppError('The setup expired. Start again.', 400, 'MFA_SETUP_EXPIRED');
  }
  return new AppError('That code is not valid.', 400, 'INVALID_CODE');
}

function challengeOr400(db, token, purpose, opts) {
  const found = mfa.loadChallenge(db, token, purpose, opts);
  if (!found) throw new AppError('The sign-in step expired. Sign in again.', 400, 'MFA_TOKEN_INVALID');
  return found;
}

function sessionBody(session, user) {
  return {
    token: session.token,
    expires_at: session.expires_at,
    absolute_expires_at: session.absolute_expires_at,
    user: {
      id: user.id, name: user.name, email: user.email, username: user.username,
      avatar_url: user.avatar_url, phone: user.phone, year_of_birth: user.year_of_birth,
    },
  };
}

// ── second step of password sign-in ───────────────────────────────────────

router.post('/verify', (req, res) => {
  const db = getDb();
  const ip = ipOf(req);
  const { mfa_token, code, remember_device } = req.body || {};
  if (!code || typeof code !== 'string') throw new AppError('code is required', 400, 'VALIDATION');
  const { challenge, user } = challengeOr400(db, mfa_token, 'verify');
  const result = mfa.verifyCode(db, user, code, { ip });
  if (!result.ok) throw codeError(result);
  if (!mfa.consumeChallenge(db, challenge.id)) throw new AppError('The sign-in step expired. Sign in again.', 400, 'MFA_TOKEN_INVALID');
  const session = issueSession(db, req, res, user, challenge.app_id);
  // Strictly true: a truthy string from a hand-made request is not consent.
  const trusted = remember_device === true ? trustDevice(db, req, res, user, { ip }) : null;
  auditLogin(user.id, 'ok', { method: `password+${result.method}`, ip });
  res.json({
    ...sessionBody(session, user),
    ...(result.method === 'recovery_code' && { recovery_codes_remaining: result.recovery_codes_remaining }),
    ...(trusted && { device_remembered_days: trusted.days }),
  });
});

router.post('/enroll/start', (req, res) => {
  const db = getDb();
  const { mfa_token, algorithm } = req.body || {};
  const { user } = challengeOr400(db, mfa_token, 'enroll');
  try {
    res.json(mfa.startEnrollment(db, user, algorithm));
  } catch (e) {
    if (e.field) throw new AppError(e.message, 400, 'VALIDATION');
    throw e;
  }
});

router.post('/enroll/confirm', (req, res) => {
  const db = getDb();
  const ip = ipOf(req);
  const { mfa_token, code } = req.body || {};
  if (!code || typeof code !== 'string') throw new AppError('code is required', 400, 'VALIDATION');
  const { challenge, user } = challengeOr400(db, mfa_token, 'enroll');
  const result = mfa.activateEnrollment(db, user, code, { ip });
  if (!result.ok) throw codeError(result);
  mfa.consumeChallenge(db, challenge.id);
  const session = issueSession(db, req, res, user, challenge.app_id);
  auditLogin(user.id, 'ok', { method: 'password+totp-enroll', ip });
  res.json({ ...sessionBody(session, user), recovery_codes: result.recovery_codes });
});

// ── signed in: own factor ─────────────────────────────────────────────────

router.get('/status', requireAuth, (req, res) => {
  const user = req.real_user || req.user;
  res.json(mfa.status(getDb(), user));
});

router.get('/session-policy', requireAuth, (req, res) => {
  const db = getDb();
  const user = req.real_user || req.user;
  const p = policyFor(user, db);
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const row = bearer && req.auth_credential_hash
    ? db.prepare('SELECT expires_at, absolute_expires_at FROM identity_sessions WHERE token_hash = ?').get(req.auth_credential_hash)
    : null;
  res.json({
    idle_minutes: p.idle,
    absolute_minutes: p.absolute,
    warn_before_seconds: WARN_BEFORE_S,
    session: row ? { expires_at: row.expires_at, absolute_expires_at: row.absolute_expires_at } : null,
  });
});

function requirePasswordIfSet(user, password) {
  if (!user.password_hash) return;
  if (!password || typeof password !== 'string' || !verifyPassword(password, user.password_hash)) {
    throw new AppError('Your current password is incorrect', 403, 'INVALID_CURRENT_PASSWORD');
  }
}

function fullUser(db, req) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get((req.real_user || req.user).id);
}

router.post('/setup', requireAuth, (req, res) => {
  const db = getDb();
  const user = fullUser(db, req);
  const { password, algorithm, current_code } = req.body || {};
  requirePasswordIfSet(user, password);
  if (mfa.isEnrolled(db, user.id)) {
    const r = mfa.verifyCode(db, user, String(current_code || ''), { ip: ipOf(req) });
    if (!r.ok) throw codeError(r);
  }
  try {
    res.json(mfa.startEnrollment(db, user, algorithm));
  } catch (e) {
    if (e.field) throw new AppError(e.message, 400, 'VALIDATION');
    throw e;
  }
});

router.post('/activate', requireAuth, (req, res) => {
  const db = getDb();
  const user = fullUser(db, req);
  const { code } = req.body || {};
  const result = mfa.activateEnrollment(db, user, String(code || ''), { ip: ipOf(req) });
  if (!result.ok) throw codeError(result);
  res.json({ ok: true, recovery_codes: result.recovery_codes });
});

router.post('/disable', requireAuth, (req, res) => {
  const db = getDb();
  const user = fullUser(db, req);
  const { password, code } = req.body || {};
  if (mfa.mfaRequiredFor(user, db)) {
    throw new AppError('Two-factor sign-in is required for your account on this instance.', 403, 'MFA_REQUIRED_BY_POLICY');
  }
  requirePasswordIfSet(user, password);
  const r = mfa.verifyCode(db, user, String(code || ''), { ip: ipOf(req) });
  if (!r.ok) throw codeError(r);
  mfa.disable(db, user, { ip: ipOf(req) });
  res.json({ ok: true });
});

// Own remembered devices. Always the caller's real user (never a view-as
// target), and revoke is scoped by user_id, so another user's id is a 404.
router.get('/trusted-devices', requireAuth, (req, res) => {
  const db = getDb();
  res.json({ remember_device_days: rememberDays(db), devices: listDevices(db, (req.real_user || req.user).id) });
});

router.delete('/trusted-devices/:deviceId', requireAuth, (req, res) => {
  const db = getDb();
  const userId = (req.real_user || req.user).id;
  if (!revokeDevice(db, userId, req.params.deviceId, { ip: ipOf(req) })) throw new AppError('Device not found', 404, 'NOT_FOUND');
  res.json({ ok: true });
});

router.delete('/trusted-devices', requireAuth, (req, res) => {
  const db = getDb();
  const userId = (req.real_user || req.user).id;
  res.json({ ok: true, revoked: revokeAllDevices(db, userId, { actorId: userId, reason: 'user', ip: ipOf(req) }) });
});

router.post('/recovery-codes', requireAuth, (req, res) => {
  const db = getDb();
  const user = fullUser(db, req);
  const { code } = req.body || {};
  const r = mfa.verifyCode(db, user, String(code || ''), { ip: ipOf(req) });
  if (!r.ok) throw codeError(r);
  res.json({ recovery_codes: mfa.regenerateRecoveryCodes(db, user, { ip: ipOf(req) }) });
});

// ── platform admin ────────────────────────────────────────────────────────

function policyBody(db) {
  return {
    mfa_required: mfa.requiredLevel(db), mfa_required_levels: mfa.REQUIRE_LEVELS, sessions: readPolicy(db), defaults: DEFAULTS, bounds: BOUNDS,
    remember_device_days: rememberDays(db), remember_device_max_days: REMEMBER_MAX_DAYS,
  };
}

router.get('/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(policyBody(getDb()));
});

router.put('/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const { mfa_required, sessions, remember_device_days } = req.body || {};
  const before = policyBody(db);
  let revokedDevices = 0;
  try {
    db.transaction(() => {
      if (mfa_required !== undefined) mfa.setRequiredLevel(db, mfa_required, req.user.id);
      if (sessions !== undefined) writePolicy(db, sessions, req.user.id);
      if (remember_device_days !== undefined) revokedDevices = setRememberDays(db, remember_device_days, req.user.id).revoked;
    })();
  } catch (e) {
    if (e.field) throw new AppError(e.message, 400, 'VALIDATION');
    throw e;
  }
  const after = policyBody(db);
  logAudit(req.user.id, null, 'platform-policy-change', {
    policy: 'sign-in',
    before: { mfa_required: before.mfa_required, sessions: before.sessions, remember_device_days: before.remember_device_days },
    after: { mfa_required: after.mfa_required, sessions: after.sessions, remember_device_days: after.remember_device_days },
    ...(revokedDevices && { revoked_trusted_devices: revokedDevices }),
  });
  res.json(after);
});

function targetUser(db, id) {
  const n = Number(id);
  const u = Number.isInteger(n) && n > 0 ? db.prepare('SELECT * FROM users WHERE id = ?').get(n) : null;
  if (!u) throw new AppError('User not found', 404, 'NOT_FOUND');
  return u;
}

router.get('/users/:id', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const s = mfa.status(db, targetUser(db, req.params.id));
  res.json({ enrolled: s.enrolled, enabled_at: s.enabled_at, recovery_codes_remaining: s.recovery_codes_remaining, required: s.required });
});

router.get('/users/:id/trusted-devices', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  res.json({ devices: listDevices(db, targetUser(db, req.params.id).id) });
});

router.delete('/users/:id/trusted-devices', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const target = targetUser(db, req.params.id);
  res.json({ ok: true, revoked: revokeAllDevices(db, target.id, { actorId: req.user.id, reason: 'admin', ip: ipOf(req) }) });
});

router.post('/users/:id/reset', requireAuth, requirePlatformAdmin, async (req, res) => {
  const db = getDb();
  const target = targetUser(db, req.params.id);
  const out = await mfa.adminReset(db, req.user, target, { ip: ipOf(req) });
  res.json({ ok: true, ...out });
});

export default router;
