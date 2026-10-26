import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import express from 'express';

// Local MFA for password sign-in (services/totp.js, services/mfa.js,
// routes/mfa.js). Driven over real HTTP against an ephemeral server; the clock
// is injected where a test needs a later time step rather than slept through.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mfa-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { hashPassword, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const totp = await import('../server/services/totp.js');
const mfa = await import('../server/services/mfa.js');

initDb();
const db = getDb();

const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api/identity/mfa', (await import('../server/routes/mfa.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const PASSWORD = 'correct horse battery staple';

function mkUser(role = 'user', { password = true } = {}) {
  const tag = randomBytes(4).toString('hex');
  const id = db.prepare("INSERT INTO users (name, email, username, role, password_hash, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, ?, 1, 'human')")
    .run(`u${tag}`, `u${tag}@t.test`, `u${tag}`, role, password ? hashPassword(PASSWORD) : null, hashApiKey(randomBytes(16).toString('hex'))).lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
function sessionFor(user) {
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(user.id, hashApiKey(token));
  return token;
}
async function call(method, path, body, token) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json };
}
const codeFor = (secretB32, alg = 'SHA1', nowMs = Date.now()) => totp.totp(totp.base32Decode(secretB32), nowMs, { algorithm: alg });

async function enroll(user, alg = 'SHA1') {
  const s = sessionFor(user);
  const start = await call('POST', '/api/identity/mfa/setup', { password: PASSWORD, algorithm: alg }, s);
  assert.equal(start.status, 200, JSON.stringify(start.body));
  // Activate on the previous step so the current one is still fresh for the test.
  const act = await call('POST', '/api/identity/mfa/activate', { code: codeFor(start.body.secret, alg, Date.now() - 30_000) }, s);
  assert.equal(act.status, 200, JSON.stringify(act.body));
  return { secret: start.body.secret, recovery: act.body.recovery_codes, session: s };
}

beforeEach(() => mfa._resetMfaRateLimitsForTests());

// ── RFC 6238 Appendix B ─────────────────────────────────────────────────────

test('TOTP matches the RFC 6238 test vectors (SHA1 and SHA256, 8 digits)', () => {
  const sha1 = Buffer.from('12345678901234567890');
  const sha256 = Buffer.from('12345678901234567890123456789012');
  const vectors = [
    [59, '94287082', '46119246'],
    [1111111109, '07081804', '68084774'],
    [1111111111, '14050471', '67062674'],
    [1234567890, '89005924', '91819424'],
    [2000000000, '69279037', '90698825'],
    [20000000000, '65353130', '77737706'],
  ];
  for (const [t, c1, c256] of vectors) {
    assert.equal(totp.totp(sha1, t * 1000, { digits: 8, algorithm: 'SHA1' }), c1, `SHA1 T=${t}`);
    assert.equal(totp.totp(sha256, t * 1000, { digits: 8, algorithm: 'SHA256' }), c256, `SHA256 T=${t}`);
  }
});

test('base32 round-trips and the otpauth URI carries issuer, algorithm, digits and period', () => {
  const buf = randomBytes(20);
  assert.deepEqual(totp.base32Decode(totp.base32Encode(buf)), buf);
  const uri = totp.otpauthUri({ secretB32: 'JBSWY3DPEHPK3PXP', account: 'a@t.test', algorithm: 'SHA256' });
  assert.match(uri, /^otpauth:\/\/totp\/AppCrane:a%40t\.test\?/);
  for (const p of ['secret=JBSWY3DPEHPK3PXP', 'issuer=AppCrane', 'algorithm=SHA256', 'digits=6', 'period=30']) assert.ok(uri.includes(p), p);
});

// ── enrollment + verification ───────────────────────────────────────────────

test('enroll then verify a code through the sign-in second step; the session is issued only after it', async () => {
  const u = mkUser();
  const { secret } = await enroll(u);
  const step = mfa.passwordLoginMfaStep(db, u);
  assert.equal(step.mfa_required, true);
  const before = db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?').get(u.id).n;
  const r = await call('POST', '/api/identity/mfa/verify', { mfa_token: step.mfa_token, code: codeFor(secret) });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.token);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?').get(u.id).n, before + 1);
  assert.ok(db.prepare('SELECT 1 FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(r.body.token)));
  const again = await call('POST', '/api/identity/mfa/verify', { mfa_token: step.mfa_token, code: codeFor(secret) });
  assert.equal(again.status, 400, 'a consumed mfa_token cannot issue a second session');
});

test('SHA256 TOTP enrolls and verifies', async () => {
  const u = mkUser();
  const { secret } = await enroll(u, 'SHA256');
  assert.equal(db.prepare('SELECT algorithm FROM user_mfa WHERE user_id = ?').get(u.id).algorithm, 'SHA256');
  assert.equal(mfa.verifyCode(db, u, codeFor(secret, 'SHA256')).ok, true);
  assert.equal(mfa.verifyCode(db, u, codeFor(secret, 'SHA1', Date.now() + 30_000)).ok, false, 'a SHA1 code is not a SHA256 code');
});

test('the TOTP secret is encrypted at rest and recovery codes are stored hashed', async () => {
  const u = mkUser();
  const { secret, recovery } = await enroll(u);
  const row = db.prepare('SELECT totp_secret_enc FROM user_mfa WHERE user_id = ?').get(u.id);
  assert.ok(!row.totp_secret_enc.includes(secret));
  assert.match(row.totp_secret_enc, /^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
  const hashes = db.prepare('SELECT code_hash FROM user_mfa_recovery_codes WHERE user_id = ?').all(u.id).map(r => r.code_hash);
  assert.equal(hashes.length, 10);
  assert.equal(recovery.length, 10);
  for (const c of recovery) assert.ok(!hashes.some(h => h.includes(c.replace('-', ''))));
});

test('a wrong code is refused with 400 (not 401) and no session is issued', async () => {
  const u = mkUser();
  const { secret } = await enroll(u);
  const step = mfa.passwordLoginMfaStep(db, u);
  const good = codeFor(secret);
  const wrong = String((Number(good) + 1) % 1_000_000).padStart(6, '0');
  const r = await call('POST', '/api/identity/mfa/verify', { mfa_token: step.mfa_token, code: wrong });
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, 'INVALID_CODE');
  assert.equal(r.body.token, undefined);
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'mfa-failed' AND user_id = ? ORDER BY id DESC").get(u.id);
  assert.ok(audit, 'a failed code is audited');
  assert.ok(!audit.detail.includes(wrong), 'the code itself is never written to the audit log');
  assert.ok(db.prepare("SELECT 1 FROM events WHERE kind = 'mfa' AND subject_user_id = ?").get(u.id), 'and recorded as an event');
});

test('a TOTP code cannot be replayed, inside its window or after', async () => {
  const u = mkUser();
  const { secret } = await enroll(u);
  const code = codeFor(secret);
  assert.equal(mfa.verifyCode(db, u, code).ok, true);
  const replay = mfa.verifyCode(db, u, code);
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replayed');
  const later = mfa.verifyCode(db, u, code, { nowMs: Date.now() + 30_000 });
  assert.equal(later.ok, false, 'still inside the ±1 step window one step later, and still refused');
  assert.equal(mfa.verifyCode(db, u, codeFor(secret, 'SHA1', Date.now() + 30_000), { nowMs: Date.now() + 30_000 }).ok, true, 'the next step is accepted');
});

test('a recovery code works once', async () => {
  const u = mkUser();
  const { recovery } = await enroll(u);
  const first = mfa.verifyCode(db, u, recovery[3].toLowerCase());
  assert.equal(first.ok, true);
  assert.equal(first.method, 'recovery_code');
  assert.equal(first.recovery_codes_remaining, 9);
  const second = mfa.verifyCode(db, u, recovery[3]);
  assert.equal(second.ok, false);
  assert.equal(mfa.verifyCode(db, u, recovery[4]).ok, true, 'other codes still work');
});

test('wrong codes are rate-limited per user, and per IP across users', async () => {
  const u = mkUser();
  await enroll(u);
  for (let i = 0; i < mfa.RATE.perUser; i++) assert.equal(mfa.verifyCode(db, u, '000000', { ip: '198.51.100.1' }).ok, false);
  const limited = mfa.verifyCode(db, u, '000000', { ip: '198.51.100.2' });
  assert.equal(limited.reason, 'rate_limited', 'the per-user limit holds from a different IP');
  assert.ok(limited.retry_after_s > 0);
  assert.equal(mfa.verifyCode(db, u, '000000', { ip: '198.51.100.2', nowMs: Date.now() + mfa.RATE.windowMs + 1000 }).reason, 'bad_code', 'and lifts after the window');

  mfa._resetMfaRateLimitsForTests();
  const ip = '198.51.100.9';
  let n = 0;
  while (n < mfa.RATE.perIp) {
    const v = mkUser();
    await enroll(v);
    for (let i = 0; i < 4 && n < mfa.RATE.perIp; i++, n++) mfa.verifyCode(db, v, '000000', { ip });
  }
  const fresh = mkUser();
  const { secret } = await enroll(fresh);
  assert.equal(mfa.verifyCode(db, fresh, codeFor(secret), { ip }).reason, 'rate_limited', 'a fresh user from a hammering IP is refused even with a right code');
});

test('the second-step ticket expires after 5 wrong attempts', async () => {
  const u = mkUser();
  await enroll(u);
  const { mfa_token } = mfa.passwordLoginMfaStep(db, u);
  for (let i = 0; i < mfa.CHALLENGE_MAX_ATTEMPTS; i++) {
    mfa._resetMfaRateLimitsForTests();
    await call('POST', '/api/identity/mfa/verify', { mfa_token, code: '000000' });
  }
  const r = await call('POST', '/api/identity/mfa/verify', { mfa_token, code: '000000' });
  assert.equal(r.body.error.code, 'MFA_TOKEN_INVALID');
});

// ── policy ──────────────────────────────────────────────────────────────────

test('default policy is "admins": an admin without MFA is sent to enrollment, a user is not', () => {
  db.prepare("DELETE FROM settings WHERE key = 'auth_mfa_required'").run();
  assert.equal(mfa.requiredLevel(db), 'admins');
  const admin = mkUser('platform_admin');
  const user = mkUser('user');
  const a = mfa.passwordLoginMfaStep(db, admin);
  assert.equal(a.mfa_enroll_required, true);
  assert.equal(a.error.code, 'MFA_ENROLL_REQUIRED');
  assert.equal(mfa.passwordLoginMfaStep(db, user), null);
  mfa.setRequiredLevel(db, 'everyone');
  assert.equal(mfa.passwordLoginMfaStep(db, user).mfa_enroll_required, true);
  mfa.setRequiredLevel(db, 'off');
  assert.equal(mfa.passwordLoginMfaStep(db, admin), null);
  db.prepare("DELETE FROM settings WHERE key = 'auth_mfa_required'").run();
});

test('forced enrollment at sign-in: start, confirm, recovery codes shown once, session issued', async () => {
  const admin = mkUser('platform_admin');
  const { mfa_token } = mfa.passwordLoginMfaStep(db, admin);
  const start = await call('POST', '/api/identity/mfa/enroll/start', { mfa_token });
  assert.equal(start.status, 200);
  assert.match(start.body.otpauth_uri, /^otpauth:\/\/totp\//);
  const refused = await call('POST', '/api/identity/mfa/verify', { mfa_token, code: codeFor(start.body.secret) });
  assert.equal(refused.status, 400, 'an enroll ticket cannot be used as a verify ticket');
  const done = await call('POST', '/api/identity/mfa/enroll/confirm', { mfa_token, code: codeFor(start.body.secret) });
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(done.body.recovery_codes.length, 10);
  assert.ok(done.body.token);
  assert.equal(mfa.isEnrolled(db, admin.id), true);
  assert.equal(mfa.passwordLoginMfaStep(db, admin).mfa_required, true, 'the next sign-in asks for a code');
});

test('a user cannot turn MFA off while the policy requires it', async () => {
  const admin = mkUser('platform_admin');
  const { secret, session } = await enroll(admin);
  const r = await call('POST', '/api/identity/mfa/disable', { password: PASSWORD, code: codeFor(secret) }, session);
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'MFA_REQUIRED_BY_POLICY');
});

test('re-enrolling over an active factor needs the password and a current code', async () => {
  const u = mkUser();
  const { secret, session } = await enroll(u);
  assert.equal((await call('POST', '/api/identity/mfa/setup', { password: 'nope' }, session)).status, 403);
  assert.equal((await call('POST', '/api/identity/mfa/setup', { password: PASSWORD }, session)).status, 400);
  assert.equal((await call('POST', '/api/identity/mfa/setup', { password: PASSWORD, current_code: codeFor(secret) }, session)).status, 200);
});

// ── admin reset ─────────────────────────────────────────────────────────────

test('a platform admin resets a user\'s MFA: audited, evented, e-mailed; a non-admin cannot', async () => {
  const admin = mkUser('platform_admin');
  const adminSession = sessionFor(admin);
  const victim = mkUser();
  await enroll(victim);
  const other = mkUser();
  const denied = await call('POST', `/api/identity/mfa/users/${victim.id}/reset`, {}, sessionFor(other));
  assert.equal(denied.status, 403);
  assert.equal(mfa.isEnrolled(db, victim.id), true);

  const r = await call('POST', `/api/identity/mfa/users/${victim.id}/reset`, {}, adminSession);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.was_enrolled, true);
  assert.equal(r.body.mailed, true);
  assert.equal(mfa.isEnrolled(db, victim.id), false);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM user_mfa_recovery_codes WHERE user_id = ?').get(victim.id).n, 0);
  const audit = db.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'mfa-reset' ORDER BY id DESC").get();
  assert.equal(audit.user_id, admin.id);
  assert.equal(JSON.parse(audit.detail).target_user_id, victim.id);
  assert.ok(db.prepare("SELECT 1 FROM events WHERE kind = 'mfa' AND severity = 'warning' AND user_id = ? AND subject_user_id = ?").get(admin.id, victim.id));
  const mail = db.prepare("SELECT to_email, subject, source FROM email_queue WHERE to_email = ? ORDER BY id DESC").get(victim.email);
  assert.ok(mail, 'the user is e-mailed');
  assert.equal(mail.source, 'mfa');
  assert.match(mail.subject, /two-factor sign-in was reset/i);
});

test('policy endpoints are platform-admin only, validate, and audit the change', async () => {
  const admin = mkUser('platform_admin');
  const s = sessionFor(admin);
  assert.equal((await call('GET', '/api/identity/mfa/policy', null, sessionFor(mkUser()))).status, 403);
  const bad = await call('PUT', '/api/identity/mfa/policy', { mfa_required: 'sometimes' }, s);
  assert.equal(bad.status, 400);
  const badIdle = await call('PUT', '/api/identity/mfa/policy', { sessions: { admin: { idle: 600 } } }, s);
  assert.equal(badIdle.status, 400, 'idle longer than the 480-minute admin absolute is refused');
  const ok = await call('PUT', '/api/identity/mfa/policy', { mfa_required: 'everyone', sessions: { admin: { idle: 15 } } }, s);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.mfa_required, 'everyone');
  assert.equal(ok.body.sessions.admin.idle, 15);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'platform-policy-change' AND user_id = ? AND detail LIKE '%sign-in%'").get(admin.id));
  db.prepare("DELETE FROM settings WHERE key IN ('auth_mfa_required', 'session_admin_idle_minutes', 'session_admin_absolute_minutes', 'session_user_idle_minutes', 'session_user_absolute_minutes')").run();
});

// ── SSO ─────────────────────────────────────────────────────────────────────

test('SSO is not double-prompted: the gate is only on password sign-in, and an SSO session works for an enrolled admin', async () => {
  for (const f of ['oidc.js', 'saml.js']) {
    const src = readFileSync(new URL(`../server/routes/${f}`, import.meta.url), 'utf8');
    assert.doesNotMatch(src, /passwordLoginMfaStep|services\/mfa\.js/, `${f} must not run the local MFA step`);
    assert.match(src, /INSERT INTO identity_sessions/, `${f} still issues its session directly (sanity check)`);
  }
  mfa.setRequiredLevel(db, 'everyone');
  const admin = mkUser('platform_admin', { password: false });
  await (async () => {
    const token = randomBytes(24).toString('base64url');
    db.prepare('INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at) VALUES (?, ?, ?, ?)')
      .run(admin.id, hashApiKey(token), null, new Date(Date.now() + 86400000).toISOString());
    const r = await call('GET', '/api/identity/mfa/status', null, token);
    assert.equal(r.status, 200, 'requireAuth accepts the IdP-issued session without a local second factor');
    assert.equal(r.body.enrolled, false);
    assert.equal(r.body.has_password, false);
  })();
  db.prepare("DELETE FROM settings WHERE key = 'auth_mfa_required'").run();
});
