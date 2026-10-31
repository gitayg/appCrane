import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import express from 'express';

// "Remember this device" for local MFA, end to end over HTTP: the admin
// setting, the checkbox signal and cookie on /mfa/verify, the skip on the next
// POST /api/identity/login (password still required), expiry under the
// current setting, revocation, and the paths that must never honour it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-trusted-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { hashPassword, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const totp = await import('../server/services/totp.js');
const mfa = await import('../server/services/mfa.js');
const td = await import('../server/services/trustedDevices.js');
const { runTrustedDevicePurge } = await import('../server/services/trustedDevicePurge.js');
const { sqlUtc } = await import('../server/services/sessionPolicy.js');
initDb();
const db = getDb();

const httpApp = express();
httpApp.set('trust proxy', true);
httpApp.use(express.json());
httpApp.use('/api/identity/mfa', (await import('../server/routes/mfa.js')).default);
httpApp.use('/api/identity', (await import('../server/routes/identity.js')).default);
httpApp.use('/api/settings', (await import('../server/routes/settings.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const PASSWORD = 'a long enough password';
const DAY = 86_400_000;
let ipSeq = 0;
// The login limiter allows 5 per minute per IP; each request gets its own.
const nextIp = () => `10.9.${Math.floor(++ipSeq / 250)}.${ipSeq % 250}`;

function mkUser(role = 'user') {
  const tag = randomBytes(4).toString('hex');
  return db.prepare("INSERT INTO users (name, email, username, role, password_hash, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, ?, 1, 'human')")
    .run(`t${tag}`, `t${tag}@t.test`, `t${tag}`, role, hashPassword(PASSWORD), hashApiKey(tag)).lastInsertRowid;
}
const userRow = (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
function enroll(id) {
  const user = userRow(id);
  const { secret } = mfa.startEnrollment(db, user);
  const key = totp.base32Decode(secret);
  assert.equal(mfa.activateEnrollment(db, user, totp.totp(key, Date.now() - 30_000)).ok, true);
  return key;
}
function sessionFor(id) {
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  return token;
}
async function call(method, path, body, headers = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp(), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})), cookies: res.headers.getSetCookie() };
}
const post = (path, body, headers) => call('POST', path, body, headers);
const trustCookie = (cookies) => cookies.find((c) => /^(__Secure-)?cc_mfa_trust=[^;]/.test(c)) || null;
const cookiePair = (setCookie) => setCookie.split(';')[0];
const login = (username, cookie, password = PASSWORD) =>
  post('/api/identity/login', { login: username, password }, cookie ? { Cookie: cookie } : {});
const setDays = (n) => db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auth_mfa_remember_days', ?)").run(String(n));
const audits = (action) => db.prepare('SELECT * FROM audit_log WHERE action = ?').all(action);

// A full password + code sign-in with the box ticked; returns the cookie pair.
async function rememberedSignIn(id, key, headers = {}) {
  const u = userRow(id);
  const s1 = await login(u.username);
  assert.equal(s1.body.error?.code, 'MFA_REQUIRED');
  // Forget the last used step so the current code is not refused as a replay.
  db.prepare('UPDATE user_mfa SET last_used_step = NULL WHERE user_id = ?').run(id);
  const code = totp.totp(key);
  const s2 = await post('/api/identity/mfa/verify', { mfa_token: s1.body.mfa_token, code, remember_device: true }, headers);
  assert.equal(s2.status, 200, JSON.stringify(s2.body));
  return { res: s2, cookie: trustCookie(s2.cookies) };
}

beforeEach(() => {
  mfa._resetMfaRateLimitsForTests();
  db.prepare("DELETE FROM settings WHERE key = 'auth_mfa_remember_days'").run();
  db.prepare("UPDATE settings SET value = 'off' WHERE key = 'auth_mfa_required'").run();
});

test('setting off (the default): no checkbox signal, no cookie, and a stale cookie is not honoured', async () => {
  assert.equal(td.rememberDays(db), 0);
  const id = mkUser();
  const key = enroll(id);
  const s1 = await login(userRow(id).username);
  assert.equal(s1.body.remember_device_days, 0, 'sign-in page is told not to show the box');
  db.prepare('UPDATE user_mfa SET last_used_step = NULL WHERE user_id = ?').run(id);
  const s2 = await post('/api/identity/mfa/verify', { mfa_token: s1.body.mfa_token, code: totp.totp(key), remember_device: true });
  assert.equal(s2.status, 200);
  assert.equal(trustCookie(s2.cookies), null);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM mfa_trusted_devices WHERE user_id = ?').get(id).n, 0);

  setDays(30);
  const { cookie } = await rememberedSignIn(id, key);
  setDays(0);
  const s3 = await login(userRow(id).username, cookiePair(cookie));
  assert.equal(s3.body.error?.code, 'MFA_REQUIRED', 'off means off for existing devices too');
});

test('on: cookie has the right attributes, next sign-in skips MFA, password still required', async () => {
  setDays(7);
  const id = mkUser();
  const key = enroll(id);
  const s1 = await login(userRow(id).username);
  assert.equal(s1.body.remember_device_days, 7);

  const { res, cookie } = await rememberedSignIn(id, key);
  assert.ok(cookie, 'trusted-device cookie issued');
  assert.equal(res.body.device_remembered_days, 7);
  assert.match(cookie, /^cc_mfa_trust=/, 'plain HTTP falls back to the bare name');
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Strict/i);
  assert.match(cookie, /Path=\/api\/identity\/login(;|$)/);
  assert.match(cookie, new RegExp(`Max-Age=${7 * 86400}(;|$)`));
  assert.doesNotMatch(cookie, /;\s*Secure/i, 'no Secure on plain HTTP, same as cc_token');

  const ok = await login(userRow(id).username, cookiePair(cookie));
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.ok(ok.body.token, 'session issued without a code');
  assert.equal(audits('mfa-skipped-trusted-device').length >= 1, true);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'login' AND detail LIKE '%password+trusted_device%'").get());

  const bad = await login(userRow(id).username, cookiePair(cookie), 'the wrong password!!');
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error.code, 'INVALID_CREDENTIALS', 'the cookie never stands in for the password');
  assert.equal(bad.body.token, undefined);
});

test('over HTTPS the cookie is __Secure- and Secure, matching the session cookie decision', async () => {
  setDays(1);
  const id = mkUser();
  const key = enroll(id);
  const { cookie } = await rememberedSignIn(id, key, { 'X-Forwarded-Proto': 'https' });
  assert.match(cookie, /^__Secure-cc_mfa_trust=/);
  assert.match(cookie, /;\s*Secure/i);
  const ok = await login(userRow(id).username, cookiePair(cookie));
  assert.equal(ok.status, 200);
});

test("another user's token is rejected", async () => {
  setDays(30);
  const a = mkUser();
  const b = mkUser();
  const keyA = enroll(a);
  enroll(b);
  const { cookie } = await rememberedSignIn(a, keyA);
  const r = await login(userRow(b).username, cookiePair(cookie));
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'MFA_REQUIRED');
});

test('expired token, and a lowered setting, are rejected', async () => {
  setDays(30);
  const id = mkUser();
  const key = enroll(id);
  const { cookie } = await rememberedSignIn(id, key);
  const pair = cookiePair(cookie);

  db.prepare('UPDATE mfa_trusted_devices SET created_at = ? WHERE user_id = ?').run(sqlUtc(Date.now() - 10 * DAY), id);
  assert.equal((await login(userRow(id).username, pair)).status, 200, '10 days old, 30 allowed');
  setDays(5);
  const lowered = await login(userRow(id).username, pair);
  assert.equal(lowered.body.error?.code, 'MFA_REQUIRED', 'created_at + current setting is the limit');

  setDays(30);
  db.prepare('UPDATE mfa_trusted_devices SET created_at = ?, expires_at = ? WHERE user_id = ?')
    .run(sqlUtc(Date.now() - DAY), sqlUtc(Date.now() - 1000), id);
  const expired = await login(userRow(id).username, pair);
  assert.equal(expired.body.error?.code, 'MFA_REQUIRED', 'past its own expires_at');
  assert.ok(expired.cookies.some((c) => /^cc_mfa_trust=;/.test(c)), 'a dead cookie is cleared');

  assert.equal(await runTrustedDevicePurge(db), 1, 'daily purge removes the expired row');
});

test('password change and MFA reset / disable / re-enroll revoke every device', async () => {
  setDays(30);
  const id = mkUser();
  let key = enroll(id);
  await rememberedSignIn(id, key);
  await rememberedSignIn(id, key);
  const count = () => db.prepare('SELECT COUNT(*) n FROM mfa_trusted_devices WHERE user_id = ?').get(id).n;
  assert.equal(count(), 2);
  const r = await post('/api/identity/set-password', { current_password: PASSWORD, password: 'another long password' },
    { Authorization: `Bearer ${sessionFor(id)}` });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(count(), 0, 'password change');
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(PASSWORD), id);

  await rememberedSignIn(id, key);
  await mfa.adminReset(db, userRow(mkUser('platform_admin')), userRow(id), { mail: async () => false });
  assert.equal(count(), 0, 'admin MFA reset');

  key = enroll(id);
  await rememberedSignIn(id, key);
  mfa.disable(db, userRow(id));
  assert.equal(count(), 0, 'MFA disable');

  key = enroll(id);
  const { cookie } = await rememberedSignIn(id, key);
  enroll(id);
  assert.equal(count(), 0, 're-enroll');
  assert.equal((await login(userRow(id).username, cookiePair(cookie))).body.error?.code, 'MFA_REQUIRED');
  assert.ok(audits('mfa-devices-revoked').length >= 4);
});

test('a re-enrolled factor invalidates a row even if a revoke was missed', async () => {
  setDays(30);
  const id = mkUser();
  const key = enroll(id);
  const { cookie } = await rememberedSignIn(id, key);
  db.prepare("UPDATE user_mfa SET enabled_at = datetime('now', '+1 minute') WHERE user_id = ?").run(id);
  assert.equal((await login(userRow(id).username, cookiePair(cookie))).body.error?.code, 'MFA_REQUIRED');
});

test('step-up checks still demand a fresh code after a remembered-device sign-in', async () => {
  setDays(30);
  const id = mkUser();
  const key = enroll(id);
  const { cookie } = await rememberedSignIn(id, key);
  const ok = await login(userRow(id).username, cookiePair(cookie));
  assert.equal(ok.status, 200);
  const auth = { Authorization: `Bearer ${ok.body.token}`, Cookie: cookiePair(cookie) };
  const dis = await post('/api/identity/mfa/disable', { password: PASSWORD, code: '' }, auth);
  assert.equal(dis.status, 400);
  assert.equal(dis.body.error.code, 'INVALID_CODE');
  const regen = await post('/api/identity/mfa/recovery-codes', { code: '' }, auth);
  assert.equal(regen.body.error.code, 'INVALID_CODE');
  const setup = await post('/api/identity/mfa/setup', { password: PASSWORD, current_code: '' }, auth);
  assert.equal(setup.body.error.code, 'INVALID_CODE');
  assert.equal(mfa.isEnrolled(db, id), true);
});

test('MFA rate limit still applies on /verify with remember_device, and no cookie is issued', async () => {
  setDays(30);
  const id = mkUser();
  enroll(id);
  let last;
  for (let i = 0; i < 7; i++) {
    const s1 = await login(userRow(id).username);
    last = await post('/api/identity/mfa/verify', { mfa_token: s1.body.mfa_token, code: '000000', remember_device: true });
    assert.equal(trustCookie(last.cookies), null);
  }
  assert.equal(last.status, 429);
});

test('the token is never stored or audited in plaintext', async () => {
  setDays(30);
  const id = mkUser();
  const key = enroll(id);
  const { cookie } = await rememberedSignIn(id, key);
  const token = decodeURIComponent(cookiePair(cookie).split('=')[1]);
  await login(userRow(id).username, cookiePair(cookie));
  assert.ok(token.length >= 43);
  const row = db.prepare('SELECT * FROM mfa_trusted_devices WHERE user_id = ?').get(id);
  assert.equal(row.token_hash, hashApiKey(token));
  assert.match(row.public_id, /^[A-Za-z0-9_-]{22}$/);
  for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all()) {
    for (const r of db.prepare(`SELECT * FROM "${name}"`).all()) {
      for (const v of Object.values(r)) {
        if (typeof v === 'string') assert.ok(!v.includes(token), `token found in ${name}`);
      }
    }
  }
});

test('device list and revoke are per user; admin revoke-all requires platform admin', async () => {
  setDays(30);
  const a = mkUser();
  const b = mkUser();
  const keyA = enroll(a);
  await rememberedSignIn(a, keyA);
  const asA = { Authorization: `Bearer ${sessionFor(a)}` };
  const asB = { Authorization: `Bearer ${sessionFor(b)}` };
  const list = await call('GET', '/api/identity/mfa/trusted-devices', undefined, asA);
  assert.equal(list.body.devices.length, 1);
  const devId = list.body.devices[0].id;
  assert.equal((await call('GET', '/api/identity/mfa/trusted-devices', undefined, asB)).body.devices.length, 0);
  assert.equal((await call('DELETE', `/api/identity/mfa/trusted-devices/${devId}`, undefined, asB)).status, 404);
  assert.equal((await call('DELETE', `/api/identity/mfa/users/${a}/trusted-devices`, undefined, asB)).status, 403);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM mfa_trusted_devices WHERE user_id = ?').get(a).n, 1);
  assert.equal((await call('DELETE', `/api/identity/mfa/trusted-devices/${devId}`, undefined, asA)).status, 200);
  await rememberedSignIn(a, keyA);
  const admin = { Authorization: `Bearer ${sessionFor(mkUser('platform_admin'))}` };
  const r = await call('DELETE', `/api/identity/mfa/users/${a}/trusted-devices`, undefined, admin);
  assert.equal(r.body.revoked, 1);
});

test('admin policy: validated 0-30, audited, turning off deletes rows; generic settings PUT refused', async () => {
  db.prepare('DELETE FROM mfa_trusted_devices').run();
  const admin = { Authorization: `Bearer ${sessionFor(mkUser('platform_admin'))}` };
  assert.equal((await call('PUT', '/api/identity/mfa/policy', { remember_device_days: 31 }, admin)).status, 400);
  assert.equal((await call('PUT', '/api/identity/mfa/policy', { remember_device_days: 1.5 }, admin)).status, 400);
  const on = await call('PUT', '/api/identity/mfa/policy', { remember_device_days: 30 }, admin);
  assert.equal(on.status, 200);
  assert.equal(on.body.remember_device_days, 30);
  assert.equal(on.body.remember_device_max_days, 30);
  const id = mkUser();
  const key = enroll(id);
  await rememberedSignIn(id, key);
  const off = await call('PUT', '/api/identity/mfa/policy', { remember_device_days: 0 }, admin);
  assert.equal(off.body.remember_device_days, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM mfa_trusted_devices').get().n, 0);
  const last = audits('platform-policy-change').at(-1);
  const detail = JSON.parse(last.detail);
  assert.equal(detail.before.remember_device_days, 30);
  assert.equal(detail.after.remember_device_days, 0);
  assert.equal(detail.revoked_trusted_devices, 1);
  const user = { Authorization: `Bearer ${sessionFor(mkUser())}` };
  assert.equal((await call('PUT', '/api/identity/mfa/policy', { remember_device_days: 30 }, user)).status, 403);
  assert.equal((await call('PUT', '/api/settings/auth_mfa_remember_days', { value: '30' }, admin)).status, 403);
});

test('only the password sign-in reads the cookie: SSO, API-key and step-up code never call it', () => {
  const read = (p) => readFileSync(new URL(`../server/${p}`, import.meta.url), 'utf8');
  const callers = [];
  for (const dir of ['routes', 'services', 'middleware', 'utils']) {
    for (const f of readdirSync(new URL(`../server/${dir}/`, import.meta.url), { recursive: true })) {
      if (!String(f).endsWith('.js')) continue;
      if (/trustedDeviceFor\(/.test(read(`${dir}/${f}`)) && `${dir}/${f}` !== 'services/trustedDevices.js') callers.push(`${dir}/${f}`);
    }
  }
  assert.deepEqual(callers, ['routes/identity.js']);
  const src = read('routes/identity.js');
  const start = src.indexOf("router.post('/login'");
  const end = src.indexOf('\nrouter.', start + 1);
  const at = src.indexOf('trustedDeviceFor(');
  assert.ok(at > start && at < end, 'the one call is inside POST /login');
  assert.ok(at > src.indexOf('verifyPassword(password', start), 'and after the password check');
  for (const f of ['routes/oidc.js', 'routes/saml.js', 'routes/ssoPopup.js', 'middleware/auth.js']) {
    assert.doesNotMatch(read(f), /trustedDevices|cc_mfa_trust/, `${f} must not read the trusted-device cookie`);
  }
});
