import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// POST /api/identity/set-password (self-service) and PUT /api/users/:id/password
// (platform admin), driven over HTTP through the real routers with the view-as
// write guard mounted the way server/index.js mounts it.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-setpw-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, hashPassword, verifyPassword } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { viewAsWriteGuard } = await import('../server/middleware/viewAsGuard.js');

initDb();
const db = getDb();

const OLD_PW = 'old-password-0001';
const NEW_PW = 'new-password-0002';

let seq = 0;
function mkUser({ role = 'user', password = OLD_PW } = {}) {
  const n = ++seq;
  const apiKey = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,password_hash,active,kind) VALUES (?,?,?,?,?,1,?)')
    .run(`pw${n}`, `pw${n}@t.test`, role, hashApiKey(apiKey), password ? hashPassword(password) : null, 'human').lastInsertRowid;
  const token = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(id, hashApiKey(token));
  return { id, token, apiKey };
}
const storedHash = (id) => db.prepare('SELECT password_hash FROM users WHERE id = ?').get(id).password_hash;
const sessionCount = (id) => db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?').get(id).n;

const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api', viewAsWriteGuard);
httpApp.use('/api/auth', (await import('../server/routes/viewAs.js')).default);
httpApp.use('/api/auth', (await import('../server/routes/auth.js')).default);
httpApp.use('/api/identity', (await import('../server/routes/identity.js')).default);
httpApp.use('/api/users', (await import('../server/routes/users.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

async function call(method, path, { token, apiKey, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (apiKey) headers['X-API-Key'] = apiKey;
  const res = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json, cookie: res.headers.get('set-cookie') || '' };
}
const setPw = (who, body) => call('POST', '/api/identity/set-password', { token: who.token, body });

test('a wrong or missing current password is refused and the password is unchanged', async () => {
  const u = mkUser();
  const before = storedHash(u.id);

  const wrong = await setPw(u, { current_password: 'not-the-password', password: NEW_PW });
  assert.equal(wrong.status, 403, JSON.stringify(wrong.body));
  assert.equal(wrong.body.error.code, 'INVALID_CURRENT_PASSWORD');
  assert.equal(wrong.body.error.message, 'Current password is incorrect');

  const missing = await setPw(u, { password: NEW_PW });
  assert.equal(missing.status, 400, JSON.stringify(missing.body));
  assert.equal(missing.body.error.code, 'CURRENT_PASSWORD_REQUIRED');

  assert.equal(storedHash(u.id), before, 'the password changed without the right current password');
  assert.equal(sessionCount(u.id), 1, 'a refused change still wiped the sessions');
});

test('the right current password changes it, invalidates old sessions, and the new token works', async () => {
  const u = mkUser();
  const second = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(u.id, hashApiKey(second));

  const r = await setPw(u, { current_password: OLD_PW, password: NEW_PW });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.token);
  assert.match(r.cookie, /cc_token=/, 'no session cookie was set');
  assert.ok(verifyPassword(NEW_PW, storedHash(u.id)));
  assert.ok(!verifyPassword(OLD_PW, storedHash(u.id)));

  assert.equal((await call('GET', '/api/identity/me', { token: u.token })).status, 401, 'the old session still works');
  assert.equal((await call('GET', '/api/identity/me', { token: second })).status, 401, 'another old session still works');
  assert.equal((await call('GET', '/api/identity/me', { token: r.body.token })).status, 200, 'the new token does not work');
  assert.equal(sessionCount(u.id), 1);
});

test('a user with no password sets one without a current password, by session or API key', async () => {
  const bySession = mkUser({ password: null });
  const r = await setPw(bySession, { password: NEW_PW });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(verifyPassword(NEW_PW, storedHash(bySession.id)));

  const byKey = mkUser({ password: null });
  const k = await call('POST', '/api/identity/set-password', { apiKey: byKey.apiKey, body: { password: NEW_PW } });
  assert.equal(k.status, 200, JSON.stringify(k.body));
  assert.ok(verifyPassword(NEW_PW, storedHash(byKey.id)));
});

test('too short and same-as-current are refused', async () => {
  const u = mkUser();
  const before = storedHash(u.id);
  const short = await setPw(u, { current_password: OLD_PW, password: 'short-pw' });
  assert.equal(short.status, 400);
  assert.equal(short.body.error.message, 'Password must be at least 12 characters');
  const same = await setPw(u, { current_password: OLD_PW, password: OLD_PW });
  assert.equal(same.status, 400);
  assert.equal(same.body.error.code, 'PASSWORD_UNCHANGED');
  assert.equal(storedHash(u.id), before);

  const fresh = mkUser({ password: null });
  assert.equal((await setPw(fresh, { password: 'short-pw' })).status, 400);
  assert.equal(storedHash(fresh.id), null);
});

test('wrong current passwords are rate limited per user, even a later right one', async () => {
  const u = mkUser();
  for (let i = 0; i < 5; i++) {
    const r = await setPw(u, { current_password: `wrong-${i}-xxxxxxxx`, password: NEW_PW });
    assert.equal(r.status, 403, `attempt ${i + 1}: ${JSON.stringify(r.body)}`);
  }
  const limited = await setPw(u, { current_password: OLD_PW, password: NEW_PW });
  assert.equal(limited.status, 429, JSON.stringify(limited.body));
  assert.equal(limited.body.error.code, 'RATE_LIMITED');
  assert.ok(verifyPassword(OLD_PW, storedHash(u.id)), 'the password changed while rate limited');

  // Another user is not affected by the first one's lockout.
  const other = mkUser();
  assert.equal((await setPw(other, { current_password: OLD_PW, password: NEW_PW })).status, 200);
});

test('the change and the failures are audited, never with a password', async () => {
  const u = mkUser();
  await setPw(u, { current_password: 'wrong-current-pw', password: NEW_PW });
  await setPw(u, { current_password: OLD_PW, password: NEW_PW });
  const rows = db.prepare("SELECT action, detail FROM audit_log WHERE user_id = ? AND action LIKE 'password-%' ORDER BY id").all(u.id);
  assert.deepEqual(rows.map((r) => r.action), ['password-change-failed', 'password-change']);
  assert.equal(JSON.parse(rows[0].detail).reason, 'bad_current_password');
  for (const r of rows) {
    for (const secret of [OLD_PW, NEW_PW, 'wrong-current-pw']) {
      assert.ok(!r.detail.includes(secret), `audit detail carries a password: ${r.action}`);
    }
  }

  const fresh = mkUser({ password: null });
  await setPw(fresh, { password: NEW_PW });
  const set = db.prepare("SELECT action FROM audit_log WHERE user_id = ? AND action LIKE 'password-%'").all(fresh.id);
  assert.deepEqual(set.map((r) => r.action), ['password-set']);
});

test('/api/auth/me reports has_password and never the hash', async () => {
  const withPw = mkUser();
  const without = mkUser({ password: null });
  const a = await call('GET', '/api/auth/me', { token: withPw.token });
  const b = await call('GET', '/api/auth/me', { token: without.token });
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.equal(a.body.user.has_password, true);
  assert.equal(b.body.user.has_password, false);
  assert.ok(!JSON.stringify(a.body).includes(storedHash(withPw.id)));
  assert.ok(!('password_hash' in a.body.user));
});

test('set-password is refused while viewing as, and works after stopping', async () => {
  const padmin = mkUser({ role: 'platform_admin' });
  const start = await call('POST', '/api/auth/view-as', { token: padmin.token, body: { role: 'user' } });
  assert.equal(start.status, 200, JSON.stringify(start.body));
  const r = await setPw(padmin, { current_password: OLD_PW, password: NEW_PW });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'VIEW_AS_READ_ONLY');
  assert.ok(verifyPassword(OLD_PW, storedHash(padmin.id)));
  await call('POST', '/api/auth/stop-viewing-as', { token: padmin.token, body: {} });
  assert.equal((await setPw(padmin, { current_password: OLD_PW, password: NEW_PW })).status, 200);
});

test('the admin route is unchanged: platform admin sets any password without a current one', async () => {
  const padmin = mkUser({ role: 'platform_admin' });
  const target = mkUser();
  const short = await call('PUT', `/api/users/${target.id}/password`, { token: padmin.token, body: { password: 'short' } });
  assert.equal(short.status, 400);
  assert.equal(short.body.error.message, 'Password must be at least 12 characters');
  const r = await call('PUT', `/api/users/${target.id}/password`, { token: padmin.token, body: { password: NEW_PW } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.message, `Password set for pw${seq}`);
  assert.ok(verifyPassword(NEW_PW, storedHash(target.id)));
  assert.equal(sessionCount(target.id), 0);

  const plain = mkUser();
  assert.equal((await call('PUT', `/api/users/${target.id}/password`, { token: plain.token, body: { password: NEW_PW } })).status, 403);
});
