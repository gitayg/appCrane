import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { randomBytes } from 'crypto';
import express from 'express';

// END-TO-END: POST /api/identity/login -> MFA second step -> session.
//
// Needs the MFA branch in server/routes/identity.js POST /login (the call to
// passwordLoginMfaStep). Until that snippet is applied this file SKIPS, by
// design, with a message saying so. IDENTITY_ROUTER_PATH lets a proof run point
// it at a patched copy.

const ROUTER = process.env.IDENTITY_ROUTER_PATH || fileURLToPath(new URL('../server/routes/identity.js', import.meta.url));
const applied = /passwordLoginMfaStep/.test(readFileSync(ROUTER, 'utf8'));
const skip = applied ? false : 'identity.js MFA snippet not applied yet (POST /login does not call passwordLoginMfaStep)';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mfaflow-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
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
httpApp.use('/api/identity', (await import(pathToFileURL(ROUTER).href)).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const PASSWORD = 'a long enough password';
function mkUser(role) {
  const tag = randomBytes(4).toString('hex');
  return db.prepare("INSERT INTO users (name, email, username, role, password_hash, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, ?, 1, 'human')")
    .run(`f${tag}`, `f${tag}@t.test`, `f${tag}`, role, hashPassword(PASSWORD), hashApiKey(tag)).lastInsertRowid;
}
async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json(), cookie: res.headers.get('set-cookie') };
}
const sessions = (id) => db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?').get(id).n;
const login = (u) => post('/api/identity/login', { login: u, password: PASSWORD });

test('an enrolled user gets no session from the password alone, then one after the code', { skip }, async () => {
  const id = mkUser('user');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const { secret } = mfa.startEnrollment(db, user);
  const r0 = mfa.activateEnrollment(db, user, totp.totp(totp.base32Decode(secret), Date.now() - 30_000));
  assert.equal(r0.ok, true);

  const step1 = await login(user.username);
  assert.equal(step1.status, 401);
  assert.equal(step1.body.error.code, 'MFA_REQUIRED');
  assert.ok(step1.body.mfa_token);
  assert.equal(step1.body.token, undefined);
  assert.equal(step1.cookie, null, 'no session cookie before the second step');
  assert.equal(sessions(id), 0);

  const step2 = await post('/api/identity/mfa/verify', { mfa_token: step1.body.mfa_token, code: totp.totp(totp.base32Decode(secret)) });
  assert.equal(step2.status, 200, JSON.stringify(step2.body));
  assert.ok(step2.body.token);
  assert.match(step2.cookie || '', /cc_token=/);
  assert.equal(sessions(id), 1);
});

test('an admin without MFA under the default policy is sent to enrollment, then signed in', { skip }, async () => {
  const id = mkUser('platform_admin');
  const step1 = await login(db.prepare('SELECT username FROM users WHERE id = ?').get(id).username);
  assert.equal(step1.status, 401);
  assert.equal(step1.body.error.code, 'MFA_ENROLL_REQUIRED');
  assert.equal(sessions(id), 0);
  const start = await post('/api/identity/mfa/enroll/start', { mfa_token: step1.body.mfa_token });
  const done = await post('/api/identity/mfa/enroll/confirm', { mfa_token: step1.body.mfa_token, code: totp.totp(totp.base32Decode(start.body.secret)) });
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(done.body.recovery_codes.length, 10);
  assert.equal(sessions(id), 1);
});

test('a regular user without MFA under the default policy signs in with the password as before', { skip }, async () => {
  const id = mkUser('user');
  const r = await login(db.prepare('SELECT username FROM users WHERE id = ?').get(id).username);
  assert.equal(r.status, 200);
  assert.ok(r.body.token);
  assert.equal(sessions(id), 1);
});

// Needs the second identity.js snippet (touchSession in GET /verify). Skips until applied.
const touchApplied = /touchSession/.test(readFileSync(ROUTER, 'utf8'));
test('per-app traffic through GET /api/identity/verify keeps an active session alive', { skip: touchApplied ? false : 'identity.js /verify touch snippet not applied yet' }, async () => {
  const id = mkUser('platform_admin');
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  const back = (s, m) => new Date(Date.parse(s.replace(' ', 'T')) - m * 60_000).toISOString().slice(0, 19).replace('T', ' ') + 'Z';
  const r0 = db.prepare('SELECT * FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(token));
  db.prepare('UPDATE identity_sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?').run(back(r0.last_seen_at, 25), back(r0.expires_at, 25), r0.id);
  const res = await fetch(`${BASE}/api/identity/verify`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(res.status, 200);
  const r1 = db.prepare('SELECT * FROM identity_sessions WHERE id = ?').get(r0.id);
  assert.ok(Date.parse(r1.expires_at.replace(' ', 'T')) > Date.now() + 29 * 60_000, `slid forward: ${r1.expires_at}`);
});
