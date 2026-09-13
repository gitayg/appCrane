import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Two defects found while adding the code-source badge.
//
// 1. App responses spread the whole apps row, so `github_token_encrypted` and
//    `claude_credentials_encrypted` went to every signed-in user who could list
//    the app — not only its admins. Ciphertext, but a stored credential all the
//    same, and the UI only ever reads the has_* booleans.
//
// 2. GET /api/enhancements/my accepted only a Bearer session. A dashboard
//    signed in with an API key got a 401 there on every page load, and the
//    dashboard reads any 401 from a session-gated route as a lapsed session and
//    signs the user out.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-app-secrets-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const ADMIN_KEY = generateApiKey('dhk_admin');
const USER_KEY = generateApiKey('dhk_user');
const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','admin@example.com','platform_admin',?,1,'human')")
  .run(hashApiKey(ADMIN_KEY)).lastInsertRowid;
const userId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('User','user@example.com','user',?,1,'human')")
  .run(hashApiKey(USER_KEY)).lastInsertRowid;

const appId = db.prepare('INSERT INTO apps (name,slug,slot,source_type,github_url,github_token_encrypted,claude_credentials_encrypted) VALUES (?,?,?,?,?,?,?)')
  .run('Secret', 'secret-app', 1, 'github', 'https://github.com/example/secret-app', encrypt('ghp_' + 'z'.repeat(36)), encrypt('{"oauth":"x"}')).lastInsertRowid;
db.prepare("INSERT INTO app_users (app_id, user_id) VALUES (?, ?)").run(appId, userId);

const SESSION = 'sess_' + 'q'.repeat(40);
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))")
  .run(userId, hashApiKey(SESSION));
db.prepare("INSERT INTO enhancement_requests (app_slug, message, user_id, status) VALUES ('secret-app', 'mine', ?, 'new')").run(userId);
db.prepare("INSERT INTO enhancement_requests (app_slug, message, user_id, status) VALUES ('secret-app', 'not mine', ?, 'new')").run(adminId);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const enhancementsRoutes = (await import('../server/routes/enhancements.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use('/api/enhancements', enhancementsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function get(path, headers) {
  const res = await fetch(`${BASE}${path}`, { headers });
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch (_) { /* not json */ }
  return { status: res.status, text, body };
}

const encryptedKeys = (text) => [...new Set([...text.matchAll(/"([a-z_]+_encrypted)"/g)].map((m) => m[1]))];

for (const [who, key] of [['platform admin', ADMIN_KEY], ['app user', USER_KEY]]) {
  test(`app list sends no encrypted column to a ${who}`, async () => {
    const r = await get('/api/apps', { 'X-API-Key': key });
    assert.equal(r.status, 200, r.text);
    const row = r.body.apps.find((a) => a.slug === 'secret-app');
    assert.ok(row, `the app is not in the list for the ${who}`);
    assert.deepEqual(encryptedKeys(r.text), [], 'an encrypted credential column left the server');
    assert.equal(row.has_github_token, true, 'the boolean the UI relies on is gone');
    assert.equal(row.has_claude_credentials, true);
  });

  test(`app detail sends no encrypted column to a ${who}`, async () => {
    const r = await get('/api/apps/secret-app', { 'X-API-Key': key });
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(encryptedKeys(r.text), [], 'an encrypted credential column left the server');
  });
}

test('no app response in apps.js spreads a raw row', () => {
  // The update and "no changes" responses are not reached above. Any `...app,`
  // or `...updated,` that is not wrapped reopens the leak for that response.
  const src = readFileSync(new URL('../server/routes/apps.js', import.meta.url), 'utf8');
  const raw = src.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => /\.\.\.(app|updated)\b(?!\w)/.test(l));
  assert.deepEqual(raw, [], 'a raw app row is spread into a response');
});

test('/api/enhancements/my answers an API-key caller with only their own requests', async () => {
  const r = await get('/api/enhancements/my', { 'X-API-Key': USER_KEY });
  assert.equal(r.status, 200, `an API-key dashboard gets ${r.status} here and is signed out: ${r.text}`);
  assert.deepEqual(r.body.requests.map((x) => x.message), ['mine']);
});

test('/api/enhancements/my still answers a Bearer session', async () => {
  const r = await get('/api/enhancements/my', { Authorization: `Bearer ${SESSION}` });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.body.requests.map((x) => x.message), ['mine']);
});

test('/api/enhancements/my still refuses a caller with no credential', async () => {
  const r = await get('/api/enhancements/my', {});
  assert.equal(r.status, 401);
});
