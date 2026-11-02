import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The Requests badge polled the whole list every 15 s to count it. Each count
// endpoint must answer exactly what the badge computed from its list endpoint
// (rows whose status is not terminal), under the same auth: no row the list
// would hide may be counted.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-enh-count-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const keys = {};
const sessions = {};
const ids = {};
for (const [name, role] of [['admin', 'platform_admin'], ['owner', 'user'], ['plain', 'user']]) {
  keys[name] = generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  ids[name] = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@example.com`, role, hashApiKey(keys[name])).lastInsertRowid;
  sessions[name] = `sess-${name}-${'x'.repeat(20)}`;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))")
    .run(ids[name], hashApiKey(sessions[name]));
}
db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES ('Mine','mine-app',1,'managed','forward_auth','private')").run();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES ('Theirs','their-app',2,'managed','forward_auth','private')").run();
const mineId = db.prepare("SELECT id FROM apps WHERE slug = 'mine-app'").get().id;
db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(mineId, ids.owner);

const ins = db.prepare('INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status) VALUES (?,?,?,?,?)');
const STATUSES = ['new', 'selected', 'in_progress', 'done', 'merged', 'FAILED', 'cancelled', 'closed', 'no_changes_needed'];
for (const slug of ['mine-app', 'their-app', '_platform', null]) {
  for (const st of STATUSES) {
    for (const who of ['owner', 'plain']) ins.run(slug, ids[who], who, `${slug}/${st}`, st);
  }
}

const enhancementsRoutes = (await import('../server/routes/enhancements.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/enhancements', enhancementsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); });

const get = (path, headers) => fetch(BASE + path, { headers });
const TERM = new Set(['done', 'merged', 'closed', 'failed', 'cancelled']);
const badgeCount = (requests) => requests.filter(r => !TERM.has((r.status || '').toLowerCase())).length;

async function pair(listPath, headers) {
  const list = await get(listPath, headers);
  assert.equal(list.status, 200, listPath);
  const count = await get(`${listPath}/count`, headers);
  assert.equal(count.status, 200, `${listPath}/count`);
  return { expected: badgeCount((await list.json()).requests), got: (await count.json()).count };
}

test('admin: /count equals the open rows of the admin list', async () => {
  const { expected, got } = await pair('/api/enhancements', { 'X-API-Key': keys.admin });
  assert.ok(expected > 0);
  assert.equal(got, expected);
});

test('owner: /owned/count equals the open rows of /owned (only the apps they own)', async () => {
  const { expected, got } = await pair('/api/enhancements/owned', { authorization: `Bearer ${sessions.owner}` });
  assert.equal(expected, 8, 'mine-app: 4 open statuses x 2 requesters');
  assert.equal(got, expected);
});

test('user: /my/count equals the open rows of /my (only their own)', async () => {
  const { expected, got } = await pair('/api/enhancements/my', { 'X-API-Key': keys.plain });
  assert.equal(expected, 16, '4 slugs x 4 open statuses');
  assert.equal(got, expected);
});

test('the counts keep the list endpoints\' gates', async () => {
  assert.equal((await get('/api/enhancements/count', {})).status, 401);
  assert.equal((await get('/api/enhancements/count', { 'X-API-Key': keys.plain })).status, 403);
  assert.equal((await get('/api/enhancements/owned/count', {})).status, 401);
  assert.equal((await get('/api/enhancements/my/count', {})).status, 401);
  const none = await get('/api/enhancements/owned/count', { authorization: `Bearer ${sessions.plain}` });
  assert.deepEqual(await none.json(), { count: 0 });
});
