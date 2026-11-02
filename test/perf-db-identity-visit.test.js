import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// /verify records one visit per user/app/day. The app it records is the one
// already resolved for the role check, not a second lookup by slug.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-perf-db-visit-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkApp = (slug, slot) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES (?,?,?,'managed','forward_auth','private')",
).run(slug, slug, slot).lastInsertRowid;
const ALPHA = mkApp('visit-alpha', 1);
const BETA = mkApp('visit-beta', 2);
const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('Vera','vera@example.com','user',1,?)")
  .run(hashApiKey('unused')).lastInsertRowid;
for (const a of [ALPHA, BETA]) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(a, uid);
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))")
  .run(uid, hashApiKey('visit-token'));

const api = express();
api.use('/api/identity', (await import('../server/routes/identity.js')).default);
api.use((await import('../server/utils/errors.js')).errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const verify = (qs) => fetch(`${BASE}/api/identity/verify${qs}`, { headers: { Authorization: 'Bearer visit-token' }, redirect: 'manual' });
const visits = () => db.prepare('SELECT app_id FROM app_visits WHERE user_id = ? ORDER BY app_id').all(uid).map(r => r.app_id);

test('a verify for ?app=<slug> records the visit against that app, once a day', async () => {
  assert.equal((await verify('?app=visit-beta&prefix=/visit-beta')).status, 200);
  assert.deepEqual(visits(), [BETA]);
  assert.equal((await verify('?app=visit-beta&prefix=/visit-beta')).status, 200);
  assert.equal((await verify('?app=visit-alpha&prefix=/visit-alpha')).status, 200);
  assert.deepEqual(visits(), [ALPHA, BETA]);
});

test('an unknown slug or a bare verify records nothing', async () => {
  db.prepare('DELETE FROM app_visits').run();
  assert.equal((await verify('?app=no-such-app')).status, 200);
  assert.equal((await verify('')).status, 200);
  assert.deepEqual(visits(), []);
});
