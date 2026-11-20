import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// A platform admin can be recorded as an owner of an app, by themselves.
// Platform admins can manage every app regardless, but only a recorded owner
// counts as one: it is who is listed as owner and who gets the owner e-mails
// (newRequestRecipients). Before this, the members list left platform admins
// out entirely, so the UI showed them as a locked "owner" that was never stored.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-pa-owner-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('PA','pa-app',1,'managed')").run().lastInsertRowid;
function mkUser(role, name) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@example.com`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, email: `${name}@example.com` };
}
const PA = mkUser('platform_admin', 'pa');
const OWNER = mkUser('user', 'own');
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, OWNER.id);

const usersRouter = (await import('../server/routes/users.js')).default;
const appsRouter = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { newRequestRecipients } = await import('../server/services/requestNotify.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRouter);
api.use('/api/apps', usersRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.close(); try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

const call = async (who, method, path, body) => {
  const res = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method, headers: { 'X-API-Key': who.key, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
};
const listed = async () => (await call(PA, 'GET', '/api/apps/pa-app/identity/users')).body.users.find((u) => u.id === PA.id);

test('the members list includes a platform admin, with the role actually recorded on the app', async () => {
  const row = await listed();
  assert.ok(row, 'platform admin missing from the members list');
  assert.equal(row.role, 'platform_admin');
  assert.equal(row.app_role, 'none');
});

test('a platform admin makes themselves an owner, is listed as one, and gets owner e-mails', async () => {
  assert.deepEqual(newRequestRecipients(db, appId, false).map((r) => r.email), [OWNER.email]);
  const r = await call(PA, 'PUT', '/api/apps/pa-app/roles', { user_id: PA.id, app_role: 'owner' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal((await listed()).app_role, 'owner');
  assert.deepEqual(newRequestRecipients(db, appId, false).map((x) => x.email).sort(), [OWNER.email, PA.email].sort());
});

test('and can step down again while another owner remains', async () => {
  const r = await call(PA, 'PUT', '/api/apps/pa-app/roles', { user_id: PA.id, app_role: 'none' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal((await listed()).app_role, 'none');
});
