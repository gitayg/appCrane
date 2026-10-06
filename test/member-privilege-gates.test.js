import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Security audit 2026-10-06 (unit515 run 1), findings H3 and H4.
//
// H3: deploy.production (denied to the 'user' tier by default) was enforced on
//     POST /deploy/:env and the MCP deploy tool, but not on four other ways to
//     put code into production: the upload route, appcrane_deploy_artifact,
//     appcrane_push_staged_file and the webhook's auto_deploy_prod switch.
// H4: PUT /:slug/users replaced the whole member list for ANY member, owners
//     included; the sibling PUT /:slug/roles requires the owner.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-privgates-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkUser = (name) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,'user',1,?)")
    .run(name, `${name}@t.test`, hashApiKey(key)).lastInsertRowid;
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const APP = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('G','gated',1,'upload','main')").run().lastInsertRowid;
const OWNER = mkUser('owner');
const MEMBER = mkUser('member');
const OTHER = mkUser('other');
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(APP, OWNER.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(APP, MEMBER.id);

const deployRoutes = (await import('../server/routes/deploy.js')).default;
const appsRoutes = (await import('../server/routes/apps.js')).default;
const webhookRoutes = (await import('../server/routes/webhooks.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const server = await new Promise((r) => {
  const app = express();
  app.use(express.json());
  app.use('/api/apps', deployRoutes);
  app.use('/api/apps', webhookRoutes);
  app.use('/api/apps', appsRoutes);
  app.use(errorHandler);
  const s = app.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = `http://127.0.0.1:${server.address().port}`;
const call = (method, path, key, body, form) => fetch(base + path, {
  method,
  headers: { 'x-api-key': key, ...(body ? { 'content-type': 'application/json' } : {}) },
  body: form || (body ? JSON.stringify(body) : undefined),
});

test('H3: a member cannot upload a production deploy', async () => {
  const form = new FormData();
  form.set('env', 'production');
  form.set('file', new Blob([Buffer.from('not really a tarball')]), 'app.tar.gz');
  const r = await call('POST', '/api/apps/gated/deploy/upload', MEMBER.key, null, form);
  assert.equal(r.status, 403, `upload to production was not refused: ${r.status} ${await r.text()}`);
});

test('H3: a member cannot switch on automatic production deploys', async () => {
  const r = await call('PUT', '/api/apps/gated/webhook', MEMBER.key, { auto_deploy_prod: true });
  assert.equal(r.status, 403, `auto_deploy_prod was accepted: ${r.status}`);
  const ok = await call('PUT', '/api/apps/gated/webhook', MEMBER.key, { auto_deploy_sandbox: true });
  assert.notEqual(ok.status, 403, 'the sandbox switch must stay open to members');
});

for (const tool of ['appcrane_deploy_artifact', 'appcrane_push_staged_file']) {
  test(`H3: a member cannot reach production through ${tool}`, async () => {
    await assert.rejects(callTool(MEMBER.row, tool, { slug: 'gated', env: 'production', token: 'x', path: '/app/x' }),
      /deploy\.production/);
  });
}

test('H4: a member cannot replace the member list', async () => {
  const r = await call('PUT', '/api/apps/gated/users', MEMBER.key, { user_ids: [MEMBER.id] });
  assert.equal(r.status, 403, `a member evicted the owner: ${r.status}`);
  assert.ok(db.prepare("SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ? AND app_role = 'owner'").get(APP, OWNER.id));
});

test('H4: the owner can, but not in a way that leaves the app without an owner', async () => {
  const bad = await call('PUT', '/api/apps/gated/users', OWNER.key, { user_ids: [MEMBER.id] });
  assert.equal(bad.status, 400, 'the last owner was removed');
  const ok = await call('PUT', '/api/apps/gated/users', OWNER.key, { user_ids: [OWNER.id, MEMBER.id, OTHER.id] });
  assert.equal(ok.status, 200);
});

test('H3 follow-up: with prod auto-deploy on, a member cannot retarget it by changing the branch filter', async () => {
  // Background commit review: branch_filter picks which branch's pushes deploy,
  // so changing it while auto_deploy_prod is on chooses what reaches production.
  db.prepare("INSERT OR IGNORE INTO webhook_configs (app_id, token, secret) VALUES (?, 'tok-gated', 'sec')").run(APP);
  db.prepare('UPDATE webhook_configs SET auto_deploy_prod = 1, branch_filter = ? WHERE app_id = ?').run('main', APP);
  const r = await call('PUT', '/api/apps/gated/webhook', MEMBER.key, { branch_filter: 'my-feature' });
  assert.equal(r.status, 403, `a member retargeted production auto-deploy: ${r.status}`);
  assert.equal(db.prepare('SELECT branch_filter b FROM webhook_configs WHERE app_id = ?').get(APP).b, 'main');
});

test('H3 follow-up: a member may switch prod auto-deploy OFF, and echo the current value', async () => {
  db.prepare('UPDATE webhook_configs SET auto_deploy_prod = 1 WHERE app_id = ?').run(APP);
  assert.equal((await call('PUT', '/api/apps/gated/webhook', MEMBER.key, { auto_deploy_prod: false })).status, 200);
  assert.equal((await call('PUT', '/api/apps/gated/webhook', MEMBER.key, { auto_deploy_prod: false, auto_deploy_sandbox: true })).status, 200);
  assert.equal((await call('PUT', '/api/apps/gated/webhook', MEMBER.key, { branch_filter: 'develop' })).status, 200,
    'with prod auto-deploy off, the branch filter only affects sandbox');
});
