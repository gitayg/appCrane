import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// A multitenant app's per-user data is deleted when that user loses access,
// on EVERY path that removes access (v2.93.4).
//
// Before this, only the MCP revoke tool called purgeTenant. The dashboard's
// "remove user" (PUT /api/apps/:slug/roles with 'none'), deleting the user
// (DELETE /api/users/:id) and removal through a SCIM group all took access away
// and left the tenant's database and files on disk, while the README promised
// purge-on-revoke without condition.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tenantpurge-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkUser = (name, role, domain = 'acme.test') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active) VALUES (?,?,?,?,1)')
    .run(name, `${name}@${domain}`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, email: `${name}@${domain}` };
};

const ADMIN = mkUser('admin', 'platform_admin');
const mkApp = (slug, slot, multitenant) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,branch,multitenant) VALUES (?,?,?,'managed','main',?)"
).run(slug, slug, slot, multitenant ? 1 : 0).lastInsertRowid;

const grant = (appId, userId) =>
  db.prepare("INSERT OR IGNORE INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, userId);

/** Write a tenant DB where the app would, and return its path. */
function seedTenant(slug, user) {
  const dir = join(process.env.DATA_DIR, 'apps', slug, 'production', 'shared', 'data',
    'tenants', user.email.split('@')[1], `u${user.id}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'db.sqlite'), 'tenant data');
  return dir;
}

const users = (await import('../server/routes/users.js')).default;
const server = await new Promise((r) => {
  const app = express();
  app.use(express.json());
  app.use('/api/users', users);
  app.use('/api/apps', users);
  app.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message, code: err.code }));
  const s = app.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const call = async (method, path, body) => {
  const res = await fetch(BASE + path, {
    method,
    headers: { 'X-API-Key': ADMIN.key, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return res.status;
};

test("dashboard removal ('none') purges the tenant's data", async () => {
  const appId = mkApp('notes', 1, true);
  const u = mkUser('dana', 'user');
  grant(appId, u.id);
  const dir = seedTenant('notes', u);

  assert.equal(await call('PUT', '/api/apps/notes/roles', { user_id: u.id, app_role: 'user' }), 200);
  assert.ok(existsSync(dir), 'a role change that keeps access must not purge');

  assert.equal(await call('PUT', '/api/apps/notes/roles', { user_id: u.id, app_role: 'none' }), 200);
  assert.ok(!existsSync(dir), 'tenant dir still on disk after removal');
});

test('deleting the user purges their tenant data on every multitenant app', async () => {
  const a = mkApp('crm', 2, true);
  const b = mkApp('wiki', 3, true);
  const u = mkUser('eli', 'user');
  grant(a, u.id); grant(b, u.id);
  const dirA = seedTenant('crm', u);
  const dirB = seedTenant('wiki', u);

  assert.equal(await call('DELETE', `/api/users/${u.id}`), 200);
  assert.ok(!existsSync(dirA) && !existsSync(dirB), 'tenant dirs still on disk after the user was deleted');
});

test('a non-multitenant app is left alone', async () => {
  const appId = mkApp('plain', 4, false);
  const u = mkUser('fay', 'user');
  grant(appId, u.id);
  const dir = seedTenant('plain', u);

  assert.equal(await call('PUT', '/api/apps/plain/roles', { user_id: u.id, app_role: 'none' }), 200);
  assert.ok(existsSync(dir), 'purged data of an app that never opted in');
});

test('SCIM group removal purges, but only when it actually removed access', async () => {
  const { reconcileGroupAccess } = await import('../server/services/scimGroupAccess.js');
  const appId = mkApp('board', 5, true);
  const viaGroup = mkUser('gil', 'user');
  const alsoByHand = mkUser('hana', 'user');
  grant(appId, alsoByHand.id); // access a human granted, before the group existed

  const g = db.prepare("INSERT INTO scim_groups (display_name) VALUES ('board')").run().lastInsertRowid;
  db.prepare("INSERT INTO scim_group_app_roles (group_id,app_id,app_role) VALUES (?,?,'user')").run(g, appId);
  for (const u of [viaGroup, alsoByHand]) db.prepare('INSERT INTO scim_group_members (group_id,user_id) VALUES (?,?)').run(g, u.id);
  reconcileGroupAccess(db);

  const dirGroup = seedTenant('board', viaGroup);
  const dirHand = seedTenant('board', alsoByHand);

  db.prepare('DELETE FROM scim_group_members WHERE group_id = ?').run(g);
  reconcileGroupAccess(db);

  assert.ok(!existsSync(dirGroup), 'tenant dir still on disk after SCIM removed access');
  assert.ok(existsSync(dirHand), 'purged a user who still has hand-granted access');
});
