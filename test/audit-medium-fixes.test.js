import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Security audit 2026-10-06 (unit515 run 1), M1, M2, M3 and M5, with the
// rules the operator set:
//   M1 only a platform admin may reset another user's password
//   M2 destructive production operations: app owner or platform admin only
//   M3 tenant purge must not follow a symbolic link out of the app's tree
//   M5 runtime logs (REST and MCP): app owner or platform admin only

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mfix-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkUser = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@acme.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const APP = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('M','mfix',1,'managed','main')").run().lastInsertRowid;
const OWNER = mkUser('owner');
const APPADMIN = mkUser('appadmin');
const MEMBER = mkUser('member');
const GLOBALADMIN = mkUser('gadmin', 'admin');
const PLATFORM = mkUser('platform', 'platform_admin');
for (const [u, r] of [[OWNER, 'owner'], [APPADMIN, 'admin'], [MEMBER, 'user'], [GLOBALADMIN, 'user'], [PLATFORM, 'user']]) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, u.id, r);
}
const setEnv = (env, key) => db.prepare('INSERT OR REPLACE INTO env_vars (app_id, env, key, value_encrypted) VALUES (?,?,?,?)')
  .run(APP, env, key, encrypt('v'));

const usersRoutes = (await import('../server/routes/users.js')).default;
const envRoutes = (await import('../server/routes/envVars.js')).default;
const backupRoutes = (await import('../server/routes/backups.js')).default;
const mdbRoutes = (await import('../server/routes/managedDb.js')).default;
const logsRoutes = (await import('../server/routes/logs.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/users', usersRoutes);
  a.use('/api/apps', envRoutes);
  a.use('/api/apps', backupRoutes);
  a.use('/api/apps', mdbRoutes);
  a.use('/api', logsRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = `http://127.0.0.1:${server.address().port}`;
const call = (method, path, who, body) => fetch(base + path, {
  method, headers: { 'x-api-key': who.key, ...(body ? { 'content-type': 'application/json' } : {}) },
  body: body ? JSON.stringify(body) : undefined,
});

test('M1: a global admin cannot reset another user\'s password; a platform admin can', async () => {
  assert.equal((await call('PUT', `/api/users/${MEMBER.id}/password`, GLOBALADMIN, { password: 'a-long-enough-password' })).status, 403);
  assert.equal((await call('PUT', `/api/users/${PLATFORM.id}/password`, GLOBALADMIN, { password: 'a-long-enough-password' })).status, 403);
  assert.equal((await call('PUT', `/api/users/${MEMBER.id}/password`, PLATFORM, { password: 'a-long-enough-password' })).status, 200);
});

test('M2: deleting a production env var is the owner\'s or a platform admin\'s call', async () => {
  for (const who of [MEMBER, APPADMIN]) {
    setEnv('production', 'SECRET');
    assert.equal((await call('DELETE', '/api/apps/mfix/env/production/SECRET', who)).status, 403, `${who.row.name} deleted a production env var`);
  }
  setEnv('production', 'SECRET');
  assert.equal((await call('DELETE', '/api/apps/mfix/env/production/SECRET', OWNER)).status, 200);
  setEnv('production', 'SECRET');
  assert.equal((await call('DELETE', '/api/apps/mfix/env/production/SECRET', PLATFORM)).status, 200);
  setEnv('sandbox', 'SBX');
  assert.equal((await call('DELETE', '/api/apps/mfix/env/sandbox/SBX', MEMBER)).status, 200, 'sandbox stays open to members');
});

test('M2: dropping the managed database, restoring production and copy-data need the owner or a platform admin', async () => {
  const bk = db.prepare("INSERT INTO backups (app_id, env, file_path, size_bytes) VALUES (?, 'production', '/nonexistent.tar.gz', 1)").run(APP).lastInsertRowid;
  for (const who of [MEMBER, APPADMIN]) {
    assert.equal((await call('DELETE', '/api/apps/mfix/database?engine=postgres&confirm=mfix', who)).status, 403, `${who.row.name} dropped the database`);
    assert.equal((await call('POST', `/api/apps/mfix/restore/${bk}`, who)).status, 403, `${who.row.name} restored production`);
    assert.equal((await call('POST', '/api/apps/mfix/copy-data', who)).status, 403, `${who.row.name} copied production data`);
  }
  // The owner passes the gate (and then fails on the missing file, not on 403).
  assert.notEqual((await call('POST', `/api/apps/mfix/restore/${bk}`, OWNER)).status, 403);
});

test('M5: runtime logs are the owner\'s or a platform admin\'s, over REST and MCP', async () => {
  for (const who of [MEMBER, APPADMIN, GLOBALADMIN]) {
    assert.equal((await call('GET', '/api/mfix/logs/production', who)).status, 403, `${who.row.name} read logs over REST`);
    await assert.rejects(callTool(who.row, 'appcrane_get_logs', { slug: 'mfix', env: 'production' }), /owner or a platform admin/,
      `${who.row.name} read logs over MCP`);
  }
  assert.notEqual((await call('GET', '/api/mfix/logs/production', OWNER)).status, 403);
});

test('M3: tenant purge refuses a symbolic link in the path and deletes nothing outside', async () => {
  const { purgeTenant } = await import('../server/services/tenants.js');
  const victim = join(process.env.DATA_DIR, 'apps', 'victim', 'production', 'shared', 'data', 'tenants', 'acme.test', 'u5');
  mkdirSync(victim, { recursive: true });
  writeFileSync(join(victim, 'db.sqlite'), 'VICTIM');
  const mine = join(process.env.DATA_DIR, 'apps', 'mfix', 'production', 'shared', 'data', 'tenants');
  mkdirSync(mine, { recursive: true });
  // Planted by the attacker's own app code, relative so it needs no DATA_DIR.
  symlinkSync('../../../../../victim/production/shared/data/tenants/acme.test', join(mine, 'acme.test'));
  await purgeTenant('mfix', 'someone@acme.test', 5);
  assert.ok(existsSync(join(victim, 'db.sqlite')), 'purge followed the link and deleted another app\'s tenant data');
});
