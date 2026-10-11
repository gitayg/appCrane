import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import express from 'express';

// The global 'admin' role (users.role = 'admin') is retired (migration 105).
// It made a person admin on every app without assignment. Former holders
// become 'user' and keep only their explicit app roles; nobody can hold
// 'admin' again — the API refuses it, and the database refuses it as the
// backstop. Per-app 'admin' (app_user_roles) is a different thing and stays.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-retire-admin-'));
process.env.ENCRYPTION_KEY = '7'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

// Stage a database as an install would have it just before this release:
// every migration up to 104 applied (and recorded), with a global admin in it.
// Then the real runner (initDb) applies 105 over it.
const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');
const before = readdirSync(DIR).filter(f => f.endsWith('.sql') && f < '105-').sort();
const exAdminKey = generateApiKey('dhk_admin');
const platformKey = generateApiKey('dhk_admin');
{
  const raw = new Database(join(process.env.DATA_DIR, 'deployhub.db'));
  raw.exec(`CREATE TABLE IF NOT EXISTS _migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  for (const f of before) {
    raw.exec(readFileSync(join(DIR, f), 'utf8'));
    raw.prepare('INSERT INTO _migrations (name) VALUES (?)').run(f);
  }
  raw.pragma('foreign_keys = ON');
  const mk = (id, name, role, key) => raw.prepare(
    'INSERT INTO users (id,name,email,role,active,api_key_hash) VALUES (?,?,?,?,1,?)'
  ).run(id, name, `${name}@t.test`, role, hashApiKey(key));
  mk(10, 'platform', 'platform_admin', platformKey);
  mk(11, 'exadmin', 'admin', exAdminKey);
  const app = (id, slug, slot) => raw.prepare(
    "INSERT INTO apps (id,name,slug,slot,source_type,branch) VALUES (?,?,?,?,'managed','main')"
  ).run(id, slug, slug, slot);
  app(1, 'kept-owner', 1);
  app(2, 'kept-user', 2);
  app(3, 'never-assigned', 3);
  raw.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (1,11,'owner'),(2,11,'user')").run();
  raw.close();
}

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { isAdmin } = await import('../server/utils/roles.js');
const { requireAdmin } = await import('../server/middleware/auth.js');

const apps = (await import('../server/routes/apps.js')).default;
const users = (await import('../server/routes/users.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json());
  a.use('/api/apps', apps); a.use('/api/users', users); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const url = (p) => `http://127.0.0.1:${server.address().port}${p}`;
const call = (key, method, p, body) => fetch(url(p), {
  method, headers: { 'content-type': 'application/json', 'x-api-key': key },
  body: body === undefined ? undefined : JSON.stringify(body),
});

test('(a) a global admin becomes a user and keeps exactly its explicit app roles', () => {
  assert.equal(db.prepare('SELECT role FROM users WHERE id = 11').get().role, 'user');
  const roles = db.prepare('SELECT app_id, app_role FROM app_user_roles WHERE user_id = 11 ORDER BY app_id').all();
  assert.deepEqual(roles.map(r => [r.app_id, r.app_role]), [[1, 'owner'], [2, 'user']]);
  assert.equal(db.prepare('SELECT role FROM users WHERE id = 10').get().role, 'platform_admin', 'platform admin untouched');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'admin'").get().n, 0);
});

test('(b) the database refuses role = admin on INSERT and on UPDATE', () => {
  assert.throws(() => db.prepare(
    "INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('x','x@t.test','admin',1,'hx')"
  ).run(), /global admin role was retired/);
  assert.throws(() => db.prepare("UPDATE users SET role = 'admin' WHERE id = 11").run(), /global admin role was retired/);
  // The other roles are still writable.
  db.prepare("UPDATE users SET role = 'user' WHERE id = 11").run();
});

test('(c) the users API refuses admin with a 400, on role change and on create', async () => {
  const put = await call(platformKey, 'PUT', '/api/users/11/role', { role: 'admin' });
  assert.equal(put.status, 400);
  assert.equal((await put.json()).error.code, 'ROLE_RETIRED');
  const post = await call(platformKey, 'POST', '/api/users', { name: 'n', email: 'n@t.test', role: 'admin' });
  assert.equal(post.status, 400);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM users WHERE email = 'n@t.test'").get().n, 0, 'no account created');
  // The supported roles still go through.
  const ok = await call(platformKey, 'PUT', '/api/users/11/role', { role: 'user' });
  assert.equal(ok.status, 200);
});

test('(d) a leftover admin role grants nothing in the helpers', () => {
  assert.equal(isAdmin({ role: 'admin' }), false);
  assert.equal(isAdmin({ role: 'platform_admin' }), true);
  let err = 'not called';
  requireAdmin({ user: { id: 99, role: 'admin' } }, {}, (e) => { err = e; });
  assert.equal(err?.status, 403);
  requireAdmin({ user: { id: 10, role: 'platform_admin' } }, {}, (e) => { err = e; });
  assert.equal(err, undefined);
});

test('(e) an ex-admin can no longer read an app it is not assigned to', async () => {
  assert.equal((await call(exAdminKey, 'GET', '/api/apps/never-assigned')).status, 403);
  assert.equal((await call(exAdminKey, 'GET', '/api/apps/kept-owner')).status, 200);
  assert.equal((await call(exAdminKey, 'GET', '/api/apps/kept-user')).status, 200);
});

test('(e) even a row the migration missed would not open the app', async () => {
  // Every reference to the old tier must be inert on its own, not only because
  // the data was cleaned. Force a stray 'admin' past the trigger and check the
  // app-scoped gate still refuses it.
  db.exec('DROP TRIGGER IF EXISTS users_no_global_admin_update');
  try {
    db.prepare("UPDATE users SET role = 'admin' WHERE id = 11").run();
    assert.equal((await call(exAdminKey, 'GET', '/api/apps/never-assigned')).status, 403);
  } finally {
    db.prepare("UPDATE users SET role = 'user' WHERE id = 11").run();
  }
});
