import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import express from 'express';

// Per-app "Separate sandbox database" (migration 107).
//
// The setting governs CATALOGUE apps (the fixture is installed as metabase,
// whose entry injects MB_DB_CONNECTION_URI). A database an app declares in its
// own deployhub.json is always separate in sandbox — see the last tests here.
//
// Off (default): sandbox and production share the app's one database per
// engine, exactly as before. On: production keeps that database (same name,
// same login, same password) and sandbox gets its own, scoped
// (app, SANDBOX_TENANT), provisioned on the sandbox deploy/restart path and
// injected under the same variable names. Off again: sandbox goes back to the
// shared database and the sandbox database is NOT dropped.
//
// No Docker: provision() is injected and writes a real managed_databases row
// with the names managedDb.namesForScope() derives, so credentialsFor() and
// listForApp() run for real. tests' real-engine counterpart is the manual
// Postgres check in the change report.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-sepsdb-'));
process.env.ENCRYPTION_KEY = '7'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt, generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { injectManagedDbForEnv } = await import('../server/services/deployer.js');
const { namesForScope, listForApp } = await import('../server/services/managedDb.js');
const { parseManifestDatabase } = await import('../server/services/manifestDatabase.js');
const { SANDBOX_TENANT, getSeparateSandboxDb } = await import('../server/services/sandboxDb.js');
const { errorHandler } = await import('../server/utils/errors.js');

// ── fixtures ────────────────────────────────────────────────────────────────
const appId = db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,branch,image_ref,catalog_slug) VALUES ('Supply','supply',1,'image','main','nginx:1','metabase')"
).run().lastInsertRowid;
const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
const NEEDS = parseManifestDatabase({ engine: 'postgres' });

let seq = 0;
function mkUser(role, appRole = null) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(`u${n}`, `u${n}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  if (appRole) db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, id, appRole);
  return { id, key, name: `${appRole || role}` };
}
const PLATFORM = mkUser('platform_admin');
const OWNER = mkUser('user', 'owner');
const APP_ADMIN = mkUser('user', 'admin');
const MEMBER = mkUser('user', 'user');
const OUTSIDER = mkUser('user');

// Production's database exists today, as Supply Hub's does.
const PROD_PASSWORD = crypto.randomBytes(18).toString('base64url');
{
  const { database, username } = namesForScope({ appId });
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
              VALUES (?, '', 'postgres', ?, ?, ?)`).run(appId, database, username, encrypt(PROD_PASSWORD));
}

// The provision() double: what managedDb.provision does to the table, without
// the engine. Records every scope it was asked for.
const provisioned = [];
// The TLS/limits step (managedDb.secureLogin) talks to a real engine, and this
// file has no Docker and sets no container prefix — so it is replaced too.
// Its own behaviour is covered by test/managed-db-tls.test.js.
const fakeSecureLogin = async () => ({ applied: false, certRequired: false, mounts: [], tls: null });
async function fakeProvision(scope, engine) {
  provisioned.push({ tenant: scope.tenant ?? null, engine });
  const { database, username } = namesForScope(scope);
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run(scope.appId, scope.tenant ?? '', engine, database, username, encrypt(crypto.randomBytes(18).toString('base64url')));
}

async function envFor(env, { isRestart = false } = {}) {
  const vars = {};
  const r = await injectManagedDbForEnv({
    app, env, runtimeEnvVars: vars, manifestNeeds: null, isRestart, provision: fakeProvision, secureLogin: fakeSecureLogin,
  });
  return { url: vars.MB_DB_CONNECTION_URI, r };
}
const parse = (u) => { const x = new URL(u); return { user: x.username, pass: x.password, db: x.pathname.slice(1) }; };

// ── HTTP: apps router (the setting) + managed-db router (list / drop) ──────
const appsRouter = (await import('../server/routes/apps.js')).default;
const mdbRoutes = await import('../server/routes/managedDb.js');
const realMdb = await import('../server/services/managedDb.js');
const dropped = [];
mdbRoutes.__setEngineForTests({
  SUPPORTED_ENGINES: realMdb.SUPPORTED_ENGINES,
  listForApp: realMdb.listForApp,
  provision: async () => { throw new Error('not used here'); },
  // Real row bookkeeping, no engine: drop the row the scope names.
  async deprovision(scope, engine) {
    dropped.push({ tenant: scope.tenant ?? null, engine });
    return db.prepare('DELETE FROM managed_databases WHERE app_id = ? AND tenant = ? AND engine = ?')
      .run(scope.appId, scope.tenant ?? '', engine).changes > 0;
  },
});
const server = await new Promise((r) => {
  const a = express(); a.use(express.json());
  a.use('/api/apps', mdbRoutes.default);
  a.use('/api/apps', appsRouter);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = () => `http://127.0.0.1:${server.address().port}/api/apps/supply`;
const putSetting = (who, v) => fetch(base(), {
  method: 'PUT', headers: { 'content-type': 'application/json', 'x-api-key': who.key },
  body: JSON.stringify({ separate_sandbox_db: v }),
});
const getDbCard = async (who) => {
  const r = await fetch(`${base()}/database`, { headers: { 'x-api-key': who.key } });
  assert.equal(r.status, 200);
  return r.json();
};

let prodBefore;

// ── tests ───────────────────────────────────────────────────────────────────

test('default off: sandbox and production get the same credentials, nothing provisioned', async () => {
  assert.equal(getSeparateSandboxDb(db, appId), false);
  const prod = await envFor('production');
  const sand = await envFor('sandbox');
  assert.ok(prod.url && sand.url);
  assert.equal(sand.url, prod.url);
  assert.equal(parse(prod.url).pass, PROD_PASSWORD);
  assert.equal(provisioned.length, 0);
  prodBefore = parse(prod.url);
});

test('members and outsiders cannot turn it on; owner, app admin and platform admin can', async () => {
  for (const who of [MEMBER, OUTSIDER]) {
    const r = await putSetting(who, true);
    assert.ok([403, 404].includes(r.status), `${who.name} got ${r.status}`);
    if (who === MEMBER) assert.equal(r.status, 403);
  }
  assert.equal(getSeparateSandboxDb(db, appId), false, 'a refused request changed nothing');
  assert.equal((await putSetting(OWNER, 'yes')).status, 400, 'non-boolean refused');

  for (const who of [APP_ADMIN, PLATFORM, OWNER]) {
    const r = await putSetting(who, true);
    const body = await r.json();
    assert.equal(r.status, 200, `${who.name}: ${JSON.stringify(body)}`);
    assert.equal(body.app.separate_sandbox_db, true);
    assert.match(body.separate_sandbox_db_notice, /next sandbox deploy or restart/);
  }
  assert.equal((await getDbCard(MEMBER)).can_change_separate_sandbox_db, false);
  assert.equal((await getDbCard(APP_ADMIN)).can_change_separate_sandbox_db, true);
});

test('on: production keeps its database and login; the sandbox deploy provisions its own', async () => {
  const prod = await envFor('production');
  assert.deepEqual(parse(prod.url), prodBefore, 'production credentials unchanged');
  assert.equal(provisioned.length, 0, 'a production deploy provisions nothing');

  const sand = await envFor('sandbox');
  assert.deepEqual(provisioned, [{ tenant: SANDBOX_TENANT, engine: 'postgres' }], 'provisioned on the sandbox deploy path');
  const s = parse(sand.url);
  assert.notEqual(s.db, prodBefore.db, 'different database');
  assert.notEqual(s.user, prodBefore.user, 'different login');
  assert.notEqual(s.pass, prodBefore.pass, 'different password');
  assert.equal(s.db, 'crane_a' + appId + '_sandbox');
  assert.equal(sand.r.separateSandbox, true);

  // Idempotent: a second sandbox deploy reuses it.
  const again = await envFor('sandbox');
  assert.equal(again.url, sand.url);
  assert.equal(provisioned.length, 1);
});

test('restart re-injects the sandbox credentials, and provisions them if the setting was turned on since the last deploy', async () => {
  const deployed = await envFor('sandbox');
  const restarted = await envFor('sandbox', { isRestart: true });
  assert.equal(restarted.url, deployed.url);
  assert.notEqual(parse(restarted.url).user, prodBefore.user);

  // The restart route goes through the same helper, for its own env.
  const src = readFileSync('server/routes/deploy.js', 'utf8');
  assert.match(src, /injectManagedDbForEnv\(\{\s*app, env, runtimeEnvVars, claimedKeys: decryptFailures, manifestNeeds: releaseDb\.needs,\s*isRestart: true/);
  const dsrc = readFileSync('server/services/deployer.js', 'utf8');
  assert.match(dsrc, /injectManagedDbForEnv\(\{\s*app, env, runtimeEnvVars, claimedKeys: decryptFailures, manifestNeeds: manifestDbNeeds/);
});

test('GET database lists both, per env, and never a password', async () => {
  const card = await getDbCard(MEMBER);
  assert.equal(card.separate_sandbox_db, true);
  assert.deepEqual(card.by_env, { production: [prodBefore.db], sandbox: [`crane_a${appId}_sandbox`] });
  assert.deepEqual(card.databases.map(d => d.env).sort(), ['production', 'sandbox']);
  assert.equal(JSON.stringify(card).includes(PROD_PASSWORD), false);
  assert.equal(/password/i.test(JSON.stringify(card.databases)), false);
});

test('off again: sandbox gets production\'s credentials back, and the sandbox database row survives', async () => {
  assert.equal((await putSetting(OWNER, false)).status, 200);
  const sand = await envFor('sandbox');
  const prod = await envFor('production');
  assert.equal(sand.url, prod.url);
  assert.deepEqual(parse(sand.url), prodBefore);
  assert.equal(provisioned.length, 1, 'nothing new provisioned');
  const rows = listForApp(appId);
  assert.ok(rows.some(r => r.tenant === SANDBOX_TENANT), 'sandbox database was not dropped');

  const card = await getDbCard(OWNER);
  assert.deepEqual(card.by_env.sandbox, [prodBefore.db], 'sandbox reads the shared database');
  assert.ok(card.databases.some(d => d.env === 'sandbox'), 'still listed so the owner can drop it');
});

test('deprovision can target the sandbox database, owner / platform admin only', async () => {
  const del = (who, qs) => fetch(`${base()}/database?${qs}`, { method: 'DELETE', headers: { 'x-api-key': who.key } });
  const qs = 'engine=postgres&env=sandbox&confirm=supply';

  for (const who of [APP_ADMIN, MEMBER]) {
    const r = await del(who, qs);
    assert.equal(r.status, 403, `${who.name} must not drop it`);
  }
  assert.equal(dropped.length, 0);
  assert.equal((await del(OWNER, 'engine=postgres&env=staging&confirm=supply')).status, 400);

  const r = await del(OWNER, qs);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.removed, true);
  assert.deepEqual(dropped, [{ tenant: SANDBOX_TENANT, engine: 'postgres' }], 'targeted the sandbox scope only');
  assert.ok(listForApp(appId).some(r => r.tenant === ''), 'production database untouched');
  assert.equal(listForApp(appId).some(r => r.tenant === SANDBOX_TENANT), false);
});

test('names: the sandbox scope derives its own database and login, distinct from production and from tenants', () => {
  const prod = namesForScope({ appId: 14 });
  const sand = namesForScope({ appId: 14, tenant: SANDBOX_TENANT });
  const tenant = namesForScope({ appId: 14, tenant: 'acme.com/u7' });
  assert.deepEqual(prod, { database: 'crane_a14', username: 'crane_a14_u' });
  assert.deepEqual(sand, { database: 'crane_a14_sandbox', username: 'crane_a14_sandbox_u' });
  assert.notEqual(tenant.database, sand.database);
});

test('turned on with no sandbox database yet, a sandbox RESTART provisions it rather than falling back to production', async () => {
  assert.equal((await putSetting(OWNER, true)).status, 200);
  const before = provisioned.length;
  const restarted = await envFor('sandbox', { isRestart: true });
  assert.equal(provisioned.length, before + 1);
  assert.equal(provisioned.at(-1).tenant, SANDBOX_TENANT);
  assert.notEqual(parse(restarted.url).user, prodBefore.user);
  assert.notEqual(parse(restarted.url).db, prodBefore.db);
});

// ── deployhub.json databases: sandbox never gets production's ───────────────
// Sandbox is deployable by members who may not deploy production, and its code
// is theirs to write. A shared database would let them read or rewrite
// production's data from sandbox, so a manifest-declared database is separate
// in sandbox whatever the setting says.
const mAppId = db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Own','owndb',2,'managed','main')"
).run().lastInsertRowid;
const mApp = db.prepare('SELECT * FROM apps WHERE id = ?').get(mAppId);
{
  const { database, username } = namesForScope({ appId: mAppId });
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
              VALUES (?, '', 'postgres', ?, ?, ?)`).run(mAppId, database, username, encrypt(PROD_PASSWORD));
}
const manifestEnv = async (env, opts = {}) => {
  const vars = {};
  await injectManagedDbForEnv({ app: mApp, env, runtimeEnvVars: vars, manifestNeeds: NEEDS, provision: fakeProvision, secureLogin: fakeSecureLogin, ...opts });
  return vars.DATABASE_URL;
};

test('deployhub.json database, setting OFF: sandbox gets its own database, never production\'s', async () => {
  assert.equal(getSeparateSandboxDb(db, mAppId), false);
  const prod = parse(await manifestEnv('production'));
  const sand = parse(await manifestEnv('sandbox'));
  assert.equal(prod.pass, PROD_PASSWORD, 'production lost its database');
  assert.notEqual(sand.user, prod.user, 'sandbox was handed production\'s login');
  assert.notEqual(sand.db, prod.db, 'sandbox was handed production\'s database');
  assert.notEqual(sand.pass, PROD_PASSWORD, 'sandbox received production\'s password');
  assert.ok(provisioned.some(p => p.tenant === SANDBOX_TENANT), 'no sandbox database was provisioned');
});

test('deployhub.json database: a sandbox restart never falls back to production\'s', async () => {
  const sand = parse(await manifestEnv('sandbox', { isRestart: true }));
  assert.notEqual(sand.pass, PROD_PASSWORD);
});
