import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// TLS, per-app client certificates and per-login limits for the managed
// databases, without a daemon: the engine builders (managedDbTls.js), the
// conversion logic (managedDb.secureLogin with its engine calls replaced),
// the deploy/restart wiring (deployer.injectManagedDbForEnv) and the argv a
// container is started with (docker.startApp through a recording shim).
//
// What the engines then DO with these statements was verified against real
// postgres:16-alpine, mariadb:11.4, mongo:8.0 and redis:8.10-alpine; the
// assertions here pin the inputs that behaviour depends on, so a change that
// weakens them goes red without needing Docker.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbtls-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

// A recording `docker` shim for the startApp argv test (same shape as
// test/container-volumes.test.js). Installed before docker.js is imported.
const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.map(a => a + "\\n").join("") + "\\0");\n' +
  'if (argv[0] === "network" && argv[1] === "inspect") process.stdout.write("false|172.20.0.0/16\\n");\n' +
  'else process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
const REAL_PATH = process.env.PATH;

const tls = await import('../server/services/managedDbTls.js');
const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const deployer = await import('../server/services/deployer.js');
const { setManagedDbSettings, getManagedDbSettings } = await import('../server/services/managedDbSettings.js');
const { encrypt } = await import('../server/services/encryption.js');
const { SANDBOX_TENANT } = await import('../server/services/sandboxDb.js');

let APP_A, APP_B, APP_CAT;
before(() => {
  initDb(process.env.DATA_DIR);
  const db = getDb();
  const ins = db.prepare('INSERT INTO apps (name, slug, slot, catalog_slug) VALUES (?, ?, ?, ?)');
  APP_A = Number(ins.run('A', 'tls-a', 1, null).lastInsertRowid);
  APP_B = Number(ins.run('B', 'tls-b', 2, null).lastInsertRowid);
  APP_CAT = Number(ins.run('Cat', 'tls-cat', 3, 'metabase').lastInsertRowid);
});
after(() => {
  process.env.PATH = REAL_PATH;
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

/** A managed_databases row as provision() would have written it (pre-TLS). */
function seedRow(appId, tenant, engine) {
  const { database, username } = mdb.namesForScope({ appId, tenant });
  getDb().prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
    VALUES (?, ?, ?, ?, ?, ?)`).run(appId, tenant || '', engine, database, username, encrypt('p'.repeat(32)));
  if (!getDb().prepare('SELECT 1 FROM managed_db_servers WHERE engine = ?').get(engine)) {
    getDb().prepare(`INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc)
      VALUES (?, ?, ?, ?, ?)`).run(engine, `x-${engine}`, 'img', engine === 'postgres' ? 45432 : 43306, encrypt('a'.repeat(32)));
  }
  return { database, username };
}

/** Engine calls replaced by a recorder. */
function recorder() {
  const calls = [];
  return {
    calls,
    ops: {
      ensureServer: async (engine) => { calls.push(['ensureServer', engine]); },
      runAdminSql: async (engine, sql) => { calls.push(['sql', engine, sql]); },
      runAdminMongo: async (script) => { calls.push(['mongo', script]); },
      ensureRedisInstance: async (o) => { calls.push(['redis', o]); },
    },
  };
}
const noOwner = async () => null;

// ---------------------------------------------------------------------------
// Engine builders
// ---------------------------------------------------------------------------

test('pg_hba: cert group needs TLS + client cert + password, plain is rejected, everyone else offered TLS', () => {
  const lines = tls.pgHbaConf().split('\n').filter((l) => l && !l.startsWith('#')).map((l) => l.split(/\s+/));
  // First match wins in Postgres, so ORDER is asserted, not just presence.
  assert.deepEqual(lines[0], ['local', 'all', 'all', 'trust']);
  assert.deepEqual(lines[1], ['hostssl', 'all', `+${tls.PG_CERT_GROUP}`, 'all', 'scram-sha-256', 'clientcert=verify-full'],
    'members must present a CA-signed cert whose CN is the login AND the password');
  assert.deepEqual(lines[2], ['host', 'all', `+${tls.PG_CERT_GROUP}`, 'all', 'reject'],
    'a member connecting without TLS must be rejected before the generic line');
  assert.deepEqual(lines[3], ['host', 'all', 'all', 'all', 'scram-sha-256']);
  assert.equal(lines.length, 4);
  assert.ok(!tls.pgHbaConf().includes('127.0.0.1/32'), 'the image default "host all all 127.0.0.1/32 trust" must not come back');
});

test('postgres server flags: TLS on, AppCrane hba, max_connections from settings, connection logging with user+db', () => {
  const args = tls.pgServerArgs({ maxConnections: 300 });
  const settings = Object.fromEntries(args.filter((_, i) => args[i - 1] === '-c').map((kv) => kv.split(/=(.*)/s).slice(0, 2)));
  assert.equal(args[0], 'postgres');
  assert.equal(settings.ssl, 'on');
  assert.equal(settings.hba_file, '/tmp/appcrane-tls/pg_hba.conf');
  assert.equal(settings.ssl_ca_file, '/tmp/appcrane-tls/ca.crt');
  assert.equal(settings.max_connections, '300');
  assert.equal(settings.log_connections, 'on');
  assert.match(settings.log_line_prefix, /user=%u db=%d/);
  assert.throws(() => tls.pgServerArgs({ maxConnections: '300; DROP' }));
});

test('mariadb server flags: TLS offered with our cert, access-denied logged', () => {
  const args = tls.mariadbServerArgs();
  assert.equal(args[0], 'mariadbd');
  assert.ok(args.includes('--ssl-cert=/tmp/appcrane-tls/server.crt'));
  assert.ok(args.includes('--ssl-ca=/tmp/appcrane-tls/ca.crt'));
  assert.ok(args.includes('--log-warnings=2'));
});

test('the TLS install snippet is a fixed literal with the engine user from a fixed table', () => {
  assert.equal(tls.installSnippet('postgres'),
    'mkdir -p /tmp/appcrane-tls && cp /etc/appcrane-tls/* /tmp/appcrane-tls/ && chown -R postgres /tmp/appcrane-tls && chmod 700 /tmp/appcrane-tls && chmod 600 /tmp/appcrane-tls/server.key /tmp/appcrane-tls/server.pem');
  assert.throws(() => tls.installSnippet('evil; rm -rf /'), /no engine user/);
  assert.equal(tls.serverMountArg('/d/_tls/server/postgres'), '/d/_tls/server/postgres:/etc/appcrane-tls:ro');
});

test('login policy SQL: cert requirement, connection limit and statement timeout per engine', () => {
  const pg = tls.loginPolicySql('postgres', 'crane_a1_u', { certRequired: true, connLimit: 25, statementTimeoutS: 300 });
  assert.match(pg, /ALTER ROLE "crane_a1_u" CONNECTION LIMIT 25;/);
  assert.match(pg, /ALTER ROLE "crane_a1_u" SET statement_timeout = '300s';/);
  assert.match(pg, new RegExp(`GRANT ${tls.PG_CERT_GROUP} TO "crane_a1_u";`));

  const pgCat = tls.loginPolicySql('postgres', 'crane_a3_u', { certRequired: false, connLimit: 25, statementTimeoutS: 0 });
  assert.ok(!pgCat.includes('GRANT'), 'a catalogue login is never put in the cert group');
  assert.match(pgCat, /RESET statement_timeout/);

  const my = tls.loginPolicySql('mariadb', 'crane_a1_u', { certRequired: true, connLimit: 25, statementTimeoutS: 300 });
  assert.equal(my, "ALTER USER 'crane_a1_u'@'%' REQUIRE SUBJECT '/CN=crane_a1_u' AND ISSUER '/CN=AppCrane Managed DB CA' WITH MAX_USER_CONNECTIONS 25 MAX_STATEMENT_TIME 300;\n");
  const myCat = tls.loginPolicySql('mariadb', 'crane_a3_u', { certRequired: false, connLimit: 10, statementTimeoutS: 60 });
  assert.equal(myCat, "ALTER USER 'crane_a3_u'@'%' WITH MAX_USER_CONNECTIONS 10 MAX_STATEMENT_TIME 60;\n",
    'no REQUIRE clause at all — certRequired=false never writes REQUIRE NONE over a converted login');

  for (const bad of ['x"; DROP ROLE postgres; --', "a'@'%", 'Upper']) {
    assert.throws(() => tls.loginPolicySql('postgres', bad, { certRequired: false, connLimit: 1, statementTimeoutS: 0 }));
  }
  assert.throws(() => tls.loginPolicySql('postgres', 'ok_u', { certRequired: false, connLimit: '25; DROP', statementTimeoutS: 0 }));
});

test('settings: defaults, bounds, and an out-of-range stored value never reaches SQL', () => {
  const db = getDb();
  assert.deepEqual(getManagedDbSettings(db), { conn_limit: 25, pg_max_connections: 300, statement_timeout_s: 300, auth_alert_threshold: 5 });
  assert.throws(() => setManagedDbSettings(db, { conn_limit: 0 }), /conn_limit must be an integer from 1/);
  assert.throws(() => setManagedDbSettings(db, { pg_max_connections: 50 }), /from 100/);
  assert.throws(() => setManagedDbSettings(db, { nope: 1 }), /unknown managed database setting/);
  db.prepare("INSERT INTO settings (key, value) VALUES ('managed_db_conn_limit', '25; DROP ROLE x')").run();
  assert.equal(getManagedDbSettings(db).conn_limit, 25, 'a hand-edited row falls back to the default');
  db.prepare("DELETE FROM settings WHERE key = 'managed_db_conn_limit'").run();
});

// ---------------------------------------------------------------------------
// Connection strings and env
// ---------------------------------------------------------------------------

const TLSP = { required: true, ca: '/run/appcrane/db/ca.crt', cert: '/run/appcrane/db/client.crt', key: '/run/appcrane/db/client.key', pem: '/run/appcrane/db/client.pem' };
const base = { host: 'host.docker.internal', port: 45432, database: 'crane_a1', username: 'crane_a1_u', password: 'pw_pw' };

test('connection strings carry the TLS parameters per engine', () => {
  const pg = mdb.tlsUrl({ ...base, engine: 'postgres' }, TLSP);
  assert.equal(pg, 'postgresql://crane_a1_u:pw_pw@host.docker.internal:45432/crane_a1?sslmode=verify-full'
    + '&sslrootcert=%2Frun%2Fappcrane%2Fdb%2Fca.crt&sslcert=%2Frun%2Fappcrane%2Fdb%2Fclient.crt&sslkey=%2Frun%2Fappcrane%2Fdb%2Fclient.key');
  const my = mdb.tlsUrl({ ...base, engine: 'mariadb', port: 43306 }, TLSP);
  assert.match(my, /^mysql:\/\/crane_a1_u:pw_pw@host\.docker\.internal:43306\/crane_a1\?ssl-mode=VERIFY_IDENTITY&ssl-ca=.*ca\.crt&ssl-cert=.*client\.crt&ssl-key=.*client\.key$/);
  const mg = mdb.tlsUrl({ ...base, engine: 'mongo', port: 47017 }, { ...TLSP, x509: true });
  assert.equal(mg, 'mongodb://host.docker.internal:47017/crane_a1?tls=true&tlsCAFile=%2Frun%2Fappcrane%2Fdb%2Fca.crt'
    + '&tlsCertificateKeyFile=%2Frun%2Fappcrane%2Fdb%2Fclient.pem&authMechanism=MONGODB-X509&authSource=%24external');
  assert.ok(!mg.includes('pw_pw'), 'an x509 login sends no password');
  const rd = mdb.tlsUrl({ ...base, engine: 'redis', port: 46379, database: '0' }, TLSP);
  assert.equal(rd, 'rediss://crane_a1_u:pw_pw@host.docker.internal:46379/0');
});

test('deployer env: URL with TLS params + DB_*_FILE paths; PG* only for an app that speaks libpq names', () => {
  const creds = { ...base, engine: 'postgres', tls: TLSP };
  const env = deployer.buildManagedDbEnv({ engine: 'postgres', url_env: 'DATABASE_URL', env: {} }, creds);
  assert.match(env.DATABASE_URL, /sslmode=verify-full/);
  assert.equal(env.DB_CA_FILE, TLSP.ca);
  assert.equal(env.DB_CERT_FILE, TLSP.cert);
  assert.equal(env.DB_KEY_FILE, TLSP.key);
  assert.equal(env.DB_CERT_KEY_FILE, TLSP.pem);
  assert.equal(env.PGSSLMODE, undefined);
  const pgEnv = deployer.buildManagedDbEnv({ engine: 'postgres', env: { host: 'PGHOST', user: 'PGUSER' } }, creds);
  assert.equal(pgEnv.PGSSLMODE, 'verify-full');
  assert.equal(pgEnv.PGSSLKEY, TLSP.key);
  for (const v of Object.values(pgEnv)) assert.ok(!String(v).includes('BEGIN'), 'paths only, never key material');
  // No TLS on the login: byte-for-byte the old output.
  const plain = deployer.buildManagedDbEnv({ engine: 'postgres', url_env: 'DATABASE_URL' }, { ...base, engine: 'postgres', url: 'postgresql://x' });
  assert.deepEqual(Object.keys(plain), ['DATABASE_URL']);
  assert.ok(!plain.DATABASE_URL.includes('?'));
});

test('a deployhub.json cannot map a field onto a TLS path variable', async () => {
  const { parseManifestDatabase } = await import('../server/services/manifestDatabase.js');
  assert.throws(() => parseManifestDatabase({ engine: 'postgres', env: { user: 'DB_KEY_FILE' } }), /reserved by AppCrane/);
  assert.throws(() => parseManifestDatabase({ engine: 'postgres', url_env: 'PGSSLKEY' }), /reserved by AppCrane/);
});

// ---------------------------------------------------------------------------
// secureLogin: conversion, split, upgrade path, limits
// ---------------------------------------------------------------------------

test('UPGRADE PATH: an existing manifest login (provisioned pre-TLS) is converted on its next deploy/restart', async () => {
  const { username } = seedRow(APP_A, null, 'postgres');
  const before = getDb().prepare('SELECT client_cert_required FROM managed_databases WHERE app_id = ? AND engine = ?').get(APP_A, 'postgres');
  assert.equal(before.client_cert_required, 0, 'precondition: an existing login with no requirement');

  const r = recorder();
  const out = await mdb.secureLogin({ appId: APP_A }, 'postgres', { certRequired: true, resolveOwner: noOwner, ops: r.ops });

  // The engine was told: limits + the cert group, for THIS login.
  const sql = r.calls.filter((c) => c[0] === 'sql').map((c) => c[2]).join('\n');
  assert.match(sql, new RegExp(`GRANT ${tls.PG_CERT_GROUP} TO "${username}";`));
  assert.match(sql, /CONNECTION LIMIT 25;/);
  assert.deepEqual(r.calls[0], ['ensureServer', 'postgres'], 'the server (and its TLS config) is ensured first');

  // The certificate exists, with CN = login, and its files are on disk.
  const certRow = getDb().prepare('SELECT * FROM managed_db_certs WHERE name = ?').get(`client:${username}`);
  assert.ok(certRow, 'client cert issued');
  assert.ok(!certRow.key_enc.includes('PRIVATE KEY'));
  const dir = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', username);
  for (const f of ['ca.crt', 'client.crt', 'client.key', 'client.pem']) assert.ok(existsSync(join(dir, f)), f);
  assert.match(readFileSync(join(dir, 'client.crt'), 'utf8'), /BEGIN CERTIFICATE/);

  // Marked, and the container gets exactly one read-only mount.
  assert.equal(getDb().prepare('SELECT client_cert_required FROM managed_databases WHERE app_id = ? AND engine = ?').get(APP_A, 'postgres').client_cert_required, 1);
  assert.deepEqual(out.mounts, [{ host: dir, container: '/run/appcrane/db', readOnly: true }]);
  assert.equal(out.tls.cert, '/run/appcrane/db/client.crt');
  assert.match(mdb.credentialsFor({ appId: APP_A }, 'postgres').url, /sslmode=verify-full/);
});

test('the requirement is sticky: a later call without certRequired keeps it (no silent downgrade)', async () => {
  const r = recorder();
  const out = await mdb.secureLogin({ appId: APP_A }, 'postgres', { certRequired: false, resolveOwner: noOwner, ops: r.ops });
  assert.equal(out.certRequired, true);
  assert.match(r.calls.find((c) => c[0] === 'sql')[2], /GRANT/);
  assert.equal(out.mounts.length, 1);
});

test("MOUNT ISOLATION: each login's container gets only its own directory — never another app's, never the parent", async () => {
  const { username: userB } = seedRow(APP_B, null, 'postgres');
  const a = await mdb.secureLogin({ appId: APP_A }, 'postgres', { certRequired: true, resolveOwner: noOwner, ops: recorder().ops });
  const b = await mdb.secureLogin({ appId: APP_B }, 'postgres', { certRequired: true, resolveOwner: noOwner, ops: recorder().ops });
  const clientRoot = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client');
  const userA = mdb.namesForScope({ appId: APP_A }).username;
  assert.equal(a.mounts.length, 1);
  assert.equal(b.mounts.length, 1);
  assert.equal(a.mounts[0].host, join(clientRoot, userA));
  assert.equal(b.mounts[0].host, join(clientRoot, userB));
  assert.notEqual(a.mounts[0].host, b.mounts[0].host);
  for (const m of [...a.mounts, ...b.mounts]) {
    assert.notEqual(m.host, clientRoot, 'mounting the parent would hand every app every key');
    assert.equal(m.readOnly, true);
  }
});

test("sandbox scope gets its OWN login's certificate, not production's", async () => {
  const { username: sbUser } = seedRow(APP_A, SANDBOX_TENANT, 'postgres');
  const out = await mdb.secureLogin({ appId: APP_A, tenant: SANDBOX_TENANT }, 'postgres', { certRequired: true, resolveOwner: noOwner, ops: recorder().ops });
  assert.equal(sbUser, `crane_a${APP_A}_sandbox_u`);
  assert.ok(out.mounts[0].host.endsWith(`/client/${sbUser}`));
  const x = (await import('crypto')).X509Certificate;
  assert.equal(new x(readFileSync(join(out.mounts[0].host, 'client.crt'))).subject, `CN=${sbUser}`);
});

test('catalogue login: limits only — no certificate, no mount, no cert group', async () => {
  const { username } = seedRow(APP_CAT, null, 'mariadb');
  const r = recorder();
  const out = await mdb.secureLogin({ appId: APP_CAT }, 'mariadb', { certRequired: false, resolveOwner: noOwner, ops: r.ops });
  assert.equal(out.certRequired, false);
  assert.deepEqual(out.mounts, []);
  const sql = r.calls.find((c) => c[0] === 'sql')[2];
  assert.equal(sql, `ALTER USER '${username}'@'%' WITH MAX_USER_CONNECTIONS 25 MAX_STATEMENT_TIME 300;\n`);
  assert.equal(getDb().prepare('SELECT 1 FROM managed_db_certs WHERE name = ?').get(`client:${username}`), undefined);
  assert.equal(mdb.tlsView(getDb().prepare('SELECT * FROM managed_databases WHERE app_id = ?').get(APP_CAT)).tls, 'offered');
});

test('a changed platform limit reaches an EXISTING login on its next deploy/restart', async () => {
  setManagedDbSettings(getDb(), { conn_limit: 7, statement_timeout_s: 60 });
  try {
    const r = recorder();
    await mdb.secureLogin({ appId: APP_CAT }, 'mariadb', { certRequired: false, resolveOwner: noOwner, ops: r.ops });
    assert.match(r.calls.find((c) => c[0] === 'sql')[2], /MAX_USER_CONNECTIONS 7 MAX_STATEMENT_TIME 60;/);
  } finally {
    setManagedDbSettings(getDb(), { conn_limit: 25, statement_timeout_s: 300 });
  }
});

test('mongo manifest login: converted to an x509 user and the password user is dropped', async () => {
  seedRow(APP_B, null, 'mongo');
  const r = recorder();
  const out = await mdb.secureLogin({ appId: APP_B }, 'mongo', { certRequired: true, resolveOwner: noOwner, ops: r.ops });
  const script = r.calls.find((c) => c[0] === 'mongo')[1];
  assert.match(script, /getSiblingDB\('\$external'\)/);
  assert.match(script, new RegExp(`user: "CN=crane_a${APP_B}_u"`));
  assert.match(script, new RegExp(`dropUser\\("crane_a${APP_B}_u"\\)`));
  assert.equal(out.tls.x509, true);
  assert.ok(!mdb.credentialsFor({ appId: APP_B }, 'mongo').url.includes('@'), 'no user:password in an x509 URL');
});

test('tlsView exposes expiry and limits, never key material or host paths', async () => {
  const row = getDb().prepare('SELECT * FROM managed_databases WHERE app_id = ? AND engine = ? AND tenant = ?').get(APP_A, 'postgres', '');
  const v = mdb.tlsView(row);
  assert.equal(v.tls, 'required');
  assert.ok(new Date(v.client_cert_expires_at) > new Date());
  assert.equal(v.connection_limit, 25);
  assert.ok(!JSON.stringify(v).includes(process.env.DATA_DIR));
  assert.ok(!JSON.stringify(v).includes('BEGIN'));
});

// ---------------------------------------------------------------------------
// Deploy / restart wiring
// ---------------------------------------------------------------------------

test('injectManagedDbForEnv: a manifest app requires the cert in BOTH envs and returns only its own mount', async () => {
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(APP_A);
  const needs = { engine: 'postgres', url_env: 'DATABASE_URL', env: {} };
  const seen = [];
  const secureLogin = (scope, engine, o) => {
    seen.push({ scope, engine, certRequired: o.certRequired, image: o.image });
    return mdb.secureLogin(scope, engine, { ...o, resolveOwner: noOwner, ops: recorder().ops });
  };
  for (const env of ['production', 'sandbox']) {
    const runtimeEnvVars = {};
    const res = await deployer.injectManagedDbForEnv({
      app, env, runtimeEnvVars, manifestNeeds: needs, isRestart: true, image: 'img:1', secureLogin,
      provision: async () => { throw new Error('must not provision: rows exist'); },
    });
    const login = mdb.namesForScope(env === 'sandbox' ? { appId: APP_A, tenant: SANDBOX_TENANT } : { appId: APP_A }).username;
    assert.equal(res.mounts.length, 1, env);
    assert.ok(res.mounts[0].host.endsWith(`/client/${login}`), `${env} mounts ${login}'s directory only`);
    assert.match(runtimeEnvVars.DATABASE_URL, new RegExp(`//${login}:.*sslmode=verify-full`));
    assert.equal(runtimeEnvVars.DB_KEY_FILE, '/run/appcrane/db/client.key');
  }
  assert.deepEqual(seen.map((s) => [s.scope.tenant || null, s.certRequired, s.image]),
    [[null, true, 'img:1'], [SANDBOX_TENANT, true, 'img:1']]);
});

test('injectManagedDbForEnv: a manifest cert failure fails the deploy; a catalogue limit failure does not', async () => {
  const appA = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(APP_A);
  const boom = async () => { throw new Error('engine down'); };
  await assert.rejects(
    deployer.injectManagedDbForEnv({ app: appA, env: 'production', runtimeEnvVars: {}, manifestNeeds: { engine: 'postgres', url_env: 'DATABASE_URL', env: {} }, isRestart: true, secureLogin: boom }),
    /Securing the managed postgres database login failed: engine down/);

  const cat = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(APP_CAT);
  const lines = [];
  const res = await deployer.injectManagedDbForEnv({ app: cat, env: 'production', runtimeEnvVars: {}, isRestart: true, secureLogin: boom, appendLog: (l) => lines.push(l) });
  assert.equal(res.source, 'catalogue');
  assert.deepEqual(res.mounts, []);
  assert.ok(lines.some((l) => /could not apply the per-login limits this time \(engine down\)/.test(l)), lines.join('\n'));
});

test('both container starts (deploy, rollback) and the restart route pass the cert mount to startApp', () => {
  // The mount must reach EVERY start of the container, or a rollback or a
  // restart would bring the app back without the certificate it needs.
  const dep = readFileSync(new URL('../server/services/deployer.js', import.meta.url), 'utf8');
  assert.equal((dep.match(/volumes: \[\.\.\.containerVolumes, \.\.\.dbCertMounts\]/g) || []).length, 2, 'deploy start + rollback start');
  const route = readFileSync(new URL('../server/routes/deploy.js', import.meta.url), 'utf8');
  assert.match(route, /volumes: \[\.\.\.containerVolumes, \.\.\.dbCertMounts\]/);
  assert.match(route, /image,\n\s+appendLog/);
});

test('startApp: the certificate mount is read-only; ordinary mounts are unchanged', async () => {
  process.env.PATH = `${SHIM_DIR}:${REAL_PATH}`;
  try {
    const { startApp } = await import('../server/services/docker.js');
    getDb().prepare("INSERT INTO apps (name, slug, slot) VALUES ('M', 'tls-mount', 9)").run();
    if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG);
    await startApp({
      slug: 'tls-mount', env: 'production', image: 'img', hostPort: 4999,
      volumes: [{ host: '/srv/d/apps/m/production/shared/data', container: '/data' },
        { host: '/srv/d/managed-db/_tls/client/crane_a1_u', container: '/run/appcrane/db', readOnly: true }],
    });
    const run = readFileSync(ARGV_LOG, 'utf8').split('\0').map((r) => r.split('\n').filter(Boolean)).find((c) => c[0] === 'run');
    const vols = run.filter((_, i) => run[i - 1] === '-v');
    assert.deepEqual(vols, ['/srv/d/apps/m/production/shared/data:/data', '/srv/d/managed-db/_tls/client/crane_a1_u:/run/appcrane/db:ro']);
  } finally {
    process.env.PATH = REAL_PATH;
  }
});

test('deprovision removes the login certificate and its files', async () => {
  const { username } = seedRow(APP_CAT, null, 'postgres');
  await mdb.secureLogin({ appId: APP_CAT }, 'postgres', { certRequired: true, resolveOwner: noOwner, ops: recorder().ops });
  const dir = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', username);
  assert.ok(existsSync(dir));
  assert.equal(statSync(dir).isDirectory(), true);
  // deprovision() would call the engine; the cert half is what is under test.
  const certs = await import('../server/services/dbCerts.js');
  certs.dropClientCert(username);
  assert.ok(!existsSync(dir));
  const src = readFileSync(new URL('../server/services/managedDb.js', import.meta.url), 'utf8');
  // Through releaseClientCerts, which drops client.* only once no other
  // non-Redis database of the login remains (test/managed-db-cert-release.test.js).
  assert.equal((src.match(/certs\.releaseClientCerts\(row\)/g) || []).length, 2, 'deprovision + deprovisionApp');
});
