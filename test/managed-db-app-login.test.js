import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';

// deployhub.json database options, without a daemon:
//   app_login        a DML-only `<login>_app` per stage, APP_DATABASE_URL
//   sandbox_url_env  production gets the sandbox database's URL; sandbox never
//                    gets production's anything
//   extensions       pg_stat_statements through a filtered function only
//
// The engine-touching calls run for REAL against SQLite and the certificate
// store, with only ensureServer/runAdminSql replaced by a recorder (the same
// `ops` seam secureLogin has). Real-engine counterpart:
// test/managed-db-app-login-real.test.js.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-applogin-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt } = await import('../server/services/encryption.js');
const { injectManagedDbForEnv } = await import('../server/services/deployer.js');
const mdb = await import('../server/services/managedDb.js');
const { parseManifestDatabase } = await import('../server/services/manifestDatabase.js');
const { SANDBOX_TENANT } = await import('../server/services/sandboxDb.js');
const appSql = await import('../server/services/managedDbAppLogin.js');
const stats = await import('../server/services/managedDbStats.js');
const dumpCmd = await import('../server/services/managedDbDumpCmd.js');
const bk = await import('../server/services/managedDbBackup.js');
const certs = await import('../server/services/dbCerts.js');

after(() => { try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {} });

// ---------------------------------------------------------------------------
// Manifest validation
// ---------------------------------------------------------------------------

test('manifest: new keys parse, with the documented defaults', () => {
  assert.deepEqual(parseManifestDatabase({ engine: 'postgres', app_login: true }),
    { engine: 'postgres', env: {}, url_env: 'DATABASE_URL', app_url_env: 'APP_DATABASE_URL' });
  assert.deepEqual(parseManifestDatabase({ engine: 'postgres', app_login: true, app_url_env: 'RW_URL' }).app_url_env, 'RW_URL');
  assert.equal(parseManifestDatabase({ engine: 'postgres', app_login: false }).app_url_env, undefined);
  assert.equal(parseManifestDatabase({ engine: 'mariadb', sandbox_url_env: 'SANDBOX_DATABASE_URL' }).sandbox_url_env, 'SANDBOX_DATABASE_URL');
  assert.deepEqual(parseManifestDatabase({ engine: 'postgres', extensions: ['pg_stat_statements', 'pg_stat_statements'] }).extensions, ['pg_stat_statements']);
  assert.equal(parseManifestDatabase({ engine: 'postgres' }).sandbox_url_env, undefined, 'no default: its presence is the opt-in');
});

test('manifest: bad names, reserved names, wrong engines and unknown extensions are refused by field', () => {
  const bad = [
    [{ engine: 'postgres', app_login: 'yes' }, /database\.app_login: must be true or false/],
    [{ engine: 'mongo', app_login: true }, /database\.app_login: is supported for postgres and mariadb only/],
    [{ engine: 'postgres', app_url_env: 'X_URL' }, /database\.app_url_env: only applies with "app_login": true/],
    [{ engine: 'postgres', app_login: true, app_url_env: 'lower_case' }, /database\.app_url_env: must be an env var name/],
    [{ engine: 'postgres', app_login: true, app_url_env: 'PORT' }, /database\.app_url_env: "PORT" is reserved/],
    [{ engine: 'postgres', app_login: true, app_url_env: 'APPCRANE_X' }, /reserved/],
    [{ engine: 'postgres', app_login: true, app_url_env: 'APP_DB_CERT_FILE' }, /reserved/],
    [{ engine: 'postgres', sandbox_url_env: 'SANDBOX_DB_KEY_FILE' }, /database\.sandbox_url_env: "SANDBOX_DB_KEY_FILE" is reserved/],
    [{ engine: 'postgres', sandbox_url_env: '1BAD' }, /database\.sandbox_url_env: must be an env var name/],
    [{ engine: 'redis', sandbox_url_env: 'SANDBOX_REDIS_URL' }, /database\.sandbox_url_env: is supported for postgres and mariadb only/],
    [{ engine: 'postgres', sandbox_url_env: 'DATABASE_URL' }, /env var "DATABASE_URL" is mapped more than once/],
    [{ engine: 'postgres', app_login: true, app_url_env: 'X', sandbox_url_env: 'X' }, /"X" is mapped more than once/],
    [{ engine: 'postgres', extensions: 'pg_stat_statements' }, /database\.extensions: must be an array/],
    [{ engine: 'postgres', extensions: ['pgcrypto'] }, /database\.extensions: "pgcrypto" is not one AppCrane installs for postgres/],
    [{ engine: 'mariadb', extensions: ['pg_stat_statements'] }, /supported: none/],
    [{ engine: 'postgres', app_logins: true }, /database\.app_logins: unknown key/],
  ];
  for (const [block, re] of bad) assert.throws(() => parseManifestDatabase(block), re, JSON.stringify(block));
});

// ---------------------------------------------------------------------------
// App-login SQL: DML only
// ---------------------------------------------------------------------------

test('app login grants: DML on tables/sequences, default privileges for the owner, never CREATE', () => {
  const pw = crypto.randomBytes(24).toString('base64url');
  const role = appSql.pgAppRoleSql('crane_a1', 'crane_a1_u_app', pw);
  assert.match(role, /ALTER ROLE "crane_a1_u_app" WITH LOGIN PASSWORD '[^']+'\n {2}NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;/);
  assert.match(role, /GRANT CONNECT ON DATABASE "crane_a1" TO "crane_a1_u_app";/);
  assert.doesNotMatch(role, /TEMPORARY|OWNER/);

  const grants = appSql.pgAppGrantsSql('crane_a1_u', 'crane_a1_u_app');
  assert.match(grants, /REVOKE CREATE ON SCHEMA public FROM "crane_a1_u_app";/);
  assert.match(grants, /GRANT USAGE ON SCHEMA public TO "crane_a1_u_app";/);
  assert.match(grants, /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "crane_a1_u_app";/);
  assert.match(grants, /GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO "crane_a1_u_app";/);
  assert.match(grants, /ALTER DEFAULT PRIVILEGES FOR ROLE "crane_a1_u" IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "crane_a1_u_app";/);
  assert.match(grants, /ALTER DEFAULT PRIVILEGES FOR ROLE "crane_a1_u" IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "crane_a1_u_app";/);
  // Every GRANT in the set, privilege by privilege: nothing that is DDL.
  for (const line of grants.split('\n').filter((l) => /^(GRANT|ALTER DEFAULT)/.test(l))) {
    assert.doesNotMatch(line, /\b(CREATE|ALL PRIVILEGES|TRUNCATE|REFERENCES|TRIGGER)\b/, line);
  }

  const maria = appSql.mariadbAppUserSql('crane_a1', 'crane_a1_u_app', pw);
  assert.match(maria, /GRANT SELECT, INSERT, UPDATE, DELETE ON `crane_a1`\.\* TO 'crane_a1_u_app'@'%';/);
  assert.doesNotMatch(maria, /ALL PRIVILEGES|GRANT OPTION|\*\.\*/);

  assert.equal(appSql.appLoginName('crane_a1_u'), 'crane_a1_u_app');
  assert.throws(() => appSql.appLoginName('crane_a1_t0123456789ab_uxxxx'), /refusing identifier/, 'over 31 bytes is refused, not truncated');
  assert.throws(() => appSql.pgAppGrantsSql('x"; DROP', 'y'), /refusing identifier/);
  assert.throws(() => appSql.pgAppRoleSql('crane_a1', 'crane_a1_u_app', "pw'; DROP ROLE x; --aaaaaaaaaaaaaa"), /safe alphabet/);
});

// ---------------------------------------------------------------------------
// pg_stat_statements: filtered to this database AND this scope's logins
// ---------------------------------------------------------------------------

test('pg_stat_statements: only the filtered SECURITY DEFINER function is reachable, filtered by dbid AND userid', () => {
  const sql = stats.pgStatStatementsSql(['crane_a1_u', 'crane_a1_u_app']);
  assert.match(sql, /CREATE EXTENSION pg_stat_statements SCHEMA appcrane_stats;/);
  for (const obj of ['appcrane_stats.pg_stat_statements FROM PUBLIC', 'appcrane_stats.pg_stat_statements_info FROM PUBLIC',
    'FUNCTION appcrane_stats.pg_stat_statements(boolean) FROM PUBLIC', 'FUNCTION appcrane_stats.pg_stat_statements_reset(oid, oid, bigint) FROM PUBLIC',
    'SCHEMA appcrane_stats FROM PUBLIC']) {
    assert.ok(sql.includes(`REVOKE ALL ON ${obj};`), `missing REVOKE ALL ON ${obj}`);
  }
  const fn = sql.slice(sql.indexOf('FUNCTION appcrane_stats.app_stat_statements()'), sql.indexOf('$f$;'));
  assert.match(fn, /SECURITY DEFINER/);
  assert.match(fn, /SET search_path = pg_catalog, pg_temp/);
  assert.match(fn, /WHERE s\.dbid = \(SELECT d\.oid FROM pg_catalog\.pg_database AS d WHERE d\.datname = pg_catalog\.current_database\(\)\)/);
  assert.match(fn, /AND s\.userid IN \(SELECT r\.oid FROM pg_catalog\.pg_roles AS r WHERE r\.rolname IN \('crane_a1_u', 'crane_a1_u_app'\)\)/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION appcrane_stats\.app_stat_statements\(\) TO "crane_a1_u", "crane_a1_u_app";/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION appcrane_stats\.app_stat_statements_reset\(\) TO "crane_a1_u";/);
  // The raw view is never granted to anyone, and pg_read_all_stats never appears.
  assert.doesNotMatch(sql, /GRANT [^\n]* ON appcrane_stats\.pg_stat_statements\b/);
  assert.doesNotMatch(sql, /pg_read_all_stats/);
  assert.throws(() => stats.pgStatStatementsSql(["x'); DROP"]), /refusing identifier/);
});

test('dumps of a database with the stats wiring leave it out; others are unchanged', () => {
  assert.deepEqual(stats.parseDumpExtensions(''), { exclude: false, keep: [] });
  assert.deepEqual(stats.parseDumpExtensions('pgcrypto\n#pgss\n#stats\n'), { exclude: true, keep: ['pgcrypto'] });
  assert.deepEqual(stats.parseDumpExtensions('uuid-ossp\n$(id)\n#stats\n'), { exclude: true, keep: ['uuid-ossp'] });
  const plain = dumpCmd.dumpArgs('postgres', { container: 'c', database: 'crane_a1' });
  assert.ok(!plain.includes('-N'));
  const none = dumpCmd.dumpArgs('postgres', { container: 'c', database: 'crane_a1', pgKeepExtensions: [] });
  assert.deepEqual(none.slice(-4), ['-N', 'appcrane_stats', '-e', '"plpgsql"']);
  const keep = dumpCmd.dumpArgs('postgres', { container: 'c', database: 'crane_a1', pgKeepExtensions: ['pgcrypto'] });
  assert.deepEqual(keep.slice(-4), ['-N', 'appcrane_stats', '-e', '"pgcrypto"']);
});

// ---------------------------------------------------------------------------
// Injection per stage
// ---------------------------------------------------------------------------

const appId = Number(db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Supply','supply',1,'managed','main')",
).run().lastInsertRowid);
const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
const NEEDS = parseManifestDatabase({
  engine: 'postgres', app_login: true, sandbox_url_env: 'SANDBOX_DATABASE_URL', extensions: ['pg_stat_statements'],
});

async function fakeProvision(scope, engine) {
  const { database, username } = mdb.namesForScope(scope);
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
              VALUES (?, ?, ?, ?, ?, ?)`)
    .run(scope.appId, scope.tenant ?? '', engine, database, username, encrypt(crypto.randomBytes(18).toString('base64url')));
}
let sqlLog = [];
const ops = {
  ensureServer: async () => ({ port: 45432 }),
  runAdminSql: async (engine, sql, o) => { sqlLog.push({ engine, sql, database: o?.database || null }); return ''; },
  runAdminMongo: async () => {},
  ensureRedisInstance: async () => {},
};
const resolveOwner = async () => null;
const seams = {
  provision: fakeProvision,
  secureLogin: (s, e, o) => mdb.secureLogin(s, e, { ...o, ops, resolveOwner }),
  ensureAppLogin: (s, e, o) => mdb.ensureAppLogin(s, e, { ...o, ops, resolveOwner }),
  ensurePgExtensions: (s, o) => mdb.ensurePgExtensions(s, { ...o, ops }),
  sandboxPeerAccess: (id, e, o) => mdb.sandboxPeerAccess(id, e, { ...o, ops, resolveOwner }),
};
async function deploy(env, { needs = NEEDS, isRestart = false, own = {} } = {}) {
  const vars = { ...own };
  const log = [];
  const r = await injectManagedDbForEnv({
    app, env, runtimeEnvVars: vars, manifestNeeds: needs, isRestart, appendLog: (l) => log.push(l), ...seams,
  });
  return { vars, r, log };
}
const url = (u) => { const x = new URL(u); return { user: decodeURIComponent(x.username), pass: decodeURIComponent(x.password), db: x.pathname.slice(1), q: x.searchParams }; };

const prodNames = mdb.namesForScope({ appId });
const sandNames = mdb.namesForScope({ appId, tenant: SANDBOX_TENANT });
let PROD;
let SAND;

test('production: DATABASE_URL (owner), APP_DATABASE_URL (its own _app login) and SANDBOX_DATABASE_URL (sandbox owner)', async () => {
  sqlLog = [];
  PROD = await deploy('production');
  const v = PROD.vars;
  assert.equal(url(v.DATABASE_URL).user, prodNames.username);
  assert.equal(url(v.APP_DATABASE_URL).user, `${prodNames.username}_app`);
  assert.equal(url(v.APP_DATABASE_URL).db, prodNames.database, 'APP_DATABASE_URL must be this stage\'s database');
  assert.equal(url(v.APP_DATABASE_URL).q.get('sslmode'), 'verify-full');
  assert.equal(url(v.APP_DATABASE_URL).q.get('sslcert'), '/run/appcrane/db-app/client.crt');
  assert.equal(url(v.SANDBOX_DATABASE_URL).user, sandNames.username);
  assert.equal(url(v.SANDBOX_DATABASE_URL).db, sandNames.database);
  assert.equal(url(v.SANDBOX_DATABASE_URL).q.get('sslcert'), '/run/appcrane/db-sandbox/client.crt');
  assert.equal(v.APP_DB_CERT_FILE, '/run/appcrane/db-app/client.crt');
  assert.equal(v.SANDBOX_DB_KEY_FILE, '/run/appcrane/db-sandbox/client.key');
  assert.equal(v.DB_CERT_FILE, '/run/appcrane/db/client.crt', 'the owner login keeps its own paths');

  const mounts = PROD.r.mounts.map((m) => [m.container, m.host, m.readOnly]);
  assert.deepEqual(mounts.map((m) => m[0]), ['/run/appcrane/db', '/run/appcrane/db-app', '/run/appcrane/db-sandbox']);
  assert.ok(mounts.every((m) => m[2] === true), 'every certificate mount is read-only');
  assert.equal(PROD.r.mounts[1].host, certs.clientTlsDir(`${prodNames.username}_app`));
  assert.equal(PROD.r.mounts[2].host, certs.peerTlsDir(sandNames.username), 'production reads its own COPY of the sandbox certificate');
  assert.notEqual(PROD.r.mounts[2].host, certs.clientTlsDir(sandNames.username), 'never the sandbox container\'s own directory');

  // The engine was told: app role, its grants on THIS database, its policy (cert group), and the stats wiring.
  const onDb = sqlLog.filter((s) => s.database === prodNames.database).map((s) => s.sql).join('\n');
  assert.match(onDb, new RegExp(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "${prodNames.username}_app"`));
  assert.match(onDb, /appcrane_stats\.app_stat_statements/);
  assert.ok(sqlLog.some((s) => s.sql.includes(`GRANT appcrane_cert_required TO "${prodNames.username}_app";`)), 'app login must require its certificate');
  assert.ok(PROD.log.some((l) => /not loaded it yet/.test(l)), 'the deploy log says the preload is off');
  // Production provisioned the sandbox database for SANDBOX_DATABASE_URL; the
  // log says that, not "Separate sandbox database is on" (a setting this
  // deploy never looked at).
  assert.ok(PROD.log.includes('Provisioned the sandbox postgres database so production can reach it via SANDBOX_DATABASE_URL'),
    `production's sandbox provisioning line: ${JSON.stringify(PROD.log)}`);
  assert.ok(!PROD.log.some((l) => /Separate sandbox database is on/.test(l)));

  const row = mdb.credentialsFor({ appId }, 'postgres');
  assert.ok(row, 'production row');
  const dbRow = db.prepare("SELECT app_user, app_password_enc, extensions FROM managed_databases WHERE app_id = ? AND tenant = ''").get(appId);
  assert.equal(dbRow.app_user, `${prodNames.username}_app`);
  assert.ok(dbRow.app_password_enc && !dbRow.app_password_enc.includes(url(v.APP_DATABASE_URL).pass), 'stored encrypted');
  assert.equal(dbRow.extensions, '["pg_stat_statements"]');
});

test('sandbox: its own APP_DATABASE_URL, no SANDBOX_DATABASE_URL, and nothing of production\'s', async () => {
  SAND = await deploy('sandbox');
  const v = SAND.vars;
  assert.equal(v.SANDBOX_DATABASE_URL, undefined, 'sandbox must never receive SANDBOX_DATABASE_URL');
  assert.equal(url(v.DATABASE_URL).user, sandNames.username);
  assert.equal(url(v.APP_DATABASE_URL).user, `${sandNames.username}_app`);
  assert.equal(url(v.APP_DATABASE_URL).db, sandNames.database);

  // No production login, password, database or certificate anywhere in sandbox's environment or mounts.
  const everything = JSON.stringify(v);
  for (const pw of [url(PROD.vars.DATABASE_URL).pass, url(PROD.vars.APP_DATABASE_URL).pass]) {
    assert.ok(!everything.includes(pw), 'sandbox env carries a production password');
  }
  for (const [k, val] of Object.entries(v)) {
    if (!/^postgres(ql)?:\/\//.test(val)) continue;
    const u = url(val);
    assert.ok(![prodNames.username, `${prodNames.username}_app`].includes(u.user), `${k} logs in as production's ${u.user}`);
    assert.notEqual(u.db, prodNames.database, `${k} points at production's database`);
  }
  for (const m of SAND.r.mounts) {
    assert.ok(!m.host.includes(`/client/${prodNames.username}`) && !m.host.includes('/peer/'), `sandbox mounts production's certificate: ${m.host}`);
  }
  assert.deepEqual(SAND.r.mounts.map((m) => m.container), ['/run/appcrane/db', '/run/appcrane/db-app']);
});

test('restart re-injects all three, without provisioning', async () => {
  const r = await deploy('production', { isRestart: true });
  assert.equal(url(r.vars.APP_DATABASE_URL).pass, url(PROD.vars.APP_DATABASE_URL).pass, 'app login password is stable');
  assert.equal(url(r.vars.SANDBOX_DATABASE_URL).user, sandNames.username);
});

test('an env var the app set itself wins over the injected second-login URLs', async () => {
  const r = await deploy('production', { own: { APP_DATABASE_URL: 'postgres://mine', SANDBOX_DATABASE_URL: 'postgres://also-mine' } });
  assert.equal(r.vars.APP_DATABASE_URL, 'postgres://mine');
  assert.equal(r.vars.SANDBOX_DATABASE_URL, 'postgres://also-mine');
  assert.ok(r.r.deferred.includes('APP_DATABASE_URL') && r.r.deferred.includes('SANDBOX_DATABASE_URL'));
});

test('opting out of app_login disables the login (kept for restores) and stops injecting it; extensions are dropped', async () => {
  sqlLog = [];
  const r = await deploy('production', { needs: parseManifestDatabase({ engine: 'postgres' }) });
  assert.equal(r.vars.APP_DATABASE_URL, undefined);
  assert.equal(r.vars.SANDBOX_DATABASE_URL, undefined);
  assert.ok(sqlLog.some((s) => s.sql.includes(`ALTER ROLE "${prodNames.username}_app" NOLOGIN;`)));
  assert.ok(sqlLog.some((s) => s.sql.includes('DROP SCHEMA IF EXISTS appcrane_stats CASCADE;') && s.database === prodNames.database));
  const row = db.prepare("SELECT app_user, app_password_enc, extensions FROM managed_databases WHERE app_id = ? AND tenant = ''").get(appId);
  assert.equal(row.app_user, `${prodNames.username}_app`);
  assert.equal(row.app_password_enc, null);
  assert.equal(row.extensions, null);
  // And back on: a fresh password.
  const again = await deploy('production');
  assert.notEqual(url(again.vars.APP_DATABASE_URL).pass, url(PROD.vars.APP_DATABASE_URL).pass);
  PROD = again;
});

// ---------------------------------------------------------------------------
// Backups re-apply the grants
// ---------------------------------------------------------------------------

test('restore re-applies the app login (CONNECT, DML grants, default privileges, policy) and the stats wiring', async () => {
  const row = db.prepare("SELECT * FROM managed_databases WHERE app_id = ? AND tenant = ''").get(appId);
  const calls = [];
  const rec = {
    ...mdb.backupAccess,
    runAdminSql: async (e, sql, o) => { calls.push({ sql, database: o?.database || null }); return ''; },
  };
  await bk.reapplyLoginPolicy(row, rec);
  const all = calls.map((c) => c.sql).join('\n');
  assert.match(all, new RegExp(`GRANT CONNECT ON DATABASE "${prodNames.database}" TO "${prodNames.username}_app";`));
  assert.match(all, new RegExp(`ALTER DEFAULT PRIVILEGES FOR ROLE "${prodNames.username}" IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${prodNames.username}_app";`));
  assert.match(all, new RegExp(`GRANT appcrane_cert_required TO "${prodNames.username}_app";`));
  assert.ok(calls.some((c) => c.database === prodNames.database && c.sql.includes('CREATE OR REPLACE FUNCTION appcrane_stats.app_stat_statements()')));
  const pw = url(PROD.vars.APP_DATABASE_URL).pass;
  assert.ok(all.includes(pw), 'the stored password is re-asserted (SQL goes over stdin, never argv)');

  // MariaDB: the same login under ACCOUNT UNLOCK + DML grant.
  const mrow = { ...row, engine: 'mariadb' };
  calls.length = 0;
  await bk.reapplyLoginPolicy(mrow, rec);
  const m = calls.map((c) => c.sql).join('\n');
  assert.match(m, new RegExp(`GRANT SELECT, INSERT, UPDATE, DELETE ON \`${prodNames.database}\`\\.\\* TO '${prodNames.username}_app'@'%';`));
  assert.match(m, new RegExp(`REQUIRE SUBJECT '/CN=${prodNames.username}_app'`));
});

test('deprovision drops the app login with the database, and its certificate', async () => {
  const calls = [];
  // dropInEngine is reached through deprovision -> dropRow -> ensureServer; run
  // the pure part: the drop SQL for both engines.
  calls.push(appSql.appLoginDropSql('postgres', `${prodNames.username}_app`));
  calls.push(appSql.appLoginDropSql('mariadb', `${prodNames.username}_app`));
  assert.match(calls[0], new RegExp(`DROP ROLE IF EXISTS "${prodNames.username}_app";`));
  assert.match(calls[1], new RegExp(`DROP USER IF EXISTS '${prodNames.username}_app'@'%';`));
  const row = db.prepare("SELECT * FROM managed_databases WHERE app_id = ? AND tenant = ''").get(appId);
  assert.ok(certs.clientCertInfo(`${prodNames.username}_app`), 'certificate issued');
  db.prepare('DELETE FROM managed_databases WHERE id = ?').run(row.id);
  certs.releaseClientCerts(row);
  assert.equal(certs.clientCertInfo(`${prodNames.username}_app`), null, 'app login certificate released');
  const srow = db.prepare("SELECT * FROM managed_databases WHERE app_id = ? AND tenant = ?").get(appId, SANDBOX_TENANT);
  db.prepare('DELETE FROM managed_databases WHERE id = ?').run(srow.id);
  certs.releaseClientCerts(srow);
  const { existsSync } = await import('fs');
  assert.equal(existsSync(join(process.env.DATA_DIR, 'managed-db', '_tls', 'peer', sandNames.username)), false, 'production\'s copy of the sandbox certificate is removed');
});
