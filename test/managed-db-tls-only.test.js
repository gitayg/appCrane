import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readdirSync, readFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The "TLS required" login level (migration 315) without a daemon: the SQL and
// pg_hba builders, the password-only list and the Job Health text, strict
// pg_hba counting TLS logins, requireTls() and its route, and the deployer
// for BookStack's catalogue entry (CA only, MYSQL_ATTR_SSL_CA). What the
// engines do with it is test/managed-db-tls-only-real.test.js.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbtlsonly-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const tls = await import('../server/services/managedDbTls.js');
const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const po = await import('../server/services/managedDbPasswordOnly.js');
const deployer = await import('../server/services/deployer.js');
const certs = await import('../server/services/dbCerts.js');
const check = await import('../server/services/managedDbTlsCheck.js');
const { findEntry } = await import('../server/services/catalogService.js');
const { encrypt, generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

let BOOK; let CAT; let PLAIN;
before(() => {
  initDb(process.env.DATA_DIR);
  const ins = getDb().prepare('INSERT INTO apps (name, slug, slot, catalog_slug) VALUES (?, ?, ?, ?)');
  BOOK = Number(ins.run('Book', 'tls-book', 1, 'bookstack').lastInsertRowid);
  CAT = Number(ins.run('Cat', 'tls-cat', 2, 'metabase').lastInsertRowid);
  PLAIN = Number(ins.run('Plain', 'tls-plain', 3, null).lastInsertRowid);
  for (const [engine, port] of [['postgres', 45432], ['mariadb', 43306]]) {
    getDb().prepare(`INSERT INTO managed_db_servers (engine, container_name, image, host_port, admin_password_enc)
      VALUES (?, ?, 'img', ?, ?)`).run(engine, `x-${engine}`, port, encrypt('a'.repeat(32)));
  }
});
after(() => {
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

function seedRow(appId, engine, { cert = 0, tlsLevel = 0 } = {}) {
  const { database, username } = mdb.namesForScope({ appId, tenant: null });
  const r = getDb().prepare(`INSERT INTO managed_databases
      (app_id, tenant, engine, db_name, db_user, password_enc, client_cert_required, tls_required)
    VALUES (?, '', ?, ?, ?, ?, ?, ?)`).run(appId, engine, database, username, encrypt('p'.repeat(32)), cert, tlsLevel);
  return { id: Number(r.lastInsertRowid), database, username };
}
const clear = () => getDb().prepare('DELETE FROM managed_databases').run();
const hbaOnDisk = () => certs.readServerFile('postgres', 'pg_hba.conf');

function pgOps({ roles = '' } = {}) {
  return {
    containerState: async () => 'running',
    exec: async () => '',
    runAdminSql: async (_e, sql) => (/pg_has_role/.test(sql) ? roles : ''),
  };
}
// `measure`: what the engine answers the TLS check (pg_stat_ssl lines, or
// the MariaDB counter lines); every other statement answers ''.
function loginOps(sync, measure = () => '') {
  const calls = [];
  return {
    calls,
    ops: {
      ensureServer: async (e) => { calls.push(['ensureServer', e]); return { port: 1 }; },
      runAdminSql: async (e, sql) => {
        if (/pg_stat_ssl|USER_STATISTICS/.test(sql)) { calls.push(['check', e, sql]); return measure(e, sql); }
        calls.push(['sql', e, sql]);
        return '';
      },
      runAdminMongo: async () => {},
      ensureRedisInstance: async () => {},
      ...(sync ? { syncPgHba: sync } : {}),
    },
  };
}

test('migration 315: tls_required exists, defaults to 0, tls_probe_base is nullable, and the table still has no CHECK', () => {
  const cols = getDb().prepare('PRAGMA table_info(managed_databases)').all();
  const col = cols.find((c) => c.name === 'tls_required');
  assert.ok(col, 'column exists');
  assert.equal(col.dflt_value, '0');
  const base = cols.find((c) => c.name === 'tls_probe_base');
  assert.ok(base);
  assert.equal(base.notnull, 0);
  const ddl = getDb().prepare("SELECT sql FROM sqlite_master WHERE name = 'managed_databases'").get().sql;
  assert.doesNotMatch(ddl, /CHECK/i);
});

test('login policy: MariaDB REQUIRE SSL, Postgres the TLS group (created idempotently); the certificate wins over TLS', () => {
  const p = { connLimit: 5, statementTimeoutS: 0 };
  const m = tls.loginPolicySql('mariadb', 'crane_a1_u', { ...p, certRequired: false, tlsRequired: true });
  assert.match(m, /^ALTER USER 'crane_a1_u'@'%' REQUIRE SSL WITH MAX_USER_CONNECTIONS 5 /);
  const both = tls.loginPolicySql('mariadb', 'crane_a1_u', { ...p, certRequired: true, tlsRequired: true });
  assert.match(both, /REQUIRE SUBJECT '\/CN=crane_a1_u' AND ISSUER/);
  assert.doesNotMatch(both, /REQUIRE SSL/);
  assert.doesNotMatch(tls.loginPolicySql('mariadb', 'crane_a1_u', { ...p, certRequired: false }), /REQUIRE/, 'neither: REQUIRE untouched (sticky)');

  const pg = tls.loginPolicySql('postgres', 'crane_a1_u', { ...p, certRequired: false, tlsRequired: true });
  assert.match(pg, new RegExp(`CREATE ROLE ${tls.PG_TLS_GROUP} NOLOGIN`));
  assert.match(pg, new RegExp(`GRANT ${tls.PG_TLS_GROUP} TO "crane_a1_u";`));
  const pgBoth = tls.loginPolicySql('postgres', 'crane_a1_u', { ...p, certRequired: true, tlsRequired: true });
  assert.match(pgBoth, new RegExp(`GRANT ${tls.PG_CERT_GROUP} TO`));
  assert.doesNotMatch(pgBoth, new RegExp(tls.PG_TLS_GROUP));
});

test('pg_hba: the TLS-group lines come after the cert-group lines; a strict body written before them still reads as strict', () => {
  const lines = tls.pgHbaConf({ strict: true }).split('\n').filter((l) => l && !l.startsWith('#'));
  const certAt = lines.findIndex((l) => l.includes(`+${tls.PG_CERT_GROUP}`));
  const tlsAt = lines.findIndex((l) => l.includes(`+${tls.PG_TLS_GROUP}`));
  assert.ok(certAt > 0 && tlsAt > certAt, 'first match wins: a member of both groups is held to the certificate');
  const legacy = tls.pgHbaConf({ strict: true }).split('\n').filter((l) => !l.includes(tls.PG_TLS_GROUP)).join('\n');
  assert.equal(tls.isStrictPgHba(legacy), true);
  assert.equal(tls.isStrictPgHba(tls.pgHbaConf().split('\n').filter((l) => !l.includes(tls.PG_TLS_GROUP)).join('\n')), false);
  const sql = tls.pgPasswordOnlyRolesSql();
  assert.match(sql, new RegExp(`g\\.rolname = '${tls.PG_TLS_GROUP}'`), 'TLS-group members are not password-only to the engine');
});

test('passwordOnlyLogins skips a TLS login; tlsOnlyLogins lists it as "TLS + password (no client certificate)"; strict holds with it', async () => {
  clear();
  const plain = seedRow(CAT, 'postgres');
  const book = seedRow(BOOK, 'mariadb');
  let list = po.passwordOnlyLogins();
  assert.deepEqual(list.map((l) => l.login).sort(), [plain.username, book.username].sort());
  const b = list.find((l) => l.login === book.username);
  assert.equal(b.tls_available, true);
  assert.equal(b.tls_ca_env, 'MYSQL_ATTR_SSL_CA', 'BookStack names its CA variable');
  assert.equal(list.find((l) => l.login === plain.username).tls_ca_env, null, 'Metabase names none');

  await mdb.syncPgHba({ ops: pgOps() });
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false, 'precondition: a plain Postgres login keeps pg_hba loose');

  getDb().prepare('UPDATE managed_databases SET tls_required = 1').run();
  assert.deepEqual(po.passwordOnlyLogins(), []);
  list = po.tlsOnlyLogins();
  assert.deepEqual(list.map((l) => [l.login, l.level, l.level_label]).sort(), [
    [plain.username, 'tls', 'TLS + password (no client certificate)'],
    [book.username, 'tls', 'TLS + password (no client certificate)'],
  ].sort());
  await mdb.syncPgHba({ ops: pgOps() });
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true, 'every Postgres login is in the cert or the TLS group');

  const detail = await po.runManagedDbLoginsCheck({ sync: async () => ({ strict: true, engineRoles: [] }) });
  assert.equal(detail.severity, undefined, 'no warning: nothing signs in with a password alone');
  assert.match(detail.message, /No managed database login signs in with a password alone/);
  assert.match(detail.message, /2 login\(s\) require TLS and the password but no client certificate/);

  getDb().prepare('UPDATE managed_databases SET client_cert_required = 1 WHERE id = ?').run(plain.id);
  assert.deepEqual(po.tlsOnlyLogins().map((l) => l.login), [book.username], 'the certificate level wins');
});

test('requireTls: owner + app login get the TLS statements, the row is marked, pg_hba re-evaluated; a certificate login is left alone; Mongo/Redis refused', async () => {
  clear();
  const pg = seedRow(CAT, 'postgres');
  getDb().prepare("UPDATE managed_databases SET app_user = ?, app_password_enc = ? WHERE id = ?").run(`${pg.username}_app`, encrypt('q'.repeat(32)), pg.id);
  let syncs = 0;
  const { calls, ops } = loginOps(async () => { syncs++; return mdb.syncPgHba({ ops: pgOps() }); });
  const r = await mdb.requireTls(pg.id, { ops, confirmNoConnections: true });
  assert.deepEqual([r.converted, r.level, r.redeploy_required, r.logins], [true, 'tls', true, [pg.username, `${pg.username}_app`]]);
  const sql = calls.filter((c) => c[0] === 'sql').map((c) => c[2]);
  assert.equal(sql.length, 2);
  assert.match(sql[0], new RegExp(`GRANT ${tls.PG_TLS_GROUP} TO "${pg.username}"`));
  assert.match(sql[1], new RegExp(`GRANT ${tls.PG_TLS_GROUP} TO "${pg.username}_app"`));
  assert.equal(getDb().prepare('SELECT tls_required FROM managed_databases WHERE id = ?').get(pg.id).tls_required, 1);
  assert.equal(syncs, 1);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true);

  const cert = seedRow(BOOK, 'mariadb', { cert: 1 });
  calls.length = 0;
  const c = await mdb.requireTls(cert.id, { ops });
  assert.deepEqual([c.converted, c.level], [false, 'certificate']);
  assert.deepEqual(calls, [], 'nothing sent to the engine');
  assert.equal(getDb().prepare('SELECT tls_required FROM managed_databases WHERE id = ?').get(cert.id).tls_required, 0);

  const mongo = seedRow(PLAIN, 'mongo');
  await assert.rejects(mdb.requireTls(mongo.id, { ops, confirmNoConnections: true }), (e) => e.code === 'TLS_LEVEL_UNSUPPORTED');
  assert.equal(await mdb.requireTls(999999, { ops }), null);
});

test('BookStack at the TLS level: deploy mounts a directory holding ca.crt only and injects MYSQL_ATTR_SSL_CA + DB_CA_FILE, no certificate variables', async () => {
  clear();
  assert.equal(findEntry('bookstack').needs.tls_ca_env, 'MYSQL_ATTR_SSL_CA');
  const book = seedRow(BOOK, 'mariadb', { tlsLevel: 1 });
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(BOOK);
  const { calls, ops } = loginOps();
  const lines = [];
  const env = {};
  const out = await deployer.injectManagedDbForEnv({
    app, env: 'production', runtimeEnvVars: env, appendLog: (l) => lines.push(l),
    secureLogin: (scope, engine, o) => mdb.secureLogin(scope, engine, { ...o, ops }),
  });
  assert.match(calls.find((c) => c[0] === 'sql')[2], new RegExp(`ALTER USER '${book.username}'@'%' REQUIRE SSL `), 're-asserted on every deploy');
  assert.equal(out.mounts.length, 1);
  assert.equal(out.mounts[0].container, certs.CLIENT_MOUNT_PATH);
  assert.equal(out.mounts[0].readOnly, true);
  assert.deepEqual(readdirSync(out.mounts[0].host), ['ca.crt'], 'the CA and nothing else');
  assert.equal(readFileSync(join(out.mounts[0].host, 'ca.crt'), 'utf8'), certs.ensureCa().certPem);
  assert.equal(statSync(join(out.mounts[0].host, 'ca.crt')).mode & 0o777, 0o444);
  assert.equal(env.MYSQL_ATTR_SSL_CA, `${certs.CLIENT_MOUNT_PATH}/ca.crt`);
  assert.equal(env.DB_CA_FILE, `${certs.CLIENT_MOUNT_PATH}/ca.crt`);
  for (const k of ['DB_CERT_FILE', 'DB_KEY_FILE', 'DB_CERT_KEY_FILE']) assert.equal(env[k], undefined, k);
  assert.equal(env.DB_USERNAME, book.username);
  assert.ok(lines.some((l) => /TLS and the password are required \(no client certificate\).*MYSQL_ATTR_SSL_CA/.test(l)));

  // A variable the app set itself still wins.
  const own = { MYSQL_ATTR_SSL_CA: '/mine.pem' };
  await deployer.injectManagedDbForEnv({ app, env: 'production', runtimeEnvVars: own, secureLogin: (s, e, o) => mdb.secureLogin(s, e, { ...o, ops }) });
  assert.equal(own.MYSQL_ATTR_SSL_CA, '/mine.pem');

  // Fail closed: the injected path names a file the container must have.
  await assert.rejects(deployer.injectManagedDbForEnv({
    app, env: 'production', runtimeEnvVars: {}, secureLogin: async () => { throw new Error('server down'); },
  }), /Securing the managed mariadb database login failed: server down/);
});

test('URLs AppCrane builds for a TLS login verify the server and carry no client certificate', () => {
  const ca = `${certs.CLIENT_MOUNT_PATH}/ca.crt`;
  const t = { required: true, level: 'tls', caOnly: true, x509: false, ca };
  const base = { host: 'h', port: 1, database: 'd', username: 'u', password: 'p' };
  const pgUrl = deployer.managedDbUrl({ ...base, engine: 'postgres', tls: t });
  assert.equal(pgUrl, `postgresql://u:p@h:1/d?sslmode=verify-full&sslrootcert=${encodeURIComponent(ca)}`);
  const myUrl = deployer.managedDbUrl({ ...base, engine: 'mariadb', tls: t });
  assert.equal(myUrl, `mysql://u:p@h:1/d?ssl-mode=VERIFY_IDENTITY&ssl-ca=${encodeURIComponent(ca)}`);
  const pgEnv = deployer.tlsFileEnv({ env: { host: 'PGHOST' } }, { engine: 'postgres', tls: t });
  assert.deepEqual(pgEnv, { DB_CA_FILE: ca, PGSSLMODE: 'verify-full', PGSSLROOTCERT: ca });
});

test('tlsView: a TLS login reads tls_required, a certificate login stays required', () => {
  clear();
  const a = seedRow(CAT, 'postgres', { tlsLevel: 1 });
  const b = seedRow(BOOK, 'mariadb', { tlsLevel: 1, cert: 1 });
  const rows = Object.fromEntries(getDb().prepare('SELECT * FROM managed_databases').all().map((r) => [r.id, r]));
  assert.equal(mdb.tlsView(rows[a.id]).tls, 'tls_required');
  assert.equal(mdb.tlsView(rows[b.id]).tls, 'required');
});

test('routes: require-tls / revert-tls are platform admin, session only, step-up, confirm, audited; tls-check reports the engine; 409 while connections are plain', async () => {
  clear();
  const book = seedRow(BOOK, 'mariadb');
  const cat = seedRow(CAT, 'postgres');
  const mongo = seedRow(PLAIN, 'mongo');
  const mkUser = (role) => {
    const key = generateApiKey('dhk_user');
    getDb().prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
      .run(`u-${role}-${Math.random()}`, `${role}${Math.random()}@t.test`, role, hashApiKey(key), 'human');
    return key;
  };
  const PLATFORM = mkUser('platform_admin');
  const USER = mkUser('user');
  getDb().prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) SELECT ?, id, ? FROM users WHERE api_key_hash = ?')
    .run(BOOK, 'owner', hashApiKey(USER));
  // Postgres answers one plain connection of cat's login until `pgTls` flips.
  let pgTls = false; let pgNone = false;
  const { calls, ops } = loginOps(async () => mdb.syncPgHba({ ops: pgOps() }), (e) => (e === 'postgres' && !pgNone ? `${cat.username} ${pgTls ? 't' : 'f'}\n` : ''));
  const routes = await import('../server/routes/managedDb.js');
  const { errorHandler } = await import('../server/utils/errors.js');
  routes.__setEngineForTests({
    requireTls: (id, o) => mdb.requireTls(id, { ...o, ops }),
    revertTls: (id) => mdb.revertTls(id, { ops }),
    measureLoginTls: (id, o) => mdb.measureLoginTls(id, { ...o, ops }),
  });
  const api = express();
  api.use(express.json());
  api.use('/api/managed-db', routes.serversRouter);
  api.use(errorHandler);
  const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}/api/managed-db`;
  const call = (path, key, body = { confirm: true }, auth = 'session') => fetch(base + path, {
    method: 'POST',
    headers: { ...(key ? (auth === 'key' ? { 'X-API-Key': key } : { Authorization: `Bearer ${key}` }) : {}), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
  const adminId = getDb().prepare('SELECT id FROM users WHERE api_key_hash = ?').get(hashApiKey(PLATFORM)).id;
  const session = (ageMin = 0) => {
    const token = generateApiKey('sess');
    getDb().prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(adminId, hashApiKey(token));
    getDb().prepare(`UPDATE identity_sessions SET created_at = datetime('now', '-${ageMin} minutes') WHERE token_hash = ?`).run(hashApiKey(token));
    return token;
  };
  const tlsOf = (id) => getDb().prepare('SELECT tls_required FROM managed_databases WHERE id = ?').get(id).tls_required;
  const policyCalls = () => calls.filter((c) => c[0] === 'sql');
  try {
    for (const path of [`/logins/${book.id}/require-tls`, `/logins/${book.id}/revert-tls`]) {
      assert.equal((await call(path, null)).status, 401);
      assert.equal((await call(path, USER, { confirm: true }, 'key')).status, 403, 'even the app owner');
      const byKey = await call(path, PLATFORM, { confirm: true }, 'key');
      assert.equal(byKey.status, 403, `${path}: a platform-admin API key is refused`);
      assert.equal(byKey.body?.error?.code, 'SESSION_REQUIRED');
      for (const body of [{}, { confirm: 'true' }]) {
        const r = await call(path, session(), body);
        assert.equal(r.status, 400);
        assert.equal(r.body?.error?.code, 'CONFIRMATION_REQUIRED');
      }
      const stale = await call(path, session(30));
      assert.equal(stale.status, 401, JSON.stringify(stale.body));
      assert.equal(stale.body?.error?.code, 'STEP_UP_REQUIRED');
    }
    assert.deepEqual(calls, [], 'nothing reached the engine');

    // Postgres, a plain connection open: the check says so, Require TLS is 409 and sends nothing.
    const chk = await call(`/logins/${cat.id}/tls-check`, PLATFORM, {}, 'key');
    assert.equal(chk.status, 200, JSON.stringify(chk.body));
    assert.deepEqual([chk.body.connections, chk.body.tls, chk.body.plain, chk.body.ready], [1, 0, 1, false]);
    assert.equal(chk.body.blocked.code, 'TLS_PLAIN_CONNECTIONS');
    const refused = await call(`/logins/${cat.id}/require-tls`, session(), { confirm: true, confirm_no_connections: true });
    assert.equal(refused.status, 409, JSON.stringify(refused.body));
    assert.equal(refused.body.error.code, 'TLS_PLAIN_CONNECTIONS');
    assert.equal(refused.body.error.check.plain, 1);
    assert.deepEqual(policyCalls(), [], 'the engine was asked, nothing was changed');
    assert.equal(tlsOf(cat.id), 0);

    pgTls = true;
    const ready = await call(`/logins/${cat.id}/tls-check`, PLATFORM, {}, 'key');
    assert.deepEqual([ready.body.connections, ready.body.tls, ready.body.ready, ready.body.blocked], [1, 1, true, null]);
    const ok = await call(`/logins/${cat.id}/require-tls`, session());
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(tlsOf(cat.id), 1);
    assert.match(policyCalls()[0][2], new RegExp(`GRANT ${tls.PG_TLS_GROUP} TO "${cat.username}"`));
    const audit = getDb().prepare("SELECT app_id, detail FROM audit_log WHERE action = 'managed-db-require-tls'").get();
    assert.equal(audit.app_id, CAT);
    assert.match(audit.detail, /"level":"tls"/);
    assert.match(audit.detail, /"check":\{"method":"current","connections":1,"tls":1,"plain":0\}/);

    // MariaDB, never measured: 409 until the check is started.
    const ns = await call(`/logins/${book.id}/require-tls`, session(), { confirm: true, confirm_no_connections: true });
    assert.equal(ns.status, 409);
    assert.equal(ns.body.error.code, 'TLS_CHECK_NOT_STARTED');
    assert.equal(tlsOf(book.id), 0);

    // Revert: REVOKE, flag back to 0, audited.
    calls.length = 0;
    const rv = await call(`/logins/${cat.id}/revert-tls`, session());
    assert.equal(rv.status, 200, JSON.stringify(rv.body));
    assert.equal(rv.body.reverted, true);
    assert.equal(tlsOf(cat.id), 0);
    assert.match(policyCalls()[0][2], new RegExp(`REVOKE ${tls.PG_TLS_GROUP} FROM "${cat.username}"`));
    const ra = getDb().prepare("SELECT app_id, detail FROM audit_log WHERE action = 'managed-db-revert-tls'").get();
    assert.equal(ra.app_id, CAT);
    const again = await call(`/logins/${cat.id}/revert-tls`, session());
    assert.equal(again.body.reverted, false);

    // No connection to measure: only with confirm_no_connections, and that is audited.
    pgNone = true;
    const none = await call(`/logins/${cat.id}/require-tls`, session());
    assert.equal(none.status, 409);
    assert.equal(none.body.error.code, 'TLS_NO_CONNECTIONS');
    assert.equal(tlsOf(cat.id), 0);
    const forced = await call(`/logins/${cat.id}/require-tls`, session(), { confirm: true, confirm_no_connections: true });
    assert.equal(forced.status, 200, JSON.stringify(forced.body));
    assert.equal(tlsOf(cat.id), 1);
    const fa = getDb().prepare("SELECT detail FROM audit_log WHERE action = 'managed-db-require-tls' ORDER BY id DESC LIMIT 1").get();
    assert.match(fa.detail, /"confirm_no_connections":true/);

    const m = await call(`/logins/${mongo.id}/require-tls`, session());
    assert.equal(m.status, 400);
    assert.equal(m.body?.error?.code, 'TLS_LEVEL_UNSUPPORTED');
    assert.equal((await call(`/logins/${mongo.id}/tls-check`, PLATFORM, {}, 'key')).status, 400);
    assert.equal((await call('/logins/424242/require-tls', session())).status, 404);
    assert.equal((await call('/logins/424242/revert-tls', session())).status, 404);
    assert.equal((await call('/logins/424242/tls-check', PLATFORM, {}, 'key')).status, 404);
  } finally {
    routes.__setEngineForTests(null);
    server.closeAllConnections?.();
    server.close();
  }
});

test('MariaDB TLS check: counts since the baseline, refuses after a server restart, and flags a connection opened before the check', () => {
  const L = ['crane_a1_u'];
  const read = (started, connId, total, ssl, open = []) => check.parseMariadbCounters(
    ['x', `S ON ${started} ${connId}`, 'x', `U crane_a1_u ${total} ${ssl}`, 'x', ...open.map((id) => `P crane_a1_u ${id}`)].join('\n'), L);
  const base = { at: 't0', ...read(1000, 50, 10, 4) };
  assert.deepEqual([base.started, base.conn_id, base.counters.crane_a1_u], [1000, 50, { total: 10, ssl: 4 }]);
  let v = check.mariadbVerdict(base, read(1001, 70, 15, 9, [60]), L);
  assert.deepEqual([v.measured, v.connections, v.tls, v.plain, v.open_unclassified], [true, 5, 5, 0, 0]);
  assert.equal(check.requireTlsRefusal(v), null);
  v = check.mariadbVerdict(base, read(1000, 70, 15, 8), L);
  assert.equal(v.plain, 1);
  assert.equal(check.requireTlsRefusal(v).code, 'TLS_PLAIN_CONNECTIONS');
  v = check.mariadbVerdict(base, read(1000, 70, 15, 9, [42, 60]), L);
  assert.equal(v.open_unclassified, 1, 'connection 42 predates the baseline session 50');
  assert.equal(check.requireTlsRefusal(v, { confirmNoConnections: true }).code, 'TLS_UNCLASSIFIED_CONNECTIONS');
  v = check.mariadbVerdict(base, read(5000, 3, 2, 2), L);
  assert.equal(v.measured, false);
  assert.equal(check.requireTlsRefusal(v).code, 'TLS_CHECK_RESTARTED');
  const off = check.parseMariadbCounters('S OFF 1000 70\nU crane_a1_u 15 9', L);
  assert.equal(check.mariadbVerdict(base, off, L).reason, 'server_restarted', 'userstat off: counting stopped');
  assert.equal(check.mariadbVerdict(null, read(1000, 70, 15, 9), L).reason, 'not_started');
  v = check.mariadbVerdict(base, read(1000, 70, 10, 4), L);
  assert.equal(check.requireTlsRefusal(v).code, 'TLS_NO_CONNECTIONS');
  assert.equal(check.requireTlsRefusal(v, { confirmNoConnections: true }), null);
  assert.throws(() => check.mariadbCountersSql(["x'; DROP"]), /refusing identifier/);
  assert.match(check.mariadbCountersSql(L, { reset: true }), /^SET GLOBAL userstat = 1;/);
  assert.doesNotMatch(check.mariadbCountersSql(L), /SET GLOBAL/);
});

test('measureLoginTls: MariaDB reset stores the baseline; a later read counts from it', async () => {
  clear();
  const book = seedRow(BOOK, 'mariadb');
  let total = 10; let ssl = 4;
  const { ops } = loginOps(null, () => `x\nS 1 1000 50\nx\nU ${book.username} ${total} ${ssl}\n`);
  const first = await mdb.measureLoginTls(book.id, { ops });
  assert.equal(first.reason, 'not_started');
  const started = await mdb.measureLoginTls(book.id, { ops, reset: true });
  assert.deepEqual([started.measured, started.connections], [true, 0]);
  const stored = JSON.parse(getDb().prepare('SELECT tls_probe_base FROM managed_databases WHERE id = ?').get(book.id).tls_probe_base);
  assert.deepEqual([stored.started, stored.conn_id, stored.counters[book.username]], [1000, 50, { total: 10, ssl: 4 }]);
  total = 13; ssl = 7;
  const later = await mdb.measureLoginTls(book.id, { ops });
  assert.deepEqual([later.connections, later.tls, later.plain], [3, 3, 0]);
  await mdb.requireTls(book.id, { ops });
  assert.equal(getDb().prepare('SELECT tls_required FROM managed_databases WHERE id = ?').get(book.id).tls_required, 1);
});

test('revertTls: MariaDB REQUIRE NONE (never for a certificate row), Postgres REVOKE; pg_hba loosens again', async () => {
  clear();
  const my = seedRow(BOOK, 'mariadb', { tlsLevel: 1 });
  const certRow = seedRow(PLAIN, 'mariadb', { tlsLevel: 1, cert: 1 });
  const pg = seedRow(CAT, 'postgres', { tlsLevel: 1 });
  getDb().prepare('UPDATE managed_databases SET tls_probe_base = ? WHERE id = ?').run('{"at":"x"}', my.id);
  await mdb.syncPgHba({ ops: pgOps() });
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), true, 'precondition: the only Postgres login is a TLS login');
  const { calls, ops } = loginOps(async () => mdb.syncPgHba({ ops: pgOps() }));
  assert.equal((await mdb.revertTls(my.id, { ops })).reverted, true);
  assert.deepEqual(calls.filter((c) => c[0] === 'sql').map((c) => c[2]), [`ALTER USER '${my.username}'@'%' REQUIRE NONE;\n`]);
  assert.deepEqual(Object.values(getDb().prepare('SELECT tls_required, tls_probe_base FROM managed_databases WHERE id = ?').get(my.id)), [0, null]);
  calls.length = 0;
  assert.equal((await mdb.revertTls(certRow.id, { ops })).reverted, true);
  assert.deepEqual(calls.filter((c) => c[0] === 'sql'), [], 'the certificate requirement is left alone');
  calls.length = 0;
  await mdb.revertTls(pg.id, { ops });
  assert.deepEqual(calls.filter((c) => c[0] === 'sql').map((c) => c[2]), [`REVOKE ${tls.PG_TLS_GROUP} FROM "${pg.username}";\n`]);
  assert.equal(tls.isStrictPgHba(hbaOnDisk()), false, 'a password-only Postgres login again: strict loosens');
  assert.equal(po.passwordOnlyLogins().some((l) => l.login === pg.username), true);
});

test('Prepare TLS: a BookStack login that is not converted still gets the CA mount, MYSQL_ATTR_SSL_CA and DB_CA_FILE on deploy; no REQUIRE SSL is sent; a failure does not stop the deploy', async () => {
  clear();
  const book = seedRow(BOOK, 'mariadb');
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(BOOK);
  const { calls, ops } = loginOps();
  const lines = [];
  const env = {};
  const out = await deployer.injectManagedDbForEnv({
    app, env: 'production', runtimeEnvVars: env, appendLog: (l) => lines.push(l),
    secureLogin: (scope, engine, o) => mdb.secureLogin(scope, engine, { ...o, ops }),
  });
  const policy = calls.find((c) => c[0] === 'sql')[2];
  assert.doesNotMatch(policy, /REQUIRE/, 'the engine is not told to require anything');
  assert.equal(out.mounts.length, 1);
  assert.deepEqual(readdirSync(out.mounts[0].host), ['ca.crt']);
  assert.equal(env.MYSQL_ATTR_SSL_CA, `${certs.CLIENT_MOUNT_PATH}/ca.crt`);
  assert.equal(env.DB_CA_FILE, `${certs.CLIENT_MOUNT_PATH}/ca.crt`);
  assert.equal(env.DB_USERNAME, book.username);
  assert.ok(out.injected.includes('MYSQL_ATTR_SSL_CA'));
  assert.ok(lines.some((l) => /TLS prepared/.test(l)), lines.join('\n'));
  assert.equal(getDb().prepare('SELECT tls_required FROM managed_databases WHERE id = ?').get(book.id).tls_required, 0);

  const own = { MYSQL_ATTR_SSL_CA: '' };
  const o2 = await deployer.injectManagedDbForEnv({ app, env: 'production', runtimeEnvVars: own, secureLogin: (s, e, o) => mdb.secureLogin(s, e, { ...o, ops }) });
  assert.equal(own.MYSQL_ATTR_SSL_CA, '', 'the app can opt out by setting the variable itself');
  assert.ok(o2.deferred.includes('MYSQL_ATTR_SSL_CA'));

  // Metabase names no CA variable: nothing prepared.
  seedRow(CAT, 'postgres');
  const cenv = {};
  const c = await deployer.injectManagedDbForEnv({ app: getDb().prepare('SELECT * FROM apps WHERE id = ?').get(CAT), env: 'production', runtimeEnvVars: cenv, secureLogin: (s, e, o) => mdb.secureLogin(s, e, { ...o, ops }) });
  assert.equal(c.mounts.length, 0);
  assert.equal(cenv.DB_CA_FILE, undefined);

  const benv = {};
  await deployer.injectManagedDbForEnv({ app, env: 'production', runtimeEnvVars: benv, secureLogin: async () => { throw new Error('server down'); } });
  assert.equal(benv.DB_USERNAME, book.username, 'a prepared (not required) login does not fail closed');
  assert.equal(benv.MYSQL_ATTR_SSL_CA, undefined, 'no CA path without its mount');
});

test('restore: reapplyLoginPolicy re-asserts REQUIRE SSL / the TLS group from the row', async () => {
  const { reapplyLoginPolicy } = await import('../server/services/managedDbBackup.js');
  for (const engine of ['mariadb', 'postgres']) {
    const sent = [];
    await reapplyLoginPolicy({ engine, db_user: 'crane_a9_u', db_name: 'crane_a9', client_cert_required: 0, tls_required: 1, extensions: null },
      { runAdminSql: async (_e, q) => { sent.push(q); return ''; } });
    assert.ok(sent.some((q) => (engine === 'mariadb' ? /REQUIRE SSL/ : new RegExp(`GRANT ${tls.PG_TLS_GROUP} TO "crane_a9_u"`)).test(q)), `${engine}: ${sent.join(' | ')}`);
  }
});
