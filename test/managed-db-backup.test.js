import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import express from 'express';

// Managed-database backup and restore (v2.102.0), without a daemon.
//
// What is pinned here, because each is a way the feature can be wrong while
// every request still returns 200:
//   - a dump names ONE database, the scope's own (incl. the env:sandbox one),
//     and no credential ever appears in argv;
//   - the Postgres restore's SESSION user is the app's own login — not the
//     superuser with --role, which a function in the dump escapes with
//     RESET ROLE (measured against postgres:16-alpine: the --role form
//     created a SUPERUSER role from a CHECK constraint, the -U <app> form
//     did not);
//   - a per-app backup holds only that app's databases, and a restore can only
//     go back into the app (and scope) the dump came from;
//   - the production restore gate covers the DATABASE, including a sandbox
//     backup whose database is the one production shares;
//   - after a restore the login policy (cert group, limits) is re-applied;
//   - the whole-system export carries managed-db/ when contents=full.
//
// Engines are replaced two ways: the engine handles (ensureServer, admin SQL)
// by an `ops` recorder, and the streamed dump/restore commands by a recording
// `docker` shim on PATH.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbbk-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_NO_RESTART_AFTER_IMPORT = '1';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker.log');
const COUNTER = join(process.env.DATA_DIR, 'redis-saves');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const argv = process.argv.slice(2);
let stdin = '';
try { stdin = fs.readFileSync(0); } catch (_) { stdin = Buffer.alloc(0); }
fs.appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, JSON.stringify({ argv, stdinBytes: stdin.length, stdin: stdin.toString('utf8').slice(0, 2000), mysqlPwd: process.env.MYSQL_PWD || null }) + '\\n');
const has = (x) => argv.includes(x);
if (has('INFO')) {
  const n = Number(fs.existsSync(process.env.CRANE_TEST_REDIS_COUNTER) ? fs.readFileSync(process.env.CRANE_TEST_REDIS_COUNTER, 'utf8') : '0') + 1;
  fs.writeFileSync(process.env.CRANE_TEST_REDIS_COUNTER, String(n));
  process.stdout.write('# Persistence\\r\\nrdb_saves:' + n + '\\r\\nrdb_bgsave_in_progress:0\\r\\nrdb_last_bgsave_status:ok\\r\\n');
} else if (has('pg_dump') || has('mariadb-dump') || has('cat') || argv.some((a) => /mongodump/.test(a))) {
  process.stdout.write('FAKE-DUMP ' + argv.join(' '));
}
`, { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = LOG;
process.env.CRANE_TEST_REDIS_COUNTER = COUNTER;
const REAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM_DIR}:${REAL_PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const bk = await import('../server/services/managedDbBackup.js');
const cmd = await import('../server/services/managedDbDumpCmd.js');
const tlsCfg = await import('../server/services/managedDbTls.js');
const { encrypt, generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { SANDBOX_TENANT } = await import('../server/services/sandboxDb.js');
const { errorHandler } = await import('../server/utils/errors.js');

initDb(process.env.DATA_DIR);
const db = getDb();

const ADMIN_PW = 'AdminPw_' + 'x'.repeat(30);
const APP_PW = 'AppPw_' + 'y'.repeat(30);
const ENGINES = ['postgres', 'mariadb', 'mongo', 'redis'];

let slot = 0;
const mkApp = (slug) => Number(db.prepare(
  "INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, ?, 'managed', 'main')",
).run(slug, slug, ++slot).lastInsertRowid);
const A = mkApp('bk-a');
const B = mkApp('bk-b');

function seed(appId, tenant, engine, { cert = false } = {}) {
  const { database, username } = mdb.namesForScope({ appId, tenant });
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc, host_port, container_name, client_cert_required)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(appId, tenant || '', engine, database, username, encrypt(APP_PW),
    engine === 'redis' ? 46379 + appId * 2 + (tenant ? 1 : 0) : null,
    engine === 'redis' ? `x-redis-${database}` : null, cert ? 1 : 0);
  return { database, username };
}
for (const e of ENGINES) {
  seed(A, '', e, { cert: true });
  seed(A, SANDBOX_TENANT, e);
  seed(B, '', e);
}
const nA = mdb.namesForScope({ appId: A });
const nAs = mdb.namesForScope({ appId: A, tenant: SANDBOX_TENANT });
const nB = mdb.namesForScope({ appId: B });

let calls;
function recorder() {
  calls = [];
  return {
    ...mdb.backupAccess,
    ensureServer: async (e) => { calls.push(['ensureServer', e]); },
    runAdminSql: async (e, sql, o) => { calls.push(['sql', e, sql, o?.database || null]); return ''; },
    runAdminMongo: async (s) => { calls.push(['mongo', s]); },
    adminCoordsFor: () => ({ port: 47017, adminPassword: ADMIN_PW }),
    ensureRedisInstance: async (o) => { calls.push(['redis', o]); },
    containerFor: (e) => `x-${e}`,
    redisDataDir: (n) => join(process.env.DATA_DIR, 'managed-db', 'redis', n),
    clientCert: () => ({ certPem: 'CERT\n', keyPem: 'KEY\n' }),
  };
}
const docker = () => (existsSync(LOG) ? readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
beforeEach(() => { rmSync(LOG, { force: true }); });
after(() => {
  process.env.PATH = REAL_PATH;
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

const noSecretIn = (argvs) => {
  for (const a of argvs) {
    const s = a.join(' ');
    assert.ok(!s.includes(ADMIN_PW), `admin password in argv: ${s}`);
    assert.ok(!s.includes(APP_PW), `app password in argv: ${s}`);
  }
};

// ---------------------------------------------------------------------------
// Dump argv: one database, no credential
// ---------------------------------------------------------------------------

test('dump argv per engine names exactly the one database and carries no password', () => {
  const conf = '/tmp/appcrane-mongotool-0123456789abcdef0123.yaml';
  for (const [scope, names] of [[{ appId: A }, nA], [{ appId: A, tenant: SANDBOX_TENANT }, nAs]]) {
    const db_ = names.database;
    const pg = cmd.dumpArgs('postgres', { container: 'c', database: db_ });
    assert.deepEqual(pg.slice(pg.indexOf('pg_dump')), ['pg_dump', '-U', 'postgres', '--no-password', '--format=custom', '-d', db_]);
    const my = cmd.dumpArgs('mariadb', { container: 'c', database: db_ });
    assert.equal(my[my.length - 1], db_, 'mariadb-dump: the database is the one positional argument');
    assert.ok(!my.includes('--all-databases') && !my.includes('-A') && !my.includes('--databases') && !my.includes('-B'),
      'never --all-databases / --databases');
    for (const f of ['--single-transaction', '--routines', '--triggers']) assert.ok(my.includes(f), f);
    const mg = cmd.dumpArgs('mongo', { container: 'c', database: db_, port: 47017, configPath: conf });
    assert.equal(mg[mg.length - 1], db_);
    assert.match(mg[4], /--db "\$3" --archive --gzip/);
    assert.ok(!mg[4].includes(db_), 'the db name reaches the shell as a positional parameter, never as source');
    noSecretIn([pg, my, mg]);
    if (scope.tenant) assert.match(db_, /_sandbox$/);
  }
  assert.throws(() => cmd.dumpArgs('postgres', { container: 'c', database: 'x; DROP' }), /refusing identifier/);
  assert.throws(() => cmd.dumpArgs('mongo', { container: 'c', database: 'crane_a1', port: 1, configPath: '/etc/passwd' }), /refusing config path/);
});

test('dumpScope: a per-app backup contains only that app\'s databases, for that scope', async () => {
  const dir = mkdtempSync(join(process.env.DATA_DIR, 'scope-'));
  const out = await bk.dumpScope({ appId: A, tenant: '' }, dir, 'production-x', { ops: recorder() });
  assert.deepEqual(out.map((d) => [d.engine, d.db_name]).sort(), ENGINES.map((e) => [e, nA.database]).sort());
  for (const d of out) {
    assert.ok(existsSync(d.file) && d.size_bytes > 0);
    const body = readFileSync(d.file, 'utf8');
    assert.ok(!body.includes(nB.database) && !body.includes(nAs.database), `${d.engine} dump touched another scope: ${body}`);
  }
  const argvs = docker().map((c) => c.argv);
  const all = argvs.map((a) => a.join(' ')).join('\n');
  assert.ok(!all.includes(nB.database), 'app B\'s database must not be named by any command of app A\'s backup');
  assert.ok(!all.includes(nAs.database), 'the sandbox database is not part of the production scope');
  noSecretIn(argvs);
  // mongo's password went in on stdin, to the config file, never argv.
  const confWrite = docker().find((c) => c.argv.includes('umask 077 && cat > "$1"'));
  assert.match(confWrite.stdin, /^password: "/);
  assert.ok(docker().some((c) => c.argv.includes('rm') && c.argv.some((a) => a.startsWith('/tmp/appcrane-mongotool-'))), 'config removed');

  rmSync(LOG, { force: true });
  const sb = await bk.dumpScope({ appId: A, tenant: SANDBOX_TENANT }, dir, 'sandbox-x', { ops: recorder() });
  assert.deepEqual([...new Set(sb.map((d) => d.db_name))], [nAs.database]);
  const sball = docker().map((c) => c.argv.join(' ')).join('\n');
  assert.ok(!new RegExp(`${nA.database}(?!_sandbox)`).test(sball), 'a sandbox-scope backup must not dump production');
});

// ---------------------------------------------------------------------------
// Restore: session user, cross-app, policy re-applied
// ---------------------------------------------------------------------------

test('postgres restore: the session user is the app login, never the superuser (-U postgres / --role)', () => {
  const a = cmd.restoreArgs('postgres', { container: 'c', database: nA.database, username: nA.username });
  const pr = a.slice(a.indexOf('pg_restore'));
  assert.equal(pr[pr.indexOf('-U') + 1], nA.username, 'pg_restore -U must be the app login');
  assert.ok(!pr.includes('--role'), '--role leaves the superuser as session user; RESET ROLE escapes it');
  assert.ok(!a.join(' ').includes('-U postgres'));
  assert.equal(pr[pr.indexOf('-d') + 1], `${nA.database}_r`, 'restores into the staging database, not the live one');
  for (const f of ['--no-owner', '--exit-on-error', '--single-transaction']) assert.ok(pr.includes(f), f);
});

test('mariadb and mongo restores also run as the app login, password by env/stdin only', async () => {
  const file = join(process.env.DATA_DIR, 'any.dump');
  writeFileSync(file, 'DUMP');
  for (const engine of ['mariadb', 'mongo']) {
    rmSync(LOG, { force: true });
    const row = db.prepare("SELECT * FROM managed_databases WHERE app_id = ? AND tenant = '' AND engine = ?").get(B, engine);
    await bk.restoreDatabase({ appId: B, tenant: '', engine, expectDbName: row.db_name }, file, { ops: recorder() });
    const load = docker().find((c) => c.stdinBytes === 4);
    assert.ok(load, `${engine}: the dump was streamed on stdin`);
    const s = load.argv.join(' ');
    if (engine === 'mariadb') {
      assert.ok(load.argv.includes(`--user=${row.db_user}`), s);
      assert.ok(load.argv.includes('--no-defaults'), 'root\'s /root/.my.cnf must not be read');
      assert.ok(load.argv.includes('-e') && load.argv.includes('MYSQL_PWD'), 'password forwarded by NAME');
      assert.equal(load.mysqlPwd, APP_PW, 'the app login\'s password reaches docker via env');
      for (const f of ['--sandbox', '--one-database']) assert.ok(load.argv.includes(f), f);
      assert.ok(!s.includes('root'), s);
    } else {
      assert.match(load.argv[5], /--username "\$4" --authenticationDatabase "\$3" --config "\$2\/app\.yaml"/);
      assert.equal(load.argv[load.argv.length - 1], row.db_user);
      assert.ok(!load.argv[5].includes('--username root'), 'mongorestore must not authenticate as root');
      const conf = docker().find((c) => c.argv.includes('app.yaml'));
      assert.equal(conf.stdin, `password: "${APP_PW}"\n`, 'app password via stdin into the scratch config');
    }
    noSecretIn(docker().map((c) => c.argv));
  }
});

test('cross-app restore is refused on the server, before any engine call', async () => {
  const file = join(process.env.DATA_DIR, 'a.dump');
  writeFileSync(file, 'DUMP');
  for (const engine of ENGINES) {
    const ops = recorder();
    await assert.rejects(
      bk.restoreDatabase({ appId: B, tenant: '', engine, expectDbName: nA.database }, file, { ops }),
      (e) => e.code === 'CROSS_APP_RESTORE',
    );
    assert.deepEqual(calls, [], `${engine}: nothing may run for a cross-app restore`);
  }
  assert.deepEqual(docker(), []);
});

test('restore re-applies the login policy (cert group, limits, grants) from the row', async () => {
  const file = join(process.env.DATA_DIR, 'p.dump');
  writeFileSync(file, 'DUMP');
  const ops = recorder();
  await bk.restoreDatabase({ appId: A, tenant: '', engine: 'postgres', expectDbName: nA.database }, file, { ops });
  const sql = calls.filter((c) => c[0] === 'sql').map((c) => c[2]);
  const swapAt = sql.findIndex((s) => s.includes(`ALTER DATABASE "${nA.database}_r" RENAME TO "${nA.database}"`));
  assert.ok(swapAt >= 0, 'the staging database is swapped in');
  const after = sql.slice(swapAt + 1).join('\n');
  assert.match(after, new RegExp(`GRANT ${tlsCfg.PG_CERT_GROUP} TO "${nA.username}";`), 'cert requirement re-asserted after restore');
  assert.match(after, new RegExp(`ALTER ROLE "${nA.username}" CONNECTION LIMIT \\d+;`));
  assert.match(after, new RegExp(`ALTER SCHEMA public OWNER TO "${nA.username}";`));

  for (const engine of ['mariadb', 'mongo', 'redis']) {
    const o = recorder();
    await bk.restoreDatabase({ appId: A, tenant: '', engine, expectDbName: nA.database }, file, { ops: o });
    if (engine === 'mariadb') {
      const s = calls.filter((c) => c[0] === 'sql').map((c) => c[2]).join('\n');
      assert.match(s, new RegExp(`REQUIRE SUBJECT '/CN=${nA.username}'`), 'mariadb cert requirement re-asserted');
      assert.match(s, new RegExp(`ACCOUNT UNLOCK`), 'the login is never left locked');
    }
    if (engine === 'mongo') assert.ok(calls.some((c) => c[0] === 'mongo' && /\$external/.test(c[1])), 'x509 user re-asserted');
    if (engine === 'redis') assert.ok(calls.some((c) => c[0] === 'redis' && c[1].tls === true), 'redis restarted with TLS + ACL');
  }
});

test('mariadb restore ends the _app login\'s open sessions too, before the database is dropped', async () => {
  // Measured on mariadb:11.4: an `_app` session opened before the restore
  // survived it (ACCOUNT LOCK refuses only NEW connections), so it could read
  // the database while it was being reloaded.
  const appUser = `${nA.username}_app`;
  db.prepare("UPDATE managed_databases SET app_user = ?, app_password_enc = ? WHERE app_id = ? AND tenant = '' AND engine = 'mariadb'")
    .run(appUser, encrypt(APP_PW), A);
  try {
    const file = join(process.env.DATA_DIR, 'm.dump');
    writeFileSync(file, 'DUMP');
    const o = recorder();
    o.runAdminSql = async (e, sql, opt) => {
      calls.push(['sql', e, sql, opt?.database || null]);
      if (sql.includes(`USER = '${nA.username}'`)) return 'ID\n11';
      if (sql.includes(`USER = '${appUser}'`)) return 'ID\n22\n23';
      return '';
    };
    await bk.restoreDatabase({ appId: A, tenant: '', engine: 'mariadb', expectDbName: nA.database }, file, { ops: o });
    const sql = calls.filter((c) => c[0] === 'sql').map((c) => c[2]);
    const dropAt = sql.findIndex((s) => s.includes(`DROP DATABASE IF EXISTS \`${nA.database}\``));
    const killed = sql.slice(0, dropAt).join('\n');
    assert.match(killed, /KILL CONNECTION 11;/, 'the owner login\'s session is ended');
    assert.match(killed, /KILL CONNECTION 22;/, 'the _app login\'s sessions are ended too');
    assert.match(killed, /KILL CONNECTION 23;/);
  } finally {
    db.prepare("UPDATE managed_databases SET app_user = NULL, app_password_enc = NULL WHERE app_id = ? AND tenant = '' AND engine = 'mariadb'").run(A);
  }
});

// ---------------------------------------------------------------------------
// Routes: per-app backups, restore gate
// ---------------------------------------------------------------------------

const mkUser = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, name };
};
const OWNER = mkUser('owner');
const APPADMIN = mkUser('appadmin');
const MEMBER = mkUser('member');
const PLATFORM = mkUser('platform', 'platform_admin');
for (const [u, r] of [[OWNER, 'owner'], [APPADMIN, 'admin'], [MEMBER, 'user'], [PLATFORM, 'user']]) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(A, u.id, r);
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(B, u.id, r);
}

const backupRoutes = await import('../server/routes/backups.js');
const settingsRoutes = await import('../server/routes/settings.js');
const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', backupRoutes.default);
  a.use('/api/settings', settingsRoutes.default);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = `http://127.0.0.1:${server.address().port}`;
const call = async (method, path, who, body) => {
  const r = await fetch(base + path, {
    method, headers: { 'x-api-key': who.key, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, body: await r.json().catch(() => null) };
};

/** A backup record as the route writes one, with real files on disk. */
function mkBackup(appId, slug, env, dbs) {
  const dir = join(process.env.DATA_DIR, 'backups', slug);
  mkdirSync(dir, { recursive: true });
  const stamp = Math.random().toString(16).slice(2);
  const tar = join(dir, `${env}-${stamp}.tar.gz`);
  const empty = mkdtempSync(join(process.env.DATA_DIR, 'e-'));
  execFileSync('tar', ['-czf', tar, '-C', empty, '.']);
  const databases = dbs.map(([engine, tenant, dbName]) => {
    const file = join(dir, `${env}-${stamp}.${engine}.dump`);
    writeFileSync(file, 'DUMP');
    return { engine, tenant, db_name: dbName, file, size_bytes: 4 };
  });
  return Number(db.prepare('INSERT INTO backups (app_id, env, size_bytes, file_path, databases) VALUES (?,?,?,?,?)')
    .run(appId, env, 1, tar, databases.length ? JSON.stringify(databases) : null).lastInsertRowid);
}

test('POST backup dumps the env\'s scope into the same record; GET lists it with size', async () => {
  backupRoutes.__setBackupDbOpsForTests(recorder());
  const r = await call('POST', '/api/apps/bk-a/backup/production', MEMBER);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.backup.databases.map((d) => d.engine).sort(), [...ENGINES].sort());
  assert.ok(r.body.backup.databases.every((d) => d.env === 'production' && d.size_bytes > 0));
  const list = await call('GET', '/api/apps/bk-a/backups', MEMBER);
  const row = list.body.backups.find((b) => b.id === Number(r.body.backup.id));
  assert.equal(row.includes_database, true);
  assert.ok(row.databases.every((d) => !('file' in d)), 'no host paths in the API');
  assert.ok(!('file_path' in row) && !JSON.stringify(list.body).includes(process.env.DATA_DIR), 'the backup row carries no host path either');
  const all = docker().map((c) => c.argv.join(' ')).join('\n');
  assert.ok(!all.includes(nB.database));
});

test('restore gate: production database needs the owner or a platform admin; members and app admins are refused', async () => {
  backupRoutes.__setBackupDbOpsForTests(recorder());
  const id = mkBackup(A, 'bk-a', 'production', [['postgres', '', nA.database]]);
  for (const who of [MEMBER, APPADMIN]) {
    const r = await call('POST', `/api/apps/bk-a/restore/${id}`, who, { include_database: true });
    assert.equal(r.status, 403, `${who.name} restored production`);
    // The env gate on its own, without the database gate behind it.
    const f = await call('POST', `/api/apps/bk-a/restore/${id}`, who, { include_database: false });
    assert.equal(f.status, 403, `${who.name} restored production files`);
  }
  assert.deepEqual(calls, [], 'no engine call before the gate');
  for (const who of [OWNER, PLATFORM]) {
    const r = await call('POST', `/api/apps/bk-a/restore/${id}`, who, {});
    assert.equal(r.status, 200, `${who.name}: ${JSON.stringify(r.body)}`);
    assert.deepEqual(r.body.databases_restored.map((d) => d.engine), ['postgres']);
  }
});

test('restore gate: a SANDBOX backup whose database is production\'s shared one is gated as production', async () => {
  backupRoutes.__setBackupDbOpsForTests(recorder());
  const shared = mkBackup(A, 'bk-a', 'sandbox', [['postgres', '', nA.database]]);
  assert.equal((await call('POST', `/api/apps/bk-a/restore/${shared}`, MEMBER, {})).status, 403);
  const filesOnly = await call('POST', `/api/apps/bk-a/restore/${shared}`, MEMBER, { include_database: false });
  assert.equal(filesOnly.status, 200, 'sandbox files alone stay open to members');
  assert.deepEqual(filesOnly.body.databases_restored, []);
  const own = mkBackup(A, 'bk-a', 'sandbox', [['postgres', SANDBOX_TENANT, nAs.database]]);
  const r = await call('POST', `/api/apps/bk-a/restore/${own}`, MEMBER, {});
  assert.equal(r.status, 200, 'the separate sandbox database follows the sandbox rule');
});

test('restore route refuses a record naming another app\'s database (cross-app), before touching anything', async () => {
  backupRoutes.__setBackupDbOpsForTests(recorder());
  const tampered = mkBackup(B, 'bk-b', 'production', [['postgres', '', nA.database]]);
  const r = await call('POST', `/api/apps/bk-b/restore/${tampered}`, OWNER, {});
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'CROSS_APP_RESTORE');
  assert.deepEqual(calls, []);
  // And a backup of A cannot be addressed through B's URL at all.
  const ofA = mkBackup(A, 'bk-a', 'production', [['postgres', '', nA.database]]);
  assert.equal((await call('POST', `/api/apps/bk-b/restore/${ofA}`, OWNER, {})).status, 404);
});

// ---------------------------------------------------------------------------
// Whole-system export + single-database restore from it
// ---------------------------------------------------------------------------

test('export contents=full carries managed-db/<engine>/<db>.dump for every database; platform does not', async () => {
  const { exportDataArchive } = await import('../server/services/configBackup.js');
  const full = await exportDataArchive({ dest: join(process.env.DATA_DIR, 'backups', 'full.tar.gz'), managedDbOps: recorder(), force: true });
  const members = execFileSync('tar', ['-tzf', full.path]).toString().split('\n').filter((m) => /^managed-db\/.+\.dump$/.test(m)).sort();
  const expected = db.prepare('SELECT engine, db_name FROM managed_databases').all().map((r) => `managed-db/${r.engine}/${r.db_name}.dump`).sort();
  assert.deepEqual(members, expected);
  assert.ok(full.manifest.includes.includes('managed-db'));
  assert.equal(full.manifest.managed_db.included, true);
  assert.equal(full.manifest.managed_db.databases.length, expected.length);
  assert.ok(full.manifest.bytes.managed_db > 0);

  const plat = await exportDataArchive({ dest: join(process.env.DATA_DIR, 'backups', 'plat.tar.gz'), contents: 'platform', managedDbOps: recorder(), force: true });
  assert.equal(plat.manifest.managed_db.included, false);
  assert.ok(!execFileSync('tar', ['-tzf', plat.path]).toString().includes('managed-db/'));
});

test('restore-database from an export: platform admin only, and the member is derived from the target app', async () => {
  settingsRoutes.__setRestoreDbOpsForTests(recorder());
  // keep_running: this test is about who may restore and which member is used;
  // stopping the app around a restore is test/managed-db-restore-stop.test.js.
  const body = { archive: 'full.tar.gz', app: 'bk-a', env: 'production', engine: 'postgres', keep_running: true };
  assert.equal((await call('POST', '/api/settings/backup/restore-database', OWNER, body)).status, 403);
  const r = await call('POST', '/api/settings/backup/restore-database', PLATFORM, body);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.db_name, nA.database);
  const sandbox = await call('POST', '/api/settings/backup/restore-database', PLATFORM, { ...body, env: 'sandbox' });
  assert.equal(sandbox.status, 200);
  assert.equal(sandbox.body.db_name, nAs.database);
});
