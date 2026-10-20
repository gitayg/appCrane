import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawnSync } from 'child_process';

// The deployhub.json database options against a REAL postgres:16-alpine,
// through the same functions the deployer calls:
//   - the `_app` login can INSERT/SELECT, cannot CREATE TABLE, and reads a
//     table the owner creates later (DEFAULT PRIVILEGES);
//   - production's sandbox URL connects to the sandbox database over TLS with
//     the copied client certificate;
//   - pg_stat_statements: the raw view leaks other databases' rows (the
//     "before"), the filtered function does not (the "after");
//   - a dump/restore round trip keeps all of the above.
// Clients run as throwaway psql containers that dial host.docker.internal,
// exactly as an app container does. Credentials reach them through the
// environment of `docker run` (`-e NAME` forwards by name), never argv.

const PREFIX = `crane-applogin-${process.pid}`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-applogin-real-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
process.env.MANAGED_DB_POSTGRES_PORT = '45633';

let dockerOk = false;
try {
  execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' });
  dockerOk = true;
} catch (_) { /* left false */ }
const skip = dockerOk ? false : 'no reachable Docker daemon on this host';

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const { SANDBOX_TENANT } = await import('../server/services/sandboxDb.js');
const { setManagedDbSettings } = await import('../server/services/managedDbSettings.js');
const { managedDbUrl } = await import('../server/services/deployer.js');
const bk = await import('../server/services/managedDbBackup.js');

let A; let B; let C;
before(() => {
  initDb(process.env.DATA_DIR);
  // This file exercises a real daemon, not memory admission (test/memory-admission.test.js); a busy
  // Docker host must not refuse its containers.
  getDb().prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
  const ins = getDb().prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)');
  A = Number(ins.run('A', 'app-a', 1).lastInsertRowid);
  B = Number(ins.run('B', 'app-b', 2).lastInsertRowid);
  C = Number(ins.run('C', 'app-c', 3).lastInsertRowid);
  setManagedDbSettings(getDb(), { pg_stat_statements: 1 });
});
after(async () => {
  if (dockerOk) await mdb.stopServer('postgres').catch(() => {});
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

/**
 * psql as an app would connect: the client certificate directory mounted
 * read-only, copied to the same path with the key at 0600 (libpq refuses a
 * 0444 key; node-postgres does not check), then `psql "$DBURL"`.
 */
function psql(dbUrl, mounts, sql) {
  const args = ['run', '--rm', '-i', '--add-host', 'host.docker.internal:host-gateway', '-e', 'DBURL'];
  const copies = [];
  mounts.forEach((m, i) => {
    args.push('-v', `${m.host}:/mnt/c${i}:ro`);
    copies.push(`mkdir -p ${m.container} && cp /mnt/c${i}/* ${m.container}/ && chmod 600 ${m.container}/*.key`);
  });
  const script = [...copies, 'exec psql "$DBURL" -X -q -A -t -v ON_ERROR_STOP=1 -f -'].join(' && ');
  args.push('--entrypoint', 'sh', 'postgres:16-alpine', '-c', script);
  const r = spawnSync('docker', args, { input: sql, env: { ...process.env, DBURL: dbUrl }, encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
}

let prodOwner; let prodApp; let peer; let ownerMounts;

test('setup: three apps, certificate-required owners, A with an _app login and pg_stat_statements', { skip }, async () => {
  for (const id of [A, B, C]) {
    await mdb.provision({ appId: id }, 'postgres');
    const s = await mdb.secureLogin({ appId: id }, 'postgres', { certRequired: true });
    if (id === A) ownerMounts = s.mounts;
  }
  await mdb.provision({ appId: A, tenant: SANDBOX_TENANT }, 'postgres');
  await mdb.secureLogin({ appId: A, tenant: SANDBOX_TENANT }, 'postgres', { certRequired: true });
  prodOwner = { ...mdb.credentialsFor({ appId: A }, 'postgres') };
  prodApp = await mdb.ensureAppLogin({ appId: A }, 'postgres', {});
  const ext = await mdb.ensurePgExtensions({ appId: A }, { extensions: ['pg_stat_statements'] });
  assert.equal(ext.preloaded, true);
  peer = await mdb.sandboxPeerAccess(A, 'postgres', {});
  assert.ok(prodApp && peer);
});

test('the _app login: INSERT/SELECT yes, CREATE TABLE no, owner-created-later table readable', { skip }, async () => {
  const own = psql(managedDbUrl(prodOwner), ownerMounts, 'CREATE TABLE items(id serial PRIMARY KEY, name text);');
  assert.equal(own.code, 0, own.err);

  const dml = psql(managedDbUrl(prodApp.creds), prodApp.mounts,
    "INSERT INTO items(name) VALUES ('one'); SELECT current_user || ' ' || count(*) FROM items;");
  console.log(`[real] app login INSERT+SELECT: rc=${dml.code} out=${JSON.stringify(dml.out)} err=${JSON.stringify(dml.err)}`);
  assert.equal(dml.code, 0, dml.err);
  assert.equal(dml.out, `${prodApp.creds.username} 1`);

  const ddl = psql(managedDbUrl(prodApp.creds), prodApp.mounts, 'CREATE TABLE evil(x int);');
  console.log(`[real] app login CREATE TABLE: rc=${ddl.code} err=${JSON.stringify(ddl.err)}`);
  assert.notEqual(ddl.code, 0);
  assert.match(ddl.err, /permission denied for schema public/);

  const drop = psql(managedDbUrl(prodApp.creds), prodApp.mounts, 'DROP TABLE items;');
  console.log(`[real] app login DROP TABLE: rc=${drop.code} err=${JSON.stringify(drop.err)}`);
  assert.match(drop.err, /must be owner of table items/);

  const later = psql(managedDbUrl(prodOwner), ownerMounts, "CREATE TABLE later(v text); INSERT INTO later VALUES ('from-owner');");
  assert.equal(later.code, 0, later.err);
  const read = psql(managedDbUrl(prodApp.creds), prodApp.mounts, 'SELECT v FROM later;');
  console.log(`[real] app login reads owner's later table: rc=${read.code} out=${JSON.stringify(read.out)} err=${JSON.stringify(read.err)}`);
  assert.equal(read.code, 0, read.err);
  assert.equal(read.out, 'from-owner');

  const plain = psql(managedDbUrl({ ...prodApp.creds, tls: null }).replace(/\?.*$/, '') + '?sslmode=disable', [], 'SELECT 1;');
  console.log(`[real] app login without TLS/cert: rc=${plain.code} err=${JSON.stringify(plain.err.split('\n').pop())}`);
  assert.notEqual(plain.code, 0, 'the app login must require TLS + its certificate');
});

test('production\'s SANDBOX_DATABASE_URL reaches the sandbox database over TLS with the copied certificate', { skip }, async () => {
  const r = psql(managedDbUrl(peer.creds), peer.mounts,
    "SELECT current_database() || ' ' || current_user || ' ssl=' || ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();");
  console.log(`[real] SANDBOX_DATABASE_URL: rc=${r.code} out=${JSON.stringify(r.out)} err=${JSON.stringify(r.err)}`);
  assert.equal(r.code, 0, r.err);
  const sand = mdb.namesForScope({ appId: A, tenant: SANDBOX_TENANT });
  assert.equal(r.out, `${sand.database} ${sand.username} ssl=true`);
  const noCert = psql(managedDbUrl(peer.creds).replace(/&sslcert=[^&]*&sslkey=[^&]*/, ''), [{ host: peer.mounts[0].host, container: '/run/appcrane/db-sandbox' }], 'SELECT 1;');
  console.log(`[real] sandbox login without client cert: rc=${noCert.code} err=${JSON.stringify(noCert.err.split('\n').pop())}`);
  assert.notEqual(noCert.code, 0);
});

test('pg_stat_statements: the raw view leaks other databases (before); the filtered function does not (after)', { skip }, async () => {
  const bCreds = mdb.credentialsFor({ appId: B }, 'postgres');
  const bMounts = (await mdb.secureLogin({ appId: B }, 'postgres', { certRequired: true })).mounts;
  const secret = 'b-secret-literal-7731';
  const bq = psql(managedDbUrl(bCreds), bMounts, `CREATE TABLE s(v text); SELECT count(*) FROM s WHERE v = '${secret}';`);
  assert.equal(bq.code, 0, bq.err);
  const aq = psql(managedDbUrl(prodApp.creds), prodApp.mounts, "SELECT count(*) FROM items WHERE name = 'a-own-literal';");
  assert.equal(aq.code, 0, aq.err);

  // BEFORE: what the extension does with its default grants. App C's database
  // gets it raw, by the superuser, exactly as a naive "CREATE EXTENSION for
  // the app" would — then C's own login reads it.
  const cNames = mdb.namesForScope({ appId: C });
  await mdb.backupAccess.runAdminSql('postgres', 'CREATE EXTENSION pg_stat_statements;', { database: cNames.database });
  const cCreds = mdb.credentialsFor({ appId: C }, 'postgres');
  const cMounts = (await mdb.secureLogin({ appId: C }, 'postgres', { certRequired: true })).mounts;
  const before_ = psql(managedDbUrl(cCreds), cMounts,
    "SELECT count(*) FILTER (WHERE dbid <> (SELECT oid FROM pg_database WHERE datname = current_database())) || ' other-db rows, '"
    + " || count(DISTINCT dbid) || ' dbids, ' || count(*) FILTER (WHERE query = '<insufficient privilege>') || ' hidden-text rows' FROM pg_stat_statements;");
  console.log(`[real] BEFORE (raw view, default grants) as app C: ${before_.out} ${before_.err}`);
  assert.equal(before_.code, 0, before_.err);
  assert.match(before_.out, /^[1-9]\d* other-db rows/, 'the raw view is expected to leak other databases\' rows');

  // AppCrane's own CREATE/ALTER ROLE ... PASSWORD statements are not recorded
  // (track_utility off for the admin sessions), as the superuser sees it.
  const pwRows = await mdb.backupAccess.runAdminSql('postgres',
    "COPY (SELECT count(*) FROM pg_stat_statements WHERE query ILIKE '%password%') TO STDOUT;", { database: cNames.database });
  console.log(`[real] statements recorded with a PASSWORD literal (superuser view): ${pwRows}`);
  assert.equal(pwRows, '0');

  // AFTER: app A, through what AppCrane installed.
  const raw = psql(managedDbUrl(prodApp.creds), prodApp.mounts, 'SELECT count(*) FROM appcrane_stats.pg_stat_statements;');
  console.log(`[real] AFTER app A raw view: rc=${raw.code} err=${JSON.stringify(raw.err)}`);
  assert.notEqual(raw.code, 0);
  assert.match(raw.err, /permission denied for (schema appcrane_stats|view pg_stat_statements)/);

  const fq = "SELECT count(*) || ' rows, ' || count(*) FILTER (WHERE dbid <> (SELECT oid FROM pg_database WHERE datname = current_database())) || ' other-db, '"
    + " || count(*) FILTER (WHERE userid NOT IN (SELECT oid FROM pg_roles WHERE rolname IN (current_user, '" + prodOwner.username + "', '" + prodApp.creds.username + "'))) || ' other-user, '"
    + " || count(*) FILTER (WHERE query LIKE '%" + secret + "%') || ' with B text, '"
    + " || count(*) FILTER (WHERE query LIKE '%FROM items WHERE name%') || ' own-text' FROM appcrane_stats.app_stat_statements();";
  for (const [who, creds, mounts] of [['app login', prodApp.creds, prodApp.mounts], ['owner', prodOwner, ownerMounts]]) {
    const f = psql(managedDbUrl(creds), mounts, fq);
    console.log(`[real] AFTER app A ${who} via app_stat_statements(): ${f.out} ${f.err}`);
    assert.equal(f.code, 0, f.err);
    const [, total, otherDb, otherUser, bText, ownText] = f.out.match(/^(\d+) rows, (\d+) other-db, (\d+) other-user, (\d+) with B text, (\d+) own-text$/);
    assert.ok(Number(total) > 0, 'A sees its own statements');
    assert.equal(otherDb, '0', 'A sees another database\'s rows');
    assert.equal(otherUser, '0', 'A sees another login\'s rows');
    assert.equal(bText, '0');
    assert.ok(Number(ownText) > 0, 'A sees its own query text');
  }
  const reset = psql(managedDbUrl(prodApp.creds), prodApp.mounts, 'SELECT appcrane_stats.app_stat_statements_reset();');
  assert.match(reset.err, /permission denied for function app_stat_statements_reset/, 'reset is the owner login\'s only');
});

test('a dump/restore round trip keeps the app login\'s grants and the stats function, and still no DDL', { skip }, async () => {
  const row = mdb.backupAccess.rowFor({ appId: A }, 'postgres');
  const file = join(process.env.DATA_DIR, 'a.dump');
  await bk.dumpDatabase(row, file);
  await bk.restoreDatabase({ appId: A, tenant: '', engine: 'postgres', expectDbName: row.db_name }, file);
  const r = psql(managedDbUrl(prodApp.creds), prodApp.mounts,
    "INSERT INTO items(name) VALUES ('after-restore'); SELECT count(*) FROM items; SELECT count(*) > 0 FROM appcrane_stats.app_stat_statements();");
  console.log(`[real] after restore, app login: rc=${r.code} out=${JSON.stringify(r.out)} err=${JSON.stringify(r.err)}`);
  assert.equal(r.code, 0, r.err);
  const ddl = psql(managedDbUrl(prodApp.creds), prodApp.mounts, 'CREATE TABLE evil(x int);');
  assert.match(ddl.err, /permission denied for schema public/);
});
