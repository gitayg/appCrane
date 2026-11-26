import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawnSync, spawn } from 'child_process';

// The "TLS required" level against a REAL postgres:16-alpine and mariadb:11.4,
// through managedDb.requireTls() (the admin route's call) and the deployer.
// Clients are throwaway containers dialling host.docker.internal, as an app
// does; passwords travel in the environment of `docker run` (-e NAME), never
// argv.
//   - a TLS login: refused without TLS, accepted with TLS and the CA only
//     (no client certificate);
//   - another app's login over TLS, with its correct password, still cannot
//     reach this app's database (grants);
//   - strict pg_hba flips when the last password-only Postgres login becomes
//     a TLS login, and the TLS login still gets in under strict;
//   - BookStack's catalogue entry: the deploy mounts the CA and sets
//     MYSQL_ATTR_SSL_CA, and a client pointed at that variable connects.

const PREFIX = `crane-tlsonly-${process.pid}`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tlsonly-real-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
process.env.MANAGED_DB_POSTGRES_PORT = '45719';
process.env.MANAGED_DB_MARIADB_PORT = '43719';
process.env.MANAGED_DB_REDIS_PORT_MIN = '49719';

let dockerOk = false;
try {
  execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' });
  dockerOk = true;
} catch (_) { /* left false */ }
const skip = dockerOk ? false : 'no reachable Docker daemon on this host';

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const po = await import('../server/services/managedDbPasswordOnly.js');
const { managedDbUrl, injectManagedDbForEnv } = await import('../server/services/deployer.js');

let T; let O; let A; let BOOK;
before(() => {
  initDb(process.env.DATA_DIR);
  getDb().prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
  const ins = getDb().prepare('INSERT INTO apps (name, slug, slot, catalog_slug) VALUES (?, ?, ?, ?)');
  T = Number(ins.run('T', 'tlsonly-t', 1, null).lastInsertRowid);
  O = Number(ins.run('O', 'tlsonly-o', 2, null).lastInsertRowid);
  A = Number(ins.run('A', 'tlsonly-a', 3, null).lastInsertRowid);
  BOOK = Number(ins.run('Book', 'tlsonly-book', 4, 'bookstack').lastInsertRowid);
});
after(async () => {
  if (dockerOk) {
    await mdb.stopServer('postgres').catch(() => {});
    await mdb.stopServer('mariadb').catch(() => {});
    for (const e of ['postgres', 'mariadb']) spawnSync('docker', ['rm', '-f', `${PREFIX}-${e}`]);
    const vols = spawnSync('docker', ['volume', 'ls', '-q', '--filter', `name=${PREFIX}`], { encoding: 'utf8' }).stdout.split('\n').filter(Boolean);
    if (vols.length) spawnSync('docker', ['volume', 'rm', '-f', ...vols]);
  }
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

function client(image, mounts, cmd, env) {
  const args = ['run', '--rm', '-i', '--add-host', 'host.docker.internal:host-gateway'];
  for (const k of Object.keys(env)) args.push('-e', k);
  for (const m of mounts) args.push('-v', `${m.host}:${m.container}:ro`);
  args.push('--entrypoint', 'sh', image, '-c', cmd);
  const r = spawnSync('docker', args, { env: { ...process.env, ...env }, encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
}
const psql = (url, mounts = []) => client('postgres:16-alpine', mounts, 'exec psql "$DBURL" -X -q -A -t -c "SELECT current_user"', { DBURL: url });
const last = (r) => JSON.stringify(r.err.split('\n').pop());
const pgUrl = (c, db, q) => `postgresql://${c.username}:${c.password}@${c.host}:${c.port}/${db || c.database}?${q}`;
const pgContainer = `${PREFIX}-postgres`;
const hbaLast = () => execFileSync('docker', ['exec', pgContainer, 'sh', '-c', 'grep -v "^#" /tmp/appcrane-tls/pg_hba.conf | tail -1'], { encoding: 'utf8' }).trim();
const rowId = (appId, engine) => getDb().prepare('SELECT id FROM managed_databases WHERE app_id = ? AND engine = ?').get(appId, engine).id;

test('Postgres: a TLS login is refused without TLS, accepted with TLS and the CA only; another app\'s password over TLS still cannot reach its database', { skip }, async () => {
  // A: a certificate login (as a deployhub.json app). T and O: catalogue-style, password-only.
  await mdb.provision({ appId: A }, 'postgres');
  const group = execFileSync('docker', ['exec', '-u', 'postgres', pgContainer, 'psql', '-X', '-q', '-A', '-t', '-c',
    "SELECT rolname || ':' || rolcanlogin FROM pg_roles WHERE rolname = 'appcrane_tls_required'"], { encoding: 'utf8' }).trim();
  assert.equal(group, 'appcrane_tls_required:false', 'ensureServer creates the TLS group (NOLOGIN) before any login joins it');
  await mdb.secureLogin({ appId: A }, 'postgres', { certRequired: true });
  for (const id of [T, O]) {
    await mdb.provision({ appId: id }, 'postgres');
    await mdb.secureLogin({ appId: id }, 'postgres', { certRequired: false });
  }
  const t = mdb.credentialsFor({ appId: T }, 'postgres');
  const o = mdb.credentialsFor({ appId: O }, 'postgres');
  assert.equal(psql(pgUrl(t, null, 'sslmode=disable')).code, 0, 'precondition: password alone works before');
  assert.match(hbaLast(), /scram-sha-256$/);

  const res = await mdb.requireTls(rowId(T, 'postgres'), { confirmNoConnections: true });
  assert.deepEqual([res.converted, res.level], [true, 'tls']);
  const mounts = (await mdb.secureLogin({ appId: T }, 'postgres', {})).mounts;
  assert.equal(mounts.length, 1);
  assert.deepEqual(readdirSync(mounts[0].host), ['ca.crt'], 'CA only, no client certificate');
  const tlsCreds = mdb.credentialsFor({ appId: T }, 'postgres');
  assert.equal(tlsCreds.tls.caOnly, true);

  const plain = psql(pgUrl(t, null, 'sslmode=disable'));
  console.log(`[real] pg TLS login, no TLS: rc=${plain.code} err=${last(plain)}`);
  assert.notEqual(plain.code, 0);
  assert.match(plain.err, /pg_hba\.conf rejects connection .*no encryption/);

  const url = managedDbUrl(tlsCreds);
  assert.doesNotMatch(url, /sslcert|sslkey/);
  const ok = psql(url, mounts);
  console.log(`[real] pg TLS login, TLS + CA only: rc=${ok.code} out=${JSON.stringify(ok.out)} err=${last(ok)}`);
  assert.equal(ok.code, 0, ok.err);
  assert.equal(ok.out, t.username);

  // O's own correct password, over TLS, aimed at T's database.
  const other = psql(pgUrl(o, t.database, 'sslmode=require'));
  console.log(`[real] pg another app's login over TLS into T's database: rc=${other.code} err=${last(other)}`);
  assert.notEqual(other.code, 0);
  assert.match(other.err, /permission denied for database/);
});

test('Postgres strict: flips when the last password-only login becomes a TLS login; the TLS login still gets in, the superuser does not', { skip }, async () => {
  assert.deepEqual(po.passwordOnlyLogins({ engine: 'postgres' }).map((l) => l.login), [mdb.credentialsFor({ appId: O }, 'postgres').username]);
  assert.match(hbaLast(), /scram-sha-256$/, 'still loose: O is password-only');
  await mdb.requireTls(rowId(O, 'postgres'), { confirmNoConnections: true });
  assert.deepEqual(po.passwordOnlyLogins({ engine: 'postgres' }), []);
  console.log(`[real] last pg_hba line after the last plain login became TLS: ${JSON.stringify(hbaLast())}`);
  assert.match(hbaLast(), /reject$/, 'strict');
  const sync = await mdb.syncPgHba();
  assert.deepEqual([sync.strict, sync.engineRoles], [true, []], 'the engine agrees: no role outside both groups');

  const t = mdb.credentialsFor({ appId: T }, 'postgres');
  const mounts = (await mdb.secureLogin({ appId: T }, 'postgres', {})).mounts;
  const ok = psql(managedDbUrl(t), mounts);
  assert.equal(ok.code, 0, ok.err);
  const admin = getDb().prepare("SELECT admin_password_enc FROM managed_db_servers WHERE engine = 'postgres'").get();
  const { decrypt } = await import('../server/services/encryption.js');
  const su = psql(`postgresql://postgres:${decrypt(admin.admin_password_enc)}@host.docker.internal:${t.port}/postgres?sslmode=require`);
  console.log(`[real] superuser over TLS under strict: rc=${su.code} err=${last(su)}`);
  assert.notEqual(su.code, 0);
  assert.match(su.err, /pg_hba\.conf rejects connection/);
});

test('MariaDB: REQUIRE SSL refuses plain, accepts TLS with the CA only; another app\'s password over TLS gets no access to this database', { skip }, async () => {
  for (const id of [T, O]) {
    await mdb.provision({ appId: id }, 'mariadb');
    await mdb.secureLogin({ appId: id }, 'mariadb', { certRequired: false });
  }
  await mdb.measureLoginTls(rowId(T, 'mariadb'), { reset: true });
  await mdb.requireTls(rowId(T, 'mariadb'), { confirmNoConnections: true });
  const t = mdb.credentialsFor({ appId: T }, 'mariadb');
  const o = mdb.credentialsFor({ appId: O }, 'mariadb');
  const mounts = (await mdb.secureLogin({ appId: T }, 'mariadb', {})).mounts;
  const my = (c, db, extra, m = []) => client('mariadb:11.4', m,
    `exec mariadb --host=host.docker.internal --port=${c.port} --user=${c.username} ${extra} -N -e "SELECT CURRENT_USER()" ${db}`,
    { MYSQL_PWD: c.password });

  const plain = my(t, t.database, '--skip-ssl');
  console.log(`[real] mariadb TLS login, no TLS: rc=${plain.code} err=${last(plain)}`);
  assert.notEqual(plain.code, 0);
  assert.match(plain.err, /Access denied/);
  const ok = my(t, t.database, `--ssl --ssl-verify-server-cert --ssl-ca=${t.tls.ca}`, mounts);
  console.log(`[real] mariadb TLS login, TLS + CA only: rc=${ok.code} out=${JSON.stringify(ok.out)} err=${last(ok)}`);
  assert.equal(ok.code, 0, ok.err);
  assert.match(ok.out, new RegExp(`^${t.username}@`));
  const other = my(o, t.database, '--ssl');
  console.log(`[real] mariadb another app's login over TLS into T's database: rc=${other.code} err=${last(other)}`);
  assert.notEqual(other.code, 0);
  assert.match(other.err, /Access denied for user .* to database/);
});

test('BookStack: the deploy mounts the CA and sets MYSQL_ATTR_SSL_CA; a client using that variable gets in, the same client without TLS does not', { skip }, async () => {
  await mdb.provision({ appId: BOOK }, 'mariadb');
  await mdb.measureLoginTls(rowId(BOOK, 'mariadb'), { reset: true });
  await mdb.requireTls(rowId(BOOK, 'mariadb'), { confirmNoConnections: true });
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(BOOK);
  const env = {};
  const out = await injectManagedDbForEnv({ app, env: 'production', runtimeEnvVars: env });
  console.log(`[real] bookstack env keys: ${Object.keys(env).sort().join(',')}; mounts=${JSON.stringify(out.mounts.map((m) => m.container))}`);
  assert.equal(out.mounts.length, 1);
  assert.equal(env.MYSQL_ATTR_SSL_CA, '/run/appcrane/db/ca.crt');
  const pick = ['DB_HOST', 'DB_PORT', 'DB_DATABASE', 'DB_USERNAME', 'MYSQL_ATTR_SSL_CA'];
  const vars = Object.fromEntries(pick.map((k) => [k, env[k]]));
  const run = (flags) => client('mariadb:11.4', out.mounts,
    `exec mariadb --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USERNAME" ${flags} -N -e "SELECT CURRENT_USER()" "$DB_DATABASE"`,
    { ...vars, MYSQL_PWD: env.DB_PASSWORD });
  const ok = run('--ssl --ssl-verify-server-cert --ssl-ca="$MYSQL_ATTR_SSL_CA"');
  console.log(`[real] bookstack-style client with MYSQL_ATTR_SSL_CA: rc=${ok.code} out=${JSON.stringify(ok.out)} err=${last(ok)}`);
  assert.equal(ok.code, 0, ok.err);
  const plain = run('--skip-ssl');
  assert.notEqual(plain.code, 0);
});

// A client container that holds one connection open for `seconds`.
function holdPg(url, seconds) {
  const child = spawn('docker', ['run', '--rm', '-e', 'DBURL', '--add-host', 'host.docker.internal:host-gateway',
    '--entrypoint', 'sh', 'postgres:16-alpine', '-c', `exec psql "$DBURL" -X -q -c "SELECT pg_sleep(${seconds})"`],
  { env: { ...process.env, DBURL: url }, stdio: 'ignore' });
  return new Promise((r) => child.on('exit', r));
}
async function waitForConnections(id, n) {
  for (let i = 0; i < 60; i++) {
    const c = await mdb.measureLoginTls(id);
    if (c.connections >= n) return c;
    await new Promise((r) => setTimeout(r, 500));
  }
  return mdb.measureLoginTls(id);
}

test('Postgres: revert puts a TLS login back on its password (strict loosens); the TLS check reads pg_stat_ssl and gates Require TLS', { skip, timeout: 180000 }, async () => {
  const id = rowId(O, 'postgres');
  const o = mdb.credentialsFor({ appId: O }, 'postgres');
  assert.notEqual(psql(pgUrl(o, null, 'sslmode=disable')).code, 0, 'precondition: TLS required');
  const rv = await mdb.revertTls(id);
  assert.equal(rv.reverted, true);
  console.log(`[real] last pg_hba line after revert: ${JSON.stringify(hbaLast())}`);
  assert.match(hbaLast(), /scram-sha-256$/, 'a password-only login again: strict loosens');
  const plainOk = psql(pgUrl(o, null, 'sslmode=disable'));
  assert.equal(plainOk.code, 0, plainOk.err);

  const plainHeld = holdPg(pgUrl(o, null, 'sslmode=disable'), 6);
  const c1 = await waitForConnections(id, 1);
  console.log(`[real] pg check with a plain connection open: ${JSON.stringify({ connections: c1.connections, tls: c1.tls, plain: c1.plain })}`);
  assert.deepEqual([c1.connections, c1.tls, c1.plain], [1, 0, 1]);
  await assert.rejects(mdb.requireTls(id, { confirmNoConnections: true }), (e) => e.code === 'TLS_PLAIN_CONNECTIONS');
  assert.equal(getDb().prepare('SELECT tls_required FROM managed_databases WHERE id = ?').get(id).tls_required, 0);
  await plainHeld;

  const tlsHeld = holdPg(pgUrl(o, null, 'sslmode=require'), 6);
  const c2 = await waitForConnections(id, 1);
  console.log(`[real] pg check with a TLS connection open: ${JSON.stringify({ connections: c2.connections, tls: c2.tls, plain: c2.plain })}`);
  assert.deepEqual([c2.connections, c2.tls, c2.plain], [1, 1, 0]);
  const conv = await mdb.requireTls(id);
  assert.equal(conv.level, 'tls');
  await tlsHeld;
  assert.notEqual(psql(pgUrl(o, null, 'sslmode=disable')).code, 0);
});

test('MariaDB: revert is REQUIRE NONE; plain gets in again', { skip }, async () => {
  const id = rowId(T, 'mariadb');
  const t = mdb.credentialsFor({ appId: T }, 'mariadb');
  const my = (extra) => client('mariadb:11.4', [], `exec mariadb --host=host.docker.internal --port=${t.port} --user=${t.username} ${extra} -N -e "SELECT CURRENT_USER()" ${t.database}`, { MYSQL_PWD: t.password });
  assert.notEqual(my('--skip-ssl').code, 0, 'precondition');
  assert.equal((await mdb.revertTls(id)).reverted, true);
  const ok = my('--skip-ssl');
  console.log(`[real] mariadb plain after revert: rc=${ok.code} out=${JSON.stringify(ok.out)}`);
  assert.equal(ok.code, 0, ok.err);
});
