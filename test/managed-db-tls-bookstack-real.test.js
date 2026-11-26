import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import { execFileSync, spawnSync } from 'child_process';

// "Prepare TLS" -> "Require TLS" -> "Revert to password" with the REAL
// linuxserver/bookstack image against a REAL mariadb:11.4 that AppCrane's own
// code starts (managedDb.provision), wired the way a deploy wires it
// (deployer.injectManagedDbForEnv: the CA mount and MYSQL_ATTR_SSL_CA):
//   1. not converted, the deploy hands BookStack the CA; the engine's own
//      counters show BookStack's connections (its migrations and its pages,
//      through php-fpm) use TLS;
//   2. Require TLS is allowed by that measurement and applies REQUIRE SSL;
//      BookStack still serves /login (200, and the page reads the database),
//      and a client without TLS is refused;
//   3. Revert to password: the client without TLS gets in again.
// The image is pinned by digest. It is ~300 MB and takes a minute to start,
// so the test runs only with APPCRANE_LIVE_BOOKSTACK=1; it then pulls the
// pinned image if it is missing.

const BOOKSTACK_IMAGE = 'lscr.io/linuxserver/bookstack@sha256:2ab643f9bce3e29b3347b595e369977eea3a40cef72d887fce635faf1cea3abc';
const PREFIX = `crane-tlsbook-${process.pid}`;
const BOOK_CONTAINER = `${PREFIX}-bookstack`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tlsbook-real-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
process.env.MANAGED_DB_POSTGRES_PORT = '45721';
process.env.MANAGED_DB_MARIADB_PORT = '43721';
process.env.MANAGED_DB_REDIS_PORT_MIN = '49721';

let skip = process.env.APPCRANE_LIVE_BOOKSTACK === '1' ? false : 'set APPCRANE_LIVE_BOOKSTACK=1 to run the real BookStack image';
if (!skip) {
  try {
    execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' });
  } catch (_) { skip = 'no reachable Docker daemon on this host'; }
}

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const { injectManagedDbForEnv } = await import('../server/services/deployer.js');

let BOOK;
before(() => {
  initDb(process.env.DATA_DIR);
  getDb().prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
  BOOK = Number(getDb().prepare('INSERT INTO apps (name, slug, slot, catalog_slug) VALUES (?, ?, ?, ?)')
    .run('Book', 'tlsbook', 1, 'bookstack').lastInsertRowid);
});
after(async () => {
  if (!skip) {
    spawnSync('docker', ['rm', '-f', BOOK_CONTAINER, `${BOOK_CONTAINER}-bogus`]);
    await mdb.stopServer('mariadb').catch(() => {});
    spawnSync('docker', ['rm', '-f', `${PREFIX}-mariadb`]);
    const vols = spawnSync('docker', ['volume', 'ls', '-q', '--filter', `name=${PREFIX}`], { encoding: 'utf8' }).stdout.split('\n').filter(Boolean);
    if (vols.length) spawnSync('docker', ['volume', 'rm', '-f', ...vols]);
  }
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const last = (s) => JSON.stringify(String(s || '').trim().split('\n').pop());

function plainClient(env, flags) {
  const r = spawnSync('docker', ['run', '--rm', '--add-host', 'host.docker.internal:host-gateway',
    '-e', 'DB_HOST', '-e', 'DB_PORT', '-e', 'DB_USERNAME', '-e', 'DB_DATABASE', '-e', 'MYSQL_PWD',
    '--entrypoint', 'sh', 'mariadb:11.4', '-c',
    `exec mariadb --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USERNAME" ${flags} -N -e "SELECT CURRENT_USER()" "$DB_DATABASE"`],
  { env: { ...process.env, DB_HOST: env.DB_HOST, DB_PORT: env.DB_PORT, DB_USERNAME: env.DB_USERNAME, DB_DATABASE: env.DB_DATABASE, MYSQL_PWD: env.DB_PASSWORD }, encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
}

async function getLogin(port) {
  const r = await fetch(`http://127.0.0.1:${port}/login`, { redirect: 'manual' });
  return { status: r.status, body: await r.text() };
}

test('BookStack (real image): prepared CA -> connections measured as TLS -> REQUIRE SSL keeps /login at 200 and refuses plain -> revert', { skip, timeout: 600000 }, async (t) => {
  const t0 = Date.now();
  if (spawnSync('docker', ['image', 'inspect', BOOKSTACK_IMAGE]).status !== 0) {
    const pull = spawnSync('docker', ['pull', BOOKSTACK_IMAGE], { encoding: 'utf8', timeout: 360000 });
    assert.equal(pull.status, 0, pull.stderr);
  }
  await mdb.provision({ appId: BOOK }, 'mariadb');
  const row = getDb().prepare("SELECT id, tls_required FROM managed_databases WHERE app_id = ? AND engine = 'mariadb'").get(BOOK);
  assert.equal(row.tls_required, 0);

  // Phase 1: the deploy prepares TLS on an unconverted login.
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(BOOK);
  const env = {};
  const lines = [];
  const out = await injectManagedDbForEnv({ app, env: 'production', runtimeEnvVars: env, appendLog: (l) => lines.push(l) });
  console.log(`[real] deploy log: ${JSON.stringify(lines)}`);
  assert.equal(out.mounts.length, 1);
  assert.equal(env.MYSQL_ATTR_SSL_CA, '/run/appcrane/db/ca.crt');

  // Reachability: a container must reach the managed server the way the app
  // will (host.docker.internal via host-gateway); skip with the reason if not.
  const probe = plainClient(env, '--ssl --skip-ssl-verify-server-cert');
  if (probe.code !== 0 && /Can't connect|Unknown server host/.test(probe.err)) {
    t.skip(`containers cannot reach the host here: ${last(probe.err)}`);
    return;
  }
  assert.equal(probe.code, 0, `precondition: the login works (TLS, no verify) ${probe.err}`);
  const plainBefore = plainClient(env, '--skip-ssl');
  console.log(`[real] plain client before Require TLS: rc=${plainBefore.code} out=${JSON.stringify(plainBefore.out)}`);
  assert.equal(plainBefore.code, 0, 'the engine still accepts plain before Require TLS');

  const started = await mdb.measureLoginTls(row.id, { reset: true });
  assert.equal(started.measured, true, JSON.stringify(started));

  const appKey = `base64:${crypto.randomBytes(32).toString('base64')}`;
  const names = ['DB_HOST', 'DB_PORT', 'DB_DATABASE', 'DB_USERNAME', 'DB_PASSWORD', 'MYSQL_ATTR_SSL_CA'];
  const runArgs = ['run', '-d', '--name', BOOK_CONTAINER, '--add-host', 'host.docker.internal:host-gateway',
    '-p', '127.0.0.1::80', '-e', 'APP_KEY', '-e', 'APP_URL', '-e', 'PUID', '-e', 'PGID', '-e', 'TZ',
    ...names.flatMap((k) => ['-e', k]),
    ...out.mounts.map((m) => ['-v', `${m.host}:${m.container}:ro`]).flat(),
    BOOKSTACK_IMAGE];
  const childEnv = { ...process.env, APP_KEY: appKey, APP_URL: 'http://127.0.0.1', PUID: '1000', PGID: '1000', TZ: 'Etc/UTC', ...Object.fromEntries(names.map((k) => [k, env[k]])) };
  const run = spawnSync('docker', runArgs, { env: childEnv, encoding: 'utf8', timeout: 120000 });
  assert.equal(run.status, 0, run.stderr);
  const hostPort = execFileSync('docker', ['port', BOOK_CONTAINER, '80/tcp'], { encoding: 'utf8' }).trim().split('\n')[0].split(':').pop();

  let page = null;
  for (let i = 0; i < 120; i++) {
    try { page = await getLogin(hostPort); if (page.status === 200) break; } catch (_) { /* not up yet */ }
    await sleep(2000);
  }
  const logs = () => spawnSync('docker', ['logs', '--tail', '40', BOOK_CONTAINER], { encoding: 'utf8' });
  if (page?.status !== 200) console.log(logs().stdout, logs().stderr);
  console.log(`[real] bookstack up after ${Math.round((Date.now() - t0) / 1000)}s: /login ${page?.status}`);
  assert.equal(page?.status, 200);
  assert.match(page.body, /<form[^>]+action="[^"]*\/login"/, 'the real login page');
  for (let i = 0; i < 3; i++) assert.equal((await getLogin(hostPort)).status, 200);

  const measured = await mdb.measureLoginTls(row.id);
  console.log(`[real] engine check after BookStack started (since the baseline): ${JSON.stringify({ connections: measured.connections, tls: measured.tls, plain: measured.plain, open_unclassified: measured.open_unclassified })}`);
  assert.equal(measured.measured, true);
  assert.ok(measured.connections > 0, 'BookStack connected (migrations and pages)');
  assert.equal(measured.plain, 0, 'every BookStack connection used TLS');

  // One page request opens its own connection, over TLS.
  const before1 = await mdb.measureLoginTls(row.id);
  assert.equal((await getLogin(hostPort)).status, 200);
  const after1 = await mdb.measureLoginTls(row.id);
  console.log(`[real] one /login request: connections ${before1.connections} -> ${after1.connections}, tls ${before1.tls} -> ${after1.tls}`);
  assert.ok(after1.connections > before1.connections, '/login reads the database');
  assert.equal(after1.plain, 0);

  // Phase 2: allowed by the measurement, no "no connections" confirm needed.
  const conv = await mdb.requireTls(row.id);
  assert.deepEqual([conv.converted, conv.level], [true, 'tls']);
  const grants = execFileSync('docker', ['exec', `${PREFIX}-mariadb`, 'mariadb', '--batch', '-N', '-e',
    `SHOW CREATE USER '${env.DB_USERNAME}'@'%'`], { encoding: 'utf8' }).trim();
  console.log(`[real] after Require TLS: ${JSON.stringify(grants.replace(/PASSWORD '[^']*'/, "PASSWORD '<redacted>'"))}`);
  assert.match(grants, /REQUIRE SSL/);
  for (let i = 0; i < 3; i++) {
    const p = await getLogin(hostPort);
    assert.equal(p.status, 200, 'BookStack keeps serving under REQUIRE SSL');
  }
  const underRequire = await mdb.measureLoginTls(row.id);
  assert.ok(underRequire.connections > after1.connections, 'and its new connections reached the engine');
  assert.equal(underRequire.plain, 0);
  const plainRefused = plainClient(env, '--skip-ssl');
  console.log(`[real] plain client under REQUIRE SSL: rc=${plainRefused.code} err=${last(plainRefused.err)}`);
  assert.notEqual(plainRefused.code, 0);
  assert.match(plainRefused.err, /Access denied/);

  // Measured, not asserted: does BookStack's PDO verify the server against
  // the CA it is given? A second BookStack handed an unrelated CA.
  const bogusDir = mkdtempSync(join(tmpdir(), 'crane-tlsbook-bogus-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=unrelated-ca',
      '-keyout', join(bogusDir, 'k.pem'), '-out', join(bogusDir, 'ca.crt')], { stdio: 'pipe' });
    chmodSync(join(bogusDir, 'ca.crt'), 0o444);
    const bogusArgs = runArgs.map((a) => (a === BOOK_CONTAINER ? `${BOOK_CONTAINER}-bogus` : a))
      .map((a) => (a === `${out.mounts[0].host}:${out.mounts[0].container}:ro` ? `${bogusDir}:${out.mounts[0].container}:ro` : a));
    assert.equal(spawnSync('docker', bogusArgs, { env: childEnv, encoding: 'utf8', timeout: 120000 }).status, 0);
    const bogusPort = execFileSync('docker', ['port', `${BOOK_CONTAINER}-bogus`, '80/tcp'], { encoding: 'utf8' }).trim().split('\n')[0].split(':').pop();
    let bogus = null;
    for (let i = 0; i < 60; i++) {
      try { bogus = await getLogin(bogusPort); if (bogus.status !== 502) break; } catch (_) { /* not up yet */ }
      await sleep(2000);
    }
    console.log(`[real] BookStack given an unrelated CA, under REQUIRE SSL: /login ${bogus?.status} (200 would mean PDO does not verify the server)`);
  } finally {
    spawnSync('docker', ['rm', '-f', `${BOOK_CONTAINER}-bogus`]);
    rmSync(bogusDir, { recursive: true, force: true });
  }

  // Revert to password.
  const rv = await mdb.revertTls(row.id);
  assert.equal(rv.reverted, true);
  assert.equal(getDb().prepare('SELECT tls_required FROM managed_databases WHERE id = ?').get(row.id).tls_required, 0);
  const plainAgain = plainClient(env, '--skip-ssl');
  console.log(`[real] plain client after revert: rc=${plainAgain.code} out=${JSON.stringify(plainAgain.out)}`);
  assert.equal(plainAgain.code, 0, plainAgain.err);
  assert.equal((await getLogin(hostPort)).status, 200);
  console.log(`[real] total ${Math.round((Date.now() - t0) / 1000)}s`);
});
