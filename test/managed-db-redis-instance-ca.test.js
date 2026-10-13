import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Two Redis gaps, without a daemon:
//
//   1. Each per-scope Redis trusts ONLY its own client CA. Before, every TLS
//      Redis had the platform CA as tls-ca-cert-file, so any AppCrane-issued
//      client certificate (app B's) plus app A's password opened app A's
//      Redis. These tests run the real managedDb functions (provision,
//      secureLogin -> ensureRedisInstance -> createRedisContainer) against a
//      recording `docker` shim and pin what the container is started with.
//   2. Failed Redis logins reach the alert path, read from `ACL LOG` by entry
//      id + count so nothing is counted twice.
//
// The engine behaviour these inputs produce (handshake refused for another
// app's certificate, ACL LOG grouping) was measured against real
// redis:8.10-alpine; the ACL LOG fixture below is that image's output.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-rdsca-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = 'rdscatest';
process.env.MANAGED_DB_BIND = '127.0.0.1';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const STATE = join(process.env.DATA_DIR, 'shim');
mkdirSync(SHIM_DIR, { recursive: true });
mkdirSync(STATE, { recursive: true });
// The shim keeps one state file per container ("<status>|redis|<config label>")
// and, at `docker run`, snapshots what the server mount holds — the file the
// instance will actually trust — so a test can read it after the fact.
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const S = process.env.CRANE_TEST_DOCKER_STATE;
const argv = process.argv.slice(2);
fs.appendFileSync(path.join(S, 'argv.log'), JSON.stringify(argv) + '\\n');
const done = (out = '', code = 0, err = '') => { if (out) process.stdout.write(out + '\\n'); if (err) process.stderr.write(err + '\\n'); process.exit(code); };
const cfile = (n) => path.join(S, 'c-' + n);
const main = () => {
  const [cmd] = argv;
  if (cmd === 'inspect') {
    const name = argv[argv.length - 1];
    return fs.existsSync(cfile(name)) ? done(fs.readFileSync(cfile(name), 'utf8')) : done('', 1, 'Error: No such object');
  }
  if (cmd === 'rm') { try { fs.unlinkSync(cfile(argv[argv.length - 1])); } catch (_) {} fs.appendFileSync(path.join(S, 'events'), 'rm ' + argv[argv.length - 1] + '\\n'); return done(); }
  if (cmd === 'start') return done();
  if (cmd === 'run') {
    const name = argv[argv.indexOf('--name') + 1];
    const label = argv.find(a => a.startsWith('appcrane-db-config=')).split('=')[1];
    const snap = {};
    argv.forEach((a, i) => {
      if (argv[i - 1] === '-v' && a.endsWith(':/etc/appcrane-tls:ro')) {
        const src = a.split(':')[0];
        snap.serverDir = src;
        snap.files = fs.readdirSync(src).sort();
        snap.clientCa = fs.existsSync(path.join(src, 'client-ca.crt')) ? fs.readFileSync(path.join(src, 'client-ca.crt'), 'utf8') : null;
      }
    });
    fs.writeFileSync(path.join(S, 'run-' + name + '.json'), JSON.stringify({ argv, ...snap }));
    fs.writeFileSync(cfile(name), 'running|redis|' + label);
    fs.appendFileSync(path.join(S, 'events'), 'run ' + name + '\\n');
    return done('0123456789abcdef');
  }
  if (cmd === 'exec') {
    if (argv.includes('PING')) return done('PONG');
    if (argv.includes('LOG')) return done(fs.existsSync(path.join(S, 'acllog-' + argv[1])) ? fs.readFileSync(path.join(S, 'acllog-' + argv[1]), 'utf8') : '[]');
    return done('OK');
  }
  done();
};
if (argv[0] === 'exec' && argv.includes('-i')) { process.stdin.on('data', () => {}); process.stdin.on('end', main); } else main();
`, { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_STATE = STATE;
const REAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const certs = await import('../server/services/dbCerts.js');
const redis = await import('../server/services/managedRedis.js');
const deployer = await import('../server/services/deployer.js');
const alerts = await import('../server/services/dbAuthAlerts.js');
const { decrypt } = await import('../server/services/encryption.js');

let APP_A, APP_B;
before(() => {
  initDb(process.env.DATA_DIR);
  const db = getDb();
  const ins = db.prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)');
  APP_A = Number(ins.run('A', 'rds-a', 1).lastInsertRowid);
  APP_B = Number(ins.run('B', 'rds-b', 2).lastInsertRowid);
  db.prepare("INSERT INTO users (name, email, role, active, api_key_hash) VALUES ('Admin', 'admin@example.test', 'platform_admin', 1, 'h-admin')").run();
});
after(() => {
  process.env.PATH = REAL_PATH;
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

const noOwner = async () => null;
const runSnap = (container) => JSON.parse(readFileSync(join(STATE, `run-${container}.json`), 'utf8'));
const rowOf = (appId) => getDb().prepare("SELECT * FROM managed_databases WHERE app_id = ? AND engine = 'redis'").get(appId);
const verifies = (leafPem, caPem) => new crypto.X509Certificate(leafPem).verify(crypto.createPublicKey(caPem));
const flagValue = (argv, flag) => {
  const cmd = argv.find(a => a.includes('redis-server'));
  const m = new RegExp(`${flag} (\\S+)`).exec(cmd);
  return m && m[1];
};

// ---------------------------------------------------------------------------
// Gap 1: one trust anchor per instance
// ---------------------------------------------------------------------------

test('a manifest Redis is started trusting ONLY its own instance CA, and the app cert is signed by it', async () => {
  for (const appId of [APP_A, APP_B]) {
    await mdb.provision({ appId }, 'redis');
    await mdb.secureLogin({ appId }, 'redis', { certRequired: true, resolveOwner: noOwner });
  }
  const a = rowOf(APP_A);
  const b = rowOf(APP_B);
  const snapA = runSnap(a.container_name);

  // The container's tls-ca-cert-file is the instance CA file, and that file
  // holds exactly ONE certificate: A's instance CA — not the platform CA.
  assert.equal(flagValue(snapA.argv, '--tls-ca-cert-file'), '/tmp/appcrane-tls/client-ca.crt');
  assert.equal((snapA.clientCa.match(/BEGIN CERTIFICATE/g) || []).length, 1);
  const caA = certs.ensureRedisCa(a.db_name);
  const caB = certs.ensureRedisCa(b.db_name);
  const platform = certs.ensureCa();
  assert.equal(snapA.clientCa, caA.certPem, "A's Redis trusts A's instance CA");
  assert.notEqual(snapA.clientCa, platform.certPem);
  assert.match(new crypto.X509Certificate(snapA.clientCa).subject, new RegExp(`CN=AppCrane Redis CA ${a.db_name}`));

  // A's server directory is A's own, never B's and never the shared one.
  assert.equal(snapA.serverDir, join(process.env.DATA_DIR, 'managed-db', '_tls', 'redis', a.db_name));
  assert.deepEqual(snapA.files, ['admin.crt', 'admin.key', 'ca.crt', 'client-ca.crt', 'server.crt', 'server.key', 'server.pem']);
  assert.notEqual(runSnap(b.container_name).serverDir, snapA.serverDir);

  // A's client cert chains to A's CA only. B's cert does not chain to A's CA
  // — which is exactly the handshake the real engine then refuses.
  const dirA = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', a.db_user);
  const dirB = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', b.db_user);
  const certA = readFileSync(join(dirA, 'redis-client.crt'), 'utf8');
  const certB = readFileSync(join(dirB, 'redis-client.crt'), 'utf8');
  assert.equal(new crypto.X509Certificate(certA).subject, `CN=${a.db_user}`);
  assert.equal(verifies(certA, caA.certPem), true);
  assert.equal(verifies(certB, caA.certPem), false, "B's certificate must not validate against A's instance CA");
  assert.equal(verifies(certA, caB.certPem), false);
  assert.equal(verifies(certA, platform.certPem), false, 'not signed by the platform CA either');
  // The admin cert redis-cli presents is under the same instance CA.
  assert.equal(verifies(readFileSync(join(snapA.serverDir, 'admin.crt'), 'utf8'), caA.certPem), true);
  // ca.crt in the app's directory is the PLATFORM CA: it verifies the server.
  assert.equal(readFileSync(join(dirA, 'ca.crt'), 'utf8'), platform.certPem);
  assert.equal(verifies(readFileSync(join(snapA.serverDir, 'server.crt'), 'utf8'), platform.certPem), true);
});

test('the instance CA is generated once and its key is stored only encrypted', async () => {
  const a = rowOf(APP_A);
  const before = getDb().prepare('SELECT * FROM managed_db_certs WHERE name = ?').get(`redis-ca:${a.db_name}`);
  assert.ok(before, 'stored');
  assert.ok(!before.key_enc.includes('PRIVATE KEY'), 'no plaintext key in SQLite');
  assert.match(decrypt(before.key_enc), /BEGIN PRIVATE KEY/);
  // A redeploy re-runs everything and must not rotate the CA.
  await mdb.provision({ appId: APP_A }, 'redis');
  await mdb.secureLogin({ appId: APP_A }, 'redis', { certRequired: true, resolveOwner: noOwner });
  const after = getDb().prepare('SELECT * FROM managed_db_certs WHERE name = ?').get(`redis-ca:${a.db_name}`);
  assert.equal(after.cert_pem, before.cert_pem);
  // No key on disk except the ones the container and the app must read.
  const all = [];
  const walk = (d) => { for (const f of readdirSync(d, { withFileTypes: true })) f.isDirectory() ? walk(join(d, f.name)) : all.push(join(d, f.name)); };
  walk(join(process.env.DATA_DIR, 'managed-db', '_tls'));
  const caKey = decrypt(after.key_enc);
  for (const f of all) assert.ok(!readFileSync(f, 'utf8').includes(caKey.trim()), `instance CA key written to ${f}`);
});

test('injected env: Redis paths + DB_*_FILE point at redis-client.*, URL is rediss:// with no query', async () => {
  const creds = mdb.credentialsFor({ appId: APP_A }, 'redis');
  assert.equal(creds.tls.cert, '/run/appcrane/db/redis-client.crt');
  const env = deployer.buildManagedDbEnv({ engine: 'redis', url_env: 'REDIS_URL' }, creds);
  assert.match(env.REDIS_URL, /^rediss:\/\/crane_a\d+_u:[^@]+@host\.docker\.internal:\d+\/0$/);
  assert.equal(env.REDIS_TLS_CA_FILE, '/run/appcrane/db/ca.crt');
  assert.equal(env.REDIS_TLS_CERT_FILE, '/run/appcrane/db/redis-client.crt');
  assert.equal(env.REDIS_TLS_KEY_FILE, '/run/appcrane/db/redis-client.key');
  assert.equal(env.DB_CERT_FILE, env.REDIS_TLS_CERT_FILE);
  assert.equal(env.DB_KEY_FILE, env.REDIS_TLS_KEY_FILE);
  assert.equal(env.DB_CERT_KEY_FILE, '/run/appcrane/db/redis-client.pem');
  // Postgres is untouched: client.*, and no REDIS_TLS_* names.
  const pg = deployer.tlsFileEnv({}, { engine: 'postgres', tls: { ca: 'a', cert: '/run/appcrane/db/client.crt', key: 'k', pem: 'p' } });
  assert.equal(pg.DB_CERT_FILE, '/run/appcrane/db/client.crt');
  assert.equal(pg.REDIS_TLS_CERT_FILE, undefined);
  const { parseManifestDatabase } = await import('../server/services/manifestDatabase.js');
  assert.throws(() => parseManifestDatabase({ engine: 'redis', env: { password: 'REDIS_TLS_KEY_FILE' } }), /reserved by AppCrane/);
});

test("a login with Postgres AND Redis keeps its Postgres client.* (platform CA) beside redis-client.*", async () => {
  const a = rowOf(APP_A);
  const pgCert = certs.ensureClientCert(a.db_user);
  certs.writeClientFiles(a.db_user, pgCert, null);
  await mdb.secureLogin({ appId: APP_A }, 'redis', { certRequired: true, resolveOwner: noOwner });
  const dir = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', a.db_user);
  assert.equal(readFileSync(join(dir, 'client.crt'), 'utf8'), pgCert.certPem, 'Redis must not overwrite the Postgres certificate');
  assert.equal(verifies(readFileSync(join(dir, 'client.crt'), 'utf8'), certs.ensureCa().certPem), true);
  assert.equal(verifies(readFileSync(join(dir, 'redis-client.crt'), 'utf8'), certs.ensureRedisCa(a.db_name).certPem), true);
});

test('CONVERSION: a TLS instance created before the instance CA (label tls1) is recreated on its next ensure', async () => {
  const a = rowOf(APP_A);
  // What an older AppCrane left running: TLS, platform-CA trust, label 'tls1'.
  writeFileSync(join(STATE, `c-${a.container_name}`), 'running|redis|tls1');
  writeFileSync(join(STATE, 'events'), '');
  await mdb.provision({ appId: APP_A }, 'redis');
  const events = readFileSync(join(STATE, 'events'), 'utf8').trim().split('\n');
  assert.deepEqual(events, [`rm ${a.container_name}`, `run ${a.container_name}`]);
  const snap = runSnap(a.container_name);
  assert.ok(snap.argv.includes(`appcrane-db-config=${redis.REDIS_TLS_CONFIG_VERSION}`));
  assert.equal(snap.clientCa, certs.ensureRedisCa(a.db_name).certPem);
  // Same volume, same port: the RDB data is not touched by the recreate.
  assert.ok(snap.argv.includes(`${join(process.env.DATA_DIR, 'managed-db', 'redis', a.db_name)}:/data`));
  assert.ok(snap.argv.some(x => x === `127.0.0.1:${a.host_port}:6379`));
  // And a current one is left alone.
  writeFileSync(join(STATE, 'events'), '');
  await mdb.provision({ appId: APP_A }, 'redis');
  assert.equal(readFileSync(join(STATE, 'events'), 'utf8'), '');
});

test('redis-cli inside the container: admin cert, platform CA for the server, no password in argv', () => {
  const args = redis.cliArgs('c1', { tls: true });
  const script = args[args.indexOf('-c') + 1];
  assert.match(script, /--cacert \/tmp\/appcrane-tls\/ca\.crt/);
  assert.match(script, /k=\/tmp\/appcrane-tls\/admin;/);
  assert.match(script, /exec redis-cli .*"\$@"$/);
  assert.deepEqual(redis.aclLogArgs('c1').slice(-4), ['--json', 'ACL', 'LOG', '128']);
  for (const a of redis.aclLogArgs('c1', { tls: true })) assert.ok(!/REDISCLI_AUTH=|-a$|--pass/.test(a));
});

test('deprovision removes the instance CA, its certificates and only the redis-client files', async () => {
  const b = rowOf(APP_B);
  const dirB = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', b.db_user);
  writeFileSync(join(dirB, 'client.crt'), 'postgres cert stays');
  certs.dropRedisCerts(b.db_name, b.db_user);
  assert.equal(getDb().prepare("SELECT COUNT(*) n FROM managed_db_certs WHERE name LIKE ?").get(`redis-%:${b.db_name}`).n, 0);
  assert.ok(!existsSync(join(process.env.DATA_DIR, 'managed-db', '_tls', 'redis', b.db_name)));
  assert.ok(!existsSync(join(dirB, 'redis-client.crt')));
  assert.ok(existsSync(join(dirB, 'client.crt')));
  const src = readFileSync(new URL('../server/services/managedDb.js', import.meta.url), 'utf8');
  // Both teardown paths release certificates through the one function that
  // routes a Redis row to dropRedisCerts (test/managed-db-cert-release.test.js).
  assert.equal((src.match(/certs\.releaseClientCerts\(row\)/g) || []).length, 2, 'deprovision + deprovisionApp');
});

// ---------------------------------------------------------------------------
// Gap 2: failed Redis logins reach the alert path
// ---------------------------------------------------------------------------

// redis:8.10-alpine, `redis-cli --json ACL LOG 128` after two wrong passwords
// for crane_a1_u and one for an unknown user (client-info shortened).
const REAL_ACL_LOG = '[{"count":1,"reason":"auth","context":"toplevel","object":"AUTH","username":"nosuch","age-seconds":2.564,"client-info":"id=14 addr=172.17.0.1:57686 laddr=172.17.0.2:6379 fd=20 name= cmd=auth user=default","entry-id":1,"timestamp-created":1791874999224,"timestamp-last-updated":1791874999224},{"count":2,"reason":"auth","context":"toplevel","object":"AUTH","username":"crane_a1_u","age-seconds":2.616,"client-info":"id=13 addr=172.17.0.1:57676 laddr=172.17.0.2:6379 fd=20 name= cmd=auth user=default","entry-id":0,"timestamp-created":1791874999124,"timestamp-last-updated":1791874999172}]';

test('ACL LOG parsing: the real redis-cli --json shape, auth entries only, client-info dropped', () => {
  const extra = REAL_ACL_LOG.replace(/\]$/, ',{"count":4,"reason":"command","context":"toplevel","object":"config","username":"crane_a1_u","entry-id":2,"timestamp-created":1,"timestamp-last-updated":2}]');
  const parsed = alerts.parseRedisAclLog(extra);
  assert.deepEqual(parsed, [
    { entryId: 1, createdMs: 1791874999224, updatedMs: 1791874999224, count: 1, username: 'nosuch' },
    { entryId: 0, createdMs: 1791874999124, updatedMs: 1791874999172, count: 2, username: 'crane_a1_u' },
  ]);
  assert.deepEqual(alerts.parseRedisAclLog('(error) NOPERM'), [], 'garbage is ignored, not thrown');
  assert.equal(alerts.parseRedisAclLog('[{"count":1,"reason":"auth","username":"<x>","entry-id":0,"timestamp-created":1}]')[0].username, '?x?');
});

function aclEntry(id, count, { username, createdMs, updatedMs }) {
  return { count, reason: 'auth', context: 'toplevel', object: 'AUTH', username, 'client-info': 'addr=172.17.0.1:1 laddr=172.17.0.2:6379',
    'entry-id': id, 'timestamp-created': createdMs, 'timestamp-last-updated': updatedMs };
}

test('THRESHOLD via scanOnce: 7 bad passwords against A (grouped by Redis) -> one audit row + one mail, counted once', async () => {
  const db = getDb();
  const a = rowOf(APP_A);
  const b = rowOf(APP_B);
  const now = new Date();
  const t = now.getTime() - 30e3;
  const secret = decrypt(a.password_enc);
  alerts.__resetCursorsForTests();
  db.prepare("DELETE FROM managed_db_auth_failures").run();
  db.prepare("DELETE FROM audit_log WHERE action = 'managed-db-auth-alert'").run();

  // Scan 1: Redis has grouped the first 3 into one entry.
  writeFileSync(join(STATE, `acllog-${a.container_name}`), JSON.stringify([aclEntry(0, 3, { username: b.db_user, createdMs: t, updatedMs: t + 2000 })]));
  const exec = async (cmd, args) => {
    const { execFile } = await import('child_process');
    return new Promise((res, rej) => execFile(cmd, args, (e, stdout, stderr) => (e ? rej(e) : res({ stdout, stderr }))));
  };
  const mails = [];
  const evaluate = (n) => alerts.evaluateAlerts(db, { now: n, sendMail: (m) => mails.push(m) });
  await alerts.scanOnce({ db, now, exec });
  assert.equal(db.prepare("SELECT SUM(count) n FROM managed_db_auth_failures WHERE engine = 'redis'").get().n, 3);
  assert.equal(mails.length, 0);

  // Scan 2: the same entry, count now 7 (four more inside the grouping
  // window), plus the same read again — only the delta is stored.
  writeFileSync(join(STATE, `acllog-${a.container_name}`), JSON.stringify([aclEntry(0, 7, { username: b.db_user, createdMs: t, updatedMs: t + 9000 })]));
  await alerts.scanOnce({ db, now, exec });
  await alerts.scanOnce({ db, now, exec });
  assert.equal(db.prepare("SELECT SUM(count) n FROM managed_db_auth_failures WHERE engine = 'redis'").get().n, 7, 'counted once');
  const raised = evaluate(now);
  // scanOnce already evaluated with the real mail queue; the alert is rate
  // limited, so this explicit evaluation raises nothing more.
  assert.equal(raised.length, 0);
  const rows = db.prepare("SELECT app_id, detail FROM audit_log WHERE action = 'managed-db-auth-alert'").all();
  assert.equal(rows.length, 1, 'one audit row');
  const detail = JSON.parse(rows[0].detail);
  assert.equal(detail.engine, 'redis');
  assert.equal(detail.login, b.db_user);
  assert.equal(detail.failures, 7);
  assert.deepEqual(detail.databases, [{ database: a.db_name, app: 'rds-a' }]);
  assert.equal(detail.cross_app, true, "B's username against A's instance");
  // The ACL LOG read carries no password on argv.
  const argvLog = readFileSync(join(STATE, 'argv.log'), 'utf8');
  assert.ok(argvLog.includes('"LOG"'));
  assert.ok(!argvLog.includes(secret), 'the password reached a docker argv');
  for (const s of [JSON.stringify(db.prepare('SELECT * FROM managed_db_auth_failures').all()), JSON.stringify(rows)]) {
    assert.ok(!s.includes(secret));
    assert.ok(!s.includes('172.17.0.1'), 'the bridge-gateway address is not stored');
  }
});

test('the alert e-mail for Redis names the instance and explains the bridge-gateway source, once per hour', () => {
  const db = getDb();
  db.prepare('DELETE FROM managed_db_auth_failures').run();
  db.prepare('DELETE FROM managed_db_auth_alerts').run();
  const a = rowOf(APP_A);
  const now = new Date('2026-10-12T12:10:00Z');
  const entries = [{ entryId: 5, createdMs: now.getTime() - 60e3, updatedMs: now.getTime() - 50e3, count: 6, username: 'default' }];
  alerts.recordRedisAclEntries(db, { container: 'cX', dbName: a.db_name }, entries, { now });
  const mails = [];
  const raised = alerts.evaluateAlerts(db, { now, sendMail: (m) => mails.push(m) });
  assert.equal(raised.length, 1);
  assert.equal(raised[0].login, `default@${a.db_name}`, 'default is per instance, so instances do not add up');
  assert.match(mails[0].subject, /Repeated failed redis logins/);
  assert.match(mails[0].text, /bridge gateway, so the username and the target instance/);
  assert.match(mails[0].text, new RegExp(`${a.db_name} \\(app rds-a\\)`));
  alerts.recordRedisAclEntries(db, { container: 'cX', dbName: a.db_name }, [{ ...entries[0], count: 20 }], { now });
  assert.equal(alerts.evaluateAlerts(db, { now, sendMail: (m) => mails.push(m) }).length, 0, 'rate limited');
  assert.equal(mails.length, 1);
});

test('an instance restart (entry ids back to 0) is a NEW entry, not a lower count', () => {
  const db = getDb();
  db.prepare('DELETE FROM managed_db_auth_failures').run();
  const now = new Date();
  const e = (createdMs, count) => [{ entryId: 0, createdMs, updatedMs: createdMs, count, username: 'u1' }];
  assert.equal(alerts.recordRedisAclEntries(db, { container: 'cR', dbName: 'crane_a99' }, e(now.getTime() - 5000, 4), { now }), 4);
  assert.equal(alerts.recordRedisAclEntries(db, { container: 'cR', dbName: 'crane_a99' }, e(now.getTime() - 1000, 2), { now }), 2);
  assert.equal(alerts.recordRedisAclEntries(db, { container: 'cR', dbName: 'crane_a99' }, e(now.getTime() - 1000, 2), { now }), 0);
});
