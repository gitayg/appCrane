import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawnSync } from 'child_process';

// Every login under TLS + its own client certificate, against a REAL
// postgres:16-alpine and mariadb:11.4, through the functions the deployer and
// the admin route call. Clients are throwaway containers dialling
// host.docker.internal, as an app does; passwords travel in the environment
// of `docker run` (-e NAME forwards by name), never argv.
//   - the `_app` login: refused without TLS, refused with TLS but no
//     certificate, refused with ANOTHER app's certificate, accepted with its
//     own (Postgres and MariaDB);
//   - strict pg_hba: off while a catalogue login is password-only, on once
//     the last one is converted (requireCertificate), off again when a new
//     password-only login is provisioned; the container is never restarted;
//   - strict refuses the superuser over TCP; the admin path keeps working.

const PREFIX = `crane-strict-${process.pid}`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-strict-real-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
process.env.MANAGED_DB_POSTGRES_PORT = '45634';
process.env.MANAGED_DB_MARIADB_PORT = '43398';
process.env.MANAGED_DB_REDIS_PORT_MIN = '49311';

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

let A; let B; let CAT; let CAT2; let UND;
before(() => {
  initDb(process.env.DATA_DIR);
  getDb().prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
  const ins = getDb().prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)');
  A = Number(ins.run('A', 'strict-a', 1).lastInsertRowid);
  B = Number(ins.run('B', 'strict-b', 2).lastInsertRowid);
  CAT = Number(ins.run('Cat', 'strict-cat', 3).lastInsertRowid);
  CAT2 = Number(ins.run('Cat2', 'strict-cat2', 4).lastInsertRowid);
  UND = Number(ins.run('Und', 'strict-und', 5).lastInsertRowid);
});
after(async () => {
  if (dockerOk) {
    await mdb.stopServer('postgres').catch(() => {});
    await mdb.stopServer('mariadb').catch(() => {});
    for (const e of ['postgres', 'mariadb']) spawnSync('docker', ['rm', '-f', `${PREFIX}-${e}`]);
    const left = spawnSync('docker', ['ps', '-aq', '--filter', `name=^${PREFIX}-redis`], { encoding: 'utf8' }).stdout.split('\n').filter(Boolean);
    if (left.length) spawnSync('docker', ['rm', '-f', ...left]);
  }
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

/** Mount each certificate directory, copy it to its container path with the key at 0600, run `cmd`. */
function client(image, mounts, cmd, env) {
  const args = ['run', '--rm', '-i', '--add-host', 'host.docker.internal:host-gateway'];
  for (const k of Object.keys(env)) args.push('-e', k);
  const copies = [];
  mounts.forEach((m, i) => {
    args.push('-v', `${m.host}:/mnt/c${i}:ro`);
    copies.push(`mkdir -p ${m.container} && cp /mnt/c${i}/* ${m.container}/ && chmod 600 ${m.container}/*.key`);
  });
  args.push('--entrypoint', 'sh', image, '-c', [...copies, cmd].join(' && '));
  const r = spawnSync('docker', args, { env: { ...process.env, ...env }, encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
}
const psql = (url, mounts = []) => client('postgres:16-alpine', mounts, 'exec psql "$DBURL" -X -q -A -t -c "SELECT current_user"', { DBURL: url });
const last = (r) => JSON.stringify(r.err.split('\n').pop());
const plainUrl = (creds) => `postgresql://${creds.username}:${creds.password}@${creds.host}:${creds.port}/${creds.database}?sslmode=disable`;
const startedAt = (name) => execFileSync('docker', ['inspect', '-f', '{{.State.StartedAt}}', name], { encoding: 'utf8' }).trim();
const pgContainer = `${PREFIX}-postgres`;
const hbaLast = () => execFileSync('docker', ['exec', pgContainer, 'sh', '-c', 'grep -v "^#" /tmp/appcrane-tls/pg_hba.conf | tail -1'], { encoding: 'utf8' }).trim();

let appA; let ownerA; let ownerB; let ownerAMounts; let ownerBMounts;

test('setup: A and B manifest-style (certificate owners, A with an _app login), CAT catalogue-style (password-only)', { skip }, async () => {
  for (const id of [A, B]) {
    await mdb.provision({ appId: id }, 'postgres');
    const s = await mdb.secureLogin({ appId: id }, 'postgres', { certRequired: true });
    if (id === A) ownerAMounts = s.mounts; else ownerBMounts = s.mounts;
  }
  ownerA = mdb.credentialsFor({ appId: A }, 'postgres');
  ownerB = mdb.credentialsFor({ appId: B }, 'postgres');
  appA = await mdb.ensureAppLogin({ appId: A }, 'postgres', {});
  assert.ok(appA.creds.tls, 'the _app login of a certificate owner requires its own certificate');
  await mdb.provision({ appId: CAT }, 'postgres');
  await mdb.secureLogin({ appId: CAT }, 'postgres', { certRequired: false });
  assert.match(hbaLast(), /scram-sha-256$/, 'a password-only login keeps the fallback line');
});

test('the _app login: no TLS refused, TLS without a certificate refused, another app\'s certificate refused, its own accepted', { skip }, () => {
  const plain = psql(plainUrl(appA.creds));
  console.log(`[real] _app no TLS: rc=${plain.code} err=${last(plain)}`);
  assert.notEqual(plain.code, 0);
  assert.match(plain.err, /no encryption|rejects connection/);

  const noCert = psql(managedDbUrl(appA.creds).replace(/&sslcert=[^&]*&sslkey=[^&]*/, ''), appA.mounts);
  console.log(`[real] _app TLS, no cert: rc=${noCert.code} err=${last(noCert)}`);
  assert.notEqual(noCert.code, 0);
  assert.match(noCert.err, /certificate/);

  // B's owner certificate, presented for A's _app login: same CA, wrong CN.
  const other = psql(managedDbUrl({ ...appA.creds, tls: ownerB.tls }), ownerBMounts);
  console.log(`[real] _app with another app's cert: rc=${other.code} err=${last(other)}`);
  assert.notEqual(other.code, 0);
  // The client sees the method's generic failure; the server log names the reason.
  assert.match(other.err, /password authentication failed for user "crane_a\d+_u_app"/);
  const logs = spawnSync('docker', ['logs', pgContainer], { encoding: 'utf8' });
  const reason = `${logs.stdout}${logs.stderr}`.split('\n').filter((l) => /certificate validation \(clientcert=verify-full\) failed/.test(l)).pop() || '';
  console.log(`[real] server log for it: ${JSON.stringify(reason.trim())}`);
  assert.match(reason, new RegExp(`failed for user "${appA.creds.username}": CN mismatch`));

  const own = psql(managedDbUrl(appA.creds), appA.mounts);
  console.log(`[real] _app with its own cert: rc=${own.code} out=${JSON.stringify(own.out)} err=${last(own)}`);
  assert.equal(own.code, 0, own.err);
  assert.equal(own.out, appA.creds.username);
});

test('strict pg_hba: flips only when the last password-only login is converted, by reload, without a restart', { skip }, async () => {
  const cat = mdb.credentialsFor({ appId: CAT }, 'postgres');
  assert.equal(psql(plainUrl(cat)).code, 0, 'precondition: the catalogue login works with a password alone');
  assert.deepEqual(po.passwordOnlyLogins({ engine: 'postgres' }).map((l) => l.login), [cat.username]);
  const start = startedAt(pgContainer);

  const id = getDb().prepare('SELECT id FROM managed_databases WHERE app_id = ? AND engine = ?').get(CAT, 'postgres').id;
  const res = await mdb.requireCertificate(id);
  assert.equal(res.redeploy_required, true);
  assert.deepEqual(po.passwordOnlyLogins({ engine: 'postgres' }), []);
  assert.match(hbaLast(), /reject$/, 'strict once nothing is password-only');
  assert.equal(startedAt(pgContainer), start, 'pg_reload_conf, not a restart');

  const catPlain = psql(plainUrl(cat));
  console.log(`[real] converted catalogue login, password only: rc=${catPlain.code} err=${last(catPlain)}`);
  assert.notEqual(catPlain.code, 0);
  const catCreds = mdb.credentialsFor({ appId: CAT }, 'postgres');
  const catMounts = (await mdb.secureLogin({ appId: CAT }, 'postgres', {})).mounts;
  const catOwn = psql(managedDbUrl(catCreds), catMounts);
  assert.equal(catOwn.code, 0, catOwn.err);

  // The superuser over TCP with its password: refused by the strict line.
  const admin = getDb().prepare("SELECT admin_password_enc FROM managed_db_servers WHERE engine = 'postgres'").get();
  const { decrypt } = await import('../server/services/encryption.js');
  const su = psql(`postgresql://postgres:${decrypt(admin.admin_password_enc)}@host.docker.internal:${cat.port}/postgres?sslmode=require`);
  console.log(`[real] superuser over TCP under strict: rc=${su.code} err=${last(su)}`);
  assert.notEqual(su.code, 0);
  assert.match(su.err, /pg_hba\.conf rejects connection/);

  // AppCrane's own admin path (unix socket, trust) is unaffected, and an
  // existing owner login still works.
  const sync = await mdb.syncPgHba();
  assert.equal(sync.strict, true);
  assert.equal(psql(managedDbUrl(ownerA), ownerAMounts).code, 0);

  // A new password-only login: strict is dropped again, at once.
  await mdb.provision({ appId: CAT2 }, 'postgres');
  assert.match(hbaLast(), /scram-sha-256$/);
  const cat2 = psql(plainUrl(mdb.credentialsFor({ appId: CAT2 }, 'postgres')));
  assert.equal(cat2.code, 0, cat2.err);
  assert.equal(startedAt(pgContainer), start, 'still the same container');

  // Deleting it makes the server strict again.
  await mdb.deprovision({ appId: CAT2 }, 'postgres');
  assert.match(hbaLast(), /reject$/);
});

test('MariaDB _app login: its own certificate only (REQUIRE SUBJECT), another app\'s refused', { skip }, async () => {
  for (const id of [A, B]) {
    await mdb.provision({ appId: id }, 'mariadb');
    await mdb.secureLogin({ appId: id }, 'mariadb', { certRequired: true });
  }
  const app = await mdb.ensureAppLogin({ appId: A }, 'mariadb', {});
  const bOwner = mdb.credentialsFor({ appId: B }, 'mariadb');
  const bMounts = (await mdb.secureLogin({ appId: B }, 'mariadb', {})).mounts;
  const my = (mounts, extra) => client('mariadb:11.4', mounts,
    `exec mariadb --host=host.docker.internal --port=${app.creds.port} --user=${app.creds.username} ${extra} -N -e "SELECT CURRENT_USER()"`,
    { MYSQL_PWD: app.creds.password });
  const t = app.creds.tls;

  const plain = my([], '--skip-ssl');
  console.log(`[real] mariadb _app no TLS: rc=${plain.code} err=${last(plain)}`);
  assert.notEqual(plain.code, 0);
  const noCert = my(app.mounts, `--ssl --ssl-ca=${t.ca}`);
  console.log(`[real] mariadb _app TLS, no cert: rc=${noCert.code} err=${last(noCert)}`);
  assert.notEqual(noCert.code, 0);
  const other = my(bMounts, `--ssl --ssl-ca=${bOwner.tls.ca} --ssl-cert=${bOwner.tls.cert} --ssl-key=${bOwner.tls.key}`);
  console.log(`[real] mariadb _app with another app's cert: rc=${other.code} err=${last(other)}`);
  assert.notEqual(other.code, 0);
  const own = my(app.mounts, `--ssl --ssl-ca=${t.ca} --ssl-cert=${t.cert} --ssl-key=${t.key}`);
  console.log(`[real] mariadb _app with its own cert: rc=${own.code} out=${JSON.stringify(own.out)} err=${last(own)}`);
  assert.equal(own.code, 0, own.err);
  assert.match(own.out, new RegExp(`^${app.creds.username}@`));
});

const pgRole = (user) => String(execFileSync('docker', ['exec', '-u', 'postgres', pgContainer, 'psql', '-X', '-q', '-A', '-t', '-c',
  `SELECT pg_has_role(oid, 'appcrane_cert_required', 'MEMBER') || ':' || rolconnlimit FROM pg_roles WHERE rolname = '${user}'`], { encoding: 'utf8' })).trim();

test('an undeclared app (no catalogue needs, no manifest): its deploy never grants the cert group or alters the login; mounts only when the engine enforces it', { skip }, async () => {
  // Provisioned while strict (CAT2 was just deprovisioned): loosened first, so the new password login works.
  await mdb.provision({ appId: UND }, 'postgres');
  const und = mdb.credentialsFor({ appId: UND }, 'postgres');
  assert.equal(psql(plainUrl(und)).code, 0, 'provisioned under strict: the password-only login is let in');
  const app = getDb().prepare('SELECT * FROM apps WHERE id = ?').get(UND);
  const id = getDb().prepare('SELECT id FROM managed_databases WHERE app_id = ? AND engine = ?').get(UND, 'postgres').id;

  // The row says 1, the engine never got the GRANT (a hand edit, or a GRANT that failed).
  getDb().prepare('UPDATE managed_databases SET client_cert_required = 1 WHERE id = ?').run(id);
  // A platform limit that differs from the login's, so a policy re-apply would show.
  getDb().prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('managed_db_conn_limit', '17')").run();
  const before = pgRole(und.username);
  assert.match(before, /^false:/);
  let lines = [];
  let out = await injectManagedDbForEnv({ app, env: 'production', runtimeEnvVars: { DATABASE_URL: plainUrl(und) }, appendLog: (l) => lines.push(l) });
  console.log(`[real] undeclared, row=1, no GRANT: role ${before} -> ${pgRole(und.username)}; mounts=${out.mounts.length}`);
  assert.equal(pgRole(und.username), before, 'no GRANT, no CONNECTION LIMIT change');
  assert.deepEqual(out.mounts, []);
  assert.ok(lines.some((l) => /does not enforce it/.test(l)));
  assert.equal(psql(plainUrl(und)).code, 0, 'the app keeps working on its password URL');

  // The umami case: the GRANT was made by hand, the app's URL is plain.
  execFileSync('docker', ['exec', '-u', 'postgres', pgContainer, 'psql', '-X', '-q', '-c', `GRANT appcrane_cert_required TO "${und.username}"`]);
  const granted = pgRole(und.username);
  lines = [];
  out = await injectManagedDbForEnv({ app, env: 'production', runtimeEnvVars: { DATABASE_URL: plainUrl(und) }, appendLog: (l) => lines.push(l) });
  console.log(`[real] undeclared, row=1, GRANT by hand, plain URL: role ${granted} -> ${pgRole(und.username)}; mounts=${out.mounts.map((m) => m.container)}; warning=${lines.some((l) => /not configured to send it/.test(l))}`);
  assert.equal(pgRole(und.username), granted, 'policy unchanged');
  assert.equal(out.mounts.length, 1);
  assert.ok(lines.some((l) => /certificate required but the app is not configured to send it/.test(l)));
  getDb().prepare("DELETE FROM settings WHERE key = 'managed_db_conn_limit'").run();
  assert.deepEqual(po.certProblems().map((p) => [p.login, p.problem]), [[und.username, 'not_sent']]);
  // With the mounted files and a URL that names them, it gets in.
  const tlsCreds = mdb.credentialsFor({ appId: UND }, 'postgres');
  assert.equal(psql(managedDbUrl(tlsCreds), out.mounts).code, 0);
});

test('MariaDB undeclared: a row marked 1 without REQUIRE stays without it; after requireCertificate the probe sees it', { skip }, async () => {
  await mdb.provision({ appId: UND }, 'mariadb');
  const id = getDb().prepare('SELECT id FROM managed_databases WHERE app_id = ? AND engine = ?').get(UND, 'mariadb').id;
  const user = getDb().prepare('SELECT db_user FROM managed_databases WHERE id = ?').get(id).db_user;
  const req = () => execFileSync('docker', ['exec', '-i', `${PREFIX}-mariadb`, 'mariadb', '-N', '--batch', '-e',
    `SELECT CONCAT(ssl_type, ':', x509_subject) FROM mysql.user WHERE User = '${user}'`], { encoding: 'utf8' }).trim();
  getDb().prepare('UPDATE managed_databases SET client_cert_required = 1 WHERE id = ?').run(id);
  const r1 = await mdb.certMountIfEnforced({ appId: UND }, 'mariadb', {});
  console.log(`[real] mariadb row=1 no REQUIRE: enforced=${r1.enforced} engine=${JSON.stringify(req())}`);
  assert.equal(r1.enforced, false);
  assert.equal(req(), ':');
  await mdb.requireCertificate(id);
  const r2 = await mdb.certMountIfEnforced({ appId: UND }, 'mariadb', {});
  console.log(`[real] mariadb after requireCertificate: enforced=${r2.enforced} engine=${JSON.stringify(req())}`);
  assert.equal(r2.enforced, true);
  assert.equal(r2.mounts.length, 1);
});

test('Redis TLS: ensuring a certificate login again (every restart) does not recreate the instance', { skip }, async () => {
  await mdb.provision({ appId: UND }, 'redis');
  await mdb.secureLogin({ appId: UND }, 'redis', { certRequired: true });
  const name = getDb().prepare('SELECT container_name FROM managed_databases WHERE app_id = ? AND engine = ?').get(UND, 'redis').container_name;
  const facts = () => execFileSync('docker', ['inspect', '-f', '{{.Id}} {{.State.StartedAt}}', name], { encoding: 'utf8' }).trim();
  const first = facts();
  await mdb.secureLogin({ appId: UND }, 'redis', {});
  await mdb.secureLogin({ appId: UND }, 'redis', { certRequired: false });
  const probe = await mdb.certMountIfEnforced({ appId: UND }, 'redis', {});
  console.log(`[real] redis TLS instance before/after two ensures: ${first} / ${facts()}; probe enforced=${probe.enforced}`);
  assert.equal(facts(), first, 'same container, not restarted');
  assert.equal(probe.enforced, true);
});
