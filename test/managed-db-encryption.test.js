import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import express from 'express';

// "Encrypt MariaDB data at rest" (services/managedDbEncryption.js and its
// wiring in managedDb.js / routes/managedDb.js / routes/settings.js), without
// a daemon. A recording `docker` shim stands in for the engine: it answers the
// commands ensureServer() issues, records the `docker run` argv (and, at that
// moment, whether each bind-mount source holds a key file), and serves the
// tablespace / Aria output the test puts in place — so the server-side safety
// rule is exercised through the real managedDb functions.
//
// What MariaDB then does with these flags was verified against real
// mariadb:11.4 (see the release notes); this file pins the inputs.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbtde-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = 'tdetest';
process.env.MANAGED_DB_BIND = '127.0.0.1';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const STATE = join(process.env.DATA_DIR, 'shim');
mkdirSync(SHIM_DIR, { recursive: true });
mkdirSync(STATE, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const S = process.env.CRANE_TEST_DOCKER_STATE;
const argv = process.argv.slice(2);
const read = (f, d = '') => { try { return fs.readFileSync(path.join(S, f), 'utf8'); } catch (_) { return d; } };
fs.appendFileSync(path.join(S, 'argv.log'), JSON.stringify(argv) + '\\n');
let stdin = '';
const done = (out = '', code = 0, err = '') => { if (out) process.stdout.write(out + '\\n'); if (err) process.stderr.write(err + '\\n'); process.exit(code); };
const main = () => {
  const [cmd] = argv;
  if (cmd === 'network') return done('172.17.0.1');
  if (cmd === 'inspect') {
    const st = read('container');
    return st ? done(st) : done('', 1, 'Error: No such object');
  }
  if (cmd === 'rm') { try { fs.unlinkSync(path.join(S, 'container')); } catch (_) {} fs.appendFileSync(path.join(S, 'events'), 'rm\\n'); return done(); }
  if (cmd === 'start') return done();
  if (cmd === 'run') {
    const label = argv.find(a => a.startsWith('appcrane-db-config=')).split('=')[1];
    const mounts = [];
    argv.forEach((a, i) => { if (argv[i - 1] === '-v') { const src = a.split(':')[0]; mounts.push({ spec: a, keyFilePresent: fs.existsSync(path.join(src, 'keys.enc')) }); } });
    const envFile = argv[argv.indexOf('--env-file') + 1];
    const envNames = fs.readFileSync(envFile, 'utf8').split('\\n').filter(Boolean).map(l => l.split('=')[0]);
    fs.writeFileSync(path.join(S, 'run.json'), JSON.stringify({ argv, mounts, envNames }));
    fs.writeFileSync(path.join(S, 'container'), 'running|mariadb|' + label);
    fs.appendFileSync(path.join(S, 'events'), 'run\\n');
    return done('0123456789abcdef');
  }
  if (cmd === 'exec') {
    if (argv.includes('mariadb-admin')) return done('', 1, 'Access denied for user');
    const sh = argv.indexOf('-c');
    if (sh !== -1 && argv[sh + 1].includes('aria_chk')) return done(read('aria', 'ARIA_SCAN_DONE'));
    if (argv.includes('mariadb')) {
      fs.appendFileSync(path.join(S, 'sql.log'), stdin + '\\n--\\n');
      if (stdin.includes('INNODB_TABLESPACES_ENCRYPTION')) return done(read('status'));
      // An Aria rebuild under aria_encrypt_tables=OFF leaves the table plain.
      if (stdin.includes('ENGINE=Aria')) fs.writeFileSync(path.join(S, 'aria'), 'ARIA_SCAN_DONE');
      return done();
    }
    return done();
  }
  done();
};
if (argv[0] === 'exec' && argv.includes('-i')) {
  process.stdin.on('data', d => { stdin += d; });
  process.stdin.on('end', main);
} else main();
`, { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_STATE = STATE;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const tde = await import('../server/services/managedDbEncryption.js');
const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const routes = await import('../server/routes/managedDb.js');
const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { generateApiKey, hashApiKey, decrypt, encrypt } = await import('../server/services/encryption.js');
const { exportConfig } = await import('../server/services/configMigration.js');

const KEY_ROW = "SELECT value FROM settings WHERE key = 'managed_db_mariadb_encryption_key_enc'";
const LOADED_ROW = "SELECT value FROM settings WHERE key = 'managed_db_mariadb_encryption_key_loaded'";

let db;
before(() => {
  initDb(process.env.DATA_DIR);
  db = getDb();
});
after(() => {
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

function resetShim() {
  for (const f of ['container', 'run.json', 'status', 'aria', 'events', 'argv.log', 'sql.log']) rmSync(join(STATE, f), { force: true });
}
function resetState() {
  db.prepare("DELETE FROM settings WHERE key LIKE 'managed_db_mariadb_encryption%'").run();
  db.prepare("DELETE FROM managed_db_servers WHERE engine = 'mariadb'").run();
  tde.removeKeyFile();
  resetShim();
}
beforeEach(resetState);

// Real `mariadb --batch` output of STATUS_SQL, captured from mariadb:11.4.
const STATUS_ON = [
  'COUNT(*)\tCOALESCE(SUM(...), 0)\tCOALESCE(SUM(...), 0)',
  '9\t9\t0',
  '@@innodb_encrypt_tables\t@@innodb_encrypt_log\t@@encrypt_tmp_files\t@@aria_encrypt_tables\t(SELECT COUNT(*) ...)',
  'ON\t1\t1\t1\t1',
].join('\n');
const statusOut = ({ total = 10, encrypted = 0, plain = 10, mode = 'decrypt', plugin = 1 } = {}) => [
  'COUNT(*)\tA\tB', `${total}\t${encrypted}\t${plain}`, 'v1\tv2\tv3\tv4\tv5',
  mode === 'decrypt' ? `OFF\t0\t0\t0\t${plugin}` : `ON\t1\t1\t1\t${plugin}`,
].join('\n');

const shimRun = () => JSON.parse(readFileSync(join(STATE, 'run.json'), 'utf8'));
const shimEvents = () => (existsSync(join(STATE, 'events')) ? readFileSync(join(STATE, 'events'), 'utf8').trim().split('\n') : []);

/** A provisioned MariaDB server (row + running container) in a given mode. */
async function serverRunning() {
  await mdb.ensureServer('mariadb');
  rmSync(join(STATE, 'events'), { force: true });
}

// ── Pure pieces ───────────────────────────────────────────────────────────

test('server flags: encrypt turns every *_encrypt_* on with the plugin forced; decrypt keeps the plugin with them off; none adds nothing', () => {
  const on = tde.serverArgs('encrypt');
  for (const f of ['--plugin-load-add=file_key_management', '--file-key-management=FORCE',
    '--file-key-management-filename=/run/appcrane-tde/keys.enc', '--file-key-management-filekey=FILE:/run/appcrane-tde/filekey',
    '--file-key-management-encryption-algorithm=AES_CTR', '--innodb-encrypt-tables=ON', '--innodb-encrypt-log=ON',
    '--innodb-encrypt-temporary-tables=ON', '--encrypt-tmp-files=ON', '--aria-encrypt-tables=ON',
    '--innodb-encryption-threads=4', '--innodb-encryption-rotate-key-age=1']) {
    assert.ok(on.includes(f), `encrypt mode must pass ${f}`);
  }
  const off = tde.serverArgs('decrypt');
  assert.ok(off.includes('--plugin-load-add=file_key_management'), 'decrypt mode keeps the key loaded');
  assert.ok(off.includes('--innodb-encrypt-tables=OFF') && off.includes('--innodb-encrypt-log=OFF') && off.includes('--aria-encrypt-tables=OFF'));
  assert.ok(off.includes('--innodb-encryption-threads=4'), 'threads decrypt in the background');
  assert.deepEqual(tde.serverArgs('none'), []);
  assert.throws(() => tde.serverArgs('maybe'));
});

test('the install snippet is a fixed literal: the wrapping secret comes from the environment and is unset before the server starts', () => {
  const s = tde.installSnippet();
  assert.ok(!s.includes(tde.fileKey()), 'the secret never appears in the command');
  assert.match(s, /printf %s "\$APPCRANE_TDE_FILEKEY" > \/run\/appcrane-tde\/filekey/);
  assert.match(s, /unset APPCRANE_TDE_FILEKEY/);
  assert.match(s, /chown -R mysql \/run\/appcrane-tde/);
});

test('key file wrapping round-trips and the wrapped bytes do not contain the key', () => {
  const plain = `1;${'ab'.repeat(32)}\n`;
  const buf = tde.wrapKeyFile(plain, 'secret-1');
  assert.equal(buf.subarray(0, 8).toString(), 'Salted__');
  assert.ok(!buf.toString('latin1').includes('ab'.repeat(32)));
  assert.equal(tde.unwrapKeyFile(buf, 'secret-1'), plain);
  assert.throws(() => tde.unwrapKeyFile(buf, 'wrong'));
});

test('status parsing: real 11.4 output, and malformed output is an error rather than zeros', () => {
  const s = tde.parseStatus(STATUS_ON);
  assert.deepEqual({ total: s.total, encrypted: s.encrypted, plain: s.plain, in_progress: s.in_progress }, { total: 9, encrypted: 9, plain: 0, in_progress: 0 });
  assert.deepEqual(s.live, { innodb_encrypt_tables: 'ON', innodb_encrypt_log: true, encrypt_tmp_files: true, aria_encrypt_tables: true, plugin_active: true });
  const mid = tde.parseStatus(statusOut({ total: 10, encrypted: 3, plain: 5 }));
  assert.equal(mid.in_progress, 2);
  assert.throws(() => tde.parseStatus(''), /unexpected/);
  assert.throws(() => tde.parseStatus('ERROR 1045 (28000): Access denied'), /unexpected/);
  assert.equal(tde.phaseFor({ enabled: true, keyLoaded: true }, s), 'on');
  assert.equal(tde.phaseFor({ enabled: true, keyLoaded: true }, mid), 'encrypting');
  assert.equal(tde.phaseFor({ enabled: false, keyLoaded: true }, mid), 'decrypting');
  assert.equal(tde.phaseFor({ enabled: false, keyLoaded: true }, tde.parseStatus(statusOut())), 'decrypted');
  assert.equal(tde.phaseFor({ enabled: false, keyLoaded: false }, null), 'off');
});

test('Aria scan parsing and rebuild statements: only plain identifiers reach SQL', () => {
  const a = tde.parseAriaScan('ENCRYPTED /var/lib/mysql/mysql/global_priv.MAI\nUNREADABLE /var/lib/mysql/x/y.MAI\nARIA_SCAN_DONE\n');
  assert.deepEqual(a, { complete: true, encrypted: ['/var/lib/mysql/mysql/global_priv.MAI'], unreadable: ['/var/lib/mysql/x/y.MAI'] });
  assert.equal(tde.parseAriaScan('ENCRYPTED /x').complete, false, 'a scan cut short is not complete');
  const r = tde.ariaRebuildSql(['/var/lib/mysql/mysql/global_priv.MAI', '/var/lib/mysql/a@002db/t.MAI', "/var/lib/mysql/x/y`;DROP.MAI"]);
  assert.deepEqual(r.sql, ['ALTER TABLE `mysql`.`global_priv` ENGINE=Aria;']);
  assert.equal(r.skipped.length, 2);
});

test('THE SAFETY RULE: the key may be unloaded only when the running server reports nothing encrypted', () => {
  const off = { enabled: false, keyLoaded: true };
  const clean = { complete: true, encrypted: [], unreadable: [] };
  const plainStatus = tde.parseStatus(statusOut());
  assert.equal(tde.unloadRefusal({ state: off, status: plainStatus, aria: clean }), null);
  assert.match(tde.unloadRefusal({ state: { enabled: true, keyLoaded: true }, status: plainStatus, aria: clean }), /Encryption is on/);
  assert.match(tde.unloadRefusal({ state: off, status: null, aria: clean }), /not running/);
  assert.match(tde.unloadRefusal({ state: off, status: tde.parseStatus(statusOut({ encrypted: 1, plain: 9 })), aria: clean }), /1 of 10 InnoDB tablespaces are still encrypted/);
  assert.match(tde.unloadRefusal({ state: off, status: tde.parseStatus(statusOut({ encrypted: 0, plain: 8 })), aria: clean }), /2 of 10/, 'mid-rotation counts as encrypted');
  assert.match(tde.unloadRefusal({ state: off, status: tde.parseStatus(statusOut({ mode: 'encrypt', encrypted: 0, plain: 10 })), aria: clean }), /still has encryption settings on/);
  assert.match(tde.unloadRefusal({ state: off, status: tde.parseStatus(statusOut({ plugin: 0 })), aria: clean }), /does not have the key plugin/);
  assert.match(tde.unloadRefusal({ state: off, status: tde.parseStatus(statusOut({ total: 0, plain: 0 })), aria: clean }), /no InnoDB tablespaces/);
  assert.match(tde.unloadRefusal({ state: off, status: plainStatus, aria: null }), /did not complete/);
  assert.match(tde.unloadRefusal({ state: off, status: plainStatus, aria: { complete: true, encrypted: ['/var/lib/mysql/a/b.MAI'], unreadable: [] } }), /Aria table\(s\) are encrypted/);
  assert.match(tde.unloadRefusal({ state: off, status: plainStatus, aria: { complete: true, encrypted: [], unreadable: ['/x.MAI'] } }), /could not describe/);
});

// ── Key storage ───────────────────────────────────────────────────────────

test('the key is generated once and stored only encrypted', () => {
  assert.equal(tde.enable(db).keyCreated, true);
  const stored = db.prepare(KEY_ROW).get().value;
  assert.match(stored, /^[0-9a-f]{32}:[0-9a-f]{32}:[0-9a-f]+$/, 'stored through encryption.js encrypt()');
  const hex = decrypt(stored);
  assert.match(hex, /^[0-9a-f]{64}$/, '256-bit key');
  assert.ok(!stored.includes(hex), 'no plaintext key in SQLite');
  assert.equal(tde.enable(db).keyCreated, false, 'turning on again reuses the key');
  tde.disable(db);
  tde.enable(db);
  assert.equal(db.prepare(KEY_ROW).get().value, stored, 'the key row is never replaced while it exists');
});

test('the key file is wrapped, private, outside the data volume, and unwraps with the ENCRYPTION_KEY-derived secret', () => {
  tde.enable(db);
  const hex = decrypt(db.prepare(KEY_ROW).get().value);
  const dir = tde.writeKeyFile(db);
  const file = join(dir, tde.KEY_FILE);
  assert.ok(!tde.isWithin(dir, tde.dataVolumeDir()), 'key directory is not inside the MariaDB data volume');
  assert.ok(!tde.isWithin(tde.dataVolumeDir(), dir));
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(dir, '..')).mode & 0o777, 0o700);
  const bytes = readFileSync(file);
  assert.ok(!bytes.toString('latin1').includes(hex), 'no plaintext key on disk');
  assert.equal(tde.unwrapKeyFile(bytes, tde.fileKey()), `1;${hex}\n`);
});

test('the key is never deleted while it is loaded', () => {
  tde.enable(db);
  assert.throws(() => tde.deleteKey(db), /refusing to delete/);
  tde.disable(db);
  assert.throws(() => tde.deleteKey(db), /refusing to delete/, 'off but still loaded (decrypting) is still refused');
  assert.ok(db.prepare(KEY_ROW).get());
  tde.markKeyUnloaded(db);
  tde.deleteKey(db);
  assert.equal(db.prepare(KEY_ROW).get(), undefined);
});

test('a restored host rewrites the key file from deployhub.db before MariaDB starts', () => {
  tde.enable(db);
  tde.removeKeyFile();
  assert.equal(tde.syncKeyFileAtBoot(db), true);
  assert.ok(existsSync(join(tde.keyDir(), tde.KEY_FILE)));
  db.prepare("DELETE FROM settings WHERE key = 'managed_db_mariadb_encryption_key_enc'").run();
  assert.throws(() => tde.writeKeyFile(db), /key is missing from AppCrane's database/);
});

test('the key travels in the config export (re-encrypted per target) and is hidden from the bulk settings read', () => {
  tde.enable(db);
  const row = exportConfig(db).settings.find(s => s.key === 'managed_db_mariadb_encryption_key_enc');
  assert.ok(row && row.encrypted === true, 'exportConfig marks it encrypted, so importConfig re-encrypts it for the target key');
});

// ── Through managedDb.ensureServer() with the docker shim ────────────────

test('ON: the container is created with the read-only key mount (written before run), the tmpfs, the flags and the secret only in the env file', async () => {
  await serverRunning();
  const plainLabel = readFileSync(join(STATE, 'container'), 'utf8');
  assert.ok(!shimRun().argv.some(a => a.includes('file_key_management')), 'off by default: no plugin');

  const r = await mdb.setMariadbEncryption(true);
  assert.equal(r.restarted, true);
  assert.deepEqual(shimEvents(), ['rm', 'run'], 'recreated once on the existing data');
  assert.notEqual(readFileSync(join(STATE, 'container'), 'utf8'), plainLabel, 'config label changed');

  const { argv, mounts, envNames } = shimRun();
  const keyMount = mounts.find(m => m.spec.endsWith(':/etc/appcrane-tde:ro'));
  assert.ok(keyMount, `read-only key mount missing: ${JSON.stringify(mounts.map(m => m.spec))}`);
  assert.equal(keyMount.spec, `${tde.keyDir()}:/etc/appcrane-tde:ro`);
  assert.equal(keyMount.keyFilePresent, true, 'key file written before docker run');
  const dataMount = mounts.find(m => m.spec.endsWith(':/var/lib/mysql'));
  const dataSrc = dataMount.spec.slice(0, -':/var/lib/mysql'.length);
  assert.ok(!tde.isWithin(resolve(tde.keyDir()), resolve(dataSrc)), 'key directory is outside the mounted data volume');
  assert.ok(argv.includes('--tmpfs') && argv[argv.indexOf('--tmpfs') + 1].startsWith('/run/appcrane-tde:'));
  for (const f of tde.serverArgs('encrypt')) assert.ok(argv.includes(f), `missing ${f}`);
  assert.ok(envNames.includes('APPCRANE_TDE_FILEKEY'), 'wrapping secret goes through the env file');
  const hex = decrypt(db.prepare(KEY_ROW).get().value);
  assert.ok(!argv.join(' ').includes(hex) && !argv.join(' ').includes(tde.fileKey()), 'no key material in argv');
});

test('OFF needs confirm, keeps the key loaded, and kicks background decryption', async () => {
  await serverRunning();
  await mdb.setMariadbEncryption(true);
  await assert.rejects(mdb.setMariadbEncryption(false), (e) => e.code === 'CONFIRM_REQUIRED');
  assert.equal(tde.getState(db).enabled, true, 'nothing changed without confirm');
  rmSync(join(STATE, 'sql.log'), { force: true });
  writeFileSync(join(STATE, 'status'), statusOut({ encrypted: 10, plain: 0 }));
  const r = await mdb.setMariadbEncryption(false, { confirm: true });
  assert.equal(r.restarted, true);
  assert.equal(db.prepare(LOADED_ROW).get().value, '1', 'key stays loaded while decrypting');
  assert.ok(shimRun().argv.includes('--innodb-encrypt-tables=OFF') && shimRun().argv.includes('--plugin-load-add=file_key_management'));
  assert.match(readFileSync(join(STATE, 'sql.log'), 'utf8'), /SET GLOBAL innodb_encrypt_tables = OFF;/);
  assert.equal(r.status.phase, 'decrypting');
});

test('unload is REFUSED while any tablespace is encrypted: key stays loaded and in SQLite, server not restarted', async () => {
  await serverRunning();
  await mdb.setMariadbEncryption(true);
  await mdb.setMariadbEncryption(false, { confirm: true });
  rmSync(join(STATE, 'events'), { force: true });
  writeFileSync(join(STATE, 'status'), statusOut({ total: 10, encrypted: 1, plain: 9 }));
  await assert.rejects(mdb.unloadMariadbEncryptionKey({ deleteKey: true }), (e) => e.code === 'ENCRYPTION_IN_USE' && /still encrypted/.test(e.message));
  assert.equal(db.prepare(LOADED_ROW).get().value, '1');
  assert.ok(db.prepare(KEY_ROW).get(), 'key never deleted while encrypted');
  assert.ok(existsSync(join(tde.keyDir(), tde.KEY_FILE)), 'key file still in place');
  assert.deepEqual(shimEvents(), [], 'no restart');

  writeFileSync(join(STATE, 'status'), statusOut());
  writeFileSync(join(STATE, 'aria'), 'ENCRYPTED /var/lib/mysql/a@002db/t.MAI\nARIA_SCAN_DONE');
  await assert.rejects(mdb.unloadMariadbEncryptionKey({ deleteKey: true }), (e) => e.code === 'ENCRYPTION_IN_USE' && /Aria/.test(e.message));
  assert.ok(db.prepare(KEY_ROW).get());
});

test('unload is refused while encryption is on, even with delete_key', async () => {
  await serverRunning();
  await mdb.setMariadbEncryption(true);
  writeFileSync(join(STATE, 'status'), statusOut());
  await assert.rejects(mdb.unloadMariadbEncryptionKey({ deleteKey: true }), (e) => e.code === 'ENCRYPTION_IN_USE');
  assert.ok(db.prepare(KEY_ROW).get());
});

test('unload succeeds once everything is plain: rebuilds encrypted Aria tables, restarts without the plugin, then deletes the key', async () => {
  await serverRunning();
  await mdb.setMariadbEncryption(true);
  await mdb.setMariadbEncryption(false, { confirm: true });
  writeFileSync(join(STATE, 'status'), statusOut());
  writeFileSync(join(STATE, 'aria'), 'ENCRYPTED /var/lib/mysql/mysql/global_priv.MAI\nARIA_SCAN_DONE');
  // The shim treats the rebuild as decrypting the table, so the rescan is clean.
  const origSql = join(STATE, 'sql.log');
  rmSync(origSql, { force: true });
  const s = await mdb.unloadMariadbEncryptionKey({ deleteKey: true });
  assert.equal(s.key_loaded, false);
  assert.equal(s.key_exists, false);
  assert.match(readFileSync(origSql, 'utf8'), /ALTER TABLE `mysql`.`global_priv` ENGINE=Aria;/);
  assert.ok(!shimRun().argv.some(a => a.includes('file_key_management')), 'restarted without the plugin');
  assert.ok(!shimRun().argv.includes('--tmpfs'));
  assert.equal(db.prepare(KEY_ROW).get(), undefined);
  assert.equal(existsSync(tde.keyDir()), false);
});

test('a server that never existed: ON is recorded and applies at creation; OFF needs no decrypt phase', async () => {
  const r = await mdb.setMariadbEncryption(true);
  assert.equal(r.restarted, false);
  assert.equal(shimEvents().length, 0);
  await mdb.ensureServer('mariadb');
  assert.ok(shimRun().argv.includes('--innodb-encrypt-tables=ON'), 'first creation already encrypted');
  db.prepare("DELETE FROM managed_db_servers WHERE engine = 'mariadb'").run();
  await mdb.setMariadbEncryption(false, { confirm: true });
  assert.equal(tde.getState(db).keyLoaded, false);
});

// ── HTTP: platform admin only, and the generic settings writer is closed ──

let seq = 0;
function mkUser(role) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`tde${n}`, `tde${n}@t.test`, role, hashApiKey(key), 'human');
  return key;
}

test('routes: only a platform admin can read or change MariaDB encryption, OFF needs confirm, refusals are 409', async () => {
  const PLATFORM = mkUser('platform_admin');
  const USER = mkUser('user');
  const calls = [];
  routes.__setEngineForTests({
    mariadbEncryptionStatus: async () => ({ phase: 'off', caveat: tde.CAVEAT }),
    setMariadbEncryption: async (enabled, opts) => {
      calls.push(['set', enabled, opts.confirm]);
      if (!enabled && !opts.confirm) throw Object.assign(new Error('confirm'), { code: 'CONFIRM_REQUIRED' });
      return { restarted: true, status: { phase: enabled ? 'encrypting' : 'decrypting' } };
    },
    unloadMariadbEncryptionKey: async () => { calls.push(['unload']); throw Object.assign(new Error('1 of 10 still encrypted'), { code: 'ENCRYPTION_IN_USE' }); },
  });
  const api = express();
  api.use(express.json());
  api.use('/api/managed-db', routes.serversRouter);
  api.use('/api/settings', settingsRoutes);
  api.use(errorHandler);
  const srv = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
  const B = `http://127.0.0.1:${srv.address().port}`;
  const req = async (method, path, key, body) => {
    const res = await fetch(`${B}${path}`, { method, headers: { 'X-API-Key': key, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  try {
    assert.equal((await req('GET', '/api/managed-db/encryption', USER)).status, 403);
    assert.equal((await req('PUT', '/api/managed-db/encryption', USER, { enabled: true })).status, 403);
    assert.equal((await req('POST', '/api/managed-db/encryption/unload-key', USER, { delete_key: true })).status, 403);
    assert.deepEqual(calls, [], 'a non-admin never reaches the engine');

    const got = await req('GET', '/api/managed-db/encryption', PLATFORM);
    assert.equal(got.status, 200);
    assert.match(got.body.caveat, /same server as the data/);
    assert.equal((await req('PUT', '/api/managed-db/encryption', PLATFORM, { enabled: 'yes' })).status, 400);
    const on = await req('PUT', '/api/managed-db/encryption', PLATFORM, { enabled: true });
    assert.equal(on.status, 200);
    assert.match(on.body.note, /connections open at that moment dropped once/);
    assert.equal((await req('PUT', '/api/managed-db/encryption', PLATFORM, { enabled: false })).status, 400);
    assert.equal((await req('PUT', '/api/managed-db/encryption', PLATFORM, { enabled: false, confirm: true })).status, 200);
    const un = await req('POST', '/api/managed-db/encryption/unload-key', PLATFORM, { delete_key: true });
    assert.equal(un.status, 409);
    assert.match(un.body.error.message, /still encrypted/);
    const audit = db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'managed-db-encryption-change'").get();
    assert.equal(audit.n, 2);

    // The generic settings writer cannot touch the key or the state flags.
    for (const k of Object.values(tde.SETTING_KEYS)) {
      assert.equal((await req('PUT', `/api/settings/${k}`, PLATFORM, { value: '0' })).status, 403, `PUT /api/settings/${k}`);
    }
    db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('managed_db_mariadb_encryption_key_enc', ?)").run(encrypt('f'.repeat(64)));
    const bulk = await req('GET', '/api/settings', PLATFORM);
    assert.equal(bulk.status, 200);
    assert.ok(!('managed_db_mariadb_encryption_key_enc' in bulk.body.settings), 'key not in the bulk read');
    assert.equal((await req('GET', '/api/settings/managed_db_mariadb_encryption_key_enc', PLATFORM)).status, 403);
  } finally {
    routes.__setEngineForTests(null);
    srv.closeAllConnections?.(); srv.close();
  }
});
