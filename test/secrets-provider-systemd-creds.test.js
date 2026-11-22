import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'child_process';
import { createServer } from 'net';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { ROOT, K_A, K_B, sandboxTree, SANDBOX_NODE_FLAGS, cleanEnv } from './secrets-provider-fake.mjs';

// APPCRANE_SECRETS_PROVIDER=systemd-creds: boot from $CREDENTIALS_DIRECTORY,
// crane secrets migrate/status --provider systemd-creds, and rotate-key with
// the key in a credential. systemd-creds and systemctl are the fakes in
// test/fixtures/systemd-creds-fake (reversible "encryption", argv logged).

const FAKE_BIN = join(ROOT, 'test', 'fixtures', 'systemd-creds-fake');
const scratch = mkdtempSync(join(tmpdir(), 'crane-sdcreds-'));
const LOG = join(scratch, 'argv.log');
const ANTHROPIC = 'sk-ant-sensitive-systemd-value';
const NEW_KEY = 'c3'.repeat(32);
let seq = 0;
let sp, mig, status, restore, rotation, encryptFn, decryptFn;
const GOLDEN = join(scratch, 'golden');
const trees = [];
const children = [];

before(async () => {
  process.env.PATH = `${FAKE_BIN}:${process.env.PATH}`;
  process.env.FAKE_SYSTEMD_LOG = LOG;
  process.env.LOG_LEVEL = 'error';
  sp = await import('../server/services/secretsProvider/index.js');
  mig = await import('../server/services/secretsProvider/migrateSystemd.js');
  status = await import('../server/services/secretsProvider/status.js');
  restore = await import('../server/services/secretsProvider/restorePlan.js');
  rotation = await import('../server/services/keyRotation/index.js');

  mkdirSync(GOLDEN);
  process.env.DATA_DIR = GOLDEN;
  process.env.ENCRYPTION_KEY = K_A;
  const { initDb } = await import('../server/db.js');
  ({ encrypt: encryptFn, decrypt: decryptFn } = await import('../server/services/encryption.js'));
  const db = initDb(GOLDEN);
  const appId = Number(db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('a', 'sd-a', 1)").run().lastInsertRowid);
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'DB_URL', ?)").run(appId, encryptFn('postgres://p'));
  db.pragma('wal_checkpoint(TRUNCATE)');
  db.close();
  delete process.env.ENCRYPTION_KEY;
});
beforeEach(() => {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('APPCRANE_SECRETS_') || k.startsWith('FAKE_CREDS') || (k.startsWith('FAKE_SYSTEMCTL'))) delete process.env[k];
  }
  delete process.env.ENCRYPTION_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.CREDENTIALS_DIRECTORY;
  rmSync(LOG, { force: true });
});
after(() => {
  for (const c of children) { try { c.kill('SIGKILL'); } catch (_) {} }
  for (const d of trees) rmSync(d, { recursive: true, force: true });
  rmSync(scratch, { recursive: true, force: true });
});

const freePort = () => new Promise((res) => {
  const s = createServer();
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
});
const argvLog = () => (existsSync(LOG) ? readFileSync(LOG, 'utf8') : '');
const calls = () => argvLog().split('\n').filter(Boolean).map((l) => JSON.parse(l));

function credDir(files) {
  const dir = join(scratch, `creds${++seq}`);
  mkdirSync(dir);
  for (const [n, v] of Object.entries(files)) writeFileSync(join(dir, n), v);
  return dir;
}

/** A host: .env, data dir with a copy of the golden db, empty credstore/drop-in/backup locations. */
function host(envText = `PORT=5001\nENCRYPTION_KEY=${K_A}\n# a comment\nANTHROPIC_API_KEY=${ANTHROPIC}\nOTHER=1\n`) {
  const dir = join(scratch, `h${++seq}`);
  const dataDir = join(dir, 'data');
  mkdirSync(dataDir, { recursive: true });
  copyFileSync(join(GOLDEN, 'deployhub.db'), join(dataDir, 'deployhub.db'));
  const envPath = join(dir, '.env');
  writeFileSync(envPath, envText);
  chmodSync(envPath, 0o640);
  const h = {
    dir, dataDir, envPath, text: envText,
    credstore: join(dir, 'credstore'), dropinDir: join(dir, 'appcrane.service.d'), backupDir: join(dir, 'backup'),
  };
  process.env.FAKE_SYSTEMCTL_DROPIN_DIR = h.dropinDir;
  return h;
}
const migrate = async (h, extra = {}) => mig.migrateToSystemdCreds({
  envPath: h.envPath, dataDir: h.dataDir, port: await freePort(), credstore: h.credstore, dropinDir: h.dropinDir,
  backupDir: h.backupDir, requireRoot: false, ...extra,
});
const unchanged = (h) => {
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text, '.env changed');
  assert.ok(!existsSync(join(h.dropinDir, 'credentials.conf')), 'drop-in written');
  const creds = existsSync(h.credstore) ? readdirSync(h.credstore) : [];
  assert.deepEqual(creds, [], `credentials left: ${creds}`);
};
/** What systemd would hand the service: each credential the drop-in names, decrypted. */
function deliver(h) {
  const dir = join(scratch, `delivered${++seq}`);
  mkdirSync(dir);
  const text = readFileSync(join(h.dropinDir, 'credentials.conf'), 'utf8');
  for (const m of text.matchAll(/^LoadCredentialEncrypted=([^:]+):(.+)$/gm)) {
    const r = spawnSync(join(FAKE_BIN, 'systemd-creds'), ['decrypt', `--name=${m[1]}`, m[2], '-']);
    assert.equal(r.status, 0, String(r.stderr));
    writeFileSync(join(dir, m[1]), r.stdout);
  }
  return dir;
}

// ── boot ───────────────────────────────────────────────────────────────────

const SD = { APPCRANE_SECRETS_PROVIDER: 'systemd-creds' };

test('boot: loads the appcrane.* credentials, ignores files without the prefix', async () => {
  const env = { ...SD, CREDENTIALS_DIRECTORY: credDir({ 'appcrane.ENCRYPTION_KEY': `${K_A}\n`, 'appcrane.ANTHROPIC_API_KEY': ANTHROPIC, 'unrelated-cred': 'x' }) };
  const warns = [];
  const r = await sp.loadPlatformSecrets({ env, log: { warn: (m) => warns.push(m) } });
  assert.equal(r.active, true);
  assert.equal(r.provider, 'systemd-creds');
  assert.deepEqual(r.keys.sort(), ['ANTHROPIC_API_KEY', 'ENCRYPTION_KEY']);
  assert.equal(env.ENCRYPTION_KEY, K_A, 'trailing newline trimmed');
  assert.equal(env.ANTHROPIC_API_KEY, ANTHROPIC);
  assert.equal(env['unrelated-cred'], undefined);
  assert.deepEqual(warns, []);
});

test('boot: no CREDENTIALS_DIRECTORY fails closed, even with a working key in .env', async () => {
  await assert.rejects(sp.loadPlatformSecrets({ env: { ...SD, ENCRYPTION_KEY: K_A }, log: { warn() {} } }),
    (e) => /CREDENTIALS_DIRECTORY is not set/.test(e.message) && /appcrane\.ENCRYPTION_KEY/.test(e.message) && /crane secrets migrate --provider systemd-creds/.test(e.message) && !e.message.includes(K_A));
});

test('boot: a required credential missing fails closed, naming it and the drop-in line', async () => {
  const env = { ...SD, ENCRYPTION_KEY: K_A, APPCRANE_SECRETS_KEYS: 'ENCRYPTION_KEY,ANTHROPIC_API_KEY', CREDENTIALS_DIRECTORY: credDir({ 'appcrane.ENCRYPTION_KEY': K_A, ANTHROPIC_API_KEY: ANTHROPIC }) };
  await assert.rejects(sp.loadPlatformSecrets({ env, log: { warn() {} } }), (e) => {
    assert.match(e.message, /credential appcrane\.ANTHROPIC_API_KEY is missing/);
    assert.match(e.message, /LoadCredentialEncrypted=appcrane\.ANTHROPIC_API_KEY:\/etc\/credstore\.encrypted\/appcrane\.ANTHROPIC_API_KEY/);
    assert.match(e.message, /reads only names starting with appcrane\./, 'points at the unprefixed file');
    assert.ok(!e.message.includes(ANTHROPIC));
    return true;
  });
});

test('boot: a different value in .env fails closed', async () => {
  const env = { ...SD, ENCRYPTION_KEY: K_B, CREDENTIALS_DIRECTORY: credDir({ 'appcrane.ENCRYPTION_KEY': K_A }) };
  await assert.rejects(sp.loadPlatformSecrets({ env, log: { warn() {} } }), (e) => /ENCRYPTION_KEY differ between systemd credentials and \.env/.test(e.message) && !e.message.includes(K_A) && !e.message.includes(K_B));
  assert.equal(env.ENCRYPTION_KEY, K_B, 'nothing was set');
});

test('boot: an appcrane.* credential off the allowlist refuses the boot, by name, never its value', async () => {
  const env = { ...SD, CREDENTIALS_DIRECTORY: credDir({ 'appcrane.ENCRYPTION_KEY': K_A, 'appcrane.NODE_OPTIONS': '--require=/tmp/x' }) };
  await assert.rejects(sp.loadPlatformSecrets({ env, log: { warn() {} } }), (e) => /NODE_OPTIONS/.test(e.message) && /not allowed/.test(e.message) && !e.message.includes('/tmp/x'));
  assert.equal(env.NODE_OPTIONS, undefined);
  assert.equal(env.ENCRYPTION_KEY, undefined, 'nothing loaded when one is refused');
});

test('boot: an ENCRYPTION_KEY that is not 64 hex refuses', async () => {
  const env = { ...SD, CREDENTIALS_DIRECTORY: credDir({ 'appcrane.ENCRYPTION_KEY': 'short' }) };
  await assert.rejects(sp.loadPlatformSecrets({ env, log: { warn() {} } }), /ENCRYPTION_KEY must be 64 hex characters/);
});

// The real server/index.js from a sandbox tree, as the systemd unit starts it.
const SDK_SPY = (file) => `data:text/javascript,${encodeURIComponent(`
import { registerHooks } from 'node:module';
import { appendFileSync } from 'node:fs';
registerHooks({ resolve(s, c, n) { if (s.includes('@aws-sdk')) appendFileSync(${JSON.stringify(file)}, s + '\\n'); return n(s, c); } });
`)}`;

async function startServer(envText, extraEnv) {
  const dir = sandboxTree();
  trees.push(dir);
  writeFileSync(join(dir, '.env'), envText);
  const port = await freePort();
  const spy = join(dir, 'sdk-resolves.txt');
  const c = spawn(process.execPath, [...SANDBOX_NODE_FLAGS, '--import', SDK_SPY(spy), 'server/index.js'], {
    cwd: dir,
    env: cleanEnv({ DATA_DIR: join(dir, 'data'), PORT: String(port), HOST: '127.0.0.1', CRANE_DOMAIN: 'crane.example.com', ...extraEnv }),
  });
  children.push(c);
  const s = { all: '', code: undefined, base: `http://127.0.0.1:${port}`, child: c, dir, spy };
  c.stdout.on('data', (d) => { s.all += d; });
  c.stderr.on('data', (d) => { s.all += d; });
  s.exited = new Promise((res) => c.on('exit', (code) => { s.code = code; res(code); }));
  return s;
}

test('real boot: server/index.js starts from the credentials, the AWS SDK never resolved, no value printed', async () => {
  const s = await startServer('APPCRANE_SECRETS_PROVIDER=systemd-creds\n', { CREDENTIALS_DIRECTORY: credDir({ 'appcrane.ENCRYPTION_KEY': K_A }) });
  let up = false;
  for (let i = 0; i < 240 && s.code === undefined; i++) {
    try { if ((await fetch(`${s.base}/api/info`)).ok) { up = true; break; } } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  s.child.kill('SIGTERM');
  await s.exited;
  assert.ok(up, s.all.slice(-2000));
  assert.match(s.all, /platform secret loaded \(keys: ENCRYPTION_KEY\)/);
  assert.equal(existsSync(s.spy), false, 'the AWS SDK was resolved');
  assert.ok(!s.all.includes(K_A));
});

test('real boot: no CREDENTIALS_DIRECTORY, key in .env: exit 1 before the database is opened', async () => {
  const s = await startServer(`APPCRANE_SECRETS_PROVIDER=systemd-creds\nENCRYPTION_KEY=${K_A}\n`, {});
  const code = await Promise.race([s.exited, new Promise((r) => setTimeout(() => r('timeout'), 60000))]);
  assert.equal(code, 1, s.all.slice(-1500));
  assert.match(s.all, /AppCrane cannot start: the platform secret could not be loaded\. APPCRANE_SECRETS_PROVIDER=systemd-creds but CREDENTIALS_DIRECTORY is not set/);
  assert.ok(!existsSync(join(s.dir, 'data', 'deployhub.db')));
  assert.ok(!s.all.includes(K_A));
});

// ── migrate ────────────────────────────────────────────────────────────────

test('migrate --dry-run changes nothing and encrypts nothing', async () => {
  const h = host();
  const r = await migrate(h, { dryRun: true });
  assert.equal(r.dry_run, true);
  assert.deepEqual(r.moved, ['ENCRYPTION_KEY'], 'ENCRYPTION_KEY only by default');
  assert.deepEqual(r.left_in_env, ['ANTHROPIC_API_KEY']);
  assert.deepEqual(r.credentials.map((c) => c.action), ['write']);
  assert.match(r.dropin_text, /LoadCredentialEncrypted=appcrane\.ENCRYPTION_KEY:/);
  unchanged(h);
  assert.ok(!existsSync(h.backupDir), 'no backup written');
  assert.ok(!calls().some((c) => c[1] === 'encrypt' || c[1] === 'daemon-reload'), argvLog());
  assert.ok(!JSON.stringify(r).includes(K_A) && !JSON.stringify(r).includes(ANTHROPIC), 'no value in the result');
});

const BOTH = ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY'];

test('migrate --keys both: credentials + drop-in written, only the key lines leave .env, mode kept, backup 0600, next boot loads them', async () => {
  const h = host();
  const steps = [];
  const r = await migrate(h, { keys: BOTH, onStep: (s) => steps.push(s) });
  assert.deepEqual(steps, ['backup', 'credentials-written', 'dropin-written', 'daemon-reloaded', 'env-committed']);

  const expected = `PORT=5001\n# a comment\nOTHER=1\nAPPCRANE_SECRETS_PROVIDER=systemd-creds\nAPPCRANE_SECRETS_KEYS=ENCRYPTION_KEY,ANTHROPIC_API_KEY\n`
    + `APPCRANE_SECRETS_CREDSTORE=${h.credstore}\nAPPCRANE_SECRETS_DROPIN_DIR=${h.dropinDir}\n`;
  assert.equal(readFileSync(h.envPath, 'utf8'), expected);
  assert.equal(statSync(h.envPath).mode & 0o777, 0o640, '.env mode kept');

  assert.deepEqual(readdirSync(h.credstore).sort(), ['appcrane.ANTHROPIC_API_KEY', 'appcrane.ENCRYPTION_KEY']);
  for (const f of readdirSync(h.credstore)) {
    assert.equal(statSync(join(h.credstore, f)).mode & 0o777, 0o600, `${f} mode`);
    assert.ok(!readFileSync(join(h.credstore, f), 'utf8').includes(K_A));
  }
  assert.equal(statSync(h.credstore).mode & 0o777, 0o700);
  const dropin = readFileSync(join(h.dropinDir, 'credentials.conf'), 'utf8');
  assert.match(dropin, /^\[Service\]$/m);
  assert.match(dropin, new RegExp(`^LoadCredentialEncrypted=appcrane\\.ENCRYPTION_KEY:${h.credstore}/appcrane\\.ENCRYPTION_KEY$`, 'm'));
  assert.match(dropin, new RegExp(`^LoadCredentialEncrypted=appcrane\\.ANTHROPIC_API_KEY:${h.credstore}/appcrane\\.ANTHROPIC_API_KEY$`, 'm'));

  assert.equal(readFileSync(r.backup, 'utf8'), h.text, 'backup is the old .env');
  assert.equal(statSync(r.backup).mode & 0o777, 0o600);
  assert.equal(statSync(h.backupDir).mode & 0o777, 0o700);
  assert.ok(calls().some((c) => c[0] === 'systemctl' && c[1] === 'daemon-reload'));
  assert.ok(r.rollback.some((s) => s.includes(`install -m 0640`) && s.includes(r.backup)));

  // What the next boot does: the .env the server will read, plus what systemd delivers.
  const { parseEnvText } = await import('../server/services/secretsProvider/envText.js');
  const env = { ...parseEnvText(readFileSync(h.envPath, 'utf8')), CREDENTIALS_DIRECTORY: deliver(h) };
  const booted = await sp.loadPlatformSecrets({ env, log: { warn() {} } });
  assert.deepEqual(booted.keys.sort(), ['ANTHROPIC_API_KEY', 'ENCRYPTION_KEY']);
  assert.equal(env.ENCRYPTION_KEY, K_A);
});

test('migrate: no value ever in argv; values go in on stdin', async () => {
  const h = host();
  await migrate(h, { keys: BOTH });
  const log = argvLog();
  assert.ok(calls().filter((c) => c[1] === 'encrypt').length === 2, log);
  assert.ok(calls().every((c) => c[0] !== 'systemd-creds' || c[1] !== 'encrypt' || c[3] === '-'), 'encrypt reads stdin');
  assert.ok(!log.includes(K_A), 'ENCRYPTION_KEY in argv');
  assert.ok(!log.includes(ANTHROPIC), 'ANTHROPIC_API_KEY in argv');
});

test('migrate: a credential that does not decrypt back leaves .env, the store and the drop-in untouched', async () => {
  const h = host();
  process.env.FAKE_CREDS_FAULT = 'decrypt-mismatch';
  await assert.rejects(migrate(h), (e) => /did not decrypt back to the value in \.env\. \.env was not changed/.test(e.message) && !!e.backup && !e.message.includes(K_A));
  unchanged(h);
});

test('migrate: encrypt failing leaves .env untouched and scrubs the value from the error', async () => {
  const h = host();
  process.env.FAKE_CREDS_FAULT = 'encrypt-fail';
  await assert.rejects(migrate(h), /systemd-creds encrypt of appcrane\.ENCRYPTION_KEY failed/);
  unchanged(h);
});

test('migrate: daemon-reload failing leaves .env untouched', async () => {
  const h = host();
  process.env.FAKE_SYSTEMCTL_RELOAD_FAIL = '1';
  await assert.rejects(migrate(h), /daemon-reload failed.*\.env was not changed/);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
});

test('migrate: systemd not seeing the drop-in leaves .env untouched', async () => {
  const h = host();
  process.env.FAKE_SYSTEMCTL_DROPIN_DIR = join(h.dir, 'elsewhere');
  await assert.rejects(migrate(h), /does not list .*credentials\.conf as a drop-in/);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
});

test('migrate refuses: unit active, unknown unit, other provider, different existing credential, not root', async () => {
  let h = host();
  process.env.FAKE_SYSTEMCTL_ACTIVE = '1';
  await assert.rejects(migrate(h), /appcrane\.service is active/);
  delete process.env.FAKE_SYSTEMCTL_ACTIVE;
  process.env.FAKE_SYSTEMCTL_LOADSTATE = 'not-found';
  await assert.rejects(migrate(h), /systemd has no unit appcrane\.service/);
  delete process.env.FAKE_SYSTEMCTL_LOADSTATE;
  unchanged(h);

  h = host(`APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nENCRYPTION_KEY=${K_A}\n`);
  await assert.rejects(migrate(h), /already uses APPCRANE_SECRETS_PROVIDER=aws-secrets-manager/);

  h = host(`ENCRYPTION_KEY=${K_A}\n`);
  mkdirSync(h.credstore);
  const other = spawnSync(join(FAKE_BIN, 'systemd-creds'), ['encrypt', '--name=appcrane.ENCRYPTION_KEY', '-', join(h.credstore, 'appcrane.ENCRYPTION_KEY')], { input: K_B });
  assert.equal(other.status, 0);
  await assert.rejects(migrate(h), /already holds a different ENCRYPTION_KEY/);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);

  h = host();
  if (process.geteuid() !== 0) await assert.rejects(migrate(h, { requireRoot: true }), /run as root/);
  unchanged(h);
});

test('migrate: a re-run after a crash before the .env rename reuses the sealed credential', async () => {
  const h = host(`ENCRYPTION_KEY=${K_A}\n`);
  await assert.rejects(migrate(h, { onStep: (s) => { if (s === 'daemon-reloaded') throw new Error('crash'); } }), /crash/);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text, 'the host still boots from .env');
  const r = await migrate(h);
  assert.deepEqual(r.credentials.map((c) => c.action), ['reuse (same value)']);
  assert.equal(calls().filter((c) => c[1] === 'encrypt').length, 1, 'sealed once');
  assert.doesNotMatch(readFileSync(h.envPath, 'utf8'), /ENCRYPTION_KEY=/);
});

test('migrate: default moves ENCRYPTION_KEY and leaves ANTHROPIC_API_KEY in .env; absent is not an error', async () => {
  const k = host();
  const d = await migrate(k);
  assert.deepEqual(d.moved, ['ENCRYPTION_KEY']);
  assert.equal(readFileSync(k.envPath, 'utf8').split('\n').filter((l) => l.startsWith('ANTHROPIC_API_KEY=')).length, 1);
  await assert.rejects(migrate(host(`OTHER=1\n`), { keys: ['ANTHROPIC_API_KEY'] }), /ANTHROPIC_API_KEY not in/);
  const h = host(`ENCRYPTION_KEY=${K_A}\nOTHER=1`);
  const r = await migrate(h, { keys: BOTH.filter((x) => x !== 'ANTHROPIC_API_KEY') });
  assert.deepEqual(r.moved, ['ENCRYPTION_KEY']);
  assert.match(readFileSync(h.envPath, 'utf8'), /^OTHER=1\nAPPCRANE_SECRETS_PROVIDER=systemd-creds\nAPPCRANE_SECRETS_KEYS=ENCRYPTION_KEY\n/);
});

test('crane secrets migrate --provider systemd-creds --dry-run (the CLI)', async () => {
  const h = host();
  const r = spawnSync(process.execPath, ['cli/index.js', 'secrets', 'migrate', '--provider', 'systemd-creds', '--dry-run',
    '--env-file', h.envPath, '--data-dir', h.dataDir, '--port', String(await freePort()),
    '--credstore-dir', h.credstore, '--dropin-dir', h.dropinDir, '--backup-dir', h.backupDir], { cwd: ROOT, env: { ...process.env }, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /Dry run: nothing was changed/);
  assert.match(r.stdout, /LoadCredentialEncrypted=appcrane\.ENCRYPTION_KEY:/);
  assert.match(r.stdout, /To roll back:/);
  assert.ok(!r.stdout.includes(K_A) && !r.stdout.includes(ANTHROPIC));
  unchanged(h);
});

// ── status ─────────────────────────────────────────────────────────────────

test('status: drop-in, credential files, keys a boot would load, keys still in .env (names only)', async () => {
  const h = host(`ENCRYPTION_KEY=${K_A}\nANTHROPIC_API_KEY=${ANTHROPIC}\n`);
  await migrate(h, { keys: ['ENCRYPTION_KEY'] });
  const s = await status.secretsStatus({ envPath: h.envPath });
  assert.equal(s.provider, 'systemd-creds');
  assert.equal(s.dropin_present, true);
  assert.equal(s.unit_sees_dropin, true);
  assert.deepEqual(s.dropin_keys, ['ENCRYPTION_KEY']);
  assert.deepEqual(s.credentials.map((c) => [c.key, c.present]), [['ENCRYPTION_KEY', true]]);
  assert.deepEqual(s.still_in_env_file, [], 'ANTHROPIC_API_KEY is not a provider key any more: the boot moves it into the database');
  assert.deepEqual(s.problems, []);
  assert.equal(s.imds, null, 'no AWS probe');
  assert.ok(!JSON.stringify(s).includes(K_A) && !JSON.stringify(s).includes(ANTHROPIC));

  rmSync(join(h.credstore, 'appcrane.ENCRYPTION_KEY'));
  for (const k of Object.keys(process.env)) if (k.startsWith('APPCRANE_SECRETS_')) delete process.env[k];
  const s2 = await status.secretsStatus({ envPath: h.envPath });
  assert.deepEqual(s2.problems, [`${h.credstore}/appcrane.ENCRYPTION_KEY is missing`]);
});

// ── rotate-key ─────────────────────────────────────────────────────────────

const dbValue = (h) => {
  const db = new Database(join(h.dataDir, 'deployhub.db'), { readonly: true });
  const v = db.prepare("SELECT value_encrypted AS v FROM env_vars WHERE key = 'DB_URL'").get().v;
  db.close();
  return v;
};
const opensWith = (h, key) => { try { return decryptFn(dbValue(h), key) === 'postgres://p'; } catch { return false; } };
const credValue = (h) => spawnSync(join(FAKE_BIN, 'systemd-creds'), ['decrypt', '--name=appcrane.ENCRYPTION_KEY', join(h.credstore, 'appcrane.ENCRYPTION_KEY'), '-'], { encoding: 'utf8' }).stdout;

test('rotate-key: the new key is sealed into the credential, never written to .env', async () => {
  const h = host(`ENCRYPTION_KEY=${K_A}\nOTHER=1\n`);
  await migrate(h);
  for (const k of Object.keys(process.env)) if (k.startsWith('APPCRANE_SECRETS_')) delete process.env[k];
  const envBefore = readFileSync(h.envPath, 'utf8');
  rmSync(LOG, { force: true });
  const res = await rotation.rotateKey({ dataDir: h.dataDir, envPath: h.envPath, port: await freePort(), newKey: NEW_KEY });
  assert.deepEqual(res.report.post_check, { ok: true });
  assert.equal(res.provider.kind, 'systemd-creds');
  assert.equal(credValue(h), NEW_KEY);
  assert.ok(opensWith(h, NEW_KEY) && !opensWith(h, K_A));
  assert.equal(readFileSync(h.envPath, 'utf8'), envBefore, '.env not touched');
  assert.ok(!readFileSync(h.envPath, 'utf8').includes(NEW_KEY));
  assert.ok(!existsSync(join(h.credstore, 'appcrane.ENCRYPTION_KEY.pending')));
  const prev = spawnSync(join(FAKE_BIN, 'systemd-creds'), ['decrypt', '--name=appcrane.ENCRYPTION_KEY', res.provider.previous_copy, '-'], { encoding: 'utf8' }).stdout;
  assert.equal(prev, K_A, 'the old credential is in the backup folder');
  assert.ok(!argvLog().includes(NEW_KEY) && !argvLog().includes(K_A), 'no key in argv');
});

test('rotate-key: the new credential not decrypting back leaves the database and the credential as they were', async () => {
  const h = host(`ENCRYPTION_KEY=${K_A}\n`);
  await migrate(h);
  for (const k of Object.keys(process.env)) if (k.startsWith('APPCRANE_SECRETS_')) delete process.env[k];
  process.env.FAKE_CREDS_FAULT = 'decrypt-mismatch';
  await assert.rejects(rotation.rotateKey({ dataDir: h.dataDir, envPath: h.envPath, port: await freePort(), newKey: NEW_KEY }));
  delete process.env.FAKE_CREDS_FAULT;
  assert.equal(credValue(h), K_A);
  assert.ok(opensWith(h, K_A) && !opensWith(h, NEW_KEY));
  assert.ok(!existsSync(join(h.credstore, 'appcrane.ENCRYPTION_KEY.pending')));
});

// ── what systemd-creds does not do ─────────────────────────────────────────

test('app secret references stay AWS-only: no AWS call, a clear error', async () => {
  process.env.APPCRANE_SECRETS_PROVIDER = 'systemd-creds';
  assert.equal(sp.appSecretsAvailable(), false);
  const ns = 'a'.repeat(32);
  await assert.rejects(sp.putAppSecret(ns, 'production', 'DB', 'v'), (e) => e.code === 'APP_SECRETS_UNSUPPORTED' && /need APPCRANE_SECRETS_PROVIDER=aws-secrets-manager/.test(e.message));
  await assert.rejects(sp.getAppSecret(ns, 'production', 'DB'), (e) => e.code === 'APP_SECRETS_UNSUPPORTED');
  await assert.rejects(sp.setPlatformSecretKey('ANTHROPIC_API_KEY', 'x'), /systemd credential, which only root can write/);
});

test('restore onto a systemd-creds host: same key merges (key line dropped, settings kept), a different key refuses', async () => {
  const env = { ...SD, CREDENTIALS_DIRECTORY: credDir({ 'appcrane.ENCRYPTION_KEY': K_A }) };
  await sp.loadPlatformSecrets({ env, log: { warn() {} } });
  const same = restore.planRestoredEnv(`ENCRYPTION_KEY=${K_A}\nOTHER=1\n`, { env });
  assert.equal(same.action, 'merge');
  assert.equal(same.text, 'OTHER=1\nAPPCRANE_SECRETS_PROVIDER=systemd-creds\n');
  const diff = restore.planRestoredEnv(`ENCRYPTION_KEY=${K_B}\n`, { env });
  assert.equal(diff.action, 'refuse');
  assert.match(diff.message, /systemd credential/);
  const note = sp.backupSecretsNote(env);
  assert.equal(note.provider, 'systemd-creds');
  assert.equal(note.encryption_key_in_provider, true);
  assert.match(note.note, /sealed with this host's \/var\/lib\/systemd\/credential\.secret/);
});
