import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { createServer } from 'net';
import http from 'http';
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { fakeSecretsManager, ROOT, K_A, K_B, cleanEnv } from './secrets-provider-fake.mjs';

// crane secrets migrate / status. Crash points are real: a child process
// SIGKILLs itself at each step, so no finally block tidies up after it.

const sm = fakeSecretsManager();
const scratch = mkdtempSync(join(tmpdir(), 'crane-migrate-'));
const ANTHROPIC = 'sk-ant-sensitive-value';
const NOT_MEASURED = { status: 'not_measured', token: null, v1: null, detail: 'test', fix: null };
let M, P, seq = 0;

before(async () => {
  await sm.start();
  Object.assign(process.env, sm.awsEnv());
  delete process.env.ENCRYPTION_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  M = await import('../server/services/secretsProvider/migrate.js');
  P = await import('../server/services/secretsProvider/index.js');
});
beforeEach(() => {
  sm.secrets.clear();
  sm.calls.length = 0;
  for (const k of Object.keys(sm.faults)) delete sm.faults[k];
});
after(() => { sm.stop(); rmSync(scratch, { recursive: true, force: true }); });

const freePort = () => new Promise((res) => {
  const s = createServer();
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
});

function host({ key = K_A, anthropic = ANTHROPIC } = {}) {
  const dir = join(scratch, `h${++seq}`);
  const dataDir = join(dir, 'data');
  mkdirSync(dataDir, { recursive: true });
  const envPath = join(dir, '.env');
  writeFileSync(envPath, `# keep this comment\nPORT=1\n${key ? `ENCRYPTION_KEY=${key}\n` : ''}${anthropic ? `ANTHROPIC_API_KEY=${anthropic}\n` : ''}OTHER=1\n`);
  return { dir, dataDir, envPath, text: readFileSync(envPath, 'utf8') };
}

const opts = async (h, extra = {}) => ({ secretId: 'plat', envPath: h.envPath, dataDir: h.dataDir, port: await freePort(), probe: async () => NOT_MEASURED, readBackDelayMs: 1, ...extra });

// What the server's boot would end up with from this .env.
async function bootKey(envPath) {
  const { parseEnvText } = await import('../server/services/secretsProvider/envText.js');
  const env = { ...parseEnvText(readFileSync(envPath, 'utf8')), AWS_REGION: 'us-east-1' };
  await P.loadPlatformSecrets({ env, log: { warn() {} } });
  return env.ENCRYPTION_KEY;
}

// ── the normal run ─────────────────────────────────────────────────────────

test('migrate creates the secret, removes the lines, adds the settings, keeps the rest', async () => {
  const h = host();
  const res = await M.migrateToSecretsManager(await opts(h, { region: 'us-east-1' }));
  assert.deepEqual(JSON.parse(sm.current('plat')), { ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: ANTHROPIC });
  assert.equal(readFileSync(h.envPath, 'utf8'), '# keep this comment\nPORT=1\nOTHER=1\nAPPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=plat\nAPPCRANE_SECRETS_REGION=us-east-1\n');
  assert.deepEqual(res.moved, ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY']);
  assert.deepEqual(res.boot_check_keys.sort(), ['ANTHROPIC_API_KEY', 'ENCRYPTION_KEY']);
  assert.ok(!JSON.stringify(res).includes(K_A) && !JSON.stringify(res).includes(ANTHROPIC));
  assert.equal(await bootKey(h.envPath), K_A);
  assert.ok(!sm.calls.some((c) => c.op === 'PutSecretValue'), 'a new name is created, not put');
});

test('ANTHROPIC_API_KEY is optional', async () => {
  const h = host({ anthropic: null });
  const res = await M.migrateToSecretsManager(await opts(h));
  assert.deepEqual(res.moved, ['ENCRYPTION_KEY']);
  assert.deepEqual(JSON.parse(sm.current('plat')), { ENCRYPTION_KEY: K_A });
});

test('an existing secret gets a new version: placeholder dropped, other keys kept', async () => {
  sm.seed('plat', JSON.stringify({ PLACEHOLDER: 'generated', SMTP_PASS: 'keep' }));
  const h = host();
  await M.migrateToSecretsManager(await opts(h));
  assert.deepEqual(JSON.parse(sm.current('plat')), { SMTP_PASS: 'keep', ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: ANTHROPIC });
  assert.ok(sm.calls.some((c) => c.op === 'PutSecretValue'));
});

test('--dry-run writes nothing', async () => {
  const h = host();
  const res = await M.migrateToSecretsManager(await opts(h, { dryRun: true }));
  assert.equal(res.dry_run, true);
  assert.equal(sm.writes().length, 0);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
  assert.equal(sm.secrets.size, 0);
});

// ── refusals: all before any change ────────────────────────────────────────

async function refused(h, extra, pattern) {
  const err = await M.migrateToSecretsManager(await opts(h, extra)).then(() => null, (e) => e);
  assert.ok(err, 'must refuse');
  assert.match(err.message, pattern);
  assert.ok(!err.message.includes(K_A) && !err.message.includes(ANTHROPIC), err.message);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text, '.env unchanged');
  assert.equal(sm.writes().length, 0, 'nothing written to the secret');
  return err;
}

test('refuses while AppCrane answers on the port', async () => {
  const srv = http.createServer((q, s) => s.end('ok'));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  await refused(host(), { port: srv.address().port }, /Stop it first/);
  srv.close();
});

test('refuses while the database is open in another process', async () => {
  const h = host();
  const dbPath = join(h.dataDir, 'deployhub.db');
  const seed = new Database(dbPath);
  seed.pragma('journal_mode = WAL');
  seed.exec('CREATE TABLE t (x)');
  await refused(h, {}, /Stop it first/);
  seed.close();
});

test('refuses when the secret already holds a different key, because overwriting could lose it', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_B }));
  const err = await refused(host(), {}, /already holds a different ENCRYPTION_KEY/);
  assert.ok(!err.message.includes(K_B));
  assert.equal(JSON.parse(sm.current('plat')).ENCRYPTION_KEY, K_B);
});

test('refuses a secret that is not a JSON object rather than replace it', async () => {
  sm.seed('plat', 'sensitive!');
  const err = await refused(host(), {}, /not a JSON object/);
  assert.doesNotMatch(err.message, /sensitive!/);
});

test('refuses a key set in this shell that differs from .env', async () => {
  process.env.ENCRYPTION_KEY = K_B;
  try {
    await refused(host(), {}, /set in this shell/);
  } finally {
    delete process.env.ENCRYPTION_KEY;
  }
});

test('refuses bad input and hosts with nothing to move', async () => {
  await refused(host(), { secretId: 'a\nENCRYPTION_KEY=evil' }, /not a valid secret/);
  await refused(host(), { region: 'x y' }, /not a valid region/);
  await refused(host({ key: null, anthropic: null }), {}, /nothing to move/);
  await refused(host({ key: null }), {}, /no ENCRYPTION_KEY/);
  await refused(host({ key: 'tooshort' }), {}, /64 hex/);
});

test('refuses when .env already points at another secret', async () => {
  const h = host();
  writeFileSync(h.envPath, `${h.text}APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=other\n`);
  h.text = readFileSync(h.envPath, 'utf8');
  await refused(h, {}, /another platform secret/);
});

const EXPOSED = { status: 'exposed', token: '200', v1: '401', detail: 'test', fix: 'the fix' };

test('IMDS exposed: refused unless accepted; not measured never blocks and is never called safe', async () => {
  const err = await refused(host(), { probe: async () => EXPOSED }, /--accept-imds-exposure/);
  assert.match(err.message, /http-put-response-hop-limit 1/);
  const res = await M.migrateToSecretsManager(await opts(host(), { probe: async () => EXPOSED, acceptImdsExposure: true }));
  assert.equal(res.imds.status, 'exposed');
  sm.secrets.clear();
  const res2 = await M.migrateToSecretsManager(await opts(host()));
  assert.equal(res2.imds.status, 'not_measured');
});

// ── failures and crashes: the host must still boot ─────────────────────────

test('a failed write leaves .env as it was', async () => {
  const h = host();
  sm.faults.CreateSecret = (input) => sm.err('InternalServiceError', `echo ${input.SecretString}`);
  const err = await M.migrateToSecretsManager(await opts(h)).then(() => null, (e) => e);
  assert.ok(err);
  assert.ok(!err.message.includes(K_A) && !err.message.includes(ANTHROPIC), err.message);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
  assert.equal(await bootKey(h.envPath), K_A);
});

test('a read-back that does not match leaves .env as it was', async () => {
  const h = host();
  sm.seed('plat', JSON.stringify({ PLACEHOLDER: 'x' }));
  let reads = 0;
  sm.faults.GetSecretValue = () => (++reads > 1 ? { reply: { VersionId: 'v', SecretString: JSON.stringify({ ENCRYPTION_KEY: K_B }) } } : undefined);
  const err = await M.migrateToSecretsManager(await opts(h)).then(() => null, (e) => e);
  assert.match(err.message, /did not read back/);
  assert.ok(!err.message.includes(K_A) && !err.message.includes(K_B));
  assert.equal(reads, 5, 'the first read plus four tries');
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
});

test('a read-back that keeps failing leaves .env as it was', async () => {
  const h = host();
  sm.seed('plat', JSON.stringify({ PLACEHOLDER: 'x' }));
  let reads = 0;
  sm.faults.GetSecretValue = () => (++reads > 1 ? sm.err('ResourceNotFoundException', 'gone') : undefined);
  await assert.rejects(M.migrateToSecretsManager(await opts(h)), /ResourceNotFoundException/);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
});

test('a read-back that only shows the new values on a later try succeeds', async () => {
  const h = host();
  let reads = 0;
  sm.faults.GetSecretValue = () => { reads++; return reads === 1 || reads === 2 ? sm.err('ResourceNotFoundException', 'not yet') : undefined; };
  await M.migrateToSecretsManager(await opts(h));
  assert.ok(!readFileSync(h.envPath, 'utf8').includes('ENCRYPTION_KEY'));
});

const CRASH_CHILD = (h, port, step) => `
import { migrateToSecretsManager } from ${JSON.stringify(join(ROOT, 'server/services/secretsProvider/migrate.js'))};
await migrateToSecretsManager({ secretId: 'plat', envPath: ${JSON.stringify(h.envPath)}, dataDir: ${JSON.stringify(h.dataDir)}, port: ${port},
  probe: async () => ({ status: 'not_measured', detail: 't' }),
  onStep(s) { if (s === ${JSON.stringify(step)}) process.kill(process.pid, 'SIGKILL'); } });
console.log('FINISHED');
`;

function runChild(code, env) {
  return new Promise((res) => {
    const c = spawn(process.execPath, ['--input-type=module', '-e', code], { cwd: ROOT, env });
    let out = '';
    c.stdout.on('data', (d) => { out += d; });
    c.stderr.on('data', (d) => { out += d; });
    c.on('close', (code2, signal) => res({ code: code2, signal, out }));
  });
}

for (const step of ['secret-written', 'read-back', 'env-staged', 'env-committed']) {
  test(`SIGKILL at ${step}: the host boots with the same key, and a re-run finishes`, async () => {
    const h = host();
    const r = await runChild(CRASH_CHILD(h, await freePort(), step), cleanEnv(sm.awsEnv()));
    assert.equal(r.signal, 'SIGKILL', r.out);
    assert.equal(await bootKey(h.envPath), K_A);
    const committed = step === 'env-committed';
    assert.equal(readFileSync(h.envPath, 'utf8').includes(K_A), !committed);

    if (!committed) {
      const writes = sm.writes().length;
      await M.migrateToSecretsManager(await opts(h));
      assert.equal(sm.writes().length, writes, 'the secret already holds these values: no second version');
    }
    assert.ok(!readFileSync(h.envPath, 'utf8').includes(K_A));
    assert.equal(await bootKey(h.envPath), K_A);
  });
}

// ── what it reports ────────────────────────────────────────────────────────

test('oldKeyCopies lists files and archives holding a key, by name, and says what it could not read', async () => {
  const h = host();
  const d = h.dataDir;
  const snap = join(d, 'update-snapshots', '20260101T000000Z');
  const clean = join(d, 'update-snapshots', '20260102T000000Z');
  const rot = join(d, 'backups', 'key-rotation-x');
  const pre = join(d, 'pre-import-1');
  for (const x of [snap, clean, rot, pre, join(d, 'backups', 'local')]) mkdirSync(x, { recursive: true });
  writeFileSync(join(snap, 'env.backup'), `ENCRYPTION_KEY=${K_A}\n`);
  writeFileSync(join(clean, 'env.backup'), 'APPCRANE_SECRETS_ID=plat\n');
  writeFileSync(join(rot, 'env.backup'), `ENCRYPTION_KEY=${K_A}\n`);
  writeFileSync(join(pre, '.env'), `ENCRYPTION_KEY=${K_A}\n`);
  const stage = join(h.dir, 'stage');
  mkdirSync(stage);
  writeFileSync(join(stage, '.env'), `ENCRYPTION_KEY=${K_A}\n`);
  writeFileSync(join(stage, 'other'), 'x');
  execFileSync('tar', ['-czf', join(d, 'backups', 'local', 'appcrane-backup-a.tar.gz'), '-C', stage, '.env']);
  execFileSync('tar', ['-czf', join(d, 'backups', 'no-env.tar.gz'), '-C', stage, 'other']);
  writeFileSync(join(d, 'backups', 'broken.tar.gz'), 'not a tar');
  writeFileSync(join(d, 'backups', 'old.zip'), 'zip');
  const res = await M.oldKeyCopies(d);
  assert.deepEqual(res.files.sort(), [join(snap, 'env.backup'), join(rot, 'env.backup'), join(pre, '.env')].sort());
  assert.deepEqual(res.archives, [join(d, 'backups', 'local', 'appcrane-backup-a.tar.gz')]);
  assert.deepEqual(res.uninspected.sort(), [join(d, 'backups', 'broken.tar.gz'), join(d, 'backups', 'old.zip')].sort());
  assert.ok(!JSON.stringify(res).includes(K_A));
});

// The real CLI. PATH holds tar and no docker, so IMDS is "not measured" without Docker.
function crane(args, h, extraEnv = {}) {
  const bin = join(scratch, 'bin');
  if (!existsSync(bin)) { mkdirSync(bin); symlinkSync(execFileSync('sh', ['-c', 'command -v tar']).toString().trim(), join(bin, 'tar')); }
  return new Promise((res) => {
    const c = spawn(process.execPath, ['cli/index.js', 'secrets', ...args, '--env-file', h.envPath], { cwd: ROOT, env: cleanEnv({ ...sm.awsEnv(), PATH: bin, ...extraEnv }) });
    let stdout = '', stderr = '';
    c.stdout.on('data', (d) => { stdout += d; });
    c.stderr.on('data', (d) => { stderr += d; });
    c.on('close', (code) => res({ code, stdout, stderr, all: stdout + stderr }));
  });
}

test('CLI: status before, migrate, status after: names only, never a value', async () => {
  const h = host();
  const snap = join(h.dataDir, 'update-snapshots', 's1');
  mkdirSync(snap, { recursive: true });
  writeFileSync(join(snap, 'env.backup'), `ENCRYPTION_KEY=${K_A}\n`);

  const s1 = await crane(['status'], h);
  assert.equal(s1.code, 0, s1.all);
  assert.match(s1.all, /not configured/);
  assert.match(s1.all, /ENCRYPTION_KEY, ANTHROPIC_API_KEY/);
  assert.match(s1.all, /not measured/);
  assert.doesNotMatch(s1.all, /\bsafe\b/i);

  const dry = await crane(['migrate', '--secret-id', 'plat', '--dry-run', '--data-dir', h.dataDir, '--port', String(await freePort())], h);
  assert.equal(dry.code, 0, dry.all);
  assert.match(dry.all, /Dry run/);
  assert.equal(sm.writes().length, 0);

  const m = await crane(['migrate', '--secret-id', 'plat', '--region', 'us-east-1', '--data-dir', h.dataDir, '--port', String(await freePort())], h);
  assert.equal(m.code, 0, m.all);
  assert.match(m.all, /Moved ENCRYPTION_KEY, ANTHROPIC_API_KEY to plat/);
  assert.ok(m.all.includes(join(snap, 'env.backup')), 'names the copy');
  assert.match(m.all, /crane rotate-key/);

  const s2 = await crane(['status', '--json'], h);
  assert.equal(s2.code, 0, s2.all);
  const st = JSON.parse(s2.stdout);
  assert.equal(st.provider, 'aws-secrets-manager');
  assert.equal(st.secret_id, 'plat');
  assert.equal(st.region, 'us-east-1');
  assert.equal(st.current_readable, true);
  assert.deepEqual(st.keys, ['ANTHROPIC_API_KEY', 'ENCRYPTION_KEY']);
  assert.deepEqual(st.still_in_env_file, []);
  assert.equal(st.imds.status, 'not_measured');

  for (const r of [s1, dry, m, s2]) {
    assert.ok(!r.all.includes(K_A) && !r.all.includes(ANTHROPIC), 'no value in stdout or stderr');
  }
});

test('CLI: status exits non-zero when the secret cannot be read, and a failed migrate exits non-zero with no value', async () => {
  const h = host();
  const fail = await crane(['migrate', '--secret-id', 'plat', '--data-dir', h.dataDir, '--port', String(await freePort())], h, { AWS_ENDPOINT_URL_SECRETS_MANAGER: 'http://127.0.0.1:1' });
  assert.notEqual(fail.code, 0);
  assert.ok(!fail.all.includes(K_A) && !fail.all.includes(ANTHROPIC));
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);

  writeFileSync(h.envPath, 'APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=absent\n');
  const st = await crane(['status'], h);
  assert.equal(st.code, 1);
  assert.match(st.all, /AWSCURRENT readable\s+NO/);
  assert.match(st.all, /ResourceNotFoundException/);
});

test('status flags an AWSPENDING version left by an interrupted rotation', async () => {
  const h = host({ key: null, anthropic: null });
  writeFileSync(h.envPath, 'APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=plat\n');
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  sm.secrets.get('plat').versions.set('pending-id', { text: '{}', stages: new Set(['AWSPENDING']) });
  const st = await crane(['status'], h);
  assert.match(st.all, /Version pending-id is labelled AWSPENDING/);
});
