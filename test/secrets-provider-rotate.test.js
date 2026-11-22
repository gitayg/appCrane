import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { createServer } from 'net';
import { copyFileSync, mkdirSync, mkdtempSync, writeFileSync, readFileSync, rmSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { fakeSecretsManager, ROOT, K_A, K_B, cleanEnv } from './secrets-provider-fake.mjs';

// crane rotate-key when ENCRYPTION_KEY lives in the platform secret.

const sm = fakeSecretsManager();
const scratch = mkdtempSync(join(tmpdir(), 'crane-sprot-'));
const GOLDEN = join(scratch, 'golden');
mkdirSync(GOLDEN);
const NEW_KEY = 'c3'.repeat(32);
let rotateKey, encrypt, decrypt, RefusedError, seq = 0;

before(async () => {
  await sm.start();
  Object.assign(process.env, sm.awsEnv());
  process.env.DATA_DIR = GOLDEN;
  process.env.LOG_LEVEL = 'error';
  process.env.ENCRYPTION_KEY = K_A;
  const { initDb } = await import('../server/db.js');
  ({ encrypt, decrypt } = await import('../server/services/encryption.js'));
  ({ rotateKey, RefusedError } = await import('../server/services/keyRotation/index.js'));
  const db = initDb(GOLDEN);
  const appId = Number(db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('a', 'rot-a', 1)").run().lastInsertRowid);
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'DB_URL', ?)").run(appId, encrypt('postgres://p'));
  db.pragma('wal_checkpoint(TRUNCATE)');
  db.close();
  delete process.env.ENCRYPTION_KEY;
});
beforeEach(() => {
  sm.secrets.clear();
  sm.calls.length = 0;
  for (const k of Object.keys(sm.faults)) delete sm.faults[k];
  for (const k of Object.keys(process.env)) if (k.startsWith('APPCRANE_SECRETS_')) delete process.env[k];
  delete process.env.ENCRYPTION_KEY;
});
after(() => { sm.stop(); rmSync(scratch, { recursive: true, force: true }); });

const freePort = () => new Promise((res) => {
  const s = createServer();
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
});

function host(envText = 'APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=plat\nOTHER=1\n') {
  const dir = join(scratch, `h${++seq}`);
  const dataDir = join(dir, 'data');
  mkdirSync(dataDir, { recursive: true });
  copyFileSync(join(GOLDEN, 'deployhub.db'), join(dataDir, 'deployhub.db'));
  const envPath = join(dir, '.env');
  writeFileSync(envPath, envText);
  return { dir, dataDir, envPath, text: envText, dbPath: join(dataDir, 'deployhub.db') };
}
const seedSecret = (extra = {}) => sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: 'sk-keep', ...extra })).VersionId;
const run = async (h, extra = {}) => rotateKey({ dataDir: h.dataDir, envPath: h.envPath, port: await freePort(), newKey: NEW_KEY, ...extra });

function dbValue(h) {
  const db = new Database(h.dbPath, { readonly: true });
  const v = db.prepare("SELECT value_encrypted AS v FROM env_vars WHERE key = 'DB_URL'").get().v;
  db.close();
  return v;
}
const opensWith = (h, key) => { try { return decrypt(dbValue(h), key) === 'postgres://p'; } catch { return false; } };

test('staged, then promoted: every label where it belongs, other keys kept, no key on disk', async () => {
  const first = seedSecret();
  const h = host();
  const res = await run(h);
  assert.deepEqual(res.report.post_check, { ok: true });
  assert.ok(opensWith(h, NEW_KEY) && !opensWith(h, K_A));
  assert.deepEqual(JSON.parse(sm.current('plat')), { ENCRYPTION_KEY: NEW_KEY, ANTHROPIC_API_KEY: 'sk-keep' });

  const ops = sm.calls.map((c) => c.op);
  const put = ops.indexOf('PutSecretValue');
  const promote = sm.calls.findIndex((c) => c.op === 'UpdateSecretVersionStage' && c.input.VersionStage === 'AWSCURRENT');
  assert.ok(put !== -1 && promote > put);
  assert.deepEqual(sm.calls[put].input.VersionStages, ['AWSPENDING']);

  const stages = sm.stages('plat');
  assert.deepEqual(stages[first], ['AWSPREVIOUS']);
  assert.deepEqual(stages[res.provider.version_id], ['AWSCURRENT'], 'AWSPENDING label is gone');

  assert.equal(readFileSync(h.envPath, 'utf8'), h.text, '.env is not touched');
  const backup = readdirSync(res.backupDir);
  assert.ok(backup.includes('secret-rotation.json') && backup.includes('deployhub.db'));
  const journal = readFileSync(join(res.backupDir, 'secret-rotation.json'), 'utf8');
  assert.ok(!journal.includes(K_A) && !journal.includes(NEW_KEY));
  assert.equal(JSON.parse(journal).new_version_id, res.provider.version_id);
});

test('a generated key works too, and the key from the provider is what decrypts', async () => {
  seedSecret();
  const h = host();
  const res = await rotateKey({ dataDir: h.dataDir, envPath: h.envPath, port: await freePort() });
  const key = JSON.parse(sm.current('plat')).ENCRYPTION_KEY;
  assert.notEqual(key, K_A);
  assert.ok(opensWith(h, key));
  assert.deepEqual(res.report.post_check, { ok: true });
});

test('dry run: reads the old key from the provider, writes nothing', async () => {
  seedSecret();
  const h = host();
  const res = await run(h, { dryRun: true });
  assert.equal(res.report.dry_run, true);
  assert.equal(res.report.values, 1);
  assert.equal(sm.writes().length, 0);
  assert.ok(opensWith(h, K_A));
});

async function assertUnchanged(h, first) {
  assert.ok(opensWith(h, K_A), 'the database still opens with the old key');
  assert.equal(JSON.parse(sm.current('plat')).ENCRYPTION_KEY, K_A, 'AWSCURRENT unchanged');
  assert.deepEqual(sm.stages('plat')[first], ['AWSCURRENT']);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
}

test('stage fails: AWSCURRENT and the database are unchanged', async () => {
  const first = seedSecret();
  const h = host();
  sm.faults.PutSecretValue = () => sm.err('InternalServiceError', 'down');
  const err = await run(h).then(() => null, (e) => e);
  assert.match(err.message, /down/);
  assert.ok(!err.dbCommitted);
  await assertUnchanged(h, first);
});

test('staged version does not read back: nothing commits and the label is cleared', async () => {
  const first = seedSecret();
  const h = host();
  sm.faults.GetSecretValue = (input) => (input.VersionStage === 'AWSPENDING' ? sm.err('ResourceNotFoundException', 'not there') : undefined);
  await assert.rejects(run(h));
  await assertUnchanged(h, first);
  assert.ok(!Object.values(sm.stages('plat')).flat().includes('AWSPENDING'));
});

test('a value that does not decrypt stops it before anything is staged', async () => {
  const first = seedSecret();
  const h = host();
  const db = new Database(h.dbPath);
  db.prepare("UPDATE env_vars SET value_encrypted = ? WHERE key = 'DB_URL'").run(encrypt('x', K_B));
  db.close();
  const before = dbValue(h);
  await assert.rejects(run(h), /do not decrypt/);
  assert.equal(sm.writes().length, 0);
  assert.equal(dbValue(h), before);
  assert.deepEqual(sm.stages('plat')[first], ['AWSCURRENT']);
});

test('promote fails after the commit: the exact recovery with the version id, and it works', async () => {
  const first = seedSecret();
  const h = host();
  sm.faults.UpdateSecretVersionStage = (input) => (input.VersionStage === 'AWSCURRENT' ? sm.err('AccessDeniedException', 'no') : undefined);
  const err = await run(h).then(() => null, (e) => e);
  assert.equal(err.dbCommitted, true);
  const put = sm.calls.find((c) => c.op === 'PutSecretValue').input.ClientRequestToken;
  assert.ok(err.message.includes(`aws secretsmanager update-secret-version-stage --secret-id plat --region us-east-1 --version-stage AWSCURRENT --move-to-version-id ${put} --remove-from-version-id ${first}`), err.message);
  assert.ok(err.message.includes(`${err.backupDir}/deployhub.db`));
  assert.ok(!err.message.includes(K_A) && !err.message.includes(NEW_KEY));
  assert.ok(opensWith(h, NEW_KEY), 'committed');
  assert.equal(JSON.parse(sm.current('plat')).ENCRYPTION_KEY, K_A);
  // the backup holds the database under the old key, the other way back
  const backup = new Database(join(err.backupDir, 'deployhub.db'), { readonly: true });
  assert.ok(decrypt(backup.prepare("SELECT value_encrypted AS v FROM env_vars WHERE key = 'DB_URL'").get().v, K_A));
  backup.close();

  // Doing what the message says finishes it.
  delete sm.faults.UpdateSecretVersionStage;
  const s = sm.secrets.get('plat');
  s.versions.get(put).stages.add('AWSCURRENT');
  s.versions.get(first).stages.delete('AWSCURRENT');
  assert.equal(JSON.parse(sm.current('plat')).ENCRYPTION_KEY, NEW_KEY);
});

test('a re-run after a rotation that died after its commit refuses and names the unfinished version', async () => {
  const first = seedSecret();
  const h = host();
  sm.faults.UpdateSecretVersionStage = () => sm.err('AccessDeniedException', 'no');
  await run(h).then(() => null, (e) => e);
  delete sm.faults.UpdateSecretVersionStage;
  const put = sm.calls.find((c) => c.op === 'PutSecretValue').input.ClientRequestToken;
  const err = await rotateKey({ dataDir: h.dataDir, envPath: h.envPath, port: await freePort() }).then(() => null, (e) => e);
  assert.match(err.message, /do not decrypt/);
  assert.ok(err.message.includes(`--move-to-version-id ${put} --remove-from-version-id ${first}`), err.message);
  assert.equal(JSON.parse(sm.current('plat')).ENCRYPTION_KEY, K_A);
});

test('post check: AWSCURRENT not holding the new key fails it, and so does a read that fails', async () => {
  seedSecret();
  const h = host();
  sm.faults.UpdateSecretVersionStage = () => ({ reply: {} }); // answers success, moves nothing
  const res = await run(h);
  assert.equal(res.report.post_check.ok, false);
  assert.match(res.report.post_check.failures.join(), /AWSCURRENT does not hold the new key/);
  assert.ok(res.provider.undo.includes('--move-to-version-id'));

  sm.secrets.clear();
  sm.calls.length = 0;
  delete sm.faults.UpdateSecretVersionStage;
  seedSecret();
  const h2 = host();
  sm.faults.GetSecretValue = (input) => (!input.VersionStage && sm.calls.some((c) => c.input.VersionStage === 'AWSCURRENT') ? sm.err('InternalServiceError', 'read failed after promote') : undefined);
  const res2 = await run(h2);
  assert.equal(res2.report.post_check.ok, false);
  assert.match(res2.report.post_check.failures.join(), /read failed after promote/);
});

test('provider unreadable: refused, never rotates the key sitting in .env', async () => {
  const h = host(`APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=plat\nENCRYPTION_KEY=${K_A}\n`);
  sm.faults.GetSecretValue = () => sm.err('AccessDeniedException', 'denied');
  const err = await run(h).then(() => null, (e) => e);
  assert.ok(err instanceof RefusedError);
  assert.match(err.message, /could not be read/);
  assert.equal(readFileSync(h.envPath, 'utf8'), h.text);
  assert.ok(opensWith(h, K_A));
});

test('the key in both places: refused', async () => {
  seedSecret();
  const h = host(`APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=plat\nENCRYPTION_KEY=${K_A}\n`);
  await assert.rejects(run(h), /in both the platform secret/);
  assert.equal(sm.writes().length, 0);
});

test('a shell key that differs from the secret: refused', async () => {
  seedSecret();
  process.env.ENCRYPTION_KEY = K_B;
  await assert.rejects(run(host()), /differs from the one in the platform secret/);
  assert.equal(sm.writes().length, 0);
});

test('a provider whose secret does not hold the key rotates .env and leaves the secret alone', async () => {
  sm.seed('plat', JSON.stringify({ ANTHROPIC_API_KEY: 'sk' }));
  const h = host(`APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=plat\nENCRYPTION_KEY=${K_A}\n`);
  const res = await run(h);
  assert.deepEqual(res.report.post_check, { ok: true });
  assert.equal(res.provider, undefined);
  assert.match(readFileSync(h.envPath, 'utf8'), new RegExp(`ENCRYPTION_KEY=${NEW_KEY}`));
  assert.equal(sm.writes().length, 0);
});

test('no provider: no AWS call, and APPCRANE_SECRETS_* stays unset', async () => {
  const h = host(`ENCRYPTION_KEY=${K_A}\nAWS_REGION=us-west-2\nAWS_PROFILE=from-dotenv\n`);
  const res = await run(h);
  assert.deepEqual(res.report.post_check, { ok: true });
  assert.equal(res.provider, undefined);
  assert.equal(sm.calls.length, 0);
  assert.equal(process.env.APPCRANE_SECRETS_PROVIDER, undefined);
  assert.equal(process.env.AWS_REGION, 'us-east-1', 'not overwritten from .env');
  assert.equal(process.env.AWS_PROFILE, undefined, 'nothing copied from .env without a provider');
});

function crane(args, env) {
  return new Promise((res) => {
    const c = spawn(process.execPath, ['cli/index.js', 'rotate-key', ...args], { cwd: ROOT, env });
    let all = '';
    c.stdout.on('data', (d) => { all += d; });
    c.stderr.on('data', (d) => { all += d; });
    c.on('close', (code) => res({ code, all }));
  });
}

test('CLI: rotates through the provider and prints neither key; a failure exits non-zero', async () => {
  seedSecret();
  const h = host();
  const args = ['--env-file', h.envPath, '--data-dir', h.dataDir, '--port', String(await freePort())];
  const ok = await crane(args, cleanEnv(sm.awsEnv()));
  assert.equal(ok.code, 0, ok.all);
  const key = JSON.parse(sm.current('plat')).ENCRYPTION_KEY;
  assert.notEqual(key, K_A);
  assert.ok(opensWith(h, key));
  assert.match(ok.all, /AWSCURRENT of plat now holds the new key/);
  assert.ok(!ok.all.includes(K_A) && !ok.all.includes(key));

  const before = sm.current('plat');
  sm.faults.UpdateSecretVersionStage = () => sm.err('AccessDeniedException', 'no');
  const bad = await crane(args, cleanEnv(sm.awsEnv()));
  assert.notEqual(bad.code, 0);
  assert.match(bad.all, /update-secret-version-stage/);
  assert.equal(sm.current('plat'), before);
  assert.ok(!bad.all.includes(key));
  assert.ok(!bad.all.includes(JSON.parse(sm.calls.findLast((c) => c.op === 'PutSecretValue').input.SecretString).ENCRYPTION_KEY));
});
