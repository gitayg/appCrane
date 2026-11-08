import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fakeSecretsManager, ROOT, K_A, K_B, cleanEnv } from './secrets-provider-fake.mjs';

// server/services/secretsProvider/* against a local fake of the Secrets Manager
// protocol.

const sm = fakeSecretsManager();
const scratch = mkdtempSync(join(tmpdir(), 'crane-sp-'));
const SETTINGS = ['APPCRANE_SECRETS_PROVIDER', 'APPCRANE_SECRETS_ID', 'APPCRANE_SECRETS_REGION', 'APPCRANE_SECRETS_APP_PREFIX'];
const quiet = { warn() {} };
let P;

function configure(secretId = 'plat') {
  for (const k of SETTINGS) delete process.env[k];
  process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager';
  if (secretId) process.env.APPCRANE_SECRETS_ID = secretId;
}

before(async () => {
  await sm.start();
  Object.assign(process.env, sm.awsEnv());
  P = await import('../server/services/secretsProvider/index.js');
});
beforeEach(() => {
  sm.secrets.clear();
  sm.calls.length = 0;
  for (const k of Object.keys(sm.faults)) delete sm.faults[k];
  configure();
});
after(() => { sm.stop(); rmSync(scratch, { recursive: true, force: true }); });

// ── off ────────────────────────────────────────────────────────────────────

function runNode(args, env) {
  return new Promise((res) => {
    const c = spawn(process.execPath, args, { cwd: ROOT, env });
    let stdout = '', stderr = '';
    c.stdout.on('data', (d) => { stdout += d; });
    c.stderr.on('data', (d) => { stderr += d; });
    c.on('close', (code) => res({ code, stdout, stderr }));
  });
}

// Records every @aws-sdk resolve, then loads the provider the way boot does.
const SDK_SPY = `
import { registerHooks } from 'node:module';
let sdk = 0;
registerHooks({ resolve(s, c, n) { if (s.includes('@aws-sdk')) sdk++; return n(s, c); } });
const P = await import('./server/services/secretsProvider/index.js');
await import('./server/services/configBackup.js').catch(() => {});
const env = { ...process.env };
const r = await P.loadPlatformSecrets({ env, log: { warn() {} } });
console.log(JSON.stringify({ sdk, active: r.active, envSame: Object.keys(env).length === Object.keys(process.env).length }));
`;

test('off: no provider means no SDK load, no call, no change to the environment', async () => {
  const r = await runNode(['--input-type=module', '-e', SDK_SPY], cleanEnv());
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout.trim().split('\n').pop()), { sdk: 0, active: false, envSame: true });
});

test('control for the test above: with a provider the same spy does see the SDK', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const r = await runNode(['--input-type=module', '-e', SDK_SPY], cleanEnv({ ...sm.awsEnv(), APPCRANE_SECRETS_PROVIDER: 'aws-secrets-manager', APPCRANE_SECRETS_ID: 'plat' }));
  assert.equal(r.code, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').pop());
  assert.ok(out.sdk > 0);
  assert.equal(out.active, true);
});

test('providerConfig: null when unset, refuses an unknown provider', () => {
  assert.equal(P.providerConfig({}), null);
  assert.equal(P.providerConfig({ APPCRANE_SECRETS_PROVIDER: '' }), null);
  assert.deepEqual(P.providerConfig({ APPCRANE_SECRETS_PROVIDER: 'aws-secrets-manager', AWS_REGION: 'eu-west-1' }), { provider: 'aws-secrets-manager', secretId: null, region: 'eu-west-1' });
  assert.equal(P.providerConfig({ APPCRANE_SECRETS_PROVIDER: 'aws-secrets-manager', APPCRANE_SECRETS_REGION: 'us-east-2', AWS_REGION: 'eu-west-1' }).region, 'us-east-2');
  assert.throws(() => P.providerConfig({ APPCRANE_SECRETS_PROVIDER: 'vault' }), /not supported/);
});

test('a provider with no platform secret loads nothing and does not need AWS', async () => {
  const env = { APPCRANE_SECRETS_PROVIDER: 'aws-secrets-manager' };
  assert.deepEqual(await P.loadPlatformSecrets({ env, log: quiet }), { active: false });
  assert.equal(sm.calls.length, 0);
});

// ── loading ────────────────────────────────────────────────────────────────

const env = (extra = {}) => ({ APPCRANE_SECRETS_PROVIDER: 'aws-secrets-manager', APPCRANE_SECRETS_ID: 'plat', AWS_REGION: 'us-east-1', ...extra });

test('load sets the keys on env', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: 'sk-from-secret' }));
  const e = env();
  const r = await P.loadPlatformSecrets({ env: e, log: quiet });
  assert.equal(e.ENCRYPTION_KEY, K_A);
  assert.equal(e.ANTHROPIC_API_KEY, 'sk-from-secret');
  assert.deepEqual(r.keys, ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY']);
});

test('the generated placeholder is never loaded', async () => {
  sm.seed('plat', JSON.stringify({ PLACEHOLDER: 'x', ENCRYPTION_KEY: K_A }));
  const e = env();
  await P.loadPlatformSecrets({ env: e, log: quiet });
  assert.equal(e.PLACEHOLDER, undefined);
});

test('a fetch failure throws and sets nothing, even with a key in .env', async () => {
  sm.faults.GetSecretValue = () => sm.err('AccessDeniedException', 'no');
  const e = env({ ENCRYPTION_KEY: K_B });
  await assert.rejects(P.loadPlatformSecrets({ env: e, log: quiet }), /AccessDeniedException/);
  assert.equal(e.ENCRYPTION_KEY, K_B);
});

test('a missing secret throws', async () => {
  await assert.rejects(P.loadPlatformSecrets({ env: env(), log: quiet }), /ResourceNotFoundException/);
});

for (const bad of ['NODE_OPTIONS', 'PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'DATA_DIR', 'APPCRANE_SECRETS_ID', 'lowercase', '1BAD', 'WITH-DASH']) {
  test(`denied key name refused, nothing set: ${bad}`, async () => {
    sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A, [bad]: 'sensitive-value-1' }));
    const e = env();
    const err = await P.loadPlatformSecrets({ env: e, log: quiet }).then(() => null, (x) => x);
    assert.ok(err, 'must refuse');
    assert.match(err.message, /not allowed/);
    assert.doesNotMatch(err.message, /sensitive-value-1/);
    assert.equal(e.ENCRYPTION_KEY, undefined);
  });
}

test('a different value in .env refuses to boot and names the key only', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const e = env({ ENCRYPTION_KEY: K_B });
  const err = await P.loadPlatformSecrets({ env: e, log: quiet }).then(() => null, (x) => x);
  assert.match(err.message, /ENCRYPTION_KEY differ/);
  assert.ok(!err.message.includes(K_A) && !err.message.includes(K_B));
  assert.equal(e.ENCRYPTION_KEY, K_B);
});

test('the same value in .env boots and warns', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const warned = [];
  const e = env({ ENCRYPTION_KEY: K_A });
  const r = await P.loadPlatformSecrets({ env: e, log: { warn: (m) => warned.push(m) } });
  assert.equal(r.active, true);
  assert.match(warned.join(), /remove the \.env line/);
  assert.ok(!warned.join().includes(K_A));
});

test('an empty .env line is not a conflict', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const e = env({ ENCRYPTION_KEY: '' });
  await P.loadPlatformSecrets({ env: e, log: quiet });
  assert.equal(e.ENCRYPTION_KEY, K_A);
});

test('no ENCRYPTION_KEY anywhere refuses, so no ephemeral key is ever generated', async () => {
  sm.seed('plat', JSON.stringify({ PLACEHOLDER: 'x' }));
  await assert.rejects(P.loadPlatformSecrets({ env: env(), log: quiet }), /no ENCRYPTION_KEY/);
});

test('a malformed ENCRYPTION_KEY refuses without quoting it', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: 'too-short-value' }));
  const err = await P.loadPlatformSecrets({ env: env(), log: quiet }).then(() => null, (x) => x);
  assert.match(err.message, /64 hex/);
  assert.doesNotMatch(err.message, /too-short-value/);
});

test('a secret that is not JSON refuses without quoting it (JSON.parse would)', async () => {
  sm.seed('plat', 'sensitive!'); // short: JSON.parse's message quotes all of it
  const err = await P.loadPlatformSecrets({ env: env(), log: quiet }).then(() => null, (x) => x);
  assert.match(err.message, /not a JSON object/);
  assert.doesNotMatch(err.message + err.stack, /sensitive/);
  assert.equal(err.cause, undefined);
});

// ── stage / promote / set ──────────────────────────────────────────────────

test('stage labels AWSPENDING only and leaves AWSCURRENT; promote moves it and AWSPREVIOUS follows', async () => {
  const first = sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A })).VersionId;
  const { versionId } = await P.stagePlatformSecret({ ENCRYPTION_KEY: K_B });
  assert.deepEqual(sm.stages('plat')[versionId], ['AWSPENDING']);
  assert.equal(JSON.parse(sm.current('plat')).ENCRYPTION_KEY, K_A);
  assert.deepEqual(await P.readPlatformSecret({ stage: 'AWSPENDING' }), { ENCRYPTION_KEY: K_B });
  await P.promotePlatformSecret(versionId);
  assert.equal(JSON.parse(sm.current('plat')).ENCRYPTION_KEY, K_B);
  assert.deepEqual(sm.stages('plat')[first], ['AWSPREVIOUS']);
  assert.deepEqual(sm.stages('plat')[versionId], ['AWSCURRENT']);
});

test('stage refuses a denied key before any call', async () => {
  await assert.rejects(P.stagePlatformSecret({ NODE_OPTIONS: 'x' }), /not allowed/);
  assert.equal(sm.writes().length, 0);
});

test('setPlatformSecretKey merges, and a denied name is refused', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  await P.setPlatformSecretKey('ANTHROPIC_API_KEY', 'sk-new');
  assert.deepEqual(JSON.parse(sm.current('plat')), { ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: 'sk-new' });
  assert.equal(P.platformKeyLoaded('ANTHROPIC_API_KEY'), true);
  await assert.rejects(P.setPlatformSecretKey('LD_PRELOAD', 'x'), /not allowed/);
});

test('a write error that echoes the value does not carry it', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  sm.faults.PutSecretValue = (input) => sm.err('ValidationException', `bad input ${input.SecretString}`);
  const err = await P.setPlatformSecretKey('ANTHROPIC_API_KEY', 'sk-echoed-value').then(() => null, (x) => x);
  assert.ok(err);
  assert.ok(!err.message.includes('sk-echoed-value') && !err.message.includes(K_A), err.message);
  assert.ok(!String(err.stack).includes('sk-echoed-value'));
});

const NS_A = 'a'.repeat(32);
const NS_B = 'b'.repeat(32);

// ── app secrets ────────────────────────────────────────────────────────────

test('appSecretName builds the path and refuses anything that could leave it', () => {
  assert.equal(P.appSecretName(NS_A, 'sandbox', 'DB_PASS'), `appcrane/apps/${NS_A}/sandbox/DB_PASS`);
  process.env.APPCRANE_SECRETS_APP_PREFIX = 'org/apps/';
  assert.equal(P.appSecretName(NS_A, 'production', 'X'), `org/apps/${NS_A}/production/X`);
  delete process.env.APPCRANE_SECRETS_APP_PREFIX;
  for (const [s, e, n] of [['a/b', 'sandbox', 'X'], ['..', 'sandbox', 'X'], [NS_A, 'staging', 'X'], [NS_A, 'sandbox', '../X'], [NS_A, 'sandbox', 'x/y'],
    [NS_A, 'sandbox', 'arn:aws:secretsmanager:us-east-1:1:secret:plat'], [NS_A, 'sandbox', ''], ['A B', 'sandbox', 'X'], [NS_A, 'sandbox', 'X#f'], [NS_A, 'sandbox', null],
    [NS_A, 'sandbox', 'x'.repeat(257)], [NS_A, 'sandbox', 'X\n'],
    // A slug or an id is not a namespace, and neither is anything near one.
    ['my-app', 'sandbox', 'X'], ['7', 'sandbox', 'X'], [7, 'sandbox', 'X'], [null, 'sandbox', 'X'], [undefined, 'sandbox', 'X'], ['', 'sandbox', 'X'],
    ['a'.repeat(31), 'sandbox', 'X'], ['a'.repeat(33), 'sandbox', 'X'], ['A'.repeat(32), 'sandbox', 'X'], [`${'a'.repeat(32)}\n`, 'sandbox', 'X'], [`${'a'.repeat(31)}/`, 'sandbox', 'X']]) {
    assert.throws(() => P.appSecretName(s, e, n), /invalid/, `${s} ${e} ${n}`);
  }
  assert.equal(P.appSecretName(NS_A, 'sandbox', 'x'.repeat(256)).length > 256, true);
  for (const bad of ['../up', 'a/../b', 'a/./b', '.', '/abs', 'a b']) {
    process.env.APPCRANE_SECRETS_APP_PREFIX = bad;
    assert.throws(() => P.appSecretName(NS_A, 'sandbox', 'X'), /safe path/, bad);
    assert.throws(() => P.appSecretPrefix(), /safe path/, bad);
  }
  delete process.env.APPCRANE_SECRETS_APP_PREFIX;
  assert.equal(P.appSecretRoot(NS_A), `appcrane/apps/${NS_A}`);
  assert.equal(sm.calls.length, 0);
});

test('getAppSecret reads the app\'s own path; sandbox cannot read production', async () => {
  sm.seed(`appcrane/apps/${NS_A}/production/DB`, 'prod-value');
  assert.equal(await P.getAppSecret(NS_A, 'production', 'DB'), 'prod-value');
  await assert.rejects(P.getAppSecret(NS_A, 'sandbox', 'DB'), /ResourceNotFoundException/);
  await assert.rejects(P.getAppSecret(NS_B, 'production', 'DB'), /ResourceNotFoundException/);
  assert.deepEqual(sm.calls.map((c) => c.input.SecretId), [`appcrane/apps/${NS_A}/production/DB`, `appcrane/apps/${NS_A}/sandbox/DB`, `appcrane/apps/${NS_B}/production/DB`]);
});

test('a reference can never reach the platform secret, even with the prefix pointed at it', async () => {
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  await assert.rejects(P.getAppSecret(NS_A, 'sandbox', 'plat'), /ResourceNotFoundException/);
  await assert.rejects(P.getAppSecret(NS_A, 'sandbox', '../../../plat'), /invalid/);
  process.env.APPCRANE_SECRETS_ID = `p/${NS_A}/sandbox/X`;
  process.env.APPCRANE_SECRETS_APP_PREFIX = 'p';
  sm.seed(`p/${NS_A}/sandbox/X`, JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const err = await P.getAppSecret(NS_A, 'sandbox', 'X').then(() => null, (x) => x);
  assert.match(err.message, /is the platform secret/);
  process.env.APPCRANE_SECRETS_ID = `arn:aws:secretsmanager:us-east-1:111122223333:secret:p/${NS_A}/sandbox/X-AbCdEf`;
  await assert.rejects(P.getAppSecret(NS_A, 'sandbox', 'X'), /is the platform secret/);
  delete process.env.APPCRANE_SECRETS_APP_PREFIX;
});

test('getAppSecret field: string, non-string, missing, and not JSON without quoting it', async () => {
  sm.seed(`appcrane/apps/${NS_A}/sandbox/J`, JSON.stringify({ user: 'u', port: 5432 }));
  assert.equal(await P.getAppSecret(NS_A, 'sandbox', 'J', 'user'), 'u');
  assert.equal(await P.getAppSecret(NS_A, 'sandbox', 'J', 'port'), '5432');
  await assert.rejects(P.getAppSecret(NS_A, 'sandbox', 'J', 'nope'), /no field nope/);
  await assert.rejects(P.getAppSecret(NS_A, 'sandbox', 'J', '__proto__'), /no field/);
  sm.seed(`appcrane/apps/${NS_A}/sandbox/T`, 'sensitive!');
  const err = await P.getAppSecret(NS_A, 'sandbox', 'T', 'x').then(() => null, (x) => x);
  assert.doesNotMatch(err.message, /sensitive!/);
});

test('getAppSecret and putAppSecret refuse with no provider configured', async () => {
  delete process.env.APPCRANE_SECRETS_PROVIDER;
  await assert.rejects(P.getAppSecret(NS_A, 'sandbox', 'X'), /no secrets provider/);
  await assert.rejects(P.putAppSecret(NS_A, 'sandbox', 'X', 'v'), /no secrets provider/);
  assert.equal(sm.calls.length, 0);
});

test('putAppSecret creates, then updates; returns the name and never the value', async () => {
  const r1 = await P.putAppSecret(NS_A, 'sandbox', 'X', 'v1');
  assert.deepEqual(r1, { name: `appcrane/apps/${NS_A}/sandbox/X` });
  assert.equal(sm.current(`appcrane/apps/${NS_A}/sandbox/X`), 'v1');
  await P.putAppSecret(NS_A, 'sandbox', 'X', 'v2');
  assert.equal(sm.current(`appcrane/apps/${NS_A}/sandbox/X`), 'v2');
  assert.deepEqual(sm.calls.map((c) => c.op), ['PutSecretValue', 'CreateSecret', 'PutSecretValue']);
  await assert.rejects(P.putAppSecret(NS_A, 'sandbox', 'X', 'x'.repeat(65537)), /65536/);
});

// ── pieces used elsewhere ──────────────────────────────────────────────────

test('saveKeyToProvider: a failed write changes neither; success drops the .env line', async () => {
  const { saveKeyToProvider } = await import('../server/services/secretsProvider/saveKey.js');
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const envPath = join(scratch, 'save.env');
  const text = 'PORT=1\nANTHROPIC_API_KEY=sk-old\nHOST=h\n';
  writeFileSync(envPath, text);
  sm.faults.PutSecretValue = () => sm.err('InternalServiceError', 'down');
  await assert.rejects(saveKeyToProvider('ANTHROPIC_API_KEY', 'sk-new', { envPath }), /down/);
  assert.equal(readFileSync(envPath, 'utf8'), text);
  assert.deepEqual(JSON.parse(sm.current('plat')), { ENCRYPTION_KEY: K_A });
  delete sm.faults.PutSecretValue;
  await saveKeyToProvider('ANTHROPIC_API_KEY', 'sk-new', { envPath });
  assert.equal(readFileSync(envPath, 'utf8'), 'PORT=1\nHOST=h\n');
  assert.equal(JSON.parse(sm.current('plat')).ANTHROPIC_API_KEY, 'sk-new');
  assert.ok(!existsSync(`${envPath}.rotate-${process.pid}.tmp`));
});

test('planRestoredEnv: every case of an archive .env over a host', async () => {
  const { planRestoredEnv } = await import('../server/services/secretsProvider/restorePlan.js');
  const host = env({ ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: 'sk-live' });
  const keyLoaded = (k) => ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY'].includes(k);
  // no provider on the host: exactly as before
  assert.deepEqual(planRestoredEnv(`ENCRYPTION_KEY=${K_B}\n`, { env: {}, keyLoaded }), { action: 'copy' });
  // provider configured, keys not in it
  assert.deepEqual(planRestoredEnv(`ENCRYPTION_KEY=${K_B}\n`, { env: host, keyLoaded: () => false }), { action: 'copy' });
  // archive from a migrated host
  assert.deepEqual(planRestoredEnv('APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=other\n', { env: host, keyLoaded }), { action: 'copy' });
  // pre-migration archive, same key: merged so the boot does not see two
  const merged = planRestoredEnv(`PORT=9\nENCRYPTION_KEY=${K_A}\nANTHROPIC_API_KEY=sk-other\n`, { env: host, keyLoaded });
  assert.equal(merged.action, 'merge');
  assert.deepEqual(merged.dropped, ['ENCRYPTION_KEY', 'ANTHROPIC_API_KEY']);
  assert.ok(!merged.text.includes(K_A) && !merged.text.includes('sk-other'));
  assert.match(merged.text, /^PORT=9$/m);
  assert.match(merged.text, /^APPCRANE_SECRETS_ID=plat$/m);
  // the merged .env really boots
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A, ANTHROPIC_API_KEY: 'sk-live' }));
  const { parseEnvText } = await import('../server/services/secretsProvider/envText.js');
  const bootEnv = { ...parseEnvText(merged.text), AWS_REGION: 'us-east-1' };
  assert.equal((await P.loadPlatformSecrets({ env: bootEnv, log: quiet })).active, true);
  // pre-migration archive under another key: its database cannot open under the secret's key
  const refused = planRestoredEnv(`ENCRYPTION_KEY=${K_B}\n`, { env: host, keyLoaded });
  assert.equal(refused.action, 'refuse');
  assert.ok(!refused.message.includes(K_A) && !refused.message.includes(K_B));
});

test('backupSecretsNote: null with no provider, names only with one', async () => {
  assert.equal(P.backupSecretsNote({}), null);
  sm.seed('plat', JSON.stringify({ ENCRYPTION_KEY: K_A }));
  const e = env();
  await P.loadPlatformSecrets({ env: e, log: quiet });
  const note = P.backupSecretsNote(e);
  assert.equal(note.encryption_key_in_provider, true);
  assert.equal(note.restorable_from_this_copy_alone, false);
  assert.equal(note.secret_id, 'plat');
  assert.ok(note.version_id);
  assert.ok(!JSON.stringify(note).includes(K_A));
});

test('encryption.js refuses an ephemeral key when a platform secret is configured', async () => {
  const code = `const { encrypt } = await import('./server/services/encryption.js');
    try { encrypt('x'); console.log('ENCRYPTED'); } catch (e) { console.log('REFUSED ' + e.message); }`;
  const on = await runNode(['--input-type=module', '-e', code], cleanEnv({ APPCRANE_SECRETS_PROVIDER: 'aws-secrets-manager', APPCRANE_SECRETS_ID: 'plat', NODE_ENV: 'development' }));
  assert.match(on.stdout, /REFUSED .*Secrets Manager/);
  const off = await runNode(['--input-type=module', '-e', code], cleanEnv({ NODE_ENV: 'development' }));
  assert.match(off.stdout, /ENCRYPTED/);
  const prod = await runNode(['--input-type=module', '-e', code], cleanEnv({ NODE_ENV: 'production' }));
  assert.match(prod.stdout, /REFUSED .*crane secrets migrate/);
});

// ── IMDS ───────────────────────────────────────────────────────────────────

test('IMDS probe: answers, nothing, and no Docker', async () => {
  const { probeImds, PROBE_ARGS, IMDS_FIX } = await import('../server/services/secretsProvider/imdsProbe.js');
  const { HELPER_IMAGE } = await import('../server/services/volumeHelper.js');
  const args = [];
  const docker = (stdout, status = 0, stderr = '') => async (a) => { args.push(a); return { status, stdout, stderr }; };

  const v2 = await probeImds({ runDocker: docker('TOKEN HTTP/1.0 200 OK\nV1 HTTP/1.0 401 Unauthorized\n'), hostAnswers: async () => { throw new Error('not asked'); } });
  assert.equal(v2.status, 'exposed');
  assert.equal(v2.token, '200');
  assert.equal(v2.fix, IMDS_FIX);
  const v1 = await probeImds({ runDocker: docker('TOKEN \nV1 HTTP/1.1 200 OK\n') });
  assert.equal(v1.status, 'exposed');

  // Nothing answers: blocked ONLY when the host itself is answered.
  assert.equal((await probeImds({ runDocker: docker('TOKEN \nV1 \n'), hostAnswers: async () => true })).status, 'blocked');
  assert.equal((await probeImds({ runDocker: docker('TOKEN \nV1 \n'), hostAnswers: async () => false })).status, 'not_measured');

  assert.equal((await probeImds({ runDocker: docker('', 125, 'Cannot connect to the Docker daemon'), hostAnswers: async () => true })).status, 'not_measured');
  assert.equal((await probeImds({ runDocker: async () => { throw new Error('spawn docker ENOENT'); } })).status, 'not_measured');

  assert.ok(args[0].includes(HELPER_IMAGE));
  assert.deepEqual(args[0].slice(0, 4), ['run', '--rm', '--network', 'bridge']);
  assert.ok(PROBE_ARGS.join(' ').includes('X-aws-ec2-metadata-token-ttl-seconds: 21600'));
  assert.ok(PROBE_ARGS.join(' ').includes('PUT /latest/api/token HTTP/1.0'));
  assert.ok(PROBE_ARGS.join(' ').includes('GET /latest/meta-data/'));
});

test('CloudFormation template: no em dash, no value, scoped resources', () => {
  const text = readFileSync(join(ROOT, 'deploy/aws/appcrane-secrets.yaml'), 'utf8');
  assert.ok(!text.includes('—'));
  assert.ok(!/^\s*SecretString\s*:/m.test(text), 'no literal secret value');
  assert.match(text, /GenerateSecretString/);
  assert.match(text, /DeletionPolicy: Retain/);
  assert.match(text, /secret:\$\{AppSecretPrefix\}\/\*/);
  assert.match(text, /prefix\/namespace\/env\/NAME/);
  assert.doesNotMatch(text, /prefix\/slug/);
  assert.ok(!/secretsmanager:DeleteSecret/.test(text), 'the secrets of a deleted app are the operator\'s to delete');
  assert.ok(!/Resource:\s*['"]?\*/.test(text), 'no wildcard resource');
});
