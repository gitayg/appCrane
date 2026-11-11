import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The reference grammar and the resolver, with getSecret injected. What a
// reference can reach is decided here: secretRefs passes a NAME and the app's own
// namespace and env, and nothing a caller wrote can become part of the path.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-secret-refs-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const {
  REF_PREFIX, SecretRefError, isSecretRef, parseSecretRef, formatSecretRef, resolveEnvValues, resolveStoredEnv,
  assertStorableValue, assertStoreRequest, storeAppSecrets,
} = await import('../server/services/secretRefs.js');
const { encrypt, decrypt } = await import('../server/services/encryption.js');
const { COLUMNS, ENCRYPTED_RE } = await import('../server/services/keyRotation/registry.js');

const NS = 'c'.repeat(32);
const APP = { slug: 'aaa', secrets_namespace: NS };

const UNSAFE_REFS = [
  'secretsmanager:',
  'secretsmanager:#field',
  'secretsmanager:TOKEN#',
  'secretsmanager:TOKEN#a#b',
  'secretsmanager:TOKEN#a/b',
  'secretsmanager:TOKEN#__proto__',
  'secretsmanager:TOKEN#constructor',
  'secretsmanager:arn:aws:secretsmanager:us-east-1:123456789012:secret:platform-AbCdEf',
  'secretsmanager:platform/keys',
  'secretsmanager:/appcrane/apps/bbb/sandbox/TOKEN',
  'secretsmanager:bbb/sandbox/TOKEN',
  'secretsmanager:../../bbb/sandbox/TOKEN',
  'secretsmanager:..',
  'secretsmanager:.',
  'secretsmanager:%2e%2e%2fbbb',
  'secretsmanager:..%2Fbbb',
  'secretsmanager:TOKEN%23field',
  'secretsmanager:bbb∕TOKEN',
  'secretsmanager:ＴＯＫＥＮ',
  'secretsmanager:TOKEN\u0000',
  'secretsmanager:TOKEN\n',
  'secretsmanager: TOKEN',
  `secretsmanager:${'A'.repeat(257)}`,
];

test('parseSecretRef accepts a name and an optional field, and nothing else', () => {
  assert.deepEqual(parseSecretRef('secretsmanager:TOKEN'), { name: 'TOKEN', field: null });
  assert.deepEqual(parseSecretRef('secretsmanager:db-creds_1#pass.word'), { name: 'db-creds_1', field: 'pass.word' });
  for (const bad of UNSAFE_REFS) assert.equal(parseSecretRef(bad), null, JSON.stringify(bad));
});

test('only the start of a value makes it a reference, and the prefix is exact', () => {
  for (const plain of ['abc secretsmanager:TOKEN', ' secretsmanager:TOKEN', 'SECRETSMANAGER:TOKEN', 'SecretsManager:TOKEN', 'postgres://u:secretsmanager:x@h/db', '']) {
    assert.equal(isSecretRef(plain), false, JSON.stringify(plain));
    assert.equal(parseSecretRef(plain), null);
  }
  assert.equal(isSecretRef('secretsmanager:a/b'), true, 'a malformed reference is still treated as one, so it is refused and not injected');
});

test('formatSecretRef round-trips and refuses what parse refuses', () => {
  assert.equal(formatSecretRef('TOKEN'), `${REF_PREFIX}TOKEN`);
  assert.equal(formatSecretRef('TOKEN', 'f'), `${REF_PREFIX}TOKEN#f`);
  assert.throws(() => formatSecretRef('a/b'), SecretRefError);
  assert.throws(() => formatSecretRef('TOKEN', '__proto__'), SecretRefError);
});

test('resolve passes the app\'s own namespace and env with the name, and leaves other values byte for byte', async () => {
  const calls = [];
  const getSecret = async (...args) => { calls.push(args); return 'the-value'; };
  const out = await resolveEnvValues(APP, 'sandbox', [
    { key: 'A', plain: 'secretsmanager:TOKEN' },
    { key: 'B', plain: 'secretsmanager:CREDS#pass' },
    { key: 'MID', plain: 'x secretsmanager:TOKEN' },
    { key: 'EMPTY', plain: '' },
  ], { getSecret });
  assert.deepEqual(out, { A: 'the-value', B: 'the-value', MID: 'x secretsmanager:TOKEN', EMPTY: '' });
  assert.deepEqual(calls, [[NS, 'sandbox', 'TOKEN', null], [NS, 'sandbox', 'CREDS', 'pass']]);
});

test('production and sandbox resolve under their own env, and an unknown env reaches nothing', async () => {
  const seen = [];
  const getSecret = async (slug, env) => { seen.push(env); return 'v'; };
  await resolveEnvValues(APP, 'production', [{ key: 'A', plain: 'secretsmanager:T' }], { getSecret });
  await resolveEnvValues(APP, 'sandbox', [{ key: 'A', plain: 'secretsmanager:T' }], { getSecret });
  assert.deepEqual(seen, ['production', 'sandbox']);
  await assert.rejects(resolveEnvValues(APP, '../production', [{ key: 'A', plain: 'secretsmanager:T' }], { getSecret }), SecretRefError);
  assert.equal(seen.length, 2);
});

test('every unsafe form fails at resolve time naming the key, without a fetch', async () => {
  let fetched = 0;
  const getSecret = async () => { fetched++; return 'v'; };
  for (const bad of UNSAFE_REFS) {
    await assert.rejects(resolveEnvValues(APP, 'sandbox', [{ key: 'MY_KEY', plain: bad }], { getSecret }), (e) => {
      assert.ok(e instanceof SecretRefError);
      assert.deepEqual(e.keys, ['MY_KEY']);
      assert.match(e.message, /MY_KEY/);
      return true;
    }, JSON.stringify(bad));
  }
  assert.equal(fetched, 0);
});

test('a failed fetch names every failing key and never repeats the provider error text', async () => {
  const SENSITIVE = 'Unexpected token h in JSON at position 0: hunter2-secret-bytes';
  const getSecret = async (slug, env, name) => {
    if (name === 'GOOD') return 'good-value';
    if (name === 'GONE') throw Object.assign(new Error(SENSITIVE), { name: 'ResourceNotFoundException' });
    throw new Error(SENSITIVE);
  };
  await assert.rejects(resolveEnvValues(APP, 'sandbox', [
    { key: 'OK', plain: 'secretsmanager:GOOD' },
    { key: 'K_GONE', plain: 'secretsmanager:GONE' },
    { key: 'K_BAD', plain: 'secretsmanager:BAD' },
  ], { getSecret }), (e) => {
    assert.deepEqual(e.keys, ['K_GONE', 'K_BAD']);
    assert.ok(e.message.includes(`K_GONE (secret not found at appcrane/apps/${NS}/sandbox/GONE)`), e.message);
    assert.match(e.message, /K_BAD/);
    assert.doesNotMatch(e.message, /hunter2|good-value|Unexpected token/);
    return true;
  });
});

test('a secret whose value looks like a reference is the value: references are not followed', async () => {
  const calls = [];
  const out = await resolveEnvValues(APP, 'sandbox', [{ key: 'A', plain: 'secretsmanager:FIRST' }], {
    getSecret: async (s, e, name) => { calls.push(name); return 'secretsmanager:SECOND'; },
  });
  assert.deepEqual(calls, ['FIRST']);
  assert.equal(out.A, 'secretsmanager:SECOND');
});

test('a non-string answer from the provider is a failure, not an injected "undefined"', async () => {
  await assert.rejects(resolveEnvValues(APP, 'sandbox', [{ key: 'A', plain: 'secretsmanager:X' }], { getSecret: async () => undefined }), /A \(/);
});

test('an env var named __proto__ stays an ordinary own key', async () => {
  const out = await resolveEnvValues(APP, 'sandbox', [{ key: '__proto__', plain: 'v' }], { getSecret: async () => 'x' });
  assert.deepEqual(Object.keys(out), ['__proto__']);
  assert.equal(Object.getPrototypeOf(out), Object.prototype);
});

test('resolveStoredEnv keeps omitting an undecryptable value and still fails on an unresolved reference', async () => {
  const rows = [
    { key: 'PLAIN', value_encrypted: encrypt('p') },
    { key: 'BROKEN', value_encrypted: 'not-a-blob' },
    { key: 'REF', value_encrypted: encrypt('secretsmanager:T') },
  ];
  const ok = await resolveStoredEnv(APP, 'sandbox', rows, { getSecret: async () => 'resolved' });
  assert.deepEqual(ok, { values: { PLAIN: 'p', REF: 'resolved' }, decryptFailures: ['BROKEN'], refKeys: ['REF'] });
  await assert.rejects(resolveStoredEnv(APP, 'sandbox', rows, { getSecret: async () => { throw new Error('x'); } }), /REF/);
});

test('write-time checks: a malformed value is refused, a value merely containing the prefix passes', () => {
  const on = { config: () => ({ provider: 'aws-secrets-manager' }) };
  const off = { config: () => null };
  for (const bad of UNSAFE_REFS) assert.throws(() => assertStorableValue(bad, on), SecretRefError, JSON.stringify(bad));
  assert.doesNotThrow(() => assertStorableValue('secretsmanager:TOKEN', on));
  assert.throws(() => assertStorableValue('secretsmanager:TOKEN', off), /no secrets provider/);
  for (const fine of ['x secretsmanager:TOKEN', 'plain', '']) assert.doesNotThrow(() => assertStorableValue(fine, off));
});

test('a store request is refused before any write: no provider, bad env, empty, oversized or already a reference', async () => {
  const on = { config: () => ({ provider: 'aws-secrets-manager' }) };
  assert.throws(() => assertStoreRequest('sandbox', { K: 'v' }, { config: () => null }), (e) => e.code === 'SECRETS_PROVIDER_NOT_CONFIGURED');
  assert.throws(() => assertStoreRequest('staging', { K: 'v' }, on), /production or sandbox/);
  assert.throws(() => assertStoreRequest('sandbox', { K: '' }, on), /empty/);
  assert.throws(() => assertStoreRequest('sandbox', { K: 'é'.repeat(32769) }, on), /65536/, 'the limit is bytes, not characters');
  assert.doesNotThrow(() => assertStoreRequest('sandbox', { K: 'x'.repeat(65536) }, on));
  assert.throws(() => assertStoreRequest('sandbox', { K: 'secretsmanager:T' }, on), /already a reference/);
});

test('storeAppSecrets returns references only, and reports the first failure without its error text', async () => {
  const puts = [];
  const putSecret = async (ns, env, key, value) => {
    puts.push([ns, env, key, value]);
    if (key === 'BAD') throw new Error('leak-the-value hunter2');
    return { name: `appcrane/apps/${ns}/${env}/${key}` };
  };
  const out = await storeAppSecrets(APP, 'production', { A: 'va', BAD: 'hunter2', C: 'vc' }, { putSecret });
  assert.deepEqual(puts.map((p) => p[2]), ['A', 'BAD'], 'stops at the first failure');
  assert.ok(puts.every((p) => p[0] === NS));
  assert.deepEqual(out.stored, [{ key: 'A', reference: 'secretsmanager:A', name: `appcrane/apps/${NS}/production/A` }]);
  assert.equal(out.failed.key, 'BAD');
  assert.doesNotMatch(JSON.stringify(out), /hunter2|"va"/);
});

test('a reference is stored as one ordinary encrypted blob, in the column key rotation covers', () => {
  assert.ok(COLUMNS.some(([table, cols]) => table === 'env_vars' && cols.includes('value_encrypted')));
  const blob = encrypt('secretsmanager:TOKEN#field');
  assert.match(blob, ENCRYPTED_RE);
  assert.equal(decrypt(blob), 'secretsmanager:TOKEN#field');
});

test('systemd-creds holds no app secrets: references and store requests are refused, naming the AWS provider', () => {
  const systemd = { config: () => ({ provider: 'systemd-creds', secretId: null, region: null }) };
  assert.throws(() => assertStorableValue('secretsmanager:DB_URL', systemd), (e) => e.code === 'SECRETS_PROVIDER_NOT_CONFIGURED' && /aws-secrets-manager/.test(e.message));
  assert.throws(() => assertStoreRequest('sandbox', { K: 'v' }, systemd), (e) => e.code === 'SECRETS_PROVIDER_NOT_CONFIGURED' && /systemd-creds/.test(e.message));
  assert.doesNotThrow(() => assertStorableValue('plain value', systemd));
});
