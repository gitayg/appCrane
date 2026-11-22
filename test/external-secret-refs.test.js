import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SignatureV4 } from '@smithy/signature-v4';
import crypto from 'node:crypto';

// The ref+ grammar, connection selection and the SigV4 signer, without a server.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-ext-refs-unit-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { parseExternalRef, isExternalRef, prefixAllows, externalSource } = await import('../server/services/externalSecrets/refs.js');
const { connectionForRef, createConnection, updateConnection, ConnectionError } = await import('../server/services/externalSecrets/connections.js');
const { signRequest } = await import('../server/services/externalSecrets/providers/awsssm.js');
const { isSecretRef, refSource, parseSecretRef, assertStorableValue, SecretRefError, resolveEnvValues } = await import('../server/services/secretRefs.js');
const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

test('each provider\'s form parses into its parts', () => {
  assert.deepEqual(parseExternalRef('ref+vault://secret/app/db#password'),
    { provider: 'vault', connection: null, mount: 'secret', path: 'app/db', key: 'password', canonical: 'secret/app/db' });
  assert.deepEqual(parseExternalRef('ref+infisical://p1/prod#K'),
    { provider: 'infisical', connection: null, project: 'p1', environment: 'prod', path: '/', name: 'K', canonical: 'p1/prod' });
  assert.equal(parseExternalRef('ref+infisical://p1/prod/a/b#K').path, '/a/b');
  assert.deepEqual(parseExternalRef('ref+op://My Vault/DB item/admin/pass word'),
    { provider: 'onepassword', connection: null, vault: 'My Vault', item: 'DB item', section: 'admin', field: 'pass word', canonical: 'My Vault/DB item' });
  assert.equal(parseExternalRef('ref+op://V/I/F').section, null);
  assert.deepEqual(parseExternalRef('ref+awsssm:///a/b/c'), { provider: 'awsssm', connection: null, name: '/a/b/c', key: null, canonical: '/a/b/c' });
  assert.deepEqual(parseExternalRef('ref+awsssm://flat#k'), { provider: 'awsssm', connection: null, name: 'flat', key: 'k', canonical: 'flat' });
  assert.equal(parseExternalRef('ref+vault://secret/app/db?connection=corp-1#password').connection, 'corp-1');
});

test('anything that could leave its path, or is not one of the forms, is refused', () => {
  for (const bad of [
    'ref+vault://secret#k', 'ref+vault://secret/a', 'ref+vault://secret/../b#k', 'ref+vault://secret/./b#k', 'ref+vault://secret//b#k',
    'ref+vault://secret/%2e%2e/b#k', 'ref+vault://secret/a#__proto__', 'ref+vault://secret/a#a#b', 'ref+vault://secret/a#a/b',
    'ref+vault://secret/a?connection=Bad#k', 'ref+vault://secret/a?other=x#k', 'ref+vault://secret/a#k?connection=x',
    'ref+vault://secret/a\n#k', 'ref+vault://secret/ a#k', 'ref+vault://secret/a\u0000#k', 'ref+vault://sécret/a#k',
    'ref+infisical://p1#K', 'ref+infisical://p1/prod', 'ref+op://V/I', 'ref+op://V/I/S/F/X', 'ref+op://V/I/F#k', 'ref+op://V/ I/F',
    'ref+awsssm://a/b', 'ref+awsssm:///', 'ref+awsssm:///a/../b', 'ref+consul://a/b#c', 'ref+vault:secret/a#k', 'ref+VAULT://secret/a#k',
    `ref+vault://secret/${'a'.repeat(1100)}#k`,
  ]) assert.equal(parseExternalRef(bad), null, JSON.stringify(bad));
});

test('a ref+ value is a reference for every caller, even malformed, so it is never injected as text', () => {
  assert.equal(isSecretRef('ref+vault://x'), true);
  assert.equal(isSecretRef(' ref+vault://secret/a#k'), false);
  assert.equal(isExternalRef('secretsmanager:X'), false);
  assert.equal(parseSecretRef('ref+vault://secret/a#k'), null, 'a ref+ value is not read as a Secrets Manager name');
  assert.equal(refSource('ref+vault://secret/a#k'), 'vault');
  assert.equal(refSource('ref+op://a/b/c'), 'onepassword');
  assert.equal(refSource('ref+awsssm:///a'), 'aws_ssm');
  assert.equal(refSource('ref+infisical://a/b#c'), 'infisical');
  assert.equal(refSource('secretsmanager:X'), 'secrets_manager');
  assert.equal(externalSource('ref+zzz://a'), 'external');
});

test('path_prefix matches whole segments with {slug} expanded', () => {
  assert.equal(prefixAllows('/appcrane/{slug}', '/appcrane/aaa/token', 'aaa'), true);
  assert.equal(prefixAllows('/appcrane/{slug}/', '/appcrane/aaa', 'aaa'), true);
  assert.equal(prefixAllows('/appcrane/{slug}', '/appcrane/aaab/token', 'aaa'), false);
  assert.equal(prefixAllows('/appcrane/{slug}', '/appcrane/bbb/token', 'aaa'), false);
  assert.equal(prefixAllows(undefined, 'anything', 'aaa'), true);
});

const mkApp = (slug, slot) => ({ id: Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug, slug, slot).lastInsertRowid), slug });

test('connection selection: own app first, then platform; another app\'s is never a candidate', () => {
  const a = mkApp('sel-a', 16100);
  const b = mkApp('sel-b', 16101);
  const ref = (s) => parseExternalRef(s);
  assert.throws(() => connectionForRef(a, ref('ref+vault://s/a#k')), /no HashiCorp Vault connection is configured/);
  createConnection({ appId: b.id, name: 'b-only', provider: 'vault', settings: { address: 'https://vault.b.test' }, credentials: { token: 't' } });
  assert.throws(() => connectionForRef(a, ref('ref+vault://s/a#k')), /no HashiCorp Vault connection/, 'app b\'s connection was picked as app a\'s default');
  assert.throws(() => connectionForRef(a, ref('ref+vault://s/a?connection=b-only#k')), /no connection named b-only/);
  createConnection({ name: 'plat', provider: 'vault', settings: { address: 'https://vault.test', allowed_apps: [a.id, b.id] }, credentials: { token: 't' } });
  assert.equal(connectionForRef(a, ref('ref+vault://s/a#k')).name, 'plat');
  createConnection({ name: 'plat2', provider: 'vault', settings: { address: 'https://vault2.test', path_prefix: 's/{slug}' }, credentials: { token: 't' } });
  assert.throws(() => connectionForRef(a, ref('ref+vault://s/a#k')), /more than one HashiCorp Vault connection/);
  assert.equal(connectionForRef(a, ref('ref+vault://s/a?connection=plat2#k')).name, 'plat2');
  createConnection({ appId: a.id, name: 'mine', provider: 'vault', settings: { address: 'https://vault.a.test' }, credentials: { token: 't' } });
  assert.equal(connectionForRef(a, ref('ref+vault://s/a#k')).name, 'mine');
  assert.equal(connectionForRef(b, ref('ref+vault://s/a#k')).name, 'b-only');
  assert.throws(() => connectionForRef({ slug: 'x' }, ref('ref+vault://s/a#k')), ConnectionError);
});

test('a platform connection must be scoped: {slug} prefix or allowed_apps; awsssm always needs the prefix; app connections take no list', () => {
  const a = mkApp('scope-a', 16110);
  const v = (settings, extra = {}) => ({ provider: 'vault', settings: { address: 'https://v.test', ...settings }, credentials: { token: 't' }, ...extra });
  assert.throws(() => createConnection({ name: 'open', ...v({}) }), /must be scoped/);
  assert.throws(() => createConnection({ name: 'open', ...v({ path_prefix: 'secret/shared' }) }), /must be scoped/, 'a prefix without {slug} scopes nothing per app');
  assert.throws(() => createConnection({ name: 'open', ...v({ allowed_apps: [] }) }), /invalid setting allowed_apps/);
  assert.throws(() => createConnection({ name: 'open', ...v({ allowed_apps: ['scope-a'] }) }), /invalid setting allowed_apps/, 'slugs can be reused; the list takes ids');
  assert.throws(() => createConnection({ name: 'open', ...v({ allowed_apps: [999999] }) }), /no app with id 999999/);
  assert.throws(() => createConnection({ name: 'ssm', provider: 'awsssm', settings: { allowed_apps: [a.id] } }), /awsssm connection needs a path_prefix containing \{slug\}/);
  assert.throws(() => createConnection({ name: 'ssm', provider: 'awsssm', settings: { path_prefix: '/shared' } }), /awsssm connection needs a path_prefix/);
  assert.throws(() => createConnection({ appId: a.id, name: 'mine-list', ...v({ allowed_apps: [a.id] }) }), /allowed_apps is for platform connections/);
  const ok = createConnection({ name: 'scoped', ...v({ allowed_apps: [a.id] }) });
  assert.throws(() => updateConnection(null, ok.id, { settings: { address: 'https://v.test' } }), /must be scoped/, 'an update unscoped it');
  assert.doesNotThrow(() => createConnection({ appId: a.id, name: 'mine-open', ...v({}) }), 'an app connection needs no scope');
});

test('the table itself refuses an unscoped platform row, so a write that skips connections.js cannot open one to every app', () => {
  const ins = (provider, settings, appId = null) => db.prepare('INSERT INTO secret_connections (name, provider, app_id, settings_json) VALUES (?, ?, ?, ?)')
    .run(`raw-${crypto.randomBytes(3).toString('hex')}`, provider, appId, JSON.stringify(settings));
  assert.throws(() => ins('vault', {}), /CHECK constraint failed/);
  assert.throws(() => ins('vault', { path_prefix: 'secret/shared' }), /CHECK constraint failed/);
  assert.throws(() => ins('vault', { allowed_apps: [] }), /CHECK constraint failed/);
  assert.throws(() => ins('awsssm', { allowed_apps: [1] }), /CHECK constraint failed/);
  assert.doesNotThrow(() => ins('vault', { path_prefix: 'secret/{slug}' }));
  assert.doesNotThrow(() => ins('vault', { allowed_apps: [1] }));
  assert.doesNotThrow(() => ins('awsssm', { path_prefix: '/appcrane/{slug}' }));
});

test('write-time check needs the app, and refuses without a store call', () => {
  assert.throws(() => assertStorableValue('ref+vault://s/a#k'), SecretRefError);
  assert.throws(() => assertStorableValue('ref+vault://s/a'), /malformed/);
});

test('a malformed ref+ value fails resolution naming the key, with no connection lookup', async () => {
  await assert.rejects(resolveEnvValues({ slug: 'x' }, 'sandbox', [{ key: 'K', plain: 'ref+vault://s/../a#k' }]), (e) => {
    assert.deepEqual(e.keys, ['K']);
    assert.match(e.message, /K \(ref\+vault:\/\/s\/\.\.\/a#k: malformed/);
    return true;
  });
});

class NodeSha256 {
  constructor(secret) { this.h = secret ? crypto.createHmac('sha256', secret) : crypto.createHash('sha256'); }
  update(d) { this.h.update(typeof d === 'string' ? Buffer.from(d, 'utf8') : Buffer.from(d)); }
  async digest() { return new Uint8Array(this.h.digest()); }
}

test('the SigV4 signature equals the AWS SDK signer\'s, with and without a session token', async () => {
  for (const creds of [
    { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' },
    { accessKeyId: 'ASIAEXAMPLE', secretAccessKey: 'secret', sessionToken: 'session-token-value' },
  ]) {
    const now = new Date('2026-11-20T10:11:12Z');
    const body = JSON.stringify({ Name: '/a/b', WithDecryption: true });
    const headers = signRequest({ url: 'https://ssm.eu-west-1.amazonaws.com/', body, target: 'AmazonSSM.GetParameter', region: 'eu-west-1', creds, now });
    const signer = new SignatureV4({ service: 'ssm', region: 'eu-west-1', sha256: NodeSha256, credentials: creds, applyChecksum: false });
    const { authorization: _, ...unsigned } = headers;
    const ref = await signer.sign({ method: 'POST', protocol: 'https:', hostname: 'ssm.eu-west-1.amazonaws.com', path: '/', query: {}, headers: unsigned, body }, { signingDate: now });
    assert.equal(headers.authorization, ref.headers.authorization);
  }
});

test('repointing a connection needs its credentials re-entered, so a stored token is never sent to a new address', () => {
  const a = mkApp('repoint-a', 16190);
  const c = createConnection({ appId: a.id, name: 'repoint', provider: 'vault', settings: { address: 'https://vault.a.test' }, credentials: { token: 't' } });
  assert.throws(() => updateConnection(a.id, c.id, { settings: { address: 'https://elsewhere.test' } }), /credentials re-entered/);
  assert.equal(db.prepare('SELECT settings_json FROM secret_connections WHERE id = ?').get(c.id).settings_json.includes('elsewhere'), false);
  updateConnection(a.id, c.id, { settings: { address: 'https://vault.a.test', path_prefix: 'secret/a' } });
  updateConnection(a.id, c.id, { settings: { address: 'https://elsewhere.test' }, credentials: { token: 't2' } });
  assert.ok(db.prepare('SELECT settings_json FROM secret_connections WHERE id = ?').get(c.id).settings_json.includes('elsewhere'));
});
