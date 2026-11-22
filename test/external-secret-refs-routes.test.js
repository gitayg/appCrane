import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { startFakeVault, startFakeInfisical, startFakeOnePasswordConnect, startFakeSsm } from './fake-secret-stores.mjs';

// ref+ references to Vault, Infisical, 1Password and SSM Parameter Store through
// the real doors (REST, MCP, a restart, a deploy) against local fakes of each
// store and a recording `docker` shim. The fakes' `calls` prove what reached a
// store; the shim's argv proves what reached a container; the database file,
// the captured log output, the audit rows and every response body are searched
// for each resolved value.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-ext-refs-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'debug';
delete process.env.APPCRANE_SECRETS_PROVIDER;
delete process.env.APPCRANE_SECRET_CONNECTIONS_PRIVATE_OK;
process.env.AWS_ACCESS_KEY_ID = 'AKIAEXTREFSTESTKEY01';
process.env.AWS_SECRET_ACCESS_KEY = 'ext-refs-test-secret-access-key';
delete process.env.AWS_SESSION_TOKEN;
process.env.AWS_REGION = 'us-east-1';

const LOGS = [];
for (const m of ['log', 'info', 'warn', 'error', 'debug']) {
  console[m] = (...a) => { LOGS.push(a.map(String).join(' ')); };
}

const vault = await startFakeVault();
const infisical = await startFakeInfisical();
const onep = await startFakeOnePasswordConnect();
const ssm = await startFakeSsm({ accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY });

const V = {
  vault: 'vault-resolved-value-71',
  approle: 'approle-resolved-value-72',
  infisical: 'infisical-resolved-value-73',
  op: 'onepassword-resolved-value-74',
  opsec: 'onepassword-section-value-75',
  ssm: 'ssm-resolved-value-76',
  ssmjson: 'ssm-json-field-value-77',
  cli: 'op-cli-resolved-value-78',
  other: 'other-app-only-value-79',
};
const CRED = {
  vaultToken: 'hvs.vault-root-token-credential',
  roleId: 'role-id-credential', secretId: 'secret-id-credential',
  infId: 'inf-client-id-credential', infSecret: 'inf-client-secret-credential',
  connect: 'connect-token-credential', sa: 'ops_service-account-credential',
  otherToken: 'hvs.other-app-token-credential',
};
vault.state.tokens.add(CRED.vaultToken);
vault.state.approles.set(CRED.roleId, CRED.secretId);
vault.state.kv.set('secret/aaa/db', { password: V.vault, port: 5432 });
vault.state.kv.set('kv/aaa/role', { api: V.approle });
vault.state.kv.set('secret/bbb/db', { password: V.other });
infisical.state.clients.set(CRED.infId, CRED.infSecret);
infisical.state.secrets.set(['proj-1', 'prod', '/backend', 'STRIPE_KEY'].join('|'), V.infisical);
onep.state.token = CRED.connect;
onep.state.vaults = [{
  id: 'vaultid00000000000000000001', name: 'Prod',
  items: [{
    id: 'itemid000000000000000000001', title: 'Database',
    sections: [{ id: 'sec1', label: 'admin' }],
    fields: [
      { id: 'f1', label: 'password', value: V.op },
      { id: 'f2', label: 'password', value: V.opsec, section: { id: 'sec1' } },
    ],
  }],
}];
ssm.state.params.set('/appcrane/aaa/token', V.ssm);
ssm.state.params.set('/appcrane/aaa/json', JSON.stringify({ inner: V.ssmjson }));

const SHIM = join(ROOT, 'bin');
const ARGV = join(ROOT, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(ARGV)}, JSON.stringify(args) + '\\n');
if (args[0] === 'version') { process.stdout.write('29.0.0\\n'); process.exit(0); }
if (args[0] === 'network' && args[1] === 'inspect') { process.stdout.write('false|172.20.0.0/16 '); process.exit(0); }
if (args[0] === 'image' && args[1] === 'inspect') { process.stdout.write('bs@sha256:' + 'b4'.repeat(32) + '\\n'); process.exit(0); }
if (args[0] === 'images') process.exit(0);
if (args[0] === 'inspect' && args.join(' ').includes('.Config.Env')) { process.stdout.write('[]\\n'); process.exit(0); }
if (args[0] === 'inspect') { process.stdout.write('example/app:1\\n'); process.exit(0); }
process.stdout.write('0123456789abcdef\\n');
`, { mode: 0o755 });
writeFileSync(join(SHIM, 'fake-op'), `#!/usr/bin/env node
if (process.env.OP_SERVICE_ACCOUNT_TOKEN !== ${JSON.stringify(CRED.sa)}) { process.stderr.write('[ERROR] invalid token\\n'); process.exit(1); }
const a = process.argv.slice(2);
if (a[0] === 'read' && a[1] === '--no-newline' && a[2] === 'op://Prod/Database/password') { process.stdout.write(${JSON.stringify(V.cli)}); process.exit(0); }
process.stderr.write('[ERROR] not found ' + a.join(' ') + '\\n'); process.exit(1);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
const dockerCalls = () => (existsSync(ARGV) ? readFileSync(ARGV, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const clearDocker = () => writeFileSync(ARGV, '');
const startedContainers = () => dockerCalls().filter((a) => ['run', 'stop', 'rm'].includes(a[0]));

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt, decrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

let slot = 15300;
const mkApp = (slug, sourceType = 'managed') => {
  const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,?,'main')").run(slug, slug, slot++, sourceType).lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(id, env);
    db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  }
  return id;
};
const APP = mkApp('aaa');
const OTHER = mkApp('bbb');
const mkUser = (name, role, roles = {}) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)').run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  for (const [appId, appRole] of Object.entries(roles)) db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, id, appRole);
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const OWNER = mkUser('owner', 'user', { [APP]: 'owner' });
const APPADMIN = mkUser('appadmin', 'user', { [APP]: 'admin' });
const MEMBER = mkUser('member', 'user', { [APP]: 'user' });
const OTHER_OWNER = mkUser('otherowner', 'user', { [OTHER]: 'owner' });
const PLATFORM = mkUser('platform', 'platform_admin');

const envRoutes = (await import('../server/routes/envVars.js')).default;
const deployRoutes = (await import('../server/routes/deploy.js')).default;
const appConnRoutes = (await import('../server/routes/appSecretConnections.js')).default;
const platformConnRoutes = (await import('../server/routes/secretConnections.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', envRoutes);
  a.use('/api/apps', appConnRoutes);
  a.use('/api/apps', deployRoutes);
  a.use('/api/secret-connections', platformConnRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(async () => {
  server.closeAllConnections?.(); server.close();
  for (const f of [vault, infisical, onep, ssm]) f.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
});
const BASE = `http://127.0.0.1:${server.address().port}`;
const BODIES = [];
const call = async (who, method, path, body) => {
  const headers = who ? { 'x-api-key': who.key } : {};
  if (body) headers['content-type'] = 'application/json';
  const r = await fetch(`${BASE}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  BODIES.push(text);
  return { status: r.status, text, json: (() => { try { return JSON.parse(text); } catch (_) { return null; } })() };
};
const unwrap = (r) => (r?.content?.[0]?.text ? JSON.parse(r.content[0].text) : r);
const setRow = (app, env, key, plain) => db.prepare(`
  INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?,?,?,?)
  ON CONFLICT(app_id, env, key) DO UPDATE SET value_encrypted = excluded.value_encrypted
`).run(app, env, key, encrypt(plain));
const rowPlain = (app, env, key) => {
  const r = db.prepare('SELECT value_encrypted FROM env_vars WHERE app_id = ? AND env = ? AND key = ?').get(app, env, key);
  return r ? decrypt(r.value_encrypted) : null;
};
const clearRows = () => db.prepare('DELETE FROM env_vars').run();
const clearCalls = () => { for (const f of [vault, infisical, onep, ssm]) f.calls.length = 0; };
const reset = () => { clearCalls(); clearDocker(); clearRows(); };
const auditText = () => db.prepare('SELECT action, detail FROM audit_log').all().map((r) => `${r.action} ${r.detail}`).join('\n');
const dbFileText = () => {
  db.pragma('wal_checkpoint(TRUNCATE)');
  const text = readdirSync(ROOT).filter((f) => f.startsWith('deployhub.db')).map((f) => readFileSync(join(ROOT, f)).toString('latin1')).join('\n');
  assert.match(text, /CREATE TABLE secret_connections/, 'the database file was not read');
  return text;
};

// --- Connections

const created = {};
test('platform connections: platform admin only, credentials go in and never come back out', async () => {
  assert.equal((await call(null, 'POST', '/api/secret-connections', {})).status, 401);
  const asOwner = await call(OWNER, 'POST', '/api/secret-connections', { name: 'x', provider: 'vault', settings: { address: vault.url }, credentials: { token: 't' } });
  assert.equal(asOwner.status, 403, asOwner.text);
  assert.equal((await call(OWNER, 'GET', '/api/secret-connections')).status, 403);

  const mk = async (body) => {
    const r = await call(PLATFORM, 'POST', '/api/secret-connections', body);
    assert.equal(r.status, 201, r.text);
    created[body.name] = r.json.connection.id;
    return r;
  };
  await mk({ name: 'corp-vault', provider: 'vault', settings: { address: vault.url, path_prefix: 'secret/{slug}' }, credentials: { token: CRED.vaultToken } });
  await mk({ name: 'role-vault', provider: 'vault', settings: { address: vault.url, auth: 'approle', path_prefix: 'kv/{slug}' }, credentials: { role_id: CRED.roleId, secret_id: CRED.secretId } });
  await mk({ name: 'corp-infisical', provider: 'infisical', settings: { site_url: infisical.url, allowed_apps: [APP] }, credentials: { client_id: CRED.infId, client_secret: CRED.infSecret } });
  await mk({ name: 'corp-op', provider: 'onepassword', settings: { connect_url: onep.url, allowed_apps: [APP] }, credentials: { token: CRED.connect } });
  await mk({ name: 'corp-ssm', provider: 'awsssm', settings: { region: 'us-east-1', endpoint: ssm.url, path_prefix: '/appcrane/{slug}' } });

  for (const b of [
    { name: 'unscoped', provider: 'vault', settings: { address: vault.url }, credentials: { token: 't' } },
    { name: 'unscoped', provider: 'vault', settings: { address: vault.url, path_prefix: 'secret/shared' }, credentials: { token: 't' } },
    { name: 'unscoped', provider: 'awsssm', settings: { endpoint: ssm.url, allowed_apps: [APP] } },
  ]) {
    const r = await call(PLATFORM, 'POST', '/api/secret-connections', b);
    assert.equal(r.status, 400, `${JSON.stringify(b)}: ${r.text}`);
    assert.match(r.text, /must be scoped|awsssm connection needs a path_prefix containing \{slug\}/);
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM secret_connections WHERE name = 'unscoped'").get().n, 0);
  const bad = [
    { name: 'Bad Name', provider: 'vault', settings: { address: vault.url }, credentials: { token: 't' } },
    { name: 'nope', provider: 'consul', settings: {}, credentials: {} },
    { name: 'nope', provider: 'vault', settings: {}, credentials: { token: 't' } },
    { name: 'nope', provider: 'vault', settings: { address: 'file:///etc/passwd' }, credentials: { token: 't' } },
    { name: 'nope', provider: 'vault', settings: { address: vault.url, extra: 1 }, credentials: { token: 't' } },
    { name: 'nope', provider: 'vault', settings: { address: vault.url }, credentials: {} },
    { name: 'nope', provider: 'vault', settings: { address: vault.url }, credentials: { token: 't', other: 'x' } },
    { name: 'corp-vault', provider: 'vault', settings: { address: vault.url }, credentials: { token: 't' } },
  ];
  for (const b of bad) assert.ok([400, 409].includes((await call(PLATFORM, 'POST', '/api/secret-connections', b)).status), JSON.stringify(b));

  const list = await call(PLATFORM, 'GET', '/api/secret-connections');
  assert.equal(list.status, 200);
  assert.deepEqual(list.json.connections.map((c) => c.name).sort(), ['corp-infisical', 'corp-op', 'corp-ssm', 'corp-vault', 'role-vault']);
  assert.ok(list.json.connections.every((c) => c.credentials_set === (c.provider !== 'awsssm') && !('credentials' in c) && !('credentials_enc' in c)));
  const row = db.prepare("SELECT settings_json, credentials_enc FROM secret_connections WHERE name = 'corp-vault'").get();
  assert.doesNotMatch(row.settings_json, /hvs\./);
  assert.equal(decrypt(row.credentials_enc), JSON.stringify({ token: CRED.vaultToken }));
});

test('app connections: the owner sets them, a member only lists them, another app cannot touch them, and SSM is platform only', async () => {
  const body = { name: 'own-vault', provider: 'vault', settings: { address: vault.url }, credentials: { token: CRED.otherToken } };
  assert.equal((await call(MEMBER, 'POST', '/api/apps/bbb/secret-connections', body)).status, 403);
  assert.equal((await call(OWNER, 'POST', '/api/apps/bbb/secret-connections', body)).status, 403, 'an owner of aaa created a connection on bbb');
  const r = await call(OTHER_OWNER, 'POST', '/api/apps/bbb/secret-connections', { ...body, name: 'b-vault' });
  assert.equal(r.status, 201, r.text);
  created['b-vault'] = r.json.connection.id;
  vault.state.tokens.add(CRED.otherToken);

  assert.equal((await call(MEMBER, 'POST', '/api/apps/aaa/secret-connections', body)).status, 403, 'a plain member created a connection');
  assert.equal((await call(APPADMIN, 'POST', '/api/apps/aaa/secret-connections', body)).status, 403, 'an app admin created a connection');
  const own = await call(OWNER, 'POST', '/api/apps/aaa/secret-connections', { ...body, name: 'a-vault', credentials: { token: CRED.vaultToken } });
  assert.equal(own.status, 201, own.text);
  created['a-vault'] = own.json.connection.id;
  assert.equal((await call(OWNER, 'POST', '/api/apps/aaa/secret-connections', { name: 'a-ssm', provider: 'awsssm', settings: {} })).status, 403);

  const asMember = await call(MEMBER, 'GET', '/api/apps/aaa/secret-connections');
  assert.equal(asMember.status, 200);
  assert.deepEqual(asMember.json.connections.map((c) => c.name), ['a-vault']);
  assert.equal('settings' in asMember.json.connections[0], false, 'a member sees settings');
  assert.ok(asMember.json.platform.some((c) => c.name === 'corp-vault'));
  assert.ok(!asMember.json.connections.concat(asMember.json.platform).some((c) => c.name === 'b-vault'), 'app aaa lists app bbb\'s connection');

  // bbb's connection id through aaa's door is not found; aaa's owner cannot change it.
  assert.equal((await call(OWNER, 'PATCH', `/api/apps/aaa/secret-connections/${created['b-vault']}`, { credentials: { token: 'x' } })).status, 404);
  assert.equal((await call(OWNER, 'DELETE', `/api/apps/aaa/secret-connections/${created['b-vault']}`)).status, 404);
  assert.equal((await call(OWNER, 'DELETE', `/api/apps/bbb/secret-connections/${created['b-vault']}`)).status, 403);
  assert.equal((await call(PLATFORM, 'DELETE', `/api/apps/bbb/secret-connections/${created['b-vault']}`)).status, 403, 'an unassigned platform admin reached an app connection');
  assert.equal((await call(PLATFORM, 'DELETE', `/api/secret-connections/${created['b-vault']}`)).status, 404, 'the platform door reached an app connection');
  assert.ok(db.prepare('SELECT 1 FROM secret_connections WHERE id = ?').get(created['b-vault']));
});

// --- Writing references

test('write: a reference is checked against the connections this app may use, on REST and MCP, without a store call', async () => {
  reset();
  const ok = await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { DB_PW: 'ref+vault://secret/aaa/db?connection=corp-vault#password', OWN_DEFAULT: 'ref+vault://secret/aaa/db#password' } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(rowPlain(APP, 'sandbox', 'DB_PW'), 'ref+vault://secret/aaa/db?connection=corp-vault#password');

  const refused = [
    ['ref+vault://secret/aaa/db', /malformed/],
    ['ref+vault://secret/../bbb/db#password', /malformed/],
    ['ref+vault://secret/%2e%2e/db#password', /malformed/],
    ['ref+vault://secret/aaa/db#__proto__', /malformed/],
    ['ref+nope://x/y#z', /malformed/],
    ['ref+vault://secret/aaa/db?connection=b-vault#password', /no connection named b-vault/],
    ['ref+vault://secret/aaa/db?connection=nope#password', /no connection named nope/],
    ['ref+vault://secret/aaa/db?connection=corp-op#password', /not a HashiCorp Vault connection/],
    ['ref+awsssm:///appcrane/bbb/token', /only allows paths under \/appcrane\/aaa/],
  ];
  for (const [value, why] of refused) {
    const r = await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { BAD: value } });
    assert.equal(r.status, 400, `${value}: ${r.text}`);
    assert.match(r.text, why, value);
    await assert.rejects(callTool(OWNER.row, 'appcrane_set_secret', { slug: 'aaa', env: 'sandbox', key: 'BAD', value }), why, `MCP ${value}`);
  }
  assert.equal(rowPlain(APP, 'sandbox', 'BAD'), null);

  const mcp = unwrap(await callTool(OWNER.row, 'appcrane_set_secret', { slug: 'aaa', env: 'sandbox', key: 'VIA_MCP', value: 'ref+op://Prod/Database/password' }));
  assert.equal(mcp.ok, true);
  for (const f of [vault, infisical, onep, ssm]) assert.deepEqual(f.calls, [], 'a write reached a store');
});

test('write: who may set the app\'s env vars is who may add a reference', async () => {
  reset();
  const ref = 'ref+op://Prod/Database/password';
  assert.equal((await call(OTHER_OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { R: ref } })).status, 403, 'an outsider wrote a reference');
  assert.equal((await call(PLATFORM, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { R: ref } })).status, 403, 'an unassigned platform admin wrote a reference');
  assert.equal((await call(MEMBER, 'PUT', '/api/apps/aaa/env/production', { vars: { R: ref } })).status, 403, 'a member without env.write.production wrote a production reference');
  await assert.rejects(callTool(OTHER_OWNER.row, 'appcrane_set_secret', { slug: 'aaa', env: 'sandbox', key: 'R', value: ref }));
  assert.equal(rowPlain(APP, 'sandbox', 'R'), null);
  assert.equal(rowPlain(APP, 'production', 'R'), null);
});

test('reads: a reference lists as its text with the store as source, and no read reaches a store', async () => {
  reset();
  setRow(APP, 'sandbox', 'V_REF', 'ref+vault://secret/aaa/db?connection=corp-vault#password');
  setRow(APP, 'sandbox', 'S_REF', 'ref+awsssm:///appcrane/aaa/token');
  const list = await call(MEMBER, 'GET', '/api/apps/aaa/env/sandbox');
  const by = Object.fromEntries(list.json.vars.map((v) => [v.key, v]));
  assert.equal(by.V_REF.value, 'ref+vault://secret/aaa/db?connection=corp-vault#password');
  assert.equal(by.V_REF.source, 'vault');
  assert.equal(by.S_REF.source, 'aws_ssm');
  const one = await call(OWNER, 'POST', '/api/apps/aaa/env/sandbox/V_REF/reveal');
  assert.equal(one.json.source, 'vault');
  const mcp = unwrap(await callTool(OWNER.row, 'appcrane_get_secret', { slug: 'aaa', env: 'sandbox' }));
  assert.equal(mcp.vars.find((v) => v.key === 'S_REF').source, 'aws_ssm');
  for (const f of [vault, infisical, onep, ssm]) assert.deepEqual(f.calls, []);
});

// --- Resolution

const ALL_REFS = {
  VAULT_PW: 'ref+vault://secret/aaa/db?connection=corp-vault#password',
  VAULT_PORT: 'ref+vault://secret/aaa/db?connection=corp-vault#port',
  APPROLE: 'ref+vault://kv/aaa/role?connection=role-vault#api',
  INF: 'ref+infisical://proj-1/prod/backend#STRIPE_KEY',
  OP: 'ref+op://Prod/Database/password',
  OP_SEC: 'ref+op://Prod/Database/admin/password',
  SSM: 'ref+awsssm:///appcrane/aaa/token',
  SSM_JSON: 'ref+awsssm:///appcrane/aaa/json#inner',
};

test('restart: every store\'s reference reaches the container as its value, and nothing else holds the value', async () => {
  reset();
  for (const [k, v] of Object.entries(ALL_REFS)) setRow(APP, 'sandbox', k, v);
  setRow(APP, 'sandbox', 'PLAIN', 'plain-value');
  const before = LOGS.length;
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 200, r.text);
  const run = dockerCalls().find((a) => a[0] === 'run');
  assert.ok(run, 'no docker run');
  for (const want of [`VAULT_PW=${V.vault}`, 'VAULT_PORT=5432', `APPROLE=${V.approle}`, `INF=${V.infisical}`, `OP=${V.op}`, `OP_SEC=${V.opsec}`, `SSM=${V.ssm}`, `SSM_JSON=${V.ssmjson}`, 'PLAIN=plain-value']) {
    assert.ok(run.includes(want), `${want} missing from docker run`);
  }
  assert.ok(!run.some((x) => x.includes('ref+')), 'a reference text reached the container');

  assert.equal(ssm.state.signatureFailures, 0, 'the SSM signature did not verify against the SDK signer');
  const vaultReads = vault.calls.filter((c) => c.path.startsWith('/v1/secret/'));
  assert.ok(vaultReads.length >= 2 && vaultReads.every((c) => c.path === '/v1/secret/data/aaa/db' && c.headers['x-vault-token'] === CRED.vaultToken));
  assert.equal(vault.calls.filter((c) => c.path === '/v1/auth/approle/login').length, 1);
  assert.equal(vault.calls.find((c) => c.path === '/v1/kv/data/aaa/role').headers['x-vault-token'], vault.state.loginToken);
  assert.equal(infisical.calls.filter((c) => c.path.endsWith('/login')).length, 1, 'one login per resolution');
  assert.deepEqual(infisical.calls.find((c) => c.path.startsWith('/api/v3')).query, { workspaceId: 'proj-1', environment: 'prod', secretPath: '/backend' });

  await new Promise((res) => setTimeout(res, 50));
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'secret-ref-resolve' ORDER BY id DESC LIMIT 1").get();
  const detail = JSON.parse(audit.detail);
  assert.equal(detail.env, 'sandbox');
  assert.deepEqual(detail.refs.map((x) => [x.key, x.provider, x.reference, x.ok]).sort(),
    Object.entries(ALL_REFS).map(([k, v]) => [k, { vault: 'vault', infisical: 'infisical', op: 'onepassword', awsssm: 'awsssm' }[v.slice(4, v.indexOf(':'))], v, true]).sort());

  const leaks = new RegExp(Object.values(V).join('|') + '|' + Object.values(CRED).map((c) => c.replace(/[.]/g, '\\.')).join('|'));
  assert.doesNotMatch(r.text, leaks, 'the response');
  assert.doesNotMatch(auditText(), leaks, 'the audit log');
  assert.doesNotMatch(LOGS.slice(before).join('\n'), leaks, 'the log output');
  assert.doesNotMatch(dbFileText(), leaks, 'the database file');
});

test('deploy: a resolved reference reaches docker run, the deploy log names the store and keys only', async () => {
  reset();
  const id = mkApp('deploy-ext', 'image');
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, OWNER.id);
  const p = getPortsForSlot(db.prepare('SELECT slot FROM apps WHERE id = ?').get(id).slot);
  db.prepare("UPDATE apps SET image_ref = 'bs:1', container_port = 3000, health_path = '/h' WHERE id = ?").run(id);
  vault.state.kv.set('secret/deploy-ext/db', { password: 'deploy-ext-vault-value' });
  setRow(id, 'sandbox', 'DB_PW', 'ref+vault://secret/deploy-ext/db?connection=corp-vault#password');
  setRow(id, 'sandbox', 'TOKEN', 'ref+op://Prod/Database/password');
  const opened = await call(PLATFORM, 'PATCH', `/api/secret-connections/${created['corp-op']}`, { settings: { connect_url: onep.url, allowed_apps: [APP, id] } });
  assert.equal(opened.status, 200, opened.text);
  const health = http.createServer((_, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"status":"ok","version":"1.0.0"}'); });
  await new Promise((r) => health.listen(p.sand_be, '127.0.0.1', r));
  const before = LOGS.length;
  try {
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
    const dep = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)").run(id, OWNER.id).lastInsertRowid;
    await deployApp(dep, app, 'sandbox', p, {}).catch(() => {});
    const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(dep);
    const run = dockerCalls().find((a) => a[0] === 'run' && a.some((x) => x.startsWith('DB_PW=')));
    assert.ok(run, `no docker run carried DB_PW. log:\n${row.log}`);
    assert.ok(run.includes('DB_PW=deploy-ext-vault-value'));
    assert.ok(run.includes(`TOKEN=${V.op}`));
    assert.match(row.log, /Resolved from HashiCorp Vault: DB_PW/);
    assert.match(row.log, /Resolved from 1Password: TOKEN/);
    assert.doesNotMatch(row.log, /deploy-ext-vault-value|onepassword-resolved/);
    assert.doesNotMatch(LOGS.slice(before).join('\n'), /deploy-ext-vault-value|onepassword-resolved/);
    assert.doesNotMatch(dbFileText(), /deploy-ext-vault-value/);
  } finally { health.closeAllConnections?.(); health.close(); }
});

test('deploy: a failed resolution fails the deploy naming the key and the reference, before docker is touched', async () => {
  reset();
  const id = mkApp('deploy-ext-bad', 'image');
  db.prepare("UPDATE apps SET image_ref = 'bs:1', container_port = 3000 WHERE id = ?").run(id);
  setRow(id, 'sandbox', 'GONE', 'ref+vault://secret/deploy-ext-bad/missing?connection=corp-vault#password');
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  const dep = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)").run(id, OWNER.id).lastInsertRowid;
  await deployApp(dep, app, 'sandbox', { sand_be: 1, prod_be: 2 }, {}).catch(() => {});
  const row = db.prepare('SELECT status, log, failure_reason FROM deployments WHERE id = ?').get(dep);
  assert.equal(row.status, 'failed', row.log);
  assert.match(row.failure_reason, /GONE \(ref\+vault:\/\/secret\/deploy-ext-bad\/missing\?connection=corp-vault#password: HashiCorp Vault \(connection corp-vault\): HTTP 404\)/);
  assert.deepEqual(dockerCalls().filter((c) => ['run', 'stop', 'rm', 'pull', 'create', 'build'].includes(c[0])), [], 'docker was used for a deploy that cannot get its env');
  const audit = JSON.parse(db.prepare("SELECT detail FROM audit_log WHERE action = 'secret-ref-resolve' AND app_id = ? ORDER BY id DESC LIMIT 1").get(id).detail);
  assert.deepEqual(audit.refs, [{ key: 'GONE', reference: 'ref+vault://secret/deploy-ext-bad/missing?connection=corp-vault#password', provider: 'vault', connection: 'corp-vault', ok: false }]);
});

test('restart: a store that refuses fails naming the key, leaves the running container alone, and repeats nothing the store said', async () => {
  reset();
  setRow(APP, 'sandbox', 'DENIED', 'ref+op://Prod/Database/password');
  const saved = onep.state.token;
  onep.state.token = 'rotated-elsewhere';
  try {
    const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
    assert.equal(r.status, 502, r.text);
    assert.match(r.text, /DENIED \(ref\+op:\/\/Prod\/Database\/password: 1Password \(connection corp-op\): HTTP 401\)/);
    assert.doesNotMatch(r.text, /Invalid token|connect-token-credential/);
    assert.deepEqual(startedContainers(), []);
  } finally { onep.state.token = saved; }
});

test('cross-app: a stored reference to another app\'s connection reaches no store and no container', async () => {
  reset();
  setRow(APP, 'sandbox', 'PROBE', 'ref+vault://secret/bbb/db?connection=b-vault#password');
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 502, r.text);
  assert.match(r.text, /PROBE .*no connection named b-vault is available to this app/);
  assert.deepEqual(vault.calls, [], 'app bbb\'s connection was used for app aaa');
  assert.deepEqual(startedContainers(), []);
  assert.doesNotMatch(r.text, new RegExp(V.other));

  // A path outside a platform connection's path_prefix, stored behind the write check.
  clearCalls();
  setRow(APP, 'sandbox', 'PROBE', 'ref+awsssm:///appcrane/bbb/token');
  const p = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(p.status, 502, p.text);
  assert.match(p.text, /only allows paths under \/appcrane\/aaa/);
  assert.deepEqual(ssm.calls, []);
});

test('platform {slug} prefix: app A reads its own subtree, and a reference into app B\'s is refused before Vault is called', async () => {
  reset();
  setRow(APP, 'sandbox', 'MINE', 'ref+vault://secret/aaa/db?connection=corp-vault#password');
  const ok = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(ok.status, 200, ok.text);
  assert.ok(dockerCalls().find((a) => a[0] === 'run').includes(`MINE=${V.vault}`));

  reset();
  const w = await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { THEIRS: 'ref+vault://secret/bbb/db?connection=corp-vault#password' } });
  assert.equal(w.status, 400, w.text);
  assert.match(w.text, /only allows paths under secret\/aaa/);
  setRow(APP, 'sandbox', 'THEIRS', 'ref+vault://secret/bbb/db?connection=corp-vault#password');
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 502, r.text);
  assert.match(r.text, /THEIRS .*only allows paths under secret\/aaa/);
  assert.deepEqual(vault.calls, [], 'Vault was asked for app bbb\'s path on app aaa\'s behalf');
  assert.doesNotMatch(r.text, new RegExp(V.other));
  assert.deepEqual(startedContainers(), []);
});

test('platform allowed_apps: a listed app resolves, an unlisted one is refused before the store is contacted', async () => {
  reset();
  setRow(APP, 'sandbox', 'INF', 'ref+infisical://proj-1/prod/backend#STRIPE_KEY');
  const ok = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(ok.status, 200, ok.text);
  assert.ok(dockerCalls().find((a) => a[0] === 'run').includes(`INF=${V.infisical}`));

  reset();
  for (const value of ['ref+infisical://proj-1/prod/backend#STRIPE_KEY', 'ref+infisical://proj-1/prod/backend?connection=corp-infisical#STRIPE_KEY']) {
    const w = await call(OTHER_OWNER, 'PUT', '/api/apps/bbb/env/sandbox', { vars: { STOLEN: value } });
    assert.equal(w.status, 400, `${value}: ${w.text}`);
    assert.match(w.text, /no Infisical connection is configured|not open to this app/);
    setRow(OTHER, 'sandbox', 'STOLEN', value);
    const r = await call(OTHER_OWNER, 'POST', '/api/apps/bbb/restart/sandbox');
    assert.equal(r.status, 502, `${value}: ${r.text}`);
    assert.match(r.text, /STOLEN .*(no Infisical connection is configured|not open to this app)/);
    assert.doesNotMatch(r.text, new RegExp(V.infisical));
  }
  assert.deepEqual(infisical.calls, [], 'Infisical was contacted for an app the connection does not list');
  assert.deepEqual(startedContainers(), []);

  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'secret-connection-update' ORDER BY id DESC LIMIT 1").get();
  assert.deepEqual(JSON.parse(audit.detail).allowed_apps.slice(0, 1), [APP], 'a change to allowed_apps is not in the audit log');
});

test('an app connection gets https only and no private address, unless the operator allows it', async () => {
  reset();
  setRow(APP, 'sandbox', 'OWN', 'ref+vault://secret/aaa/db?connection=a-vault#password');
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 502, r.text);
  assert.match(r.text, /OWN .*an app connection must use https/);
  assert.deepEqual(vault.calls, [], 'an app connection dialled a loopback http address');
  process.env.APPCRANE_SECRET_CONNECTIONS_PRIVATE_OK = '1';
  try {
    clearDocker();
    const ok = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
    assert.equal(ok.status, 200, ok.text);
    assert.ok(dockerCalls().find((a) => a[0] === 'run').includes(`OWN=${V.vault}`));
  } finally { delete process.env.APPCRANE_SECRET_CONNECTIONS_PRIVATE_OK; }
});

test('1Password service account: resolved through the op CLI with the token in its env only, and a missing CLI is named', async () => {
  reset();
  const c = await call(OWNER, 'POST', '/api/apps/aaa/secret-connections', { name: 'a-op-sa', provider: 'onepassword', settings: { mode: 'service_account' }, credentials: { token: CRED.sa } });
  assert.equal(c.status, 201, c.text);
  setRow(APP, 'sandbox', 'CLI', 'ref+op://Prod/Database/password?connection=a-op-sa');
  process.env.APPCRANE_OP_CLI = join(SHIM, 'fake-op');
  try {
    const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
    assert.equal(r.status, 200, r.text);
    const run = dockerCalls().find((a) => a[0] === 'run');
    assert.ok(run.includes(`CLI=${V.cli}`));
    assert.ok(!run.some((x) => x.includes(CRED.sa)), 'the service account token reached the container');
    process.env.APPCRANE_OP_CLI = join(SHIM, 'no-such-op');
    clearDocker();
    const missing = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
    assert.equal(missing.status, 502, missing.text);
    assert.match(missing.text, /CLI .*the 1Password CLI \(op\) is not installed/);
    assert.deepEqual(startedContainers(), []);
  } finally { delete process.env.APPCRANE_OP_CLI; }
});

test('deleting an app removes its connections', async () => {
  const { deleteApp } = await import('../server/services/appDelete.js');
  const id = mkApp('goes-away');
  db.prepare("INSERT INTO secret_connections (name, provider, app_id, settings_json) VALUES ('mine', 'vault', ?, '{}')").run(id);
  await deleteApp(db.prepare('SELECT * FROM apps WHERE id = ?').get(id));
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM secret_connections WHERE app_id = ?').get(id).n, 0);
});

test('no API response in this file carried a credential or a resolved value', () => {
  const all = BODIES.join('\n');
  for (const s of [...Object.values(CRED), ...Object.values(V)]) assert.ok(!all.includes(s), s);
});
