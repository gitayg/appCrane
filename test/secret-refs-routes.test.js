import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// References through the real doors: REST, MCP, a restart, a deploy and a promote,
// with the real secretsProvider against a fake Secrets Manager (JSON 1.1 over HTTP)
// and a recording `docker` shim. `aws.calls` is the proof of what reached AWS, and
// the shim's argv the proof of what reached a container.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-secret-refs-routes-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

function fakeSecretsManager() {
  const secrets = new Map();
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const op = String(req.headers['x-amz-target'] || '').split('.').pop();
      const input = body ? JSON.parse(body) : {};
      const id = input.SecretId ?? input.Name;
      calls.push({ op, id });
      const send = (status, out) => { res.writeHead(status, { 'content-type': 'application/x-amz-json-1.1' }); res.end(JSON.stringify(out)); };
      const missing = () => send(400, { __type: 'ResourceNotFoundException', message: 'not found' });
      const meta = { ARN: `arn:aws:secretsmanager:us-east-1:000000000000:secret:${id}`, Name: id, VersionId: 'v1' };
      if (op === 'GetSecretValue') return secrets.has(id) ? send(200, { ...meta, SecretString: secrets.get(id), VersionStages: ['AWSCURRENT'] }) : missing();
      if (op === 'DescribeSecret') return secrets.has(id) ? send(200, meta) : missing();
      if (op === 'PutSecretValue') { if (!secrets.has(id)) return missing(); secrets.set(id, input.SecretString); return send(200, meta); }
      if (op === 'CreateSecret') {
        if (secrets.has(id)) return send(400, { __type: 'ResourceExistsException', message: 'exists' });
        secrets.set(id, input.SecretString); return send(200, meta);
      }
      return send(400, { __type: 'InvalidRequestException', message: `unexpected ${op}` });
    });
  });
  return { server, secrets, calls };
}
const aws = fakeSecretsManager();
await new Promise((r) => aws.server.listen(0, '127.0.0.1', r));
process.env.AWS_ENDPOINT_URL_SECRETS_MANAGER = `http://127.0.0.1:${aws.server.address().port}`;
process.env.AWS_ACCESS_KEY_ID = 'AKIATESTTESTTESTTEST';
process.env.AWS_SECRET_ACCESS_KEY = 'test-secret-access-key';
process.env.AWS_REGION = 'us-east-1';
process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager';
process.env.APPCRANE_SECRETS_REGION = 'us-east-1';
delete process.env.APPCRANE_SECRETS_ID;
delete process.env.APPCRANE_SECRETS_APP_PREFIX;

const SHIM = join(ROOT, 'bin');
const ARGV = join(ROOT, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(ARGV)}, JSON.stringify(args) + '\\n');
if (args[0] === 'version') { if (fs.existsSync(${JSON.stringify(join(ROOT, 'docker-down'))})) process.exit(1); process.stdout.write('29.0.0\\n'); process.exit(0); }
if (args[0] === 'network' && args[1] === 'inspect') { process.stdout.write('false|172.20.0.0/16 '); process.exit(0); }
if (args[0] === 'image' && args[1] === 'inspect') { process.stdout.write('bs@sha256:' + 'b4'.repeat(32) + '\\n'); process.exit(0); }
if (args[0] === 'images') process.exit(0);
if (args[0] === 'inspect' && args.join(' ').includes('.Config.Env')) { process.stdout.write('[]\\n'); process.exit(0); }
if (args[0] === 'inspect') { process.stdout.write('example/app:1\\n'); process.exit(0); }
process.stdout.write('0123456789abcdef\\n');
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
const dockerCalls = () => (existsSync(ARGV) ? readFileSync(ARGV, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const clearDocker = () => writeFileSync(ARGV, '');
const startedContainers = () => dockerCalls().filter((a) => ['run', 'stop', 'rm'].includes(a[0]));

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt, decrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

let slot = 14200;
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
const mkUser = (name, role, appRole) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)').run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  if (appRole) db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, id, appRole);
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const OWNER = mkUser('owner', 'user', 'owner');
const APPADMIN = mkUser('appadmin', 'user', 'admin');
const MEMBER = mkUser('member', 'user', 'user');
const PLATFORM = mkUser('platform', 'platform_admin', null);

const envRoutes = (await import('../server/routes/envVars.js')).default;
const deployRoutes = (await import('../server/routes/deploy.js')).default;
const statusRoutes = (await import('../server/routes/secretsProviderStatus.js')).default;
const appRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { default: log } = await import('../server/utils/logger.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp, promoteApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { deleteApp } = await import('../server/services/appDelete.js');
const { renameApp } = await import('../server/services/appRename.js');

const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', envRoutes);
  a.use('/api/apps', deployRoutes);
  a.use('/api/secrets-provider/status', statusRoutes);
  a.use('/api/apps', appRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(async () => {
  server.closeAllConnections?.(); server.close();
  aws.server.closeAllConnections?.(); aws.server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
});
const BASE = `http://127.0.0.1:${server.address().port}`;
const call = async (who, method, path, body) => {
  const headers = who ? { 'x-api-key': who.key } : {};
  if (body) headers['content-type'] = 'application/json';
  const r = await fetch(`${BASE}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
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
const secretPath = (slug, env, name) => `appcrane/apps/${db.prepare('SELECT secrets_namespace FROM apps WHERE slug = ?').get(slug).secrets_namespace}/${env}/${name}`;
const clearRows = () => db.prepare('DELETE FROM env_vars').run();
const secretIds = () => aws.calls.map((c) => c.id);
const reset = () => { aws.calls.length = 0; aws.secrets.clear(); clearDocker(); clearRows(); };

const UNSAFE = [
  'secretsmanager:arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/keys',
  'secretsmanager:platform/keys',
  'secretsmanager:../../bbb/sandbox/TOKEN',
  'secretsmanager:%2e%2e%2fbbb',
  'secretsmanager:bbb∕TOKEN',
  'secretsmanager:',
];

test('store: the value reaches AWS under the app\'s path, env_vars holds only the reference, nothing else holds the value', async () => {
  reset();
  const PLAIN = 'store-plaintext-value-1';
  for (const [via, write] of [
    ['REST', () => call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { VIA_REST: PLAIN }, store: 'secrets_manager' })],
    ['MCP', () => callTool(OWNER.row, 'appcrane_set_secret', { slug: 'aaa', env: 'sandbox', key: 'VIA_MCP', value: PLAIN, store: 'secrets_manager' })],
  ]) {
    const out = await write();
    assert.doesNotMatch(JSON.stringify(out), new RegExp(PLAIN), `${via} returned the plaintext`);
  }
  assert.equal(rowPlain(APP, 'sandbox', 'VIA_REST'), 'secretsmanager:VIA_REST');
  assert.equal(rowPlain(APP, 'sandbox', 'VIA_MCP'), 'secretsmanager:VIA_MCP');
  assert.equal(aws.secrets.get(secretPath('aaa', 'sandbox', 'VIA_REST')), PLAIN);
  assert.equal(aws.secrets.get(secretPath('aaa', 'sandbox', 'VIA_MCP')), PLAIN);
  await new Promise((r) => setTimeout(r, 50));
  const audit = db.prepare('SELECT detail FROM audit_log').all().map((r) => r.detail).join('\n');
  assert.doesNotMatch(audit, new RegExp(PLAIN), 'the audit log holds the plaintext');
});

test('store: a failing AWS write leaves no row and no value, and says so without AWS\'s text', async () => {
  reset();
  const saved = process.env.AWS_ENDPOINT_URL_SECRETS_MANAGER;
  process.env.AWS_ENDPOINT_URL_SECRETS_MANAGER = 'http://127.0.0.1:1';
  try {
    const r = await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { WONT: 'plain-never-stored' }, store: 'secrets_manager' });
    assert.equal(r.status, 502, r.text);
    assert.match(r.text, /WONT/);
    assert.doesNotMatch(r.text, /plain-never-stored|127\.0\.0\.1/);
    assert.equal(rowPlain(APP, 'sandbox', 'WONT'), null);
  } finally { process.env.AWS_ENDPOINT_URL_SECRETS_MANAGER = saved; }
});

test('the production write gate runs before AWS is called, on REST and MCP', async () => {
  reset();
  const r = await call(MEMBER, 'PUT', '/api/apps/aaa/env/production', { vars: { GATED: 'x' }, store: 'secrets_manager' });
  assert.equal(r.status, 403, r.text);
  db.prepare("UPDATE role_permissions SET granted = 0 WHERE permission = 'env.write.production' AND role = 'admin'").run();
  try {
    await assert.rejects(callTool(APPADMIN.row, 'appcrane_set_secret', { slug: 'aaa', env: 'production', key: 'GATED', value: 'x', store: 'secrets_manager' }), /env\.write\.production/);
  } finally {
    db.prepare("UPDATE role_permissions SET granted = 1 WHERE permission = 'env.write.production' AND role = 'admin'").run();
  }
  assert.deepEqual(aws.calls, [], 'AWS was called before the gate refused');
  assert.equal(rowPlain(APP, 'production', 'GATED'), null);
});

test('a bad key or an unknown store value is refused before AWS', async () => {
  reset();
  assert.equal((await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { 'BAD-KEY': 'x' }, store: 'secrets_manager' })).status, 400);
  assert.equal((await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { K: 'x' }, store: 'vault' })).status, 400);
  assert.equal((await call(OWNER, 'PUT', '/api/apps/aaa/env/staging', { vars: { K: 'x' }, store: 'secrets_manager' })).status, 400);
  await assert.rejects(callTool(OWNER.row, 'appcrane_set_secret', { slug: 'aaa', key: 'BAD-KEY', value: 'x', store: 'secrets_manager' }), /Invalid env var key/);
  assert.deepEqual(aws.calls, []);
});

test('no provider configured: store and a direct reference are refused with a clear error, and an ordinary value is unaffected', async () => {
  reset();
  delete process.env.APPCRANE_SECRETS_PROVIDER;
  try {
    const r = await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { K: 'plain-x' }, store: 'secrets_manager' });
    assert.equal(r.status, 400, r.text);
    assert.equal(r.json.code ?? r.json.error?.code, 'SECRETS_PROVIDER_NOT_CONFIGURED', r.text);
    assert.equal((await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { K: 'secretsmanager:K' } })).status, 400);
    await assert.rejects(callTool(OWNER.row, 'appcrane_set_secret', { slug: 'aaa', key: 'K', value: 'x', store: 'secrets_manager' }), /no(ne is)? .*configured/);
    assert.equal(rowPlain(APP, 'sandbox', 'K'), null);
    assert.equal((await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { K: 'plain secretsmanager:K' } })).status, 200);
    assert.equal(rowPlain(APP, 'sandbox', 'K'), 'plain secretsmanager:K');
    assert.deepEqual(aws.calls, []);
  } finally { process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager'; }
});

test('a direct reference is stored as text; an unsafe one is refused at write on REST and MCP', async () => {
  reset();
  assert.equal((await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { DIRECT: 'secretsmanager:EXISTING#pw' } })).status, 200);
  assert.equal(rowPlain(APP, 'sandbox', 'DIRECT'), 'secretsmanager:EXISTING#pw');
  for (const bad of UNSAFE) {
    const r = await call(OWNER, 'PUT', '/api/apps/aaa/env/sandbox', { vars: { BAD_REF: bad } });
    assert.equal(r.status, 400, `${JSON.stringify(bad)}: ${r.text}`);
    await assert.rejects(callTool(OWNER.row, 'appcrane_set_secret', { slug: 'aaa', key: 'BAD_REF', value: bad }), /malformed/);
  }
  assert.equal(rowPlain(APP, 'sandbox', 'BAD_REF'), null);
  assert.deepEqual(aws.calls, [], 'a direct reference is checked, never fetched, at write time');
});

test('reads return the reference text with source and never call AWS', async () => {
  reset();
  setRow(APP, 'sandbox', 'REF', 'secretsmanager:TOKEN');
  setRow(APP, 'sandbox', 'NORMAL', 'normal-value-xyz');
  aws.secrets.set(secretPath('aaa', 'sandbox', 'TOKEN'), 'aws-only-value');

  const list = await call(OWNER, 'GET', '/api/apps/aaa/env/sandbox');
  const listed = Object.fromEntries(list.json.vars.map((v) => [v.key, v]));
  assert.equal(listed.REF.value, 'secretsmanager:TOKEN');
  assert.equal(listed.REF.source, 'secrets_manager');
  assert.equal(listed.NORMAL.value, '********');
  assert.equal('source' in listed.NORMAL, false, 'a normal value gets no new field');

  const bulk = await call(OWNER, 'GET', '/api/apps/aaa/env/sandbox?reveal=true');
  assert.equal(bulk.json.vars.find((v) => v.key === 'REF').source, 'secrets_manager');
  assert.equal('source' in bulk.json.vars.find((v) => v.key === 'NORMAL'), false);

  const one = await call(OWNER, 'POST', '/api/apps/aaa/env/sandbox/REF/reveal');
  assert.equal(one.json.value, 'secretsmanager:TOKEN');
  assert.equal(one.json.source, 'secrets_manager');

  const mcpList = unwrap(await callTool(OWNER.row, 'appcrane_get_secret', { slug: 'aaa', env: 'sandbox' }));
  const mcpRef = mcpList.vars.find((v) => v.key === 'REF');
  assert.equal(mcpRef.value, 'secretsmanager:TOKEN');
  assert.equal(mcpRef.source, 'secrets_manager');
  assert.equal('source' in mcpList.vars.find((v) => v.key === 'NORMAL'), false);
  assert.equal('value' in mcpList.vars.find((v) => v.key === 'NORMAL'), false, 'the masked MCP list still returns no value for a normal var');

  const mcpOne = unwrap(await callTool(OWNER.row, 'appcrane_reveal_secret', { slug: 'aaa', env: 'sandbox', key: 'REF' }));
  assert.equal(mcpOne.value, 'secretsmanager:TOKEN');
  assert.equal(mcpOne.source, 'secrets_manager');
  const mcpNormal = unwrap(await callTool(OWNER.row, 'appcrane_reveal_secret', { slug: 'aaa', env: 'sandbox', key: 'NORMAL' }));
  assert.equal(mcpNormal.value, 'normal-value-xyz');
  assert.equal('source' in mcpNormal, false);

  assert.deepEqual(aws.calls, [], 'a read reached AWS');
  for (const r of [list, bulk, one]) assert.doesNotMatch(r.text, /aws-only-value/);
});

test('deleting a reference names the secret left behind and calls AWS for nothing; a normal delete is unchanged', async () => {
  reset();
  setRow(APP, 'sandbox', 'REF', 'secretsmanager:TOKEN#f');
  setRow(APP, 'sandbox', 'NORMAL', 'v');
  const r = await call(OWNER, 'DELETE', '/api/apps/aaa/env/sandbox/REF');
  assert.equal(r.status, 200);
  assert.equal(r.json.aws_secret_retained, secretPath('aaa', 'sandbox', 'TOKEN'));
  const n = await call(OWNER, 'DELETE', '/api/apps/aaa/env/sandbox/NORMAL');
  assert.equal('aws_secret_retained' in n.json, false);
  assert.deepEqual(aws.calls, []);
});

test('restart: a reference is resolved into the container and its text is not', async () => {
  reset();
  setRow(APP, 'sandbox', 'REF', 'secretsmanager:TOKEN');
  setRow(APP, 'sandbox', 'FIELD', 'secretsmanager:CREDS#pw');
  setRow(APP, 'sandbox', 'MID', 'x secretsmanager:TOKEN');
  aws.secrets.set(secretPath('aaa', 'sandbox', 'TOKEN'), 'resolved-token');
  aws.secrets.set(secretPath('aaa', 'sandbox', 'CREDS'), JSON.stringify({ pw: 'resolved-pw' }));
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 200, r.text);
  assert.doesNotMatch(r.text, /resolved-/);
  const run = dockerCalls().find((a) => a[0] === 'run');
  assert.ok(run, 'no docker run');
  assert.ok(run.includes('REF=resolved-token'));
  assert.ok(run.includes('FIELD=resolved-pw'));
  assert.ok(run.includes('MID=x secretsmanager:TOKEN'), 'a value merely containing the prefix is untouched');
  assert.equal(run.filter((x) => x.startsWith('REF=secretsmanager') || x.startsWith('FIELD=secretsmanager')).length, 0);
});

test('restart: an unresolved reference fails naming the key, and the running container is left alone', async () => {
  reset();
  setRow(APP, 'sandbox', 'NOT_THERE', 'secretsmanager:MISSING');
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 502, r.text);
  assert.match(r.text, /NOT_THERE/);
  assert.deepEqual(startedContainers(), [], 'docker stop, rm or run ran for a restart that cannot get its env');
});

test('app A cannot reach app B, the platform secret, or production from sandbox, by any reference form', async () => {
  reset();
  aws.secrets.set('platform/keys', JSON.stringify({ ENCRYPTION_KEY: 'platform-key-value' }));
  aws.secrets.set(secretPath('bbb', 'sandbox', 'TOKEN'), 'app-b-value');
  aws.secrets.set(secretPath('aaa', 'production', 'TOKEN'), 'production-value');
  const LEAKS = /platform-key-value|app-b-value|production-value/;

  // A plain name resolves only under aaa/sandbox, where none of these exist.
  setRow(APP, 'sandbox', 'PROBE', 'secretsmanager:TOKEN');
  let r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 502, r.text);
  assert.ok(secretIds().length > 0 && secretIds().every((id) => id === secretPath('aaa', 'sandbox', 'TOKEN')), JSON.stringify(secretIds()));

  // Forms stored behind the write check (a restored backup, an import).
  for (const bad of UNSAFE) {
    aws.calls.length = 0;
    clearDocker();
    setRow(APP, 'sandbox', 'PROBE', bad);
    r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
    assert.equal(r.status, 502, `${JSON.stringify(bad)}: ${r.text}`);
    assert.match(r.text, /PROBE/);
    assert.doesNotMatch(r.text, LEAKS);
    assert.deepEqual(aws.calls, [], `${JSON.stringify(bad)} reached AWS`);
    assert.deepEqual(startedContainers(), []);
  }

  // The same name in production reads production's own, and app B's stays out of it.
  aws.calls.length = 0;
  clearDocker();
  setRow(APP, 'production', 'PROBE', 'secretsmanager:TOKEN');
  r = await call(OWNER, 'POST', '/api/apps/aaa/restart/production');
  assert.equal(r.status, 200, r.text);
  assert.deepEqual([...new Set(secretIds())], [secretPath('aaa', 'production', 'TOKEN')]);
  assert.ok(dockerCalls().find((a) => a[0] === 'run').includes('PROBE=production-value'));
});

test('sandbox reference reads the sandbox secret when both exist', async () => {
  reset();
  aws.secrets.set(secretPath('aaa', 'sandbox', 'TOKEN'), 'sandbox-value');
  aws.secrets.set(secretPath('aaa', 'production', 'TOKEN'), 'production-value');
  setRow(APP, 'sandbox', 'PROBE', 'secretsmanager:TOKEN');
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 200, r.text);
  const run = dockerCalls().find((a) => a[0] === 'run');
  assert.ok(run.includes('PROBE=sandbox-value'));
  assert.equal(run.some((x) => x.includes('production-value')), false);
});

test('no provider configured: a stored reference fails the restart rather than injecting its text', async () => {
  reset();
  setRow(APP, 'sandbox', 'REF', 'secretsmanager:TOKEN');
  delete process.env.APPCRANE_SECRETS_PROVIDER;
  try {
    const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
    assert.equal(r.status, 502, r.text);
    assert.match(r.text, /REF \(no secrets provider/);
    assert.deepEqual(startedContainers(), []);
  } finally { process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager'; }
});

const mkDeployment = (appId, env, status = 'pending') => db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, ?, ?, ?)").run(appId, env, status, OWNER.id).lastInsertRowid;

test('deploy: an unresolved reference fails the deployment naming the key, before docker is touched', async () => {
  reset();
  const id = mkApp('deploy-bad', 'image');
  db.prepare("UPDATE apps SET image_ref = 'bs:1', container_port = 3000 WHERE id = ?").run(id);
  setRow(id, 'sandbox', 'NOT_THERE', 'secretsmanager:MISSING');
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  const dep = mkDeployment(id, 'sandbox');
  await deployApp(dep, app, 'sandbox', { sand_be: 1, prod_be: 2 }, {}).catch(() => {});
  const row = db.prepare('SELECT status, log, failure_reason FROM deployments WHERE id = ?').get(dep);
  assert.equal(row.status, 'failed', row.log);
  assert.match(`${row.failure_reason}\n${row.log}`, /NOT_THERE/);
  assert.deepEqual(dockerCalls(), [], 'docker was used (a pull, a stop, a run) for a deploy that cannot get its env');
  assert.doesNotMatch(row.log || '', /secretsmanager:MISSING/);
});

test('deploy: a resolved reference reaches docker run as its value, and the log carries names only', async () => {
  reset();
  const id = mkApp('deploy-good', 'image');
  const p = getPortsForSlot(db.prepare('SELECT slot FROM apps WHERE id = ?').get(id).slot);
  db.prepare("UPDATE apps SET image_ref = 'bs:1', container_port = 3000, health_path = '/h' WHERE id = ?").run(id);
  aws.secrets.set(secretPath('deploy-good', 'sandbox', 'TOKEN'), 'deploy-resolved-value');
  setRow(id, 'sandbox', 'REF', 'secretsmanager:TOKEN');
  const health = http.createServer((_, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"status":"ok","version":"1.0.0"}'); });
  await new Promise((r) => health.listen(p.sand_be, '127.0.0.1', r));
  try {
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
    const dep = mkDeployment(id, 'sandbox');
    await deployApp(dep, app, 'sandbox', p, {}).catch(() => {});
    const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(dep);
    const run = dockerCalls().find((a) => a[0] === 'run' && a.some((x) => x.startsWith('REF=')));
    assert.ok(run, `no docker run carried REF. log:\n${row.log}`);
    assert.ok(run.includes('REF=deploy-resolved-value'));
    assert.match(row.log, /Resolved from AWS Secrets Manager: REF/);
    assert.doesNotMatch(row.log, /deploy-resolved-value/);
  } finally { health.closeAllConnections?.(); health.close(); }
});

function liveSandboxRelease(slug, appId) {
  const sandboxDir = join(ROOT, 'apps', slug, 'sandbox');
  const rel = join(sandboxDir, 'releases', '1000-upload');
  mkdirSync(rel, { recursive: true });
  mkdirSync(join(sandboxDir, 'shared', 'data'), { recursive: true });
  writeFileSync(join(rel, 'package.json'), '{"name":"x","version":"1.0.0"}');
  writeFileSync(join(sandboxDir, 'shared', '.env.sandbox'), 'X=1\n');
  symlinkSync(join(sandboxDir, 'shared', '.env.sandbox'), join(rel, '.env'));
  return db.prepare("INSERT INTO deployments (app_id, env, version, status, commit_hash, release_path, deployed_by) VALUES (?, 'sandbox', '1.0.0', 'live', 'unknown', ?, ?)").run(appId, rel, OWNER.id).lastInsertRowid;
}

test('promote (copy): an unresolved reference stops before the release is copied or the live row is touched', async () => {
  reset();
  const id = mkApp('promo-bad', 'upload');
  liveSandboxRelease('promo-bad', id);
  const live = mkDeployment(id, 'production', 'live');
  setRow(id, 'production', 'NOT_THERE', 'secretsmanager:MISSING');
  await assert.rejects(promoteApp(db.prepare('SELECT * FROM apps WHERE id = ?').get(id), OWNER.id), /NOT_THERE/);
  const relDir = join(ROOT, 'apps', 'promo-bad', 'production', 'releases');
  assert.equal(existsSync(relDir) ? readdirSync(relDir).length : 0, 0, 'a production release was copied');
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(live).status, 'live');
  assert.deepEqual(startedContainers(), []);
});

test('promote (copy): the host .env.production gets neither the AWS value nor the reference, and sandbox refs are not copied', async () => {
  reset();
  writeFileSync(join(ROOT, 'docker-down'), '');
  try {
    const id = mkApp('promo-good', 'upload');
    liveSandboxRelease('promo-good', id);
    aws.secrets.set(secretPath('promo-good', 'production', 'TOKEN'), 'prod-aws-value');
    setRow(id, 'production', 'REF', 'secretsmanager:TOKEN');
    setRow(id, 'production', 'PLAIN', 'plain-value');
    setRow(id, 'sandbox', 'ONLY_SANDBOX', 'secretsmanager:SB');
    const out = await promoteApp(db.prepare('SELECT * FROM apps WHERE id = ?').get(id), OWNER.id);
    assert.equal(out.mode, 'copy');
    const file = readFileSync(join(ROOT, 'apps', 'promo-good', 'production', 'shared', '.env.production'), 'utf8');
    assert.match(file, /^PLAIN=plain-value$/m);
    assert.match(file, /^# REF comes from Secrets Manager/m);
    assert.doesNotMatch(file, /prod-aws-value|secretsmanager:|ONLY_SANDBOX/);
    assert.equal(rowPlain(id, 'production', 'ONLY_SANDBOX'), null);
    assert.ok(secretIds().every((s) => s === secretPath('promo-good', 'production', 'TOKEN')), JSON.stringify(secretIds()));
    for (let i = 0; i < 100; i++) {
      const s = db.prepare('SELECT status FROM deployments WHERE id = ?').get(out.deployment_id).status;
      if (s === 'failed' || s === 'live') break;
      await new Promise((r) => setTimeout(r, 50));
    }
  } finally { rmSync(join(ROOT, 'docker-down'), { force: true }); }
});

test('stored .env files: a reference layers on as its value when resolved, and is refused without that', async () => {
  reset();
  const store = await import('../server/services/envFileStore.js');
  const { resolveStoredEnv } = await import('../server/services/secretRefs.js');
  const id = mkApp('envfile-app');
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  const content = Buffer.from('A=1\n');
  store.storeEnvFiles(db, id, 'sandbox', store.encryptEnvFiles([{ rel_path: '.env', mode: 0o600, bytes: content.length, content }]));
  setRow(id, 'sandbox', 'REF', 'secretsmanager:TOKEN');
  aws.secrets.set(secretPath('envfile-app', 'sandbox', 'TOKEN'), 'file-value');

  const refused = mkdtempSync(join(ROOT, 'rel-'));
  assert.throws(() => store.restoreStoredEnvFiles(db, app, 'sandbox', refused), /REF/);
  assert.equal(existsSync(join(refused, '.env')), false, 'a file was written before the refusal');

  const dir = mkdtempSync(join(ROOT, 'rel-'));
  const rows = db.prepare('SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ?').all(id, 'sandbox');
  store.restoreStoredEnvFiles(db, app, 'sandbox', dir, await resolveStoredEnv(app, 'sandbox', rows));
  const text = readFileSync(join(dir, '.env'), 'utf8');
  assert.match(text, /REF=.*file-value/);
  assert.doesNotMatch(text, /secretsmanager:/);
});

test('deployApp layers a resolved reference into a stored .env file of a local-repo clone', async () => {
  reset();
  writeFileSync(join(ROOT, 'docker-down'), '');
  try {
    const lg = await import('../server/services/localGit.js');
    const store = await import('../server/services/envFileStore.js');
    await lg.createAppRepo('envfile-deploy');
    const id = mkApp('envfile-deploy');
    db.prepare("UPDATE apps SET repo_backend = 'local' WHERE id = ?").run(id);
    const pushed = await lg.pushFilesToManagedRepo('envfile-deploy', [
      { path: 'package.json', content: JSON.stringify({ name: 'x', version: '1.0.0', scripts: { start: 'node s.js' } }) },
      { path: 's.js', content: 'console.log(1)\n' },
    ], { branch: 'main' });
    db.prepare('UPDATE apps SET last_managed_push_sha = ? WHERE id = ?').run(pushed.commit.sha, id);
    store.putStoredEnvFile(db, id, 'sandbox', '.env', 'A=1\n');
    setRow(id, 'sandbox', 'REF', 'secretsmanager:TOKEN');
    aws.secrets.set(secretPath('envfile-deploy', 'sandbox', 'TOKEN'), 'envfile-deploy-value');
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
    const dep = mkDeployment(id, 'sandbox');
    await deployApp(dep, app, 'sandbox', getPortsForSlot(app.slot), {}).catch(() => {});
    const log = db.prepare('SELECT log FROM deployments WHERE id = ?').get(dep).log || '';
    assert.match(log, /Restored 1 stored \.env file\(s\).*appended: REF/, log);
    assert.doesNotMatch(log, /envfile-deploy-value|secretsmanager:TOKEN/);
    assert.equal(aws.calls.filter((c) => c.op === 'GetSecretValue').length, 1, 'one read per deploy');
  } finally { rmSync(join(ROOT, 'docker-down'), { force: true }); }
});

test('status: platform admin only, shape fixed, no AWS call, no secret names', async () => {
  reset();
  assert.equal((await call(null, 'GET', '/api/secrets-provider/status')).status, 401);
  assert.equal((await call(OWNER, 'GET', '/api/secrets-provider/status')).status, 403);
  const r = await call(PLATFORM, 'GET', '/api/secrets-provider/status');
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { active: true, provider: 'aws-secrets-manager', region: 'us-east-1', platform_secret_configured: false, app_prefix: 'appcrane/apps' });
  process.env.APPCRANE_SECRETS_ID = 'platform/keys';
  delete process.env.APPCRANE_SECRETS_PROVIDER;
  try {
    const off = await call(PLATFORM, 'GET', '/api/secrets-provider/status');
    assert.deepEqual(off.json, { active: false, provider: null, region: null, platform_secret_configured: false, app_prefix: null });
    process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager';
    const on = await call(PLATFORM, 'GET', '/api/secrets-provider/status');
    assert.equal(on.json.platform_secret_configured, true);
    assert.doesNotMatch(on.text, /platform\/keys/);
  } finally {
    delete process.env.APPCRANE_SECRETS_ID;
    process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager';
  }
  assert.deepEqual(aws.calls, []);
});

// --- An app's secrets belong to that app, not to whatever holds its slug next.

const appRow = (id) => db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
const mkOwnedApp = (slug) => {
  const id = mkApp(slug);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, OWNER.id);
  return id;
};
const storeOk = async (slug, vars) => {
  const r = await call(OWNER, 'PUT', `/api/apps/${slug}/env/sandbox`, { vars, store: 'secrets_manager' });
  assert.equal(r.status, 200, r.text);
};

test('app A stores a secret and is deleted; app B on the same slug cannot read it or overwrite it', async () => {
  reset();
  const A = mkOwnedApp('reuse-slug');
  await storeOk('reuse-slug', { TOKEN: 'app-a-old-secret' });
  const pathOfA = [...aws.secrets.keys()].find((k) => k.endsWith('/sandbox/TOKEN'));
  assert.equal(aws.secrets.get(pathOfA), 'app-a-old-secret');
  await deleteApp(appRow(A));

  const B = mkOwnedApp('reuse-slug');
  assert.notEqual(B, A);
  setRow(B, 'sandbox', 'TOKEN', 'secretsmanager:TOKEN');
  clearDocker();
  const restart = await call(OWNER, 'POST', '/api/apps/reuse-slug/restart/sandbox');
  assert.equal(restart.status, 502, restart.text);
  assert.match(restart.text, /TOKEN/);
  assert.doesNotMatch(restart.text, /app-a-old-secret/);
  assert.ok(!dockerCalls().flat().some((x) => x.includes('app-a-old-secret')), 'app A\'s secret reached app B\'s container');

  await storeOk('reuse-slug', { TOKEN: 'app-b-new-secret' });
  assert.equal(aws.secrets.get(pathOfA), 'app-a-old-secret', 'app B overwrote app A\'s secret');
  await deleteApp(appRow(B));
});

test('a slug freed by a rename gives the next app nothing of the renamed app', async () => {
  reset();
  const A = mkOwnedApp('freed-slug');
  await storeOk('freed-slug', { TOKEN: 'renamed-app-secret' });
  await renameApp({ app: appRow(A), newSlug: 'freed-slug-2', redirect: false, user: PLATFORM.row });
  const B = mkOwnedApp('freed-slug');
  setRow(B, 'sandbox', 'TOKEN', 'secretsmanager:TOKEN');
  clearDocker();
  const r = await call(OWNER, 'POST', '/api/apps/freed-slug/restart/sandbox');
  assert.equal(r.status, 502, r.text);
  assert.ok(!dockerCalls().flat().some((x) => x.includes('renamed-app-secret')), 'the renamed app\'s secret reached the new holder of its slug');
  await deleteApp(appRow(B));
  await deleteApp(appRow(A));
});

test('an app with a reference is renamed and still resolves, with no change in AWS', async () => {
  reset();
  const A = mkOwnedApp('rename-me');
  await storeOk('rename-me', { TOKEN: 'survives-rename' });
  const before = [...aws.secrets.keys()];
  await renameApp({ app: appRow(A), newSlug: 'renamed-now', redirect: false, user: PLATFORM.row });
  clearDocker();
  const r = await call(OWNER, 'POST', '/api/apps/renamed-now/restart/sandbox');
  assert.equal(r.status, 200, r.text);
  const run = dockerCalls().find((a) => a[0] === 'run');
  assert.ok(run?.includes('TOKEN=survives-rename'), 'the renamed app lost its secret');
  assert.deepEqual([...aws.secrets.keys()], before);
  await deleteApp(appRow(A));
});

test('deleting an app leaves its secrets in AWS and says where, with no value', async () => {
  reset();
  const A = mkOwnedApp('leaves-secrets');
  await storeOk('leaves-secrets', { TOKEN: 'left-behind-value', OTHER: 'other-value' });
  setRow(A, 'production', 'PLAIN', 'plain-value');
  const path = secretPath('leaves-secrets', 'sandbox', 'TOKEN');
  const root = path.slice(0, -'sandbox/TOKEN'.length);
  const warned = [];
  const warn = log.warn;
  log.warn = (m) => warned.push(String(m));
  let out;
  try { out = await deleteApp(appRow(A)); } finally { log.warn = warn; }
  assert.deepEqual(out.aws_secrets_retained, {
    path_prefix: root, referenced: [`${root}sandbox/OTHER`, path], undecryptable_env_vars: 0,
  });
  assert.ok(warned.some((m) => m.includes(root) && m.includes('leaves-secrets')), JSON.stringify(warned));
  assert.doesNotMatch(JSON.stringify([out, warned]), /left-behind-value|other-value|plain-value/);
  assert.equal(aws.secrets.get(path), 'left-behind-value');
  assert.ok(!aws.calls.some((c) => /delete/i.test(c.op)), 'AppCrane called a delete in AWS');
});

test('a delete with no references says the path while a provider is on, and nothing when it is off', async () => {
  reset();
  const on = await deleteApp(appRow(mkOwnedApp('no-refs-on')));
  assert.match(on.aws_secrets_retained.path_prefix, /^appcrane\/apps\/[a-f0-9]{32}\/$/);
  assert.deepEqual(on.aws_secrets_retained.referenced, []);
  delete process.env.APPCRANE_SECRETS_PROVIDER;
  try {
    const off = await deleteApp(appRow(mkOwnedApp('no-refs-off')));
    assert.equal('aws_secrets_retained' in off, false);
  } finally {
    process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager';
  }
});

test('both faces of app delete pass on what stays in AWS, and leave it out when there is nothing to say', async () => {
  reset();
  const faces = {
    REST: async (slug) => {
      const r = await call(OWNER, 'DELETE', `/api/apps/${slug}?confirm=true`);
      assert.equal(r.status, 200, r.text);
      return r.json;
    },
    MCP: async (slug) => unwrap(await callTool(OWNER.row, 'appcrane_delete_app', { slug, confirm_slug: slug })),
  };
  for (const [face, del] of Object.entries(faces)) {
    const slug = `face-${face.toLowerCase()}`;
    mkOwnedApp(slug);
    await storeOk(slug, { TOKEN: 'face-secret-value' });
    const out = await del(slug);
    assert.match(out.aws_secrets_retained?.path_prefix ?? '', /^appcrane\/apps\/[a-f0-9]{32}\/$/, `${face}: ${JSON.stringify(out)}`);
    assert.deepEqual(out.aws_secrets_retained.referenced, [`${out.aws_secrets_retained.path_prefix}sandbox/TOKEN`], face);
    assert.doesNotMatch(JSON.stringify(out), /face-secret-value/, face);

    delete process.env.APPCRANE_SECRETS_PROVIDER;
    try {
      const offSlug = `${slug}-off`;
      mkOwnedApp(offSlug);
      assert.equal('aws_secrets_retained' in await del(offSlug), false, face);
    } finally {
      process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager';
    }
  }
});

test('a delete still goes through when the provider setting is one AppCrane does not know', async () => {
  reset();
  const A = mkOwnedApp('bad-provider');
  process.env.APPCRANE_SECRETS_PROVIDER = 'vault';
  try {
    await deleteApp(appRow(A));
    assert.equal(appRow(A), undefined);
  } finally {
    process.env.APPCRANE_SECRETS_PROVIDER = 'aws-secrets-manager';
  }
});

test('a caller holding a partial app row resolves the same namespace; an unknown app reaches nothing', async () => {
  reset();
  const { resolveEnvValues, SecretRefError } = await import('../server/services/secretRefs.js');
  const seen = [];
  const getSecret = async (ns) => { seen.push(ns); return 'v'; };
  const rows = [{ key: 'K', plain: 'secretsmanager:T' }];
  await resolveEnvValues({ id: APP, slug: 'aaa' }, 'sandbox', rows, { getSecret });
  assert.deepEqual(seen, [appRow(APP).secrets_namespace]);
  for (const app of [{ slug: 'aaa' }, { id: 999999, slug: 'aaa' }]) {
    await assert.rejects(resolveEnvValues(app, 'sandbox', rows, { getSecret }), SecretRefError);
  }
  assert.equal(seen.length, 1, 'a fetch ran for an app with no namespace');
});

test('a missing secret is reported with the path it was looked for at', async () => {
  reset();
  setRow(APP, 'sandbox', 'NOT_THERE', 'secretsmanager:MISSING');
  const r = await call(OWNER, 'POST', '/api/apps/aaa/restart/sandbox');
  assert.equal(r.status, 502, r.text);
  assert.ok(r.text.includes(`secret not found at ${secretPath('aaa', 'sandbox', 'MISSING')}`), r.text);
});

test('app-path gives a platform admin one app\'s path, and nobody else anything', async () => {
  reset();
  const r = await call(PLATFORM, 'GET', '/api/secrets-provider/status/app-path/aaa');
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json, { slug: 'aaa', path_prefix: `appcrane/apps/${appRow(APP).secrets_namespace}/` });
  assert.equal((await call(PLATFORM, 'GET', '/api/secrets-provider/status/app-path/no-such-app')).status, 404);
  assert.equal((await call(OWNER, 'GET', '/api/secrets-provider/status/app-path/aaa')).status, 403);
  assert.equal((await call(null, 'GET', '/api/secrets-provider/status/app-path/aaa')).status, 401);
  assert.deepEqual(aws.calls, []);
});

test('status: the prefix comes out of a real configured prefix, and null when it is unsafe', async () => {
  process.env.APPCRANE_SECRETS_APP_PREFIX = 'org/apps//';
  try {
    assert.equal((await call(PLATFORM, 'GET', '/api/secrets-provider/status')).json.app_prefix, 'org/apps');
    process.env.APPCRANE_SECRETS_APP_PREFIX = 'org/../apps';
    assert.equal((await call(PLATFORM, 'GET', '/api/secrets-provider/status')).json.app_prefix, null);
  } finally {
    delete process.env.APPCRANE_SECRETS_APP_PREFIX;
  }
});
