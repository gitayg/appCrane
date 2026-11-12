import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import express from 'express';

// APPCRANE_PRIVATE_API_PORT (utils/ingress.js): with it set, a personal user key
// (users.api_key_hash, dhk_user_* / dhk_admin_*) is refused on a request Caddy
// stamped X-AppCrane-Ingress: public, and accepted on one stamped private or
// with no stamp at all (Node's own port, reached directly). Every other
// credential is untouched. Driven over real HTTP against an ephemeral server,
// git with the real git CLI.

const run = promisify(execFile);
const ROOT = mkdtempSync(join(tmpdir(), 'crane-privport-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'your-crane-host.test';
delete process.env.APPCRANE_PRIVATE_API_PORT;
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const oauthStore = await import('../server/services/oauthStore.js');
const ingress = await import('../server/utils/ingress.js');
const lg = await import('../server/services/localGit.js');
const { createGitHttpRouter } = await import('../server/routes/gitHttp.js');

initDb();
const db = getDb();
const APP = db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('pp','pp-app',941,'managed','local','main')").run().lastInsertRowid;
await lg.createAppRepo('pp-app');
await lg.pushFilesToManagedRepo('pp-app', [{ path: 'a.txt', content: 'a\n' }], { branch: 'main', message: 'a' });

function mkUser(role = 'user') {
  const key = generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  const tag = randomBytes(3).toString('hex');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`u${tag}`, `u${tag}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(APP, id);
  return { id, key };
}
const U = mkUser();
const ADMIN = mkUser('platform_admin');
const SESSION = randomBytes(24).toString('base64url');
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(U.id, hashApiKey(SESSION));
const MCP_KEY = generateApiKey('dhk_mcp');
db.prepare('INSERT INTO user_mcp_keys (user_id, key_hash, label) VALUES (?, ?, ?)').run(U.id, hashApiKey(MCP_KEY), 'k');

const httpApp = express();
httpApp.use('/git', createGitHttpRouter());
httpApp.use(express.json());
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.get('/api/apps', requireAuth, (req, res) => res.json({ ok: true, uid: req.user.id }));
httpApp.use('/api', (await import('../server/routes/apiKeys.js')).default);
httpApp.use('/api/identity', (await import('../server/routes/identity.js')).default);
httpApp.use('/api/enhancements', (await import('../server/routes/enhancements.js')).default);
httpApp.use('/api', (await import('../server/routes/me.js')).default);
httpApp.use('/api/plan', (await import('../server/routes/plan.js')).default);
httpApp.use('/api/ask', (await import('../server/routes/ask.js')).default);
httpApp.use('/api/coder', (await import('../server/routes/coder.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const PUBLIC = { 'X-AppCrane-Ingress': 'public' };
const PRIVATE = { 'X-AppCrane-Ingress': 'private' };
const on = () => { process.env.APPCRANE_PRIVATE_API_PORT = '8443'; };
const off = () => { delete process.env.APPCRANE_PRIVATE_API_PORT; };
beforeEach(() => { off(); ingress._resetIngressAuditForTests(); });

const json = async (res) => { try { return await res.json(); } catch (_) { return null; } };
async function rest(headers) {
  const res = await fetch(`${BASE}/api/apps`, { headers });
  return { status: res.status, body: await json(res) };
}
async function verify(headers) {
  const res = await fetch(`${BASE}/api/identity/verify?app=pp-app`, { headers, redirect: 'manual' });
  return { status: res.status, body: await json(res), user: res.headers.get('x-appcrane-user-id') };
}
async function mcp(headers) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
  });
  return { status: res.status, body: await json(res) };
}
// issuerOf() uses CRANE_DOMAIN when set, so that is the resource a token names.
const RESOURCE = 'https://your-crane-host.test/api/mcp';
async function oauthToken(userId) {
  const { client } = oauthStore.registerClient({ client_name: 'T', redirect_uris: ['http://127.0.0.1:1/cb'], grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none' });
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const code = oauthStore.createCode({ clientId: client.client_id, userId, redirectUri: 'http://127.0.0.1:1/cb', codeChallenge: challenge, scope: 'mcp', resource: RESOURCE, readOnly: false });
  return oauthStore.redeemCode({ code, client, redirectUri: 'http://127.0.0.1:1/cb', verifier, resource: RESOURCE }).access_token;
}
// git ls-remote with the key as the Basic password and the ingress stamp as an
// extra header, the way Caddy would deliver it.
async function gitLsRemote(key, extra = {}) {
  const url = `${BASE.replace('://', `://x:${key}@`)}/git/pp-app.git`;
  const args = [];
  for (const [k, v] of Object.entries(extra)) args.push('-c', `http.extraHeader=${k}: ${v}`);
  try {
    const r = await run('git', [...args, 'ls-remote', url], { env: { PATH: process.env.PATH, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    return { ok: true, out: r.stdout };
  } catch (e) {
    return { ok: false, out: `${e.stdout}${e.stderr}` };
  }
}
const audits = () => db.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'user-key.public-refused' ORDER BY id").all();

test('setting off: a user key on a public-stamped request works (today\'s behaviour)', async () => {
  assert.equal((await rest({ 'X-API-Key': U.key, ...PUBLIC })).status, 200);
  assert.equal((await verify({ 'X-API-Key': U.key, ...PUBLIC })).status, 200);
  assert.equal((await gitLsRemote(U.key, PUBLIC)).ok, true);
});

test('setting on: user key + public stamp is refused with 403 USER_KEY_PRIVATE_PORT_ONLY on REST, naming the private port', async () => {
  on();
  for (const key of [U.key, ADMIN.key]) {
    const r = await rest({ 'X-API-Key': key, ...PUBLIC });
    assert.equal(r.status, 403, JSON.stringify(r.body));
    assert.equal(r.body.error.code, 'USER_KEY_PRIVATE_PORT_ONLY');
    assert.match(r.body.error.message, /https:\/\/your-crane-host\.test:8443/);
  }
  // Case and whitespace do not get a public request past the check.
  assert.equal((await rest({ 'X-API-Key': U.key, 'X-AppCrane-Ingress': ' Public ' })).status, 403);
});

test('setting on: a refused public use does not count as a use of the key', async () => {
  on();
  db.prepare('UPDATE users SET api_key_last_used_at = NULL WHERE id = ?').run(U.id);
  assert.equal((await rest({ 'X-API-Key': U.key, ...PUBLIC })).status, 403);
  assert.equal(db.prepare('SELECT api_key_last_used_at FROM users WHERE id = ?').get(U.id).api_key_last_used_at, null);
});

test('setting on: user key + private stamp works, and with no stamp (direct to Node) works', async () => {
  on();
  const priv = await rest({ 'X-API-Key': U.key, ...PRIVATE });
  assert.equal(priv.status, 200, JSON.stringify(priv.body));
  assert.equal(priv.body.uid, U.id);
  assert.equal((await rest({ 'X-API-Key': U.key })).status, 200);
});

test('setting on: /api/identity/verify (forward_auth) refuses a user key on public, accepts it on private and direct', async () => {
  on();
  const pub = await verify({ 'X-API-Key': U.key, ...PUBLIC });
  assert.equal(pub.status, 403, JSON.stringify(pub.body));
  assert.equal(pub.body.error.code, 'USER_KEY_PRIVATE_PORT_ONLY');
  assert.equal(pub.user, null, 'a refused verify must not emit identity headers');
  const priv = await verify({ 'X-API-Key': U.key, ...PRIVATE });
  assert.equal(priv.status, 200, JSON.stringify(priv.body));
  assert.equal(priv.user, String(U.id));
  assert.equal((await verify({ 'X-API-Key': U.key })).status, 200);
});

test('setting on: git over HTTPS refuses a user key on public, clones on private and direct', async () => {
  on();
  const pub = await gitLsRemote(U.key, PUBLIC);
  assert.equal(pub.ok, false);
  assert.match(pub.out, /private API port/);
  const priv = await gitLsRemote(U.key, PRIVATE);
  assert.equal(priv.ok, true, priv.out);
  assert.match(priv.out, /refs\/heads\/main/);
  assert.equal((await gitLsRemote(U.key)).ok, true);
});

test('setting on: other routes that read users.api_key_hash themselves refuse it on public too', async () => {
  on();
  const me = await fetch(`${BASE}/api/me`, { headers: { 'X-API-Key': U.key, ...PUBLIC } });
  assert.equal(me.status, 403);
  assert.equal((await fetch(`${BASE}/api/me`, { headers: { 'X-API-Key': U.key, ...PRIVATE } })).status, 200);
  const pw = await fetch(`${BASE}/api/identity/set-password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': U.key, ...PUBLIC },
    body: JSON.stringify({ password: 'a-long-enough-password' }),
  });
  assert.equal(pw.status, 403, 'a user key must not turn into a session on the public port');
  const enh = await fetch(`${BASE}/api/enhancements`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': U.key, ...PUBLIC },
    body: JSON.stringify({ message: 'x' }),
  });
  assert.equal(enh.status, 403);
});

test('setting on: plan, ask, coder and enhancement-comment auth refuse a user key on public only', async () => {
  on();
  const calls = [
    ['GET', '/api/plan/999999', {}],
    ['GET', `/api/plan/999999?token=${U.key}`, null],
    ['POST', '/api/ask/no-such-app', {}],
    ['POST', '/api/ask/no-such-app', 'bearer'],
    ['GET', '/api/coder/models', {}],
    ['POST', '/api/enhancements/999999/delete', {}],
    ['GET', '/api/enhancements/999999/comments', {}],
  ];
  for (const [method, path, keyHeader] of calls) {
    const auth = keyHeader === 'bearer' ? { Authorization: `Bearer ${U.key}` } : keyHeader ? { 'X-API-Key': U.key } : {};
    const pub = await fetch(`${BASE}${path}`, { method, headers: { ...auth, ...PUBLIC } });
    const pubBody = await json(pub);
    assert.equal(pub.status, 403, `${method} ${path}: ${JSON.stringify(pubBody)}`);
    assert.equal(pubBody?.error?.code, 'USER_KEY_PRIVATE_PORT_ONLY', `${method} ${path}`);
    const priv = await fetch(`${BASE}${path}`, { method, headers: { ...auth, ...PRIVATE } });
    const privBody = await json(priv);
    assert.notEqual(privBody?.error?.code, 'USER_KEY_PRIVATE_PORT_ONLY', `${method} ${path} on private`);
    assert.notEqual(priv.status, 401, `${method} ${path} on private: ${JSON.stringify(privBody)}`);
  }
});

test('every route that accepts a personal key records it as used (api_key_last_used_at)', async () => {
  // A key used only on a route with its own key fallback looked never-used, and
  // a cleanup of never-used keys would revoke it. Each call uses a fresh user.
  const calls = [
    ['GET', '/api/me', {}],
    ['POST', '/api/identity/set-password', {}, { password: 'a-long-enough-password' }],
    ['GET', '/api/identity/verify?app=pp-app', {}],
    ['POST', '/api/enhancements', {}, { message: 'x' }],
    ['GET', '/api/plan/999999', {}],
    ['GET', '/api/plan/999999?token=KEY', null],
    ['POST', '/api/ask/no-such-app', {}],
    ['POST', '/api/ask/no-such-app', 'bearer'],
    ['GET', '/api/coder/models', {}],
    ['POST', '/api/enhancements/999999/delete', {}],
    ['GET', '/api/enhancements/999999/comments', {}],
  ];
  const lastUsed = (id) => db.prepare('SELECT api_key_last_used_at v FROM users WHERE id = ?').get(id).v;
  for (const [method, path, keyHeader, body] of calls) {
    const u = mkUser();
    assert.equal(lastUsed(u.id), null);
    const auth = keyHeader === 'bearer' ? { Authorization: `Bearer ${u.key}` } : keyHeader ? { 'X-API-Key': u.key } : {};
    const res = await fetch(`${BASE}${path.replace('KEY', u.key)}`, {
      method, redirect: 'manual',
      headers: { ...auth, ...PRIVATE, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    assert.notEqual(res.status, 401, `${method} ${path} did not accept the key`);
    assert.ok(lastUsed(u.id), `${method} ${path} accepted the key without recording the use`);
  }
});

test('setting on: dashboard session, MCP key and MCP OAuth token on public still work', async () => {
  on();
  assert.equal((await rest({ Authorization: `Bearer ${SESSION}`, ...PUBLIC })).status, 200, 'session on REST');
  assert.equal((await verify({ Authorization: `Bearer ${SESSION}`, ...PUBLIC })).status, 200, 'session on verify');
  assert.equal((await mcp({ 'X-API-Key': MCP_KEY, ...PUBLIC })).status, 200, 'dhk_mcp_ key on MCP');
  const access = await oauthToken(U.id);
  assert.equal((await mcp({ Authorization: `Bearer ${access}`, ...PUBLIC })).status, 200, 'OAuth token on MCP');
  assert.equal((await mcp({ 'X-API-Key': U.key, ...PUBLIC })).status, 403, 'a user key on MCP is still a user key');
});

test('setting on: the refusal is audited once per user per hour', async () => {
  on();
  const before = audits().length;
  for (let i = 0; i < 3; i++) assert.equal((await rest({ 'X-API-Key': U.key, ...PUBLIC })).status, 403);
  const rows = audits().slice(before);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].user_id, U.id);
  const d = JSON.parse(rows[0].detail);
  assert.equal(d.via, 'rest');
  assert.equal(d.path, '/api/apps');
});

test('an unusable port value is treated as unset: no refusal', async () => {
  for (const v of ['abc', '443', '80', '0', '70000', process.env.PORT || '5001']) {
    process.env.APPCRANE_PRIVATE_API_PORT = v;
    assert.equal(ingress.privateApiPort(), null, v);
    assert.equal((await rest({ 'X-API-Key': U.key, ...PUBLIC })).status, 200, v);
  }
});

test('platform admins see the private port in GET /api/api-key-policy', async () => {
  on();
  const r = await fetch(`${BASE}/api/api-key-policy`, { headers: { 'X-API-Key': ADMIN.key, ...PRIVATE } });
  assert.equal(r.status, 200);
  assert.deepEqual((await r.json()).private_api, { configured: true, port: 8443, user_keys_public: false });
});
