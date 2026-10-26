import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes, createHash } from 'crypto';
import http from 'node:http';
import express from 'express';

// MCP front door for hosted apps (routes/appMcp.js, services/appMcp/*). Driven
// over real HTTP the way an MCP client would, against a local HTTP server that
// stands in for the app's container on the backend port Caddy would proxy to.
// Docker is not involved: the claim is about what AppCrane sends the app.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-appmcp-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { identitySecretFor } = await import('../server/services/identitySignature.js');
const { verifyIdentity } = await import('../packages/tenant/index.js');
const { setRules } = await import('../server/services/accessRules.js');
const { parseAppMcp, setAppMcp, storeManifestMcp, getAppMcp, AppMcpError } = await import('../server/services/appMcp/manifest.js');
const { resolveRequestedResource } = await import('../server/services/appMcp/oauthResource.js');
const { __setLimitsForTests, __resetRateLimitForTests, LIMITS } = await import('../server/services/appMcp/upstream.js');
const { registerClient, createCode, redeemCode } = await import('../server/services/oauthStore.js');
const appMcp = await import('../server/routes/appMcp.js');

initDb();
const db = getDb();
const DEFAULT_LIMITS = { ...LIMITS };

// Slots far above anything a dev box allocates; ports 7899 / 7901.
const SLOT_A = 1950;
const SLOT_B = 1951;
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('Alpha','alpha',?,'managed','local','main')").run(SLOT_A);
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('Beta','beta',?,'managed','local','main')").run(SLOT_B);
const ALPHA = db.prepare("SELECT id FROM apps WHERE slug='alpha'").get().id;
const BETA = db.prepare("SELECT id FROM apps WHERE slug='beta'").get().id;

function mkUser(roles = {}) {
  const key = generateApiKey('dhk_user');
  const tag = randomBytes(3).toString('hex');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?, 'user', ?, 1, 'human')")
    .run(`User ${tag}`, `u${tag}@t.test`, hashApiKey(key)).lastInsertRowid);
  for (const [appId, role] of Object.entries(roles)) {
    db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(Number(appId), id, role);
  }
  return { id, key, email: `u${tag}@t.test` };
}
const owner = mkUser({ [ALPHA]: 'owner', [BETA]: 'owner' });
const member = mkUser({ [ALPHA]: 'user' });
const outsider = mkUser({ [BETA]: 'user' });

function mcpKey(user, readOnly) {
  const key = generateApiKey('dhk_mcp');
  db.prepare('INSERT INTO user_mcp_keys (user_id, key_hash, label, read_only) VALUES (?,?,?,?)').run(user.id, hashApiKey(key), 'test', readOnly ? 1 : 0);
  return key;
}

const ALPHA_DECL = parseAppMcp({
  tools: [
    { name: 'list_orders', description: 'List orders', method: 'GET', path: '/api/orders',
      input_schema: { type: 'object', properties: { status: { type: 'string' } } } },
    { name: 'create_order', description: 'Create an order', method: 'POST', path: '/api/orders',
      input_schema: { type: 'object', properties: { item: { type: 'string' }, qty: { type: 'integer' } }, required: ['item'] } },
    { name: 'delete_order', description: 'Delete an order', method: 'DELETE', path: '/api/orders/{id}',
      input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
    { name: 'reset_all', description: 'Admin reset', method: 'POST', path: '/api/admin/reset', roles: ['admin'] },
    { name: 'get_report', description: 'A report', method: 'GET', path: '/api/reports/{id}',
      input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
    { name: 'slow', description: 'Slow', method: 'GET', path: '/slow' },
    { name: 'big', description: 'Big', method: 'GET', path: '/big' },
  ],
});
setAppMcp(db, ALPHA, 'production', ALPHA_DECL);
setAppMcp(db, BETA, 'production', parseAppMcp({ path: '/mcp' }));
setRules(db, ALPHA, 'production', 'dashboard', [{ path: '/api/reports/*', roles: ['admin'] }]);

// The stand-in app containers.
const received = [];
function appServer(port) {
  const s = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      received.push({ port, method: req.method, url: req.url, headers: req.headers, body });
      if (req.url === '/slow') { setTimeout(() => { try { res.end('late'); } catch (_) {} }, 2000); return; }
      if (req.url === '/big') { res.setHeader('Content-Type', 'text/plain'); return res.end('é'.repeat(4000)); }
      if (req.url === '/mcp') {
        const msg = JSON.parse(body || '{}');
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Mcp-Session-Id', 'sess-1');
        return res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { echoed: msg.method, user: req.headers['x-appcrane-user-email'] } })}\n\n`);
      }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, path: req.url, secret: 'RESP-SECRET-777' }));
    });
  });
  return new Promise((r, j) => { s.once('error', j); s.listen(port, '127.0.0.1', () => r(s)); });
}
const appA = await appServer(getPortsForSlot(SLOT_A).prod_be);
const appB = await appServer(getPortsForSlot(SLOT_B).prod_be);

const httpApp = express();
httpApp.use(express.json({ limit: '50mb' }));
httpApp.use('/.well-known', appMcp.appMcpWellKnownRouter);
httpApp.use('/api/mcp/apps', appMcp.default);
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => {
  for (const s of [server, appA, appB]) { s.closeAllConnections?.(); s.unref(); s.close(); }
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

let rid = 0;
async function rpc(target, auth, method, params = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth?.key) headers['X-API-Key'] = auth.key;
  if (auth?.bearer) headers.Authorization = `Bearer ${auth.bearer}`;
  const res = await fetch(`${BASE}/api/mcp/apps/${target}`, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: ++rid, method, params }) });
  let body = null;
  try { body = await res.json(); } catch (_) {}
  return { status: res.status, body, headers: res.headers };
}
const names = (r) => r.body.result.tools.map((t) => t.name).sort();
const call = (target, auth, name, args) => rpc(target, auth, 'tools/call', { name, arguments: args });
const lastReceived = () => received[received.length - 1];

function oauthToken(user, resource, readOnly = false) {
  const { client } = registerClient({ client_name: 'Test', redirect_uris: ['http://127.0.0.1:5000/cb'], grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none' });
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const code = createCode({ clientId: client.client_id, userId: user.id, redirectUri: 'http://127.0.0.1:5000/cb', codeChallenge: challenge, scope: readOnly ? 'mcp:read' : 'mcp', resource, readOnly });
  return redeemCode({ code, client, redirectUri: 'http://127.0.0.1:5000/cb', verifier, resource }).access_token;
}

test('initialize answers; tools/list shows only the tools the caller may call', async () => {
  const init = await rpc('alpha', owner, 'initialize', { protocolVersion: '2025-06-18' });
  assert.equal(init.status, 200);
  assert.equal(init.body.result.serverInfo.name, 'appcrane-app-alpha');
  assert.deepEqual(names(await rpc('alpha', owner, 'tools/list')),
    ['big', 'create_order', 'delete_order', 'get_report', 'list_orders', 'reset_all', 'slow']);
  // member: no admin-only tool, and get_report is hidden by the /api/reports/* admin rule
  assert.deepEqual(names(await rpc('alpha', member, 'tools/list')),
    ['big', 'create_order', 'delete_order', 'list_orders', 'slow']);
});

test('tools/call translates to the declared method, path and body, with signed identity for the caller', async () => {
  const r = await call('alpha', member, 'create_order', { item: 'widget', qty: 3 });
  assert.equal(r.body.result.isError, false, JSON.stringify(r.body));
  const got = lastReceived();
  assert.equal(got.method, 'POST');
  assert.equal(got.url, '/api/orders');
  assert.deepEqual(JSON.parse(got.body), { item: 'widget', qty: 3 });
  const who = verifyIdentity({ headers: got.headers }, { secret: identitySecretFor(db, ALPHA, 'production') });
  assert.equal(who.userId, String(member.id));
  assert.equal(who.email, member.email);
  assert.equal(got.headers['x-appcrane-app-role'], 'user');
  assert.equal(got.headers['x-appcrane-is-admin'], '0');
  assert.equal(got.headers['x-appcrane-mcp-tool'], 'create_order');
  // another app's secret does not verify it
  assert.throws(() => verifyIdentity({ headers: got.headers }, { secret: identitySecretFor(db, BETA, 'production') }), /does not match/);

  await call('alpha', member, 'delete_order', { id: 'a/b c' });
  assert.equal(lastReceived().method, 'DELETE');
  assert.equal(lastReceived().url, '/api/orders/a%2Fb%20c');
  await call('alpha', member, 'list_orders', { status: 'open' });
  assert.equal(lastReceived().url, '/api/orders?status=open');
  assert.equal(lastReceived().body, '');
});

test('the caller cannot set identity headers', async () => {
  const before = received.length;
  const res = await fetch(`${BASE}/api/mcp/apps/alpha`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': member.key, 'X-AppCrane-User-Email': 'boss@t.test', 'X-AppCrane-App-Role': 'owner', 'X-AppCrane-Is-Admin': '1' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_orders', arguments: {} } }),
  });
  assert.equal(res.status, 200);
  assert.equal(received.length, before + 1);
  assert.equal(lastReceived().headers['x-appcrane-user-email'], member.email);
  assert.equal(lastReceived().headers['x-appcrane-app-role'], 'user');
  assert.equal(lastReceived().headers['x-appcrane-is-admin'], '0');
});

test('a member is refused an admin-only tool; the owner may call it', async () => {
  const before = received.length;
  const r = await call('alpha', member, 'reset_all', {});
  assert.match(r.body.error.message, /needs the admin role/);
  assert.equal(received.length, before, 'the app was not called');
  const ok = await call('alpha', owner, 'reset_all', {});
  assert.equal(ok.body.result.isError, false);
  assert.equal(lastReceived().headers['x-appcrane-app-role'], 'owner');
  assert.equal(lastReceived().headers['x-appcrane-is-admin'], '1');
});

test('path access rules apply to the translated request', async () => {
  const before = received.length;
  const r = await call('alpha', member, 'get_report', { id: 'q3' });
  assert.match(r.body.error.message, /requires the admin role for this path/);
  assert.equal(received.length, before);
  const ok = await call('alpha', owner, 'get_report', { id: 'q3' });
  assert.equal(ok.body.result.isError, false);
  assert.equal(lastReceived().url, '/api/reports/q3');
});

test('a read-only key sees and calls only read-only (GET) tools', async () => {
  const ro = { key: mcpKey(owner, true) };
  assert.deepEqual(names(await rpc('alpha', ro, 'tools/list')), ['big', 'get_report', 'list_orders', 'slow']);
  const r = await call('alpha', ro, 'create_order', { item: 'x' });
  assert.match(r.body.error.message, /read-only/);
  assert.equal((await call('alpha', ro, 'list_orders', {})).body.result.isError, false);
  const full = { key: mcpKey(owner, false) };
  assert.equal((await call('alpha', full, 'create_order', { item: 'x' })).body.result.isError, false);
});

test('OAuth: a token for app A is accepted on A and refused on app B and on another env', async () => {
  const tokA = oauthToken(owner, `${BASE}/api/mcp/apps/alpha`);
  const okA = await call('alpha', { bearer: tokA }, 'list_orders', {});
  assert.equal(okA.body.result.isError, false);
  const onB = await rpc('beta', { bearer: tokA }, 'tools/list');
  assert.equal(onB.status, 401);
  assert.match(onB.headers.get('www-authenticate'), /resource_metadata="[^"]+\/\.well-known\/oauth-protected-resource\/api\/mcp\/apps\/beta"/);
  assert.equal((await rpc('alpha-sandbox', { bearer: tokA }, 'tools/list')).status, 401);
  const onPlatform = await fetch(`${BASE}/api/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokA}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  assert.equal(onPlatform.status, 401, 'an app token is not a token for POST /api/mcp');
  // a token for the platform endpoint is not a token for an app
  const platformTok = oauthToken(owner, `${BASE}/api/mcp`);
  assert.equal((await rpc('alpha', { bearer: platformTok }, 'tools/list')).status, 401);
  // a read-only OAuth grant is read-only here too
  const roTok = oauthToken(owner, `${BASE}/api/mcp/apps/alpha`, true);
  assert.match((await call('alpha', { bearer: roTok }, 'create_order', { item: 'x' })).body.error.message, /read-only/);
});

test('protected-resource metadata names each app endpoint as its own resource', async () => {
  const r = await fetch(`${BASE}/.well-known/oauth-protected-resource/api/mcp/apps/alpha`);
  const b = await r.json();
  assert.equal(b.resource, `${BASE}/api/mcp/apps/alpha`);
  assert.deepEqual(b.authorization_servers, [BASE]);
  assert.equal((await fetch(`${BASE}/.well-known/oauth-protected-resource/api/mcp/apps/nope`)).status, 404);
  const fakeReq = { protocol: 'http', get: () => server.address().port && `127.0.0.1:${server.address().port}` };
  const exists = (s) => ['alpha', 'beta'].includes(s);
  assert.equal(resolveRequestedResource(fakeReq, undefined, exists), `${BASE}/api/mcp`);
  assert.equal(resolveRequestedResource(fakeReq, `${BASE}/api/mcp/apps/alpha-sandbox`, exists), `${BASE}/api/mcp/apps/alpha-sandbox`);
  assert.equal(resolveRequestedResource(fakeReq, `${BASE}/api/mcp/apps/nope`, exists), null);
  assert.equal(resolveRequestedResource(fakeReq, `${BASE}/api/mcp/apps/alpha/extra`, exists), null);
  assert.equal(resolveRequestedResource(fakeReq, `${BASE}/api/mcp/apps/alpha?x=1`, exists), null);
  assert.equal(resolveRequestedResource(fakeReq, 'https://elsewhere.test/api/mcp/apps/alpha', exists), null);
});

test('an API key outside the MCP app scope, or with an empty scope, is refused', async () => {
  db.prepare('UPDATE users SET mcp_app_scope = ? WHERE id = ?').run('["beta"]', owner.id);
  try {
    const r = await rpc('alpha', owner, 'tools/list');
    assert.equal(r.status, 403);
    assert.match(r.body.error.message, /scope does not include 'alpha'/);
    db.prepare('UPDATE users SET mcp_app_scope = ? WHERE id = ?').run('[]', owner.id);
    assert.match((await rpc('alpha', owner, 'tools/list')).body.error.message, /locked out/);
  } finally {
    db.prepare('UPDATE users SET mcp_app_scope = NULL WHERE id = ?').run(owner.id);
  }
  assert.equal((await rpc('alpha', owner, 'tools/list')).status, 200);
});

test('a caller with no access to the app is refused', async () => {
  const r = await rpc('alpha', outsider, 'tools/list');
  assert.equal(r.status, 403);
  assert.equal((await rpc('alpha', null, 'tools/list')).status, 401);
});

test('"MCP: OAuth only" refuses API keys and keeps OAuth working', async () => {
  const tokA = oauthToken(member, `${BASE}/api/mcp/apps/alpha`);
  db.prepare("INSERT INTO settings (key,value) VALUES ('mcp_oauth_only','true') ON CONFLICT(key) DO UPDATE SET value='true'").run();
  try {
    const r = await rpc('alpha', member, 'tools/list');
    assert.equal(r.status, 401);
    assert.match(r.headers.get('www-authenticate'), /API keys are turned off/);
    assert.equal((await rpc('alpha', { bearer: tokA }, 'tools/list')).status, 200);
  } finally {
    db.prepare("UPDATE settings SET value='false' WHERE key='mcp_oauth_only'").run();
  }
  assert.equal((await rpc('alpha', member, 'tools/list')).status, 200);
});

test('timeouts, response caps, request caps and the rate limit', async () => {
  __setLimitsForTests({ timeoutMs: 300, maxResponseBytes: 1024 });
  try {
    const slow = await call('alpha', owner, 'slow', {});
    assert.equal(slow.body.result.isError, true);
    assert.match(slow.body.result.content[0].text, /did not answer within 300 ms/);
    const big = await call('alpha', owner, 'big', {});
    const text = big.body.result.content[0].text;
    assert.match(text, /\[response truncated by AppCrane at 1024 bytes\]$/);
    assert.ok(!text.includes('�'), 'no broken character at the cut');
    __setLimitsForTests({ maxRequestBytes: 2000 });
    const huge = await call('alpha', owner, 'create_order', { item: 'x'.repeat(5000) });
    assert.equal(huge.status, 413);
    __resetRateLimitForTests();
    __setLimitsForTests({ callsPerMinute: 2 });
    assert.equal((await call('alpha', member, 'list_orders', {})).body.result.isError, false);
    assert.equal((await call('alpha', member, 'list_orders', {})).body.result.isError, false);
    assert.match((await call('alpha', member, 'list_orders', {})).body.error.message, /Rate limited/);
    assert.equal((await call('alpha', owner, 'list_orders', {})).body.result.isError, false, 'per caller');
  } finally {
    __setLimitsForTests(DEFAULT_LIMITS);
    __resetRateLimitForTests();
  }
});

test('events and audit rows are recorded without arguments or response bodies', async () => {
  db.prepare("DELETE FROM events WHERE kind = 'mcp.app_tool'").run();
  await call('alpha', member, 'create_order', { item: 'ARG-SECRET-555' });
  await call('alpha', member, 'reset_all', {});
  const evs = db.prepare("SELECT severity, user_id, app_id, summary, data FROM events WHERE kind = 'mcp.app_tool' ORDER BY id").all();
  assert.equal(evs.length, 2);
  assert.equal(evs[0].severity, 'info');
  assert.equal(evs[0].user_id, member.id);
  assert.equal(evs[0].app_id, ALPHA);
  assert.equal(evs[1].severity, 'warning');
  assert.match(evs[1].summary, /refused role/);
  const audits = db.prepare("SELECT detail FROM audit_log WHERE action = 'mcp.app_tool'").all();
  assert.ok(audits.length >= 2);
  const all = JSON.stringify([evs, audits]);
  assert.ok(!all.includes('ARG-SECRET-555'), 'no argument values');
  assert.ok(!all.includes('RESP-SECRET-777'), 'no response body');
  assert.equal(JSON.parse(evs[0].data).tool, 'create_order');
  assert.equal(JSON.parse(evs[0].data).method, 'POST');
});

test('passthrough: an app that speaks MCP gets the call with signed identity; read-only keys may not call its tools', async () => {
  const r = await rpc('beta', owner, 'tools/call', { name: 'anything', arguments: {} });
  assert.equal(r.status, 200);
  assert.equal(r.body.result.echoed, 'tools/call');
  assert.equal(r.body.result.user, owner.email);
  assert.equal(r.headers.get('mcp-session-id'), 'sess-1');
  const got = lastReceived();
  assert.equal(got.url, '/mcp');
  assert.equal(verifyIdentity({ headers: got.headers }, { secret: identitySecretFor(db, BETA, 'production') }).userId, String(owner.id));
  const ro = { key: mcpKey(owner, true) };
  assert.match((await rpc('beta', ro, 'tools/call', { name: 'anything' })).body.error.message, /read-only/);
  assert.equal((await rpc('beta', ro, 'tools/list')).body.result.echoed, 'tools/list');
});

test('a Crew agent token calls app tools as its owner', async () => {
  const { issueInitialToken } = await import('../server/services/crewTokens.js');
  db.prepare("INSERT INTO crew_agents (name, owner_user_id, kind) VALUES ('member-bot', ?, 'hosted')").run(member.id);
  const { token } = issueInitialToken(db.prepare('SELECT * FROM users WHERE id = ?').get(member.id), 'member-bot');
  const r = await call('alpha', { bearer: token }, 'list_orders', {});
  assert.equal(r.body.result.isError, false);
  assert.equal(lastReceived().headers['x-appcrane-user-email'], member.email);
  assert.match((await call('alpha', { bearer: token }, 'reset_all', {})).body.error.message, /needs the admin role/);
  assert.equal((await rpc('alpha', { bearer: 'dhk_crew_' + 'x'.repeat(43) }, 'tools/list')).status, 401);
});

test('catalogue lists the app endpoints the caller can use', async () => {
  const res = await fetch(`${BASE}/api/mcp/apps`, { headers: { 'X-API-Key': member.key } });
  const b = await res.json();
  assert.deepEqual(b.apps.map((a) => a.slug), ['alpha']);
  assert.equal(b.apps[0].url, `${BASE}/api/mcp/apps/alpha`);
  assert.equal(b.apps[0].claude_command, `claude mcp add --transport http alpha ${BASE}/api/mcp/apps/alpha`);
  assert.equal(b.apps[0].tools, 5);
  const detail = await (await fetch(`${BASE}/api/mcp/apps/alpha/tools`, { headers: { 'X-API-Key': member.key } })).json();
  assert.equal(detail.envs.production.tool_list.find((t) => t.name === 'reset_all').allowed, false);
  assert.equal((await fetch(`${BASE}/api/mcp/apps/alpha/tools`, { headers: { 'X-API-Key': outsider.key } })).status, 403);
});

test('the deploy hook: an invalid declaration throws with the field named; a valid one is stored, and none clears it', () => {
  const bad = [
    [{ tools: [{ name: 'x', method: 'GET', path: '/a' }] }, /mcp\.tools\[0\]\.description: is required/],
    [{ tools: [{ name: 'x', description: 'd', method: 'TRACE', path: '/a' }] }, /mcp\.tools\[0\]\.method/],
    [{ tools: [{ name: 'x', description: 'd', method: 'GET', path: '/a/../b' }] }, /mcp\.tools\[0\]\.path/],
    [{ tools: [{ name: 'x', description: 'd', method: 'GET', path: '/a/{id}' }] }, /input_schema: is required/],
    [{ tools: [{ name: 'x', description: 'd', method: 'POST', path: '/a', readOnly: true }] }, /only a GET tool can be read-only/],
    [{ tools: [{ name: 'x', description: 'd', method: 'GET', path: '/a', roles: ['god'] }] }, /unknown role/],
    [{ tools: [{ name: 'x', description: 'd', method: 'GET', path: '/a' }, { name: 'x', description: 'd', method: 'GET', path: '/b' }] }, /declared twice/],
    [{ tools: [], path: '/mcp' }, /not both/],
    [{ tool: [] }, /mcp\.tool: unknown key/],
    ['yes', /must be an object/],
  ];
  for (const [block, re] of bad) assert.throws(() => parseAppMcp(block), (e) => e instanceof AppMcpError && re.test(e.message), JSON.stringify(block));
  assert.equal(parseAppMcp(undefined), null);
  storeManifestMcp(BETA, 'sandbox', parseAppMcp({ tools: [{ name: 'ping', description: 'Ping', method: 'GET', path: '/ping' }] }));
  assert.equal(getAppMcp(db, BETA, 'sandbox').tools[0].readOnly, true);
  storeManifestMcp(BETA, 'sandbox', parseAppMcp(undefined));
  assert.equal(getAppMcp(db, BETA, 'sandbox'), null);
});
