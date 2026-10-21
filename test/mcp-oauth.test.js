import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import express from 'express';

// MCP OAuth 2.1 (routes/oauth.js, routes/oauthConsent.js, services/oauth*.js,
// the OAuth branch of middleware/auth.js). Everything is driven over real HTTP
// against an ephemeral server with fetch, the way an MCP client would: discover,
// register, authorize (a signed-in user approves), exchange with PKCE, call
// POST /api/mcp. Every refusal has a working baseline in the same file.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-oauth-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;
process.env.OAUTH_REGISTER_PER_HOUR = '1000';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const oauth = await import('../server/routes/oauth.js');

initDb();
const db = getDb();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('alpha','alpha',921,'managed','local','main')").run();
const ALPHA = db.prepare("SELECT id FROM apps WHERE slug='alpha'").get().id;

function mkUser() {
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?, 'user', ?, 1, 'human')")
    .run(`o${randomBytes(3).toString('hex')}`, `o${randomBytes(3).toString('hex')}@t.test`, hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(ALPHA, id);
  const session = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(id, hashApiKey(session));
  return { id, session };
}
const alice = mkUser();

const httpApp = express();
httpApp.use(express.json());
httpApp.use(express.urlencoded({ extended: true }));
httpApp.use('/.well-known', oauth.wellKnownRouter);
httpApp.use('/oauth', oauth.default);
httpApp.use('/api/oauth', (await import('../server/routes/oauthConsent.js')).default);
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.get('/api/apps', requireAuth, (req, res) => res.json({ ok: true }));
httpApp.use('/api', (await import('../server/routes/userMcpKeys.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const REDIRECT = 'http://127.0.0.1:53682/callback';
const json = async (res) => { try { return await res.json(); } catch (_) { return null; } };

async function register(extra = {}) {
  const res = await fetch(`${BASE}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Test Client', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], ...extra }),
  });
  return { status: res.status, body: await json(res) };
}

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

function authorizeUrl(clientId, challenge, over = {}) {
  const p = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, code_challenge: challenge,
    code_challenge_method: 'S256', scope: 'mcp', state: 'st-123', resource: `${BASE}/api/mcp`, ...over,
  });
  for (const [k, v] of Object.entries(over)) if (v === null) p.delete(k);
  return `${BASE}/oauth/authorize?${p}`;
}

async function approve(user, location, body = { decision: 'approve' }) {
  const id = new URL(location, BASE).searchParams.get('request');
  const view = await fetch(`${BASE}/api/oauth/authorize-requests/${id}`, { headers: { Authorization: `Bearer ${user.session}` } });
  const viewBody = await json(view);
  const res = await fetch(`${BASE}/api/oauth/authorize-requests/${id}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${user.session}` }, body: JSON.stringify(body),
  });
  return { view: viewBody, status: res.status, redirect: (await json(res))?.redirect_to };
}

async function getCode(clientId, user = alice, over = {}, decision = { decision: 'approve' }) {
  const p = pkce();
  const res = await fetch(authorizeUrl(clientId, p.challenge, over), { redirect: 'manual', headers: { Cookie: `cc_token=${user.session}` } });
  assert.equal(res.status, 302);
  const loc = res.headers.get('location');
  assert.match(loc, /^\/mcp\/authorize\?request=/);
  const a = await approve(user, loc, decision);
  assert.equal(a.status, 200);
  const back = new URL(a.redirect);
  return { ...p, code: back.searchParams.get('code'), back, view: a.view };
}

async function token(params, headers = {}) {
  const res = await fetch(`${BASE}/oauth/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(params).toString(),
  });
  return { status: res.status, body: await json(res), headers: res.headers };
}

async function rpc(accessToken, method, params = {}) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: res.status, body: await json(res), headers: res.headers };
}

async function fullFlow(over = {}, decision) {
  const client = (await register()).body;
  const c = await getCode(client.client_id, alice, over, decision);
  const t = await token({ grant_type: 'authorization_code', code: c.code, redirect_uri: REDIRECT, code_verifier: c.verifier, client_id: client.client_id, resource: `${BASE}/api/mcp` });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  return { client, tokens: t.body, c };
}

test('metadata documents and the 401 challenge point an MCP client at AppCrane', async () => {
  const r = await fetch(`${BASE}/api/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' });
  assert.equal(r.status, 401);
  assert.equal(r.headers.get('www-authenticate'), `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource/api/mcp", scope="mcp"`);

  for (const path of ['/.well-known/oauth-protected-resource/api/mcp', '/.well-known/oauth-protected-resource']) {
    const prm = await (await fetch(BASE + path)).json();
    assert.deepEqual(prm, {
      resource: `${BASE}/api/mcp`, authorization_servers: [BASE], scopes_supported: ['mcp'],
      bearer_methods_supported: ['header'], resource_name: 'AppCrane MCP',
    });
  }
  const as = await (await fetch(`${BASE}/.well-known/oauth-authorization-server`)).json();
  assert.equal(as.issuer, BASE);
  assert.equal(as.authorization_endpoint, `${BASE}/oauth/authorize`);
  assert.equal(as.token_endpoint, `${BASE}/oauth/token`);
  assert.equal(as.registration_endpoint, `${BASE}/oauth/register`);
  assert.equal(as.revocation_endpoint, `${BASE}/oauth/revoke`);
  assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(as.response_types_supported, ['code']);
  assert.deepEqual(as.grant_types_supported, ['authorization_code', 'refresh_token']);
  assert.equal(as.authorization_response_iss_parameter_supported, true);
});

test('happy path: register, sign-in approval, PKCE exchange, tools/list over POST /api/mcp', async () => {
  const reg = await register();
  assert.equal(reg.status, 201);
  assert.match(reg.body.client_id, /^mcpc_/);
  assert.equal(reg.body.client_secret, undefined);

  // Not signed in: the browser is sent to sign-in with the consent page as the target.
  const p0 = pkce();
  const anon = await fetch(authorizeUrl(reg.body.client_id, p0.challenge), { redirect: 'manual' });
  assert.equal(anon.status, 302);
  assert.match(anon.headers.get('location'), /^\/login\?redirect=%2Fmcp%2Fauthorize%3Frequest%3D/);

  const c = await getCode(reg.body.client_id);
  assert.equal(c.view.client_name, 'Test Client');
  assert.equal(c.view.redirect_host, '127.0.0.1:53682');
  assert.equal(c.view.loopback, true);
  assert.equal(c.view.scope, 'mcp');
  assert.equal(c.back.origin + c.back.pathname, REDIRECT);
  assert.equal(c.back.searchParams.get('state'), 'st-123');
  assert.equal(c.back.searchParams.get('iss'), BASE);

  const t = await token({ grant_type: 'authorization_code', code: c.code, redirect_uri: REDIRECT, code_verifier: c.verifier, client_id: reg.body.client_id, resource: `${BASE}/api/mcp` });
  assert.equal(t.status, 200);
  assert.equal(t.headers.get('cache-control'), 'no-store');
  assert.match(t.body.access_token, /^dhk_oat_/);
  assert.match(t.body.refresh_token, /^dhk_ort_/);
  assert.equal(t.body.token_type, 'Bearer');
  assert.equal(t.body.expires_in, 3600);
  assert.equal(t.body.scope, 'mcp');

  const list = await rpc(t.body.access_token, 'tools/list');
  assert.equal(list.status, 200);
  const names = list.body.result.tools.map(x => x.name);
  assert.ok(names.includes('appcrane_list_apps'));
  assert.ok(names.includes('appcrane_deploy'), 'a full-scope grant must see write tools');
  const apps = await rpc(t.body.access_token, 'tools/call', { name: 'appcrane_list_apps', arguments: {} });
  assert.match(apps.body.result.content[0].text, /"alpha"/);

  // Stored hashed, never in plaintext.
  const raw = db.prepare('SELECT token_hash FROM oauth_tokens').all().map(r => r.token_hash);
  assert.ok(raw.includes(hashApiKey(t.body.access_token)));
  assert.ok(!raw.includes(t.body.access_token));
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'oauth-client-authorized' AND user_id = ?").get(alice.id).n >= 1, true);
});

test('a wrong code_verifier, a wrong redirect_uri, or a different client cannot redeem a code', async () => {
  const client = (await register()).body;
  const other = (await register()).body;
  const c = await getCode(client.client_id);
  const base = { grant_type: 'authorization_code', code: c.code, redirect_uri: REDIRECT, code_verifier: c.verifier, client_id: client.client_id };
  const wrongVerifier = await token({ ...base, code_verifier: pkce().verifier });
  assert.equal(wrongVerifier.status, 400);
  assert.equal(wrongVerifier.body.error, 'invalid_grant');
  const wrongRedirect = await token({ ...base, redirect_uri: 'http://127.0.0.1:53682/other' });
  assert.equal(wrongRedirect.body.error, 'invalid_grant');
  const wrongClient = await token({ ...base, client_id: other.client_id });
  assert.equal(wrongClient.body.error, 'invalid_grant');
  // The code survived those attempts (they never consumed it): the right request still works.
  const ok = await token(base);
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
});

test('a reused code is refused and revokes what the first exchange issued', async () => {
  const client = (await register()).body;
  const c = await getCode(client.client_id);
  const req = { grant_type: 'authorization_code', code: c.code, redirect_uri: REDIRECT, code_verifier: c.verifier, client_id: client.client_id };
  const first = await token(req);
  assert.equal(first.status, 200);
  assert.ok((await rpc(first.body.access_token, 'tools/list')).body.result);
  const second = await token(req);
  assert.equal(second.status, 400);
  assert.equal(second.body.error, 'invalid_grant');
  assert.equal((await rpc(first.body.access_token, 'tools/list')).status, 401, 'the first token survived code reuse');
});

test('an expired access token gets 401 with the challenge', async () => {
  const { tokens } = await fullFlow();
  assert.equal((await rpc(tokens.access_token, 'tools/list')).status, 200);
  db.prepare("UPDATE oauth_tokens SET expires_at = datetime('now','-1 minute') WHERE token_hash = ?").run(hashApiKey(tokens.access_token));
  const r = await rpc(tokens.access_token, 'tools/list');
  assert.equal(r.status, 401);
  assert.match(r.headers.get('www-authenticate'), /resource_metadata=/);
});

test('refresh rotates: the new pair works, the old refresh token is refused and kills the connection', async () => {
  const { client, tokens } = await fullFlow();
  const r1 = await token({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id });
  assert.equal(r1.status, 200, JSON.stringify(r1.body));
  assert.notEqual(r1.body.refresh_token, tokens.refresh_token);
  assert.equal((await rpc(r1.body.access_token, 'tools/list')).status, 200);
  const replay = await token({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id });
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.equal((await rpc(r1.body.access_token, 'tools/list')).status, 401, 'replaying a spent refresh token left the connection alive');
  const after = await token({ grant_type: 'refresh_token', refresh_token: r1.body.refresh_token, client_id: client.client_id });
  assert.equal(after.body.error, 'invalid_grant');
});

test('revocation: the RFC 7009 endpoint and the user\'s own connections list both end a connection', async () => {
  const a = await fullFlow();
  const rev = await fetch(`${BASE}/oauth/revoke`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: a.tokens.refresh_token, client_id: a.client.client_id }).toString(),
  });
  assert.equal(rev.status, 200);
  assert.equal((await rpc(a.tokens.access_token, 'tools/list')).status, 401);

  const b = await fullFlow();
  const list = await (await fetch(`${BASE}/api/oauth/connections`, { headers: { Authorization: `Bearer ${alice.session}` } })).json();
  const mine = list.connections.find(x => x.client_name === 'Test Client');
  assert.ok(mine);
  assert.deepEqual(mine.redirect_hosts, ['127.0.0.1:53682']);
  // Another user cannot revoke it.
  const bob = mkUser();
  const foreign = await fetch(`${BASE}/api/oauth/connections/${mine.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${bob.session}` } });
  assert.equal(foreign.status, 404);
  assert.equal((await rpc(b.tokens.access_token, 'tools/list')).status, 200);
  const del = await fetch(`${BASE}/api/oauth/connections/${mine.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${alice.session}` } });
  assert.equal(del.status, 200);
  assert.equal((await rpc(b.tokens.access_token, 'tools/list')).status, 401);
  const refresh = await token({ grant_type: 'refresh_token', refresh_token: b.tokens.refresh_token, client_id: b.client.client_id });
  assert.equal(refresh.body.error, 'invalid_grant');
});

test('an OAuth access token is refused on REST routes and on the MCP management routes', async () => {
  const { tokens } = await fullFlow();
  const rest = await fetch(`${BASE}/api/apps`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(rest.status, 403);
  assert.equal((await rest.json()).error.code, 'KEY_SCOPE_RESTRICTED');
  const keys = await fetch(`${BASE}/api/me/mcp-keys`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(keys.status, 403);
  const conns = await fetch(`${BASE}/api/oauth/connections`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(conns.status, 403);
  // The session baseline reaches the same REST route.
  assert.equal((await fetch(`${BASE}/api/apps`, { headers: { Authorization: `Bearer ${alice.session}` } })).status, 200);
});

test('scope: mcp:read and the consent read-only box give a read-only connection; the user\'s MCP app scope applies', async () => {
  for (const [over, decision] of [[{ scope: 'mcp:read' }, undefined], [{}, { decision: 'approve', read_only: true }]]) {
    const { tokens } = await fullFlow(over, decision);
    assert.equal(tokens.scope, 'mcp:read');
    const names = (await rpc(tokens.access_token, 'tools/list')).body.result.tools.map(x => x.name);
    assert.ok(names.includes('appcrane_list_apps'));
    assert.ok(!names.includes('appcrane_deploy'), 'a read-only grant was advertised a write tool');
    const w = await rpc(tokens.access_token, 'tools/call', { name: 'appcrane_deploy', arguments: { slug: 'alpha', env: 'sandbox' } });
    assert.match(w.body.error.message, /read-only/);
  }
  const { tokens } = await fullFlow();
  db.prepare("UPDATE users SET mcp_app_scope = '[]' WHERE id = ?").run(alice.id);
  try {
    assert.deepEqual((await rpc(tokens.access_token, 'tools/list')).body.result.tools, []);
  } finally {
    db.prepare('UPDATE users SET mcp_app_scope = NULL WHERE id = ?').run(alice.id);
  }
});

test('a token issued for another resource is refused', async () => {
  const { tokens } = await fullFlow();
  db.prepare("UPDATE oauth_grants SET resource = 'https://elsewhere.test/api/mcp' WHERE id = (SELECT grant_id FROM oauth_tokens WHERE token_hash = ?)").run(hashApiKey(tokens.access_token));
  assert.equal((await rpc(tokens.access_token, 'tools/list')).status, 401);
});

test('authorize refuses bad requests: unknown client and unregistered redirect get a page, the rest go back as errors', async () => {
  const client = (await register()).body;
  const { challenge } = pkce();
  const unknown = await fetch(authorizeUrl('mcpc_nope', challenge), { redirect: 'manual' });
  assert.equal(unknown.status, 400);
  const badRedirect = await fetch(authorizeUrl(client.client_id, challenge, { redirect_uri: 'https://evil.test/cb' }), { redirect: 'manual' });
  assert.equal(badRedirect.status, 400, 'an unregistered redirect_uri was redirected to');
  for (const [over, error] of [
    [{ code_challenge_method: 'plain' }, 'invalid_request'],
    [{ code_challenge: null, code_challenge_method: null }, 'invalid_request'],
    [{ response_type: 'token' }, 'unsupported_response_type'],
    [{ resource: 'https://elsewhere.test/api/mcp' }, 'invalid_target'],
  ]) {
    const r = await fetch(authorizeUrl(client.client_id, challenge, over), { redirect: 'manual' });
    assert.equal(r.status, 302);
    const loc = new URL(r.headers.get('location'));
    assert.equal(loc.origin + loc.pathname, REDIRECT);
    assert.equal(loc.searchParams.get('error'), error, JSON.stringify(over));
    assert.equal(loc.searchParams.get('state'), 'st-123');
    assert.equal(loc.searchParams.get('iss'), BASE);
  }
  // A denial goes back as access_denied with no code.
  const p = pkce();
  const res = await fetch(authorizeUrl(client.client_id, p.challenge), { redirect: 'manual', headers: { Cookie: `cc_token=${alice.session}` } });
  const denied = await approve(alice, res.headers.get('location'), { decision: 'deny' });
  const back = new URL(denied.redirect);
  assert.equal(back.searchParams.get('error'), 'access_denied');
  assert.equal(back.searchParams.get('code'), null);
  // A pending request is answered once.
  const again = await approve(alice, res.headers.get('location'));
  assert.equal(again.status, 404);
});

test('registration accepts only https and loopback redirect URIs, and confidential clients must authenticate', async () => {
  for (const uri of ['http://evil.test/cb', 'javascript:alert(1)', 'https://x.test/cb#frag', 'myapp://cb']) {
    const r = await register({ redirect_uris: [uri] });
    assert.equal(r.status, 400, uri);
    assert.equal(r.body.error, 'invalid_redirect_uri');
  }
  // URI shape only: the default 'allowlist' registration policy (oauth-client-policy.test.js) is lifted here.
  db.prepare("INSERT INTO settings (key, value) VALUES ('oauth_dcr_mode', 'open') ON CONFLICT(key) DO UPDATE SET value = 'open'").run();
  for (const uri of ['https://claude.example/api/mcp/auth_callback', 'http://localhost:33418/callback', 'http://[::1]:9/cb']) {
    assert.equal((await register({ redirect_uris: [uri] })).status, 201, uri);
  }
  db.prepare("DELETE FROM settings WHERE key = 'oauth_dcr_mode'").run();
  const conf = await register({ token_endpoint_auth_method: 'client_secret_basic' });
  assert.equal(conf.status, 201);
  assert.match(conf.body.client_secret, /^dhk_ocs_/);
  const c = await getCode(conf.body.client_id);
  const body = { grant_type: 'authorization_code', code: c.code, redirect_uri: REDIRECT, code_verifier: c.verifier };
  const noAuth = await token({ ...body, client_id: conf.body.client_id });
  assert.equal(noAuth.status, 401);
  assert.equal(noAuth.body.error, 'invalid_client');
  const badSecret = await token(body, { Authorization: 'Basic ' + Buffer.from(`${conf.body.client_id}:wrong`).toString('base64') });
  assert.equal(badSecret.status, 401);
  const good = await token(body, { Authorization: 'Basic ' + Buffer.from(`${conf.body.client_id}:${conf.body.client_secret}`).toString('base64') });
  assert.equal(good.status, 200, JSON.stringify(good.body));
});

test('registration is rate limited per client address', async () => {
  const { createOAuthLimiter } = await import('../server/services/oauthRateLimit.js');
  const limiter = createOAuthLimiter('t', { max: 2, windowMs: 60_000 });
  const results = [];
  const fakeRes = () => ({ code: 200, set() {}, status(c) { this.code = c; return this; }, json() { results.push(this.code); } });
  for (let i = 0; i < 3; i++) {
    let passed = false;
    const res = fakeRes();
    limiter({ ip: '203.0.113.9' }, res, () => { passed = true; });
    if (passed) results.push(200);
  }
  assert.deepEqual(results, [200, 200, 429]);
  const { OAUTH_LIMITS } = await import('../server/services/oauthRateLimit.js');
  assert.ok(OAUTH_LIMITS.token.max <= 60 && OAUTH_LIMITS.authorize.max <= 60);
});
