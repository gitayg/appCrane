import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import express from 'express';

// MCP OAuth hardening (security review 2026-10, F-001 + F-002): a connection has
// an absolute lifetime refresh cannot extend; password change, API key rotation,
// admin key regeneration, demotion and deactivation end it; approving needs a
// fresh sign-in and never an API key; platform admins can list and revoke any
// user's connections; the consent screen states the real scope; client
// registration follows the platform policy; read-only connections never reach
// the plaintext-secret tools. Real HTTP against an ephemeral server, as in
// mcp-oauth.test.js; every refusal has a working baseline next to it.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-oauthsec-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;
process.env.OAUTH_REGISTER_PER_HOUR = '1000';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho 5\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, hashPassword, encrypt } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const oauth = await import('../server/routes/oauth.js');

initDb();
const db = getDb();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('alpha','alpha',931,'managed','local','main')").run();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('beta','beta',932,'managed','local','main')").run();
const ALPHA = db.prepare("SELECT id FROM apps WHERE slug='alpha'").get().id;
db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'sandbox', 'API_TOKEN', ?)").run(ALPHA, encrypt('plaintext-sandbox-secret'));

function mkUser({ role = 'user', owner = true, password = null } = {}) {
  const apiKey = generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind,password_hash) VALUES (?,?,?,?,1,'human',?)")
    .run(`s${randomBytes(3).toString('hex')}`, `s${randomBytes(3).toString('hex')}@t.test`, role, hashApiKey(apiKey), password ? hashPassword(password) : null).lastInsertRowid;
  if (owner) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(ALPHA, id);
  const session = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(id, hashApiKey(session));
  return { id, session, apiKey };
}

const httpApp = express();
httpApp.use(express.json());
httpApp.use(express.urlencoded({ extended: true }));
httpApp.use('/.well-known', oauth.wellKnownRouter);
httpApp.use('/oauth', oauth.default);
httpApp.use('/api/oauth', (await import('../server/routes/oauthConsent.js')).default);
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.use('/api/identity', (await import('../server/routes/identity.js')).default);
httpApp.use('/api/users', (await import('../server/routes/users.js')).default);
httpApp.use('/api', (await import('../server/routes/apiKeys.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const REDIRECT = 'http://127.0.0.1:53682/callback';
const json = async (res) => { try { return await res.json(); } catch (_) { return null; } };
const setMode = (mode) => db.prepare("INSERT INTO settings (key, value) VALUES ('oauth_dcr_mode', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(mode);

async function register(uris = [REDIRECT]) {
  const res = await fetch(`${BASE}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Claude', redirect_uris: uris, token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'] }),
  });
  return { status: res.status, body: await json(res) };
}

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

async function startAuthorize(clientId, user, redirect = REDIRECT, extra = {}) {
  const p = pkce();
  const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirect, code_challenge: p.challenge, code_challenge_method: 'S256', scope: 'mcp', state: 's', ...extra });
  const res = await fetch(`${BASE}/oauth/authorize?${q}`, { redirect: 'manual', headers: { Cookie: `cc_token=${user.session}` } });
  const loc = res.headers.get('location');
  return { ...p, status: res.status, requestId: loc ? new URL(loc, BASE).searchParams.get('request') : null };
}

async function consentView(requestId, headers) {
  const r = await fetch(`${BASE}/api/oauth/authorize-requests/${requestId}`, { headers });
  return { status: r.status, body: await json(r) };
}

async function decide(requestId, headers, body) {
  const r = await fetch(`${BASE}/api/oauth/authorize-requests/${requestId}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { status: r.status, body: await json(r) };
}

async function token(params) {
  const res = await fetch(`${BASE}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params).toString() });
  return { status: res.status, body: await json(res) };
}

async function rpc(accessToken, method, params = {}) {
  const res = await fetch(`${BASE}/api/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  return { status: res.status, body: await json(res) };
}

async function connect(user, { readOnly = false } = {}) {
  const client = (await register()).body;
  const a = await startAuthorize(client.client_id, user);
  assert.equal(a.status, 302);
  const d = await decide(a.requestId, { Authorization: `Bearer ${user.session}` }, { decision: 'approve', read_only: readOnly });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  const code = new URL(d.body.redirect_to).searchParams.get('code');
  const t = await token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: a.verifier, client_id: client.client_id });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  const grantId = db.prepare('SELECT grant_id FROM oauth_tokens WHERE token_hash = ?').get(hashApiKey(t.body.access_token)).grant_id;
  return { client, tokens: t.body, grantId };
}

const refresh = (c, rt = c.tokens.refresh_token) => token({ grant_type: 'refresh_token', refresh_token: rt, client_id: c.client.client_id });
async function assertDead(c, what) {
  assert.equal((await rpc(c.tokens.access_token, 'tools/list')).status, 401, `${what}: access token still works`);
  const r = await refresh(c);
  assert.equal(r.body.error, 'invalid_grant', `${what}: refresh still works`);
}

// ---------------------------------------------------------------- F-001

test('F-001 refresh cannot carry a connection past its absolute lifetime (the API key window)', async () => {
  const u = mkUser();
  const c = await connect(u);
  db.prepare("UPDATE oauth_grants SET created_at = datetime('now', '-89 days', '-23 hours') WHERE id = ?").run(c.grantId);
  const r1 = await refresh(c);
  assert.equal(r1.status, 200, 'baseline: inside the window a refresh works');
  const newest = db.prepare("SELECT expires_at FROM oauth_tokens WHERE token_hash = ?").get(hashApiKey(r1.body.refresh_token)).expires_at;
  const limit = db.prepare("SELECT datetime(created_at, '+90 days') AS e FROM oauth_grants WHERE id = ?").get(c.grantId).e;
  console.log(`# rotated refresh expires ${newest}; grant limit ${limit}; access expires_in ${r1.body.expires_in}`);
  assert.ok(newest <= limit, `rotation pushed the refresh token to ${newest}, past the grant limit ${limit}`);
  assert.ok(r1.body.expires_in <= 3600);

  db.prepare("UPDATE oauth_grants SET created_at = datetime('now', '-90 days', '-1 minute') WHERE id = ?").run(c.grantId);
  const r2 = await refresh({ ...c, tokens: r1.body });
  console.log(`# past the window: ${r2.status} ${JSON.stringify(r2.body)}`);
  assert.equal(r2.status, 400);
  assert.equal(r2.body.error, 'invalid_grant');
  assert.match(r2.body.error_description, /maximum lifetime of 90 days/);
  assert.equal((await rpc(r1.body.access_token, 'tools/list')).status, 401, 'an access token outlived its grant');

  db.prepare("INSERT INTO settings (key, value) VALUES ('api_key_max_age_days', '30') ON CONFLICT(key) DO UPDATE SET value = '30'").run();
  try {
    const d = await connect(u);
    db.prepare("UPDATE oauth_grants SET created_at = datetime('now', '-31 days') WHERE id = ?").run(d.grantId);
    assert.equal((await refresh(d)).body.error, 'invalid_grant', 'shortening the window must shorten live connections');
  } finally {
    db.prepare("DELETE FROM settings WHERE key = 'api_key_max_age_days'").run();
  }
});

test('F-001 a password change ends every connection the user approved', async () => {
  const u = mkUser();
  const c = await connect(u);
  const other = await connect(mkUser());
  const res = await fetch(`${BASE}/api/identity/set-password`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${u.session}` }, body: JSON.stringify({ password: 'a-brand-new-password-1' }) });
  assert.equal(res.status, 200, JSON.stringify(await json(res)));
  await assertDead(c, 'after password change');
  assert.equal((await rpc(other.tokens.access_token, 'tools/list')).status, 200, 'another user\'s connection must survive');
});

test('F-001 rotating the API key, or an admin regenerating it, ends every connection', async () => {
  const u = mkUser();
  const c = await connect(u);
  const res = await fetch(`${BASE}/api/me/api-key/rotate`, { method: 'POST', headers: { 'X-API-Key': u.apiKey } });
  assert.equal(res.status, 200, JSON.stringify(await json(res)));
  await assertDead(c, 'after key rotation');

  const pa = mkUser({ role: 'platform_admin', owner: false });
  const v = mkUser();
  const cv = await connect(v);
  const regen = await fetch(`${BASE}/api/users/${v.id}/regenerate-key?confirm=true`, { method: 'POST', headers: { 'X-API-Key': pa.apiKey } });
  assert.equal(regen.status, 200, JSON.stringify(await json(regen)));
  await assertDead(cv, 'after admin key regeneration');
});

test('F-001 demoting a platform admin ends their connections; deactivation refuses and revokes them', async () => {
  const pa = mkUser({ role: 'platform_admin', owner: false });
  const victim = mkUser({ role: 'platform_admin', owner: false });
  const c = await connect(victim);
  assert.equal((await rpc(c.tokens.access_token, 'tools/list')).status, 200);
  const dem = await fetch(`${BASE}/api/users/${victim.id}/role`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-API-Key': pa.apiKey }, body: JSON.stringify({ role: 'user' }) });
  assert.equal(dem.status, 200, JSON.stringify(await json(dem)));
  await assertDead(c, 'after demotion');

  const u = mkUser();
  const d = await connect(u);
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(u.id);
  assert.equal((await rpc(d.tokens.access_token, 'tools/list')).status, 403);
  db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(u.id);
  await assertDead(d, 'after deactivation and reactivation');
  assert.ok(db.prepare('SELECT revoked_at FROM oauth_grants WHERE id = ?').get(d.grantId).revoked_at, 'the grant was not revoked');
});

test('F-001 approving needs a fresh sign-in: a stale session needs the password, an API key is refused', async () => {
  const u = mkUser({ password: 'the-right-password-1' });
  const client = (await register()).body;

  const a = await startAuthorize(client.client_id, u);
  const view = await consentView(a.requestId, { Authorization: `Bearer ${u.session}` });
  assert.equal(view.body.reauth.required, false, 'baseline: a session made just now is fresh');
  db.prepare("UPDATE identity_sessions SET created_at = datetime('now', '-11 minutes') WHERE token_hash = ?").run(hashApiKey(u.session));
  const staleView = await consentView(a.requestId, { Authorization: `Bearer ${u.session}` });
  assert.deepEqual([staleView.body.reauth.required, staleView.body.reauth.reason, staleView.body.reauth.has_password], [true, 'stale_session', true]);
  const stale = await decide(a.requestId, { Authorization: `Bearer ${u.session}` }, { decision: 'approve' });
  console.log(`# stale session approve: ${stale.status} ${stale.body.error.code}`);
  assert.equal(stale.status, 403);
  assert.equal(stale.body.error.code, 'REAUTH_REQUIRED');
  const wrong = await decide(a.requestId, { Authorization: `Bearer ${u.session}` }, { decision: 'approve', password: 'not-it' });
  assert.equal(wrong.body.error.code, 'REAUTH_FAILED');
  const ok = await decide(a.requestId, { Authorization: `Bearer ${u.session}` }, { decision: 'approve', password: 'the-right-password-1' });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.ok(new URL(ok.body.redirect_to).searchParams.get('code'));

  const b = await startAuthorize(client.client_id, u);
  const byKey = await decide(b.requestId, { 'X-API-Key': u.apiKey }, { decision: 'approve', password: 'the-right-password-1' });
  console.log(`# api key approve: ${byKey.status} ${byKey.body.error.code}`);
  assert.equal(byKey.status, 403);
  assert.equal(byKey.body.error.code, 'REAUTH_REQUIRED');
  const denyByKey = await decide(b.requestId, { 'X-API-Key': u.apiKey }, { decision: 'deny' });
  assert.equal(denyByKey.status, 200, 'denying needs no fresh sign-in');
});

test('F-001 a platform admin lists and revokes any user\'s connections; a member cannot', async () => {
  const pa = mkUser({ role: 'platform_admin', owner: false });
  const u = mkUser();
  const c = await connect(u);
  const member = await fetch(`${BASE}/api/oauth/admin/grants`, { headers: { Authorization: `Bearer ${u.session}` } });
  assert.equal(member.status, 403);
  const list = await (await fetch(`${BASE}/api/oauth/admin/grants?user_id=${u.id}`, { headers: { Authorization: `Bearer ${pa.session}` } })).json();
  const g = list.grants.find((x) => x.id === c.grantId);
  assert.ok(g, 'the admin list shows the user\'s connection');
  assert.equal(g.user.id, u.id);
  assert.match(g.expires_at, /^\d{4}-\d{2}-\d{2} /);
  const del = await fetch(`${BASE}/api/oauth/admin/grants/${c.grantId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${pa.session}` } });
  assert.equal(del.status, 200);
  await assertDead(c, 'after admin revoke');

  const c2 = await connect(u);
  const all = await fetch(`${BASE}/api/oauth/admin/users/${u.id}/revoke-all`, { method: 'POST', headers: { Authorization: `Bearer ${pa.session}` } });
  assert.ok((await all.json()).revoked >= 1);
  await assertDead(c2, 'after admin revoke-all');
  const own = await (await fetch(`${BASE}/api/oauth/connections`, { headers: { Authorization: `Bearer ${u.session}` } })).json();
  assert.equal(own.connections.length, 0);
});

// ---------------------------------------------------------------- F-002

test('F-002 the consent screen states the real scope: every app + admin tools for a platform admin, owned apps for a member', async () => {
  const client = (await register()).body;
  const pa = mkUser({ role: 'platform_admin', owner: false });
  const member = mkUser();
  const paView = (await consentView((await startAuthorize(client.client_id, pa)).requestId, { Authorization: `Bearer ${pa.session}` })).body;
  const mView = (await consentView((await startAuthorize(client.client_id, member)).requestId, { Authorization: `Bearer ${member.session}` })).body;
  console.log(`# platform admin: ${JSON.stringify(paView.access.lines_full)}`);
  console.log(`# member: ${JSON.stringify(mView.access.lines_full)}`);
  assert.equal(paView.client_verified, false);
  assert.match(paView.access.lines_full[0], /EVERY app on this AppCrane \(2\)/);
  assert.ok(paView.access.lines_full.some((l) => /^Platform administration: \d+ admin tools/.test(l)));
  assert.ok(paView.access.lines_full.some((l) => /appcrane_reveal_secret/.test(l)));
  assert.equal(mView.access.lines_full[0], 'Only the apps you own: alpha.');
  assert.ok(!mView.access.lines_full.some((l) => /Platform administration|EVERY app/.test(l)), 'a member was told they get admin scope');
  assert.ok(mView.access.lines_read_only.some((l) => /secrets or file contents are refused/.test(l)));
  assert.ok(!mView.access.lines_read_only.some((l) => /appcrane_reveal_secret/.test(l)));
  assert.match(paView.access.lines_full.at(-1), /at most 90 days/);
});

test('F-002 registration policy: allowlist (default) refuses an unlisted redirect host; approval mode waits for an admin', async () => {
  db.prepare("DELETE FROM settings WHERE key LIKE 'oauth_dcr_%'").run();
  const evil = await register(['https://evil.test/cb']);
  console.log(`# allowlist register evil.test: ${evil.status} ${evil.body.error}`);
  assert.equal(evil.status, 400);
  assert.equal(evil.body.error, 'invalid_redirect_uri');
  for (const uri of ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback', 'http://localhost:3118/callback', 'http://127.0.0.1:9/callback']) {
    assert.equal((await register([uri])).status, 201, uri);
  }

  setMode('open');
  const late = (await register(['https://evil.test/cb'])).body;
  setMode('allowlist');
  const u = mkUser();
  const refused = await startAuthorize(late.client_id, u, 'https://evil.test/cb');
  assert.equal(refused.status, 403, 'a client registered while open must not authorize once the allowlist is on');

  setMode('approval');
  const pa = mkUser({ role: 'platform_admin', owner: false });
  const pending = (await register(['https://evil.test/cb'])).body;
  assert.equal((await startAuthorize(pending.client_id, u, 'https://evil.test/cb')).status, 403);
  const ap = await fetch(`${BASE}/api/oauth/admin/clients/${pending.client_id}/approval`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pa.session}` }, body: JSON.stringify({ approved: true }) });
  assert.equal(ap.status, 200);
  const after = await startAuthorize(pending.client_id, u, 'https://evil.test/cb');
  assert.equal(after.status, 302);
  assert.equal((await consentView(after.requestId, { Authorization: `Bearer ${u.session}` })).body.client_verified, true);

  const pol = await fetch(`${BASE}/api/oauth/admin/policy`, { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pa.session}` }, body: JSON.stringify({ mode: 'allowlist', redirect_hosts: ['claude.ai', 'tools.example.org'] }) });
  assert.deepEqual((await pol.json()).redirect_hosts, ['claude.ai', 'tools.example.org']);
  assert.equal((await register(['https://tools.example.org/cb'])).status, 201);
  assert.equal((await register(['https://claude.com/api/mcp/auth_callback'])).status, 400, 'a host taken off the list is refused');
  const bad = await fetch(`${BASE}/api/oauth/admin/policy`, { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pa.session}` }, body: JSON.stringify({ redirect_hosts: ['https://x/'] }) });
  assert.equal(bad.status, 400);
  db.prepare("DELETE FROM settings WHERE key LIKE 'oauth_dcr_%'").run();
});

test('F-002 a read-only connection is refused the plaintext-secret tools and is not shown them', async () => {
  const u = mkUser();
  const full = await connect(u);
  const ok = await rpc(full.tokens.access_token, 'tools/call', { name: 'appcrane_reveal_secret', arguments: { slug: 'alpha', key: 'API_TOKEN' } });
  assert.match(JSON.stringify(ok.body), /plaintext-sandbox-secret/, 'baseline: a full connection reveals for an owner');

  const ro = await connect(u, { readOnly: true });
  const names = (await rpc(ro.tokens.access_token, 'tools/list')).body.result.tools.map((t) => t.name);
  assert.ok(names.includes('appcrane_get_secret'), 'the masked listing stays available');
  assert.ok(!names.includes('appcrane_reveal_secret') && !names.includes('appcrane_cat'), 'read-only was shown a secret tool');
  for (const [name, args] of [['appcrane_reveal_secret', { slug: 'alpha', key: 'API_TOKEN' }], ['appcrane_cat', { slug: 'alpha', path: '/app/.env' }]]) {
    const r = await rpc(ro.tokens.access_token, 'tools/call', { name, arguments: args });
    const text = JSON.stringify(r.body);
    console.log(`# read-only ${name}: ${text.slice(0, 160)}`);
    assert.match(text, /plaintext secrets or raw file contents and this MCP key is read-only/);
    assert.doesNotMatch(text, /plaintext-sandbox-secret/);
  }
  const masked = await rpc(ro.tokens.access_token, 'tools/call', { name: 'appcrane_get_secret', arguments: { slug: 'alpha' } });
  assert.doesNotMatch(JSON.stringify(masked.body), /plaintext-sandbox-secret/);
  assert.match(JSON.stringify(masked.body), /API_TOKEN/);
});
