import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import express from 'express';

// Fine-grained MCP scopes and blueprints (services/mcpScopes.js,
// services/mcpBlueprints.js): driven over real HTTP through the real routers.
// A scoped credential (blueprint on a dhk_mcp_* key, fine-grained OAuth scopes,
// a blueprint picked at consent) is held to its scopes on tools/list AND
// tools/call; an unscoped one keeps the role-based behaviour unchanged.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-scopes-'));
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
const oauth = await import('../server/routes/oauth.js');
const { getToolCatalog } = await import('../server/services/mcpTools.js');
const { TOOL_SCOPES, SCOPE } = await import('../server/services/mcpScopes.js');

initDb();
const db = getDb();
for (const [slug, slot] of [['alpha', 931], ['beta', 932]]) {
  db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES (?,?,?,'managed','local','main')").run(slug, slug, slot);
}
const appId = (slug) => db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug).id;

function mkUser(role = 'user') {
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`s${randomBytes(3).toString('hex')}`, `s${randomBytes(3).toString('hex')}@t.test`, role, hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
  for (const slug of ['alpha', 'beta']) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId(slug), id);
  const session = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(id, hashApiKey(session));
  return { id, session };
}
const alice = mkUser();
const admin = mkUser('platform_admin');

const httpApp = express();
httpApp.use(express.json());
httpApp.use(express.urlencoded({ extended: true }));
httpApp.use('/.well-known', oauth.wellKnownRouter);
httpApp.use('/oauth', oauth.default);
httpApp.use('/api/oauth', (await import('../server/routes/oauthConsent.js')).default);
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.use('/api', (await import('../server/routes/userMcpKeys.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const REDIRECT = 'http://127.0.0.1:53682/callback';
const json = async (res) => { try { return await res.json(); } catch (_) { return null; } };

async function api(user, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${user.session}` },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await json(res) };
}

async function rpc(cred, method, params = {}) {
  const auth = cred.startsWith('dhk_mcp_') ? { 'X-API-Key': cred } : { Authorization: `Bearer ${cred}` };
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...auth },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: res.status, body: await json(res), headers: res.headers };
}
const toolNames = async (cred) => (await rpc(cred, 'tools/list')).body.result.tools.map((t) => t.name);
const call = (cred, name, args = {}) => rpc(cred, 'tools/call', { name, arguments: args });

async function key(body = {}) {
  const r = await api(alice, 'POST', '/api/me/mcp-keys', body);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body.api_key;
}
const bp = (name) => db.prepare('SELECT id FROM mcp_scope_blueprints WHERE name = ?').get(name).id;

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

async function oauthToken(scope, decision = { decision: 'approve' }) {
  const reg = await json(await fetch(`${BASE}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Scoped', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' }),
  }));
  const p = pkce();
  const q = new URLSearchParams({
    response_type: 'code', client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: p.challenge,
    code_challenge_method: 'S256', state: 's', resource: `${BASE}/api/mcp`, ...(scope ? { scope } : {}),
  });
  const a = await fetch(`${BASE}/oauth/authorize?${q}`, { redirect: 'manual', headers: { Cookie: `cc_token=${alice.session}` } });
  const id = new URL(a.headers.get('location'), BASE).searchParams.get('request');
  const view = await api(alice, 'GET', `/api/oauth/authorize-requests/${id}`);
  const ok = await api(alice, 'POST', `/api/oauth/authorize-requests/${id}`, decision);
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  const code = new URL(ok.body.redirect_to).searchParams.get('code');
  const t = await fetch(`${BASE}/oauth/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: p.verifier, client_id: reg.client_id, resource: `${BASE}/api/mcp` }),
  });
  const body = await json(t);
  assert.equal(t.status, 200, JSON.stringify(body));
  return { ...body, view: view.body };
}

test('every appcrane_* tool has exactly one scope group, and read tools never sit in a write group', () => {
  const catalog = getToolCatalog();
  const unmapped = catalog.map((t) => t.name).filter((n) => !TOOL_SCOPES[n]);
  assert.deepEqual(unmapped, [], `tools with no scope in services/mcpScopes.js: ${unmapped.join(', ')}`);
  const readGroups = new Set([SCOPE.READ, SCOPE.SECRETS]);
  for (const t of catalog) {
    const g = TOOL_SCOPES[t.name];
    if (t.readOnly) assert.ok(readGroups.has(g), `${t.name} is readOnly but mapped to ${g}`);
    else assert.ok(!readGroups.has(g), `${t.name} changes state but is mapped to read group ${g}`);
  }
  for (const n of ['appcrane_reveal_secret', 'appcrane_cat']) assert.equal(TOOL_SCOPES[n], SCOPE.SECRETS);
});

test('a read-only blueprint key: write tools are hidden from tools/list and refused 403 insufficient_scope on tools/call', async () => {
  const k = await key({ blueprint: 'read-only' });
  const names = await toolNames(k);
  assert.ok(names.includes('appcrane_list_apps'));
  assert.ok(names.includes('appcrane_submit_feedback'));
  for (const n of ['appcrane_deploy', 'appcrane_set_secret', 'appcrane_reveal_secret', 'appcrane_grant_app_access', 'appcrane_promote']) {
    assert.ok(!names.includes(n), `${n} listed for a read-only blueprint`);
  }
  const d = await call(k, 'appcrane_deploy', { slug: 'alpha', env: 'sandbox' });
  assert.equal(d.status, 403);
  assert.match(d.headers.get('www-authenticate'), /^Bearer error="insufficient_scope", scope="mcp:deploy:sandbox", resource_metadata="/);
  assert.match(d.body.error.message, /needs scope mcp:deploy:sandbox/);
  const ok = await call(k, 'appcrane_list_apps');
  assert.equal(ok.status, 200);
  assert.match(ok.body.result.content[0].text, /"alpha"/);
});

test('deploy-sandbox blueprint: sandbox passes the scope gate, production and promote are refused', async () => {
  const k = await key({ blueprint: 'deploy-sandbox' });
  const names = await toolNames(k);
  assert.ok(names.includes('appcrane_deploy'));
  assert.ok(!names.includes('appcrane_promote'));
  const prod = await call(k, 'appcrane_deploy', { slug: 'nope', env: 'production' });
  assert.equal(prod.status, 403);
  assert.match(prod.headers.get('www-authenticate'), /scope="mcp:deploy"/);
  const viaStage = await call(k, 'appcrane_rollback', { slug: 'nope', stage: 'production' });
  assert.equal(viaStage.status, 403, 'stage=production must count as production');
  const promote = await call(k, 'appcrane_promote', { slug: 'nope' });
  assert.equal(promote.status, 403);
  const sb = await call(k, 'appcrane_deploy', { slug: 'nope', env: 'sandbox' });
  assert.equal(sb.status, 200, 'sandbox is past the scope gate; the handler answers');
  assert.doesNotMatch(sb.body.error?.message || '', /scope mcp:/);
});

test('a scoped credential without mcp:github is refused the GitHub passthrough', async () => {
  const k = await key({ blueprint: 'app-admin' });
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': k, 'X-Github-Token': 'ghp_test' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'create_issue', arguments: {} } }),
  });
  assert.equal(res.status, 403);
  assert.match(res.headers.get('www-authenticate'), /scope="mcp:github"/);
});

test('an unscoped key and a legacy OAuth token keep today\'s role-based catalogue and calls', async () => {
  const legacy = await key();
  const names = await toolNames(legacy);
  for (const n of ['appcrane_deploy', 'appcrane_set_secret', 'appcrane_promote', 'appcrane_grant_app_access']) assert.ok(names.includes(n), n);
  const r = await call(legacy, 'appcrane_deploy', { slug: 'nope', env: 'production' });
  assert.equal(r.status, 200);
  assert.doesNotMatch(r.body.error?.message || '', /scope/);

  const t = await oauthToken('mcp');
  assert.equal(t.scope, 'mcp');
  assert.deepEqual(new Set(await toolNames(t.access_token)), new Set(names));
});

test('fine-grained OAuth scopes are granted as asked and enforced; token scope says so', async () => {
  const t = await oauthToken('mcp:read mcp:deploy:sandbox');
  assert.deepEqual(t.view.requested_scopes, ['mcp:deploy:sandbox', 'mcp:read']);
  assert.equal(t.scope, 'mcp:deploy:sandbox mcp:read');
  const names = await toolNames(t.access_token);
  assert.ok(names.includes('appcrane_deploy'));
  assert.ok(!names.includes('appcrane_set_secret'));
  const s = await call(t.access_token, 'appcrane_set_secret', { slug: 'alpha', env: 'sandbox', key: 'A', value: 'b' });
  assert.equal(s.status, 403);
  assert.match(s.headers.get('www-authenticate'), /scope="mcp:app:write"/);
});

test('a blueprint picked at consent narrows a full-scope request', async () => {
  const t = await oauthToken('mcp', { decision: 'approve', blueprint_id: bp('read-only') });
  assert.equal(t.scope, 'mcp:feedback mcp:read');
  const d = await call(t.access_token, 'appcrane_deploy', { slug: 'alpha' });
  assert.equal(d.status, 403);
});

test('blueprint app restriction, live narrowing, and deletion failing closed', async () => {
  const created = await api(admin, 'POST', '/api/oauth/admin/blueprints', { name: 'alpha-only', scopes: ['mcp:read', 'mcp:deploy:sandbox'], apps: ['alpha'] });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const k = await key({ blueprint: 'alpha-only' });
  const apps = await call(k, 'appcrane_list_apps');
  const listed = JSON.parse(apps.body.result.content[0].text).apps.map((a) => a.slug);
  assert.deepEqual(listed, ['alpha'], 'alice owns beta too; the blueprint limits the key to alpha');
  const beta = await call(k, 'appcrane_get_app', { slug: 'beta' });
  assert.match(beta.body.error.message, /outside this key's MCP scope/);

  assert.ok((await toolNames(k)).includes('appcrane_deploy'));
  const narrowed = await api(admin, 'PATCH', `/api/oauth/admin/blueprints/${created.body.blueprint.id}`, { scopes: ['mcp:read'] });
  assert.equal(narrowed.status, 200);
  assert.ok(!(await toolNames(k)).includes('appcrane_deploy'), 'narrowing a blueprint applies to keys already issued');

  const del = await api(admin, 'DELETE', `/api/oauth/admin/blueprints/${created.body.blueprint.id}`);
  assert.equal(del.status, 200);
  assert.deepEqual(await toolNames(k), [], 'a key whose blueprint was deleted can call nothing, it does not fall back to unscoped');
  assert.equal((await call(k, 'appcrane_list_apps')).status, 403);
});

test('only a platform admin manages blueprints, and only known scopes are accepted', async () => {
  assert.equal((await api(alice, 'POST', '/api/oauth/admin/blueprints', { name: 'x', scopes: ['mcp:read'] })).status, 403);
  const badScope = await api(admin, 'POST', '/api/oauth/admin/blueprints', { name: 'x', scopes: ['mcp:everything'] });
  assert.equal(badScope.status, 400);
  assert.equal((await api(admin, 'DELETE', `/api/oauth/admin/blueprints/${bp('read-only')}`)).status, 400, 'built-ins are not deletable');
  assert.equal((await api(alice, 'POST', '/api/me/mcp-keys', { blueprint: 'no-such' })).status, 400);
  const listed = await api(alice, 'GET', '/api/oauth/blueprints');
  assert.deepEqual(listed.body.blueprints.map((b) => b.name).sort(), ['app-admin', 'deploy-sandbox', 'read-only']);
});

test('the admin API serves the scope groups the UI draws, with plain names and every tool placed', async () => {
  const r = await api(admin, 'GET', '/api/oauth/admin/blueprints');
  assert.equal(r.status, 200);
  const groups = r.body.scope_groups;
  assert.ok(groups.every((g) => g.label && g.description && g.scope.startsWith('mcp:')));
  const byScope = Object.fromEntries(groups.map((g) => [g.scope, g.tools]));
  assert.ok(byScope['mcp:deploy'].includes('appcrane_deploy'), 'deploy any env opens the env-dependent deploy tools too');
  assert.ok(byScope['mcp:deploy'].includes('appcrane_promote'));
  assert.ok(!byScope['mcp:deploy:sandbox'].includes('appcrane_promote'));
  const placed = new Set(groups.flatMap((g) => g.tools));
  assert.deepEqual(Object.keys(TOOL_SCOPES).filter((t) => !placed.has(t)), []);
});

test('pinning a blueprint to a client: platform admin only, existing blueprint only', async () => {
  const reg = await json(await fetch(`${BASE}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Pin me', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' }),
  }));
  const path = `/api/oauth/admin/clients/${encodeURIComponent(reg.client_id)}/blueprint`;
  assert.equal((await api(alice, 'PUT', path, { blueprint_id: bp('read-only') })).status, 403);
  assert.equal((await api(admin, 'PUT', path, { blueprint_id: 99999 })).status, 400);
  assert.equal((await api(admin, 'PUT', path, { blueprint_id: bp('read-only') })).status, 200);
  assert.equal(db.prepare('SELECT blueprint_id FROM oauth_clients WHERE client_id = ?').get(reg.client_id).blueprint_id, bp('read-only'));
  assert.equal((await api(admin, 'PUT', path, { blueprint_id: null })).status, 200);
  assert.equal(db.prepare('SELECT blueprint_id FROM oauth_clients WHERE client_id = ?').get(reg.client_id).blueprint_id, null);
});

test('the policy reports the ID-JAG prerequisites and refuses to turn ID-JAG on without CRANE_DOMAIN', async () => {
  const p = await api(admin, 'GET', '/api/oauth/admin/policy');
  assert.equal(p.body.crane_domain_set, false);
  assert.equal(p.body.oidc_configured, false);
  assert.equal(p.body.cimd_enabled, true);
  const refused = await api(admin, 'PUT', '/api/oauth/admin/policy', { id_jag_enabled: true });
  assert.equal(refused.status, 400);
  assert.equal(refused.body.error.code, 'CRANE_DOMAIN_REQUIRED');
  assert.equal((await api(admin, 'GET', '/api/oauth/admin/policy')).body.id_jag_enabled, false);
  const off = await api(admin, 'PUT', '/api/oauth/admin/policy', { cimd_enabled: false });
  assert.equal(off.body.cimd_enabled, false);
  assert.equal((await api(admin, 'PUT', '/api/oauth/admin/policy', { cimd_enabled: true })).body.cimd_enabled, true);
});
