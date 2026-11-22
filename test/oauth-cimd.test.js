import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import https from 'https';
import express from 'express';

// OAuth Client ID Metadata Documents (services/oauthCimd.js) over real HTTP:
// a client_id that is an https URL is fetched from a real TLS server (a test CA,
// a test name resolved to 127.0.0.1) through the SSRF-guarded fetcher. The
// relaxation the happy path needs is exactly "127.0.0.1 is allowed"; every
// refusal test runs with the production address check.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cimd-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const oauth = await import('../server/routes/oauth.js');
const { configureCimdFetch } = await import('../server/services/oauthCimd.js');
const { isBlockedAddress } = await import('../server/services/remoteFetch.js');
const { generateCa, issueCert } = await import('../server/services/dbPki.js');

initDb();
const db = getDb();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('alpha','alpha',941,'managed','local','main')").run();
const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('cimd','cimd@t.test','user',?,1,'human')")
  .run(hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) SELECT id, ?, 'owner' FROM apps WHERE slug='alpha'").run(uid);
const SESSION = generateApiKey('sess');
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(uid, hashApiKey(SESSION));

const HOST = 'client.example.test';
const ca = generateCa({ commonName: 'CIMD Test CA' });
const leaf = issueCert({ ca, commonName: HOST, usage: 'server', dnsNames: [HOST] });
const docs = new Map();
const hits = new Map();
const tls = https.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
  hits.set(req.url, (hits.get(req.url) || 0) + 1);
  const d = docs.get(req.url);
  if (!d) { res.writeHead(404); return res.end(); }
  res.writeHead(d.status || 200, { 'Content-Type': 'application/json', ...(d.headers || {}) });
  res.end(typeof d.body === 'string' ? d.body : JSON.stringify(d.body));
});
await new Promise((r) => tls.listen(0, '127.0.0.1', r));
const ORIGIN = `https://${HOST}:${tls.address().port}`;
const resolveTestName = async (name) => (name === HOST ? [{ address: '127.0.0.1', family: 4 }] : []);
const allowLoopback = (ip) => (ip === '127.0.0.1' ? false : isBlockedAddress(ip));

const httpApp = express();
httpApp.use(express.json());
httpApp.use(express.urlencoded({ extended: true }));
httpApp.use('/.well-known', oauth.wellKnownRouter);
httpApp.use('/oauth', oauth.default);
httpApp.use('/api/oauth', (await import('../server/routes/oauthConsent.js')).default);
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => {
  for (const s of [server, tls]) { s.closeAllConnections?.(); s.unref(); s.close(); }
});
beforeEach(() => configureCimdFetch({ resolve: resolveTestName, ca: ca.certPem, isBlocked: allowLoopback }));

const REDIRECT = 'http://127.0.0.1:53682/callback';
const json = async (res) => { try { return await res.json(); } catch (_) { return null; } };
function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}
function publish(path, over = {}) {
  const clientId = `${ORIGIN}${path}`;
  docs.set(path, {
    body: { client_id: clientId, client_name: 'Doc Client', client_uri: ORIGIN, logo_uri: `${ORIGIN}/logo.png`, redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none', ...over.body },
    headers: over.headers, status: over.status,
  });
  return clientId;
}
function authorize(clientId, challenge, redirectUri = REDIRECT) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge,
    code_challenge_method: 'S256', scope: 'mcp', state: 'st', resource: `${BASE}/api/mcp`,
  });
  return fetch(`${BASE}/oauth/authorize?${q}`, { redirect: 'manual', headers: { Cookie: `cc_token=${SESSION}` } });
}

test('authorization server metadata advertises client ID metadata documents; PRM and the 401 challenge are in place', async () => {
  const as = await json(await fetch(`${BASE}/.well-known/oauth-authorization-server`));
  assert.equal(as.client_id_metadata_document_supported, true);
  const prm = await json(await fetch(`${BASE}/.well-known/oauth-protected-resource/api/mcp`));
  assert.equal(prm.resource, `${BASE}/api/mcp`);
  assert.deepEqual(prm.authorization_servers, [BASE]);
  const r = await fetch(`${BASE}/api/mcp`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(r.status, 401);
  assert.match(r.headers.get('www-authenticate'), new RegExp(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/api/mcp"`));
});

test('happy path: a URL client_id is fetched, shown with its host on consent, and completes the code flow', async () => {
  const clientId = publish('/happy.json');
  const p = pkce();
  const a = await authorize(clientId, p.challenge);
  assert.equal(a.status, 302, await a.clone().text());
  const id = new URL(a.headers.get('location'), BASE).searchParams.get('request');
  assert.ok(id);
  const view = await json(await fetch(`${BASE}/api/oauth/authorize-requests/${id}`, { headers: { Authorization: `Bearer ${SESSION}` } }));
  assert.equal(view.client_name, 'Doc Client');
  assert.deepEqual(view.client_id_document, { url: clientId, host: `${HOST}:${tls.address().port}`, client_uri: ORIGIN, logo_uri: `${ORIGIN}/logo.png` });
  const ok = await json(await fetch(`${BASE}/api/oauth/authorize-requests/${id}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${SESSION}` }, body: JSON.stringify({ decision: 'approve' }),
  }));
  const code = new URL(ok.redirect_to).searchParams.get('code');
  const t = await fetch(`${BASE}/oauth/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: p.verifier, client_id: clientId, resource: `${BASE}/api/mcp` }),
  });
  const body = await json(t);
  assert.equal(t.status, 200, JSON.stringify(body));
  const list = await json(await fetch(`${BASE}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${body.access_token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }));
  assert.ok(list.result.tools.some((x) => x.name === 'appcrane_list_apps'));
});

test('a logo on another host is not shown', async () => {
  const clientId = publish('/otherlogo.json', { body: { logo_uri: 'https://elsewhere.example.test/logo.png' } });
  const a = await authorize(clientId, pkce().challenge);
  const id = new URL(a.headers.get('location'), BASE).searchParams.get('request');
  const view = await json(await fetch(`${BASE}/api/oauth/authorize-requests/${id}`, { headers: { Authorization: `Bearer ${SESSION}` } }));
  assert.equal(view.client_id_document.logo_uri, null);
});

test('a redirect_uri the document does not list is refused with an error page and no redirect', async () => {
  const clientId = publish('/mismatch.json');
  const a = await authorize(clientId, pkce().challenge, 'http://127.0.0.1:9999/evil');
  assert.equal(a.status, 400);
  assert.equal(a.headers.get('location'), null);
  assert.match(await a.text(), /does not exactly match/);
});

test('documents whose client_id differs, that carry a secret, or that ask for a secret auth method are refused', async () => {
  for (const [path, body, re] of [
    ['/wrongid.json', { client_id: `${ORIGIN}/other.json` }, /not exactly the URL/],
    ['/secret.json', { client_secret: 'x' }, /must not contain a client_secret/],
    ['/basic.json', { token_endpoint_auth_method: 'client_secret_basic' }, /not supported/],
  ]) {
    const a = await authorize(publish(path, { body }), pkce().challenge);
    assert.equal(a.status, 400, path);
    assert.match(await a.text(), re, path);
  }
});

test('a host that resolves to a private address is refused by the production address check, with no connection made', async () => {
  configureCimdFetch({ resolve: resolveTestName, ca: ca.certPem });
  const clientId = publish('/private.json');
  const a = await authorize(clientId, pkce().challenge);
  assert.equal(a.status, 400);
  assert.match(await a.text(), /private, loopback or link-local/);
  assert.equal(hits.get('/private.json') || 0, 0);
  for (const literal of ['https://127.0.0.1/c.json', 'https://169.254.169.254/latest.json', 'https://[::1]/c.json', 'https://10.0.0.5/c.json']) {
    const r = await authorize(literal, pkce().challenge);
    assert.equal(r.status, 400, literal);
    assert.match(await r.text(), /private, loopback or link-local/, literal);
  }
});

test('a redirecting document is refused and the redirect is not followed', async () => {
  const target = publish('/target.json');
  docs.set('/redirect.json', { status: 302, headers: { Location: target }, body: '' });
  const a = await authorize(`${ORIGIN}/redirect.json`, pkce().challenge);
  assert.equal(a.status, 400);
  assert.match(await a.text(), /redirected/);
  assert.equal(hits.get('/target.json') || 0, 0);
});

test('an oversized document is refused', async () => {
  const clientId = publish('/big.json', { body: { padding: 'x'.repeat(6000) } });
  const a = await authorize(clientId, pkce().challenge);
  assert.equal(a.status, 400);
  assert.match(await a.text(), /larger than 5120 bytes/);
});

test('client_id URLs that are not https, have no path, or carry credentials or a fragment are refused before any fetch', async () => {
  for (const bad of [`https://${HOST}`, `https://${HOST}/`, `https://u:p@${HOST}/c.json`, `https://${HOST}/a/../c.json`]) {
    const a = await authorize(bad, pkce().challenge);
    assert.equal(a.status, 400, bad);
  }
});

test('the cache is honoured: within max-age no refetch; no-store refetches every time; refusals are not cached', async () => {
  const cached = publish('/cached.json', { headers: { 'Cache-Control': 'max-age=600' } });
  await authorize(cached, pkce().challenge);
  await authorize(cached, pkce().challenge);
  assert.equal(hits.get('/cached.json'), 1);

  const fresh = publish('/nostore.json', { headers: { 'Cache-Control': 'no-store' } });
  await authorize(fresh, pkce().challenge);
  await authorize(fresh, pkce().challenge);
  assert.equal(hits.get('/nostore.json'), 2);

  docs.set('/flaky.json', { status: 500, body: '' });
  assert.equal((await authorize(`${ORIGIN}/flaky.json`, pkce().challenge)).status, 400);
  publish('/flaky.json');
  assert.equal((await authorize(`${ORIGIN}/flaky.json`, pkce().challenge)).status, 302, 'the 500 was not cached');
  assert.equal(hits.get('/flaky.json'), 2);
});

test('a platform admin can turn metadata-document clients off', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('oauth_cimd_enabled', '0')").run();
  try {
    const a = await authorize(publish('/off.json'), pkce().challenge);
    assert.equal(a.status, 400);
    assert.equal(hits.get('/off.json') || 0, 0);
    const as = await json(await fetch(`${BASE}/.well-known/oauth-authorization-server`));
    assert.equal(as.client_id_metadata_document_supported, false);
  } finally {
    db.prepare("DELETE FROM settings WHERE key = 'oauth_cimd_enabled'").run();
  }
});

test('dynamic registration still works alongside metadata documents', async () => {
  const r = await fetch(`${BASE}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'DCR', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' }),
  });
  assert.equal(r.status, 201);
  assert.match((await json(r)).client_id, /^mcpc_/);
});
