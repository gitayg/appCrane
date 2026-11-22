import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import http from 'http';
import express from 'express';

// ID-JAG (services/oauthIdJag.js): a test IdP publishes OIDC discovery and a
// JWKS over real HTTP; assertions are signed with its keys and redeemed at the
// real /oauth/token with the jwt-bearer grant. The resulting access token is
// then used on POST /api/mcp, where the client's pinned blueprint applies.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-idjag-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.example.test';
const ISSUER = 'https://crane.example.test';
process.env.OAUTH_REGISTER_PER_HOUR = '1000';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const oauth = await import('../server/routes/oauth.js');
const { setClientApproval } = await import('../server/services/oauthStore.js');
const { clearJwksCache } = await import('../server/services/idpJwks.js');

initDb();
const db = getDb();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('alpha','alpha',951,'managed','local','main')").run();
const SUB = 'idp-subject-1';
const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind,sso_sub) VALUES ('jag','jag@t.test','user',?,1,'human',?)")
  .run(hashApiKey(generateApiKey('dhk_user')), SUB).lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) SELECT id, ?, 'owner' FROM apps WHERE slug='alpha'").run(uid);

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const rogue = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = (k, kid, alg) => ({ ...k.publicKey.export({ format: 'jwk' }), kid, alg, use: 'sig' });
const published = [jwk(rsa, 'rsa-1', 'RS256'), jwk(ec, 'ec-1', 'ES256'), { ...jwk(rogue, 'enc-1', 'RSA-OAEP'), use: 'enc' }];
let jwksHits = 0;
const idp = http.createServer((req, res) => {
  const issuer = `http://127.0.0.1:${idp.address().port}`;
  res.setHeader('Content-Type', 'application/json');
  if (req.url === '/.well-known/openid-configuration') return res.end(JSON.stringify({ issuer, jwks_uri: `${issuer}/jwks` }));
  if (req.url === '/jwks') { jwksHits += 1; return res.end(JSON.stringify({ keys: published })); }
  res.statusCode = 404; res.end('{}');
});
await new Promise((r) => idp.listen(0, '127.0.0.1', r));
const IDP = `http://127.0.0.1:${idp.address().port}`;
for (const [k, v] of [['oidc_enabled', '1'], ['oidc_discovery_url', IDP], ['oidc_client_id', 'appcrane-at-idp'], ['oauth_id_jag_enabled', '1']]) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(k, v);
}

const httpApp = express();
httpApp.use(express.json());
httpApp.use(express.urlencoded({ extended: true }));
httpApp.use('/.well-known', oauth.wellKnownRouter);
httpApp.use('/oauth', oauth.default);
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { for (const s of [server, idp]) { s.closeAllConnections?.(); s.unref(); s.close(); } });

const json = async (res) => { try { return await res.json(); } catch (_) { return null; } };

async function register(method = 'client_secret_basic') {
  const r = await json(await fetch(`${BASE}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Agent', redirect_uris: ['http://127.0.0.1:53682/cb'], token_endpoint_auth_method: method }),
  }));
  return r;
}
const READ_ONLY = db.prepare("SELECT id FROM mcp_scope_blueprints WHERE name = 'read-only'").get().id;
function trust(client, { approve = true, blueprint = READ_ONLY } = {}) {
  if (approve) setClientApproval(client.client_id, uid, true);
  db.prepare('UPDATE oauth_clients SET blueprint_id = ? WHERE client_id = ?').run(blueprint, client.client_id);
  return client;
}
const confidential = trust(await register());

function sign({ header = {}, claims = {}, key = rsa.privateKey, alg = 'RS256' } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const h = { alg, typ: 'oauth-id-jag+jwt', kid: alg.startsWith('ES') ? 'ec-1' : 'rsa-1', ...header };
  const c = {
    iss: IDP, sub: SUB, aud: ISSUER, client_id: confidential.client_id, jti: crypto.randomBytes(12).toString('base64url'),
    iat: now, exp: now + 300, resource: `${ISSUER}/api/mcp`, ...claims,
  };
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const input = `${enc(h)}.${enc(c)}`;
  const sig = alg.startsWith('ES')
    ? crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' })
    : crypto.sign('sha256', Buffer.from(input), key);
  return `${input}.${sig.toString('base64url')}`;
}

async function redeem(assertion, client = confidential, extra = {}) {
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  const body = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion, ...extra };
  if (client.client_secret) headers.Authorization = `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}`;
  else body.client_id = client.client_id;
  const r = await fetch(`${BASE}/oauth/token`, { method: 'POST', headers, body: new URLSearchParams(body) });
  return { status: r.status, body: await json(r) };
}

async function rpc(accessToken, method, params = {}) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: res.status, body: await json(res) };
}

test('metadata advertises the jwt-bearer grant and the ID-JAG profile when turned on', async () => {
  const as = await json(await fetch(`${BASE}/.well-known/oauth-authorization-server`));
  assert.ok(as.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:jwt-bearer'));
  assert.deepEqual(as.authorization_grant_profiles_supported, ['urn:ietf:params:oauth:grant-profile:id-jag']);
});

test('a valid assertion is exchanged for an access token (no refresh token) held to the client\'s blueprint', async () => {
  const r = await redeem(sign());
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.match(r.body.access_token, /^dhk_oat_/);
  assert.equal(r.body.refresh_token, undefined);
  assert.equal(r.body.scope, 'mcp:feedback mcp:read');
  const list = await rpc(r.body.access_token, 'tools/list');
  const names = list.body.result.tools.map((t) => t.name);
  assert.ok(names.includes('appcrane_list_apps'));
  assert.ok(!names.includes('appcrane_deploy'));
  const d = await rpc(r.body.access_token, 'tools/call', { name: 'appcrane_deploy', arguments: { slug: 'alpha' } });
  assert.equal(d.status, 403);
  const grant = db.prepare("SELECT via, user_id FROM oauth_grants WHERE via = 'id-jag' ORDER BY id DESC").get();
  assert.deepEqual({ ...grant }, { via: 'id-jag', user_id: uid });
});

test('an ES256 assertion verifies too', async () => {
  const r = await redeem(sign({ alg: 'ES256', key: ec.privateKey }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
});

test('the same assertion cannot be redeemed twice', async () => {
  const a = sign();
  assert.equal((await redeem(a)).status, 200);
  const again = await redeem(a);
  assert.equal(again.status, 400);
  assert.match(again.body.error_description, /already used/);
});

test('wrong audience, expired, unknown key, forged signature, wrong typ, wrong client, wrong issuer, too long-lived: all refused', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const [label, assertion, re] of [
    ['audience', sign({ claims: { aud: 'https://other.example.test' } }), /aud is not this AppCrane/],
    ['two audiences', sign({ claims: { aud: [ISSUER, 'https://other.example.test'] } }), /aud is not this AppCrane/],
    ['expired', sign({ claims: { iat: now - 400, exp: now - 100 } }), /expired/],
    ['unknown key', sign({ header: { kid: 'nope' } }), /key the IdP does not publish/],
    ['forged', sign({ key: rogue.privateKey }), /signature does not verify/],
    ['id token typ', sign({ header: { typ: 'JWT' } }), /typ is not oauth-id-jag\+jwt/],
    ['client', sign({ claims: { client_id: 'mcpc_someoneelse' } }), /client_id is not the client/],
    ['issuer', sign({ claims: { iss: 'https://idp.example.test' } }), /iss is not the IdP/],
    ['lifetime', sign({ claims: { iat: now, exp: now + 3600 } }), /longer than 600 seconds/],
    ['alg none', `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'oauth-id-jag+jwt', kid: 'rsa-1' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: IDP })).toString('base64url')}.`, /alg "none" is not accepted/],
    ['unlinked subject', sign({ claims: { sub: 'someone-new' } }), /no AppCrane account is linked/],
  ]) {
    const r = await redeem(assertion);
    assert.equal(r.status, 400, `${label}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error, 'invalid_grant', label);
    assert.match(r.body.error_description, re, label);
  }
});

test('a resource the assertion does not name, or that AppCrane does not protect, is refused', async () => {
  const mismatch = await redeem(sign(), confidential, { resource: `${ISSUER}/api/mcp/apps/alpha` });
  assert.equal(mismatch.body.error, 'invalid_target');
  const unknown = await redeem(sign({ claims: { resource: 'https://elsewhere.example.test/mcp' } }));
  assert.equal(unknown.body.error, 'invalid_target');
});

test('only a confidential, approved client with a pinned blueprint may present one; and only when turned on', async () => {
  const pub = trust(await register('none'));
  const p = await redeem(sign({ claims: { client_id: pub.client_id } }), pub);
  assert.equal(p.body.error, 'unauthorized_client');
  const unapproved = trust(await register(), { approve: false });
  assert.equal((await redeem(sign({ claims: { client_id: unapproved.client_id } }), unapproved)).body.error, 'unauthorized_client');
  const noBlueprint = trust(await register(), { blueprint: null });
  assert.equal((await redeem(sign({ claims: { client_id: noBlueprint.client_id } }), noBlueprint)).body.error, 'unauthorized_client');

  delete process.env.CRANE_DOMAIN;
  try {
    const r = await redeem(sign({ claims: { aud: BASE } }));
    assert.equal(r.body.error, 'unsupported_grant_type');
    assert.match(r.body.error_description, /CRANE_DOMAIN/);
  } finally {
    process.env.CRANE_DOMAIN = 'crane.example.test';
  }
  db.prepare("UPDATE settings SET value = '0' WHERE key = 'oauth_id_jag_enabled'").run();
  try {
    assert.equal((await redeem(sign())).body.error, 'unsupported_grant_type');
  } finally {
    db.prepare("UPDATE settings SET value = '1' WHERE key = 'oauth_id_jag_enabled'").run();
  }
});

test('a key rotated in at the IdP is picked up by one forced JWKS refresh; unknown kids cannot force another within a minute', async () => {
  clearJwksCache();
  assert.equal((await redeem(sign())).status, 200);
  const rotated = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  published.push(jwk(rotated, 'rsa-2', 'RS256'));
  const before = jwksHits;
  const r = await redeem(sign({ header: { kid: 'rsa-2' }, key: rotated.privateKey }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(jwksHits, before + 1, 'exactly one forced refresh');
  const made = await redeem(sign({ header: { kid: 'made-up' } }));
  assert.match(made.body.error_description, /key the IdP does not publish/);
  assert.equal(jwksHits, before + 1, 'a second unknown kid inside the window does not refetch');
});

test('a key the IdP publishes for encryption is never used to verify', async () => {
  const r = await redeem(sign({ header: { kid: 'enc-1' }, key: rogue.privateKey }));
  assert.match(r.body.error_description, /published for encryption/);
});
