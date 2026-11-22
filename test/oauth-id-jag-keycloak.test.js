import { test, after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import { execFileSync, spawnSync } from 'child_process';
import express from 'express';

// ID-JAG verification against a REAL OIDC provider: Keycloak in Docker. AppCrane
// reads Keycloak's discovery document and JWKS exactly as it would a
// production IdP's, with Keycloak's own kids, its extra signing key and its
// encryption key in the set.
//
// Keycloak 26.2.5 cannot issue an ID-JAG: its RFC 8693 token exchange answers a
// request for urn:ietf:params:oauth:token-type:id-jag with
// {"error":"invalid_request","error_description":"requested_token_type unsupported"}
// (the last test asserts that). So the assertions here are signed with an RSA
// key this test generates and installs in the Keycloak realm as a key provider;
// Keycloak publishes it under the kid it computes, which is the kid used.
//
// Skipped, with the reason, when Docker or the pinned image is not present.

const IMAGE = 'quay.io/keycloak/keycloak:26.2.5@sha256:4883630ef9db14031cde3e60700c9a9a8eaf1b5c24db1589d6a2d43de38ba2a9';
const dockerOk = spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'ignore' }).status === 0;
const skip = dockerOk ? false : `needs Docker and ${IMAGE} (docker pull it first)`;

const ROOT = mkdtempSync(join(tmpdir(), 'crane-idjag-kc-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.example.test';
process.env.OAUTH_REGISTER_PER_HOUR = '1000';
const ISSUER = 'https://crane.example.test';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const oauth = await import('../server/routes/oauth.js');
const { setClientApproval } = await import('../server/services/oauthStore.js');
const { clearJwksCache } = await import('../server/services/idpJwks.js');

initDb();
const db = getDb();
const SUB = 'kc-linked-subject';
const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind,sso_sub) VALUES ('kc','kc@t.test','user',?,1,'human',?)")
  .run(hashApiKey(generateApiKey('dhk_user')), SUB).lastInsertRowid;

const NAME = `crane-kc-idjag-${crypto.randomBytes(4).toString('hex')}`;
const ADMIN_PW = crypto.randomBytes(12).toString('hex');
let KC = null;
let tok = null;
let realmId = null;
let disc = null;
const keyA = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

const httpApp = express();
httpApp.use(express.urlencoded({ extended: true }));
httpApp.use(express.json());
httpApp.use('/oauth', oauth.default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(() => {
  server.closeAllConnections?.(); server.unref(); server.close();
  if (dockerOk) spawnSync('docker', ['rm', '-f', NAME], { stdio: 'ignore' });
});

const form = (o) => new URLSearchParams(o);
const admin = (path, method = 'GET', body) => fetch(`${KC}/admin/realms/crane-test${path}`, {
  method, headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}),
});
async function installKey(name, kp, priority) {
  const r = await admin('/components', 'POST', {
    name, providerId: 'rsa', providerType: 'org.keycloak.keys.KeyProvider', parentId: realmId,
    config: { priority: [String(priority)], enabled: ['true'], active: ['true'], algorithm: ['RS256'], privateKey: [kp.privateKey.export({ type: 'pkcs1', format: 'pem' })] },
  });
  assert.equal(r.status, 201, await r.text());
  return r.headers.get('location').split('/').pop();
}
async function published() {
  return (await (await fetch(disc.jwks_uri)).json()).keys;
}
async function kidOf(kp) {
  const n = kp.publicKey.export({ format: 'jwk' }).n;
  return (await published()).find((k) => k.n === n)?.kid;
}

before(async () => {
  if (skip) return;
  execFileSync('docker', ['run', '-d', '--rm', '--name', NAME, '-p', '127.0.0.1::8080',
    '-e', 'KC_BOOTSTRAP_ADMIN_USERNAME=admin', '-e', `KC_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PW}`, IMAGE, 'start-dev'], { stdio: 'ignore' });
  KC = `http://${execFileSync('docker', ['port', NAME, '8080']).toString().trim().split('\n')[0]}`;
  const deadline = Date.now() + 180_000;
  for (;;) {
    try { if ((await fetch(`${KC}/realms/master`)).ok) break; } catch (_) { /* still starting */ }
    if (Date.now() > deadline) throw new Error('Keycloak did not start within 180 s');
    await new Promise((r) => setTimeout(r, 1000));
  }
  tok = (await (await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST', body: form({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: ADMIN_PW }),
  })).json()).access_token;
  const created = await fetch(`${KC}/admin/realms`, { method: 'POST', headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ realm: 'crane-test', enabled: true }) });
  assert.equal(created.status, 201);
  realmId = (await (await admin('')).json()).id;
  await installKey('crane-test-a', keyA, 200);
  disc = await (await fetch(`${KC}/realms/crane-test/.well-known/openid-configuration`)).json();
  for (const [k, v] of [['oidc_enabled', '1'], ['oidc_discovery_url', `${KC}/realms/crane-test`], ['oidc_client_id', 'appcrane'], ['oauth_id_jag_enabled', '1']]) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(k, v);
  }
});

let client = null;
async function agentClient() {
  if (client) return client;
  const r = await fetch(`${BASE}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'KC agent', redirect_uris: ['http://127.0.0.1:53682/cb'], token_endpoint_auth_method: 'client_secret_basic' }),
  });
  client = await r.json();
  setClientApproval(client.client_id, uid, true);
  db.prepare("UPDATE oauth_clients SET blueprint_id = (SELECT id FROM mcp_scope_blueprints WHERE name = 'read-only') WHERE client_id = ?").run(client.client_id);
  return client;
}

function sign(kid, kp, { header = {}, claims = {} } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const h = { alg: 'RS256', typ: 'oauth-id-jag+jwt', kid, ...header };
  const c = { iss: disc.issuer, sub: SUB, aud: ISSUER, client_id: client.client_id, jti: crypto.randomBytes(12).toString('base64url'), iat: now, exp: now + 300, ...claims };
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const input = `${enc(h)}.${enc(c)}`;
  const sig = h.alg.startsWith('PS')
    ? crypto.sign('sha256', Buffer.from(input), { key: kp.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 })
    : crypto.sign('sha256', Buffer.from(input), kp.privateKey);
  return `${input}.${sig.toString('base64url')}`;
}
async function redeem(assertion) {
  const c = await agentClient();
  const r = await fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${Buffer.from(`${c.client_id}:${c.client_secret}`).toString('base64')}` },
    body: form({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
  });
  return { status: r.status, body: await r.json() };
}

test('Keycloak discovery and JWKS: an assertion signed with the realm key Keycloak publishes is accepted under Keycloak\'s kid', { skip }, async () => {
  await agentClient();
  const kid = await kidOf(keyA);
  assert.ok(kid, 'Keycloak publishes the installed key');
  const keys = await published();
  assert.ok(keys.some((k) => k.use === 'enc'), 'the set also holds Keycloak\'s encryption key');
  const r = await redeem(sign(kid, keyA));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.scope, 'mcp:feedback mcp:read');
});

test('against Keycloak\'s set: unknown kid, its encryption key, an alg the key is not published for, and a forged signature are refused', { skip }, async () => {
  const keys = await published();
  const enc = keys.find((k) => k.use === 'enc');
  const kidA = await kidOf(keyA);
  const rogue = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  for (const [label, assertion, re] of [
    ['unknown kid', sign('not-a-keycloak-kid', keyA), /key the IdP does not publish/],
    ['enc key', sign(enc.kid, keyA), /published for encryption/],
    ['alg', sign(kidA, keyA, { header: { alg: 'PS256' } }), /published for a different alg/],
    ['forged', sign(kidA, rogue), /signature does not verify/],
  ]) {
    const r = await redeem(assertion);
    assert.equal(r.body.error, 'invalid_grant', label);
    assert.match(r.body.error_description, re, label);
  }
});

test('Keycloak key rotation: a new realm key is accepted through one forced JWKS refresh, a removed one is refused once the cache is refreshed', { skip }, async () => {
  clearJwksCache();
  const kidA = await kidOf(keyA);
  assert.equal((await redeem(sign(kidA, keyA))).status, 200);
  const keyB = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const compB = await installKey('crane-test-b', keyB, 300);
  const kidB = await kidOf(keyB);
  assert.ok(kidB && kidB !== kidA);
  const rb = await redeem(sign(kidB, keyB));
  assert.equal(rb.status, 200, `rotated-in key refused: ${JSON.stringify(rb.body)}`);

  const compA = (await (await admin('/components?type=org.keycloak.keys.KeyProvider')).json()).find((c) => c.name === 'crane-test-a').id;
  assert.equal((await admin(`/components/${compA}`, 'DELETE')).status, 204);
  assert.equal(await kidOf(keyA), undefined, 'Keycloak no longer publishes key A');
  clearJwksCache();
  const ra = await redeem(sign(kidA, keyA));
  assert.match(ra.body.error_description, /key the IdP does not publish/);
  assert.ok(compB);
});

test('a real Keycloak ID token is not an ID-JAG, and Keycloak cannot issue an ID-JAG itself', { skip }, async () => {
  const mk = await admin('/clients', 'POST', { clientId: 'kc-agent', secret: 'kc-agent-secret-test', publicClient: false, directAccessGrantsEnabled: true, attributes: { 'standard.token.exchange.enabled': 'true' } });
  assert.equal(mk.status, 201);
  assert.equal((await admin('/users', 'POST', { username: 'person', enabled: true, email: 'person@t.test', emailVerified: true, firstName: 'P', lastName: 'Q', credentials: [{ type: 'password', value: 'person-pass-test', temporary: false }] })).status, 201);
  const ut = await (await fetch(disc.token_endpoint, { method: 'POST', body: form({ grant_type: 'password', client_id: 'kc-agent', client_secret: 'kc-agent-secret-test', username: 'person', password: 'person-pass-test', scope: 'openid' }) })).json();
  assert.ok(ut.id_token);
  const r = await redeem(ut.id_token);
  assert.equal(r.body.error, 'invalid_grant');
  assert.match(r.body.error_description, /typ is not oauth-id-jag\+jwt/);

  const x = await fetch(disc.token_endpoint, {
    method: 'POST',
    body: form({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', client_id: 'kc-agent', client_secret: 'kc-agent-secret-test',
      subject_token: ut.access_token, subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag', audience: ISSUER,
    }),
  });
  assert.equal(x.status, 400);
  assert.deepEqual(await x.json(), { error: 'invalid_request', error_description: 'requested_token_type unsupported' });
});
