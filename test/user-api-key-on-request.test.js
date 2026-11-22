import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { generateKeyPairSync, createSign, randomBytes } from 'crypto';
import { inflateRawSync } from 'zlib';
import express from 'express';
import Database from 'better-sqlite3';

// Personal API keys exist only on request (migration 169): every way an
// account is created leaves users.api_key_hash NULL, except an agent identity,
// whose creator is shown its key. Driven over real HTTP: OIDC against a local
// fake IdP (real discovery, token exchange and RS256 id_token), SAML through
// the real /start and /callback with only the XML signature check stubbed,
// SCIM and admin create through their routes.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-keyreq-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const MIGRATIONS = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const { SAML } = await import('@node-saml/node-saml');

initDb();
const db = getDb();
const setSetting = (k, v) => db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);

const ADMIN_KEY = generateApiKey('dhk_admin');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('admin','admin@t.test','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY));

const SCIM_TOKEN = generateApiKey('scim');
setSetting('scim_token_hash', hashApiKey(SCIM_TOKEN));
setSetting('scim_enabled', '1');

// ── fake OIDC IdP ──────────────────────────────────────────────────────────
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const JWK = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
let pendingNonce = null;
let nextClaims = null;
const idp = express();
idp.use(express.urlencoded({ extended: false }));
let IDP = '';
idp.get('/.well-known/openid-configuration', (req, res) => res.json({
  issuer: IDP, authorization_endpoint: `${IDP}/auth`, token_endpoint: `${IDP}/token`, jwks_uri: `${IDP}/jwks`,
}));
idp.get('/jwks', (req, res) => res.json({ keys: [JWK] }));
idp.post('/token', (req, res) => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = b64({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const body = b64({ iss: IDP, aud: 'crane-test', exp: Math.floor(Date.now() / 1000) + 300, nonce: pendingNonce, ...nextClaims });
  const sig = createSign('SHA256').update(`${head}.${body}`).sign(privateKey).toString('base64url');
  res.json({ id_token: `${head}.${body}.${sig}`, token_type: 'Bearer' });
});
const idpServer = await new Promise((r) => { const s = idp.listen(0, '127.0.0.1', () => r(s)); });
IDP = `http://127.0.0.1:${idpServer.address().port}`;

setSetting('oidc_enabled', '1');
setSetting('oidc_discovery_url', IDP);
setSetting('oidc_client_id', 'crane-test');
setSetting('oidc_client_secret_enc', encrypt('s3cret'));
setSetting('oidc_auto_provision', '1');

setSetting('saml_enabled', '1');
setSetting('saml_idp_sso_url', 'http://127.0.0.1:9/sso');
setSetting('saml_idp_cert_enc', encrypt('MIIBfakecertfortests'));
setSetting('saml_auto_provision', '1');

// ── AppCrane under test ────────────────────────────────────────────────────
const app = express();
app.use(express.json({ type: ['application/json', 'application/scim+json'] }));
app.use(express.urlencoded({ extended: false }));
app.use('/api/auth/oidc', (await import('../server/routes/oidc.js')).default);
app.use('/api/auth/saml', (await import('../server/routes/saml.js')).default);
app.use('/api/scim/v2', (await import('../server/routes/scim.js')).default);
app.use('/api/users', (await import('../server/routes/users.js')).default);
app.get('/api/whoami', requireAuth, (req, res) => res.json({ id: req.user.id }));
app.use(errorHandler);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => {
  for (const s of [server, idpServer]) { s.closeAllConnections?.(); s.unref(); s.close(); }
});

const cookiesOf = (res) => (res.headers.getSetCookie?.() || []).map((c) => c.split(';')[0]).join('; ');
const userRow = (where, v) => db.prepare(`SELECT * FROM users WHERE ${where} = ?`).get(v);
const KEY_COLS = (u) => ({ api_key_hash: u.api_key_hash, api_key_issued_at: u.api_key_issued_at, api_key_expires_at: u.api_key_expires_at });
const NO_KEY = { api_key_hash: null, api_key_issued_at: null, api_key_expires_at: null };

test('migration 169: api_key_hash accepts NULL, and the rebuild keeps every column, row, index, trigger and the id high-water mark', () => {
  const files = readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql')).sort();
  const old = new Database(':memory:');
  for (const f of files.filter((x) => x < '169')) old.exec(readFileSync(join(MIGRATIONS, f), 'utf8'));
  const cols = (d) => d.prepare('PRAGMA table_info(users)').all().map((c) => `${c.name}|${c.type}|${c.dflt_value}|${c.pk}`).sort();
  const objects = (d) => d.prepare("SELECT type || ':' || name AS o FROM sqlite_master WHERE tbl_name = 'users' ORDER BY o").all().map((r) => r.o);
  const beforeCols = cols(old);
  const beforeObjects = objects(old);
  assert.equal(old.prepare("SELECT \"notnull\" FROM pragma_table_info('users') WHERE name = 'api_key_hash'").get().notnull, 1, 'pre-169 the column is NOT NULL');

  old.prepare("INSERT INTO users (name,email,role,api_key_hash,department,location) VALUES ('a','a@t.test','platform_admin','h1','eng','tlv')").run();
  old.prepare("INSERT INTO users (name,email,role,api_key_hash) VALUES ('b','b@t.test','user','h2')").run();
  old.prepare("INSERT INTO users (name,email,role,api_key_hash) VALUES ('c','c@t.test','user','h3')").run();
  old.prepare("DELETE FROM users WHERE email = 'c@t.test'").run();
  old.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (2, 't1', datetime('now','+1 day'))").run();
  const beforeRows = old.prepare('SELECT * FROM users ORDER BY id').all();

  old.exec(readFileSync(join(MIGRATIONS, files.find((f) => f.startsWith('169-'))), 'utf8'));

  assert.equal(old.prepare("SELECT \"notnull\" FROM pragma_table_info('users') WHERE name = 'api_key_hash'").get().notnull, 0);
  assert.deepEqual(cols(old), beforeCols, 'same columns, types and defaults');
  assert.deepEqual(objects(old), beforeObjects, 'same indexes and triggers');
  assert.deepEqual(old.prepare('SELECT * FROM users ORDER BY id').all(), beforeRows, 'every row copied unchanged');
  assert.equal(old.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'users'").get().seq, 3, 'a deleted top id is not handed out again');
  assert.deepEqual(old.pragma('foreign_key_check'), []);
  assert.equal(old.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = 2').get().n, 1);

  const id = old.prepare("INSERT INTO users (name,email) VALUES ('d','d@t.test')").run().lastInsertRowid;
  assert.equal(id, 4);
  assert.deepEqual(KEY_COLS(old.prepare('SELECT * FROM users WHERE id = 4').get()), NO_KEY, 'no key, so the issue trigger stamps nothing');
  old.prepare("INSERT INTO users (name,email) VALUES ('e','e@t.test')").run();
  assert.throws(() => old.prepare("INSERT INTO users (name,email,role) VALUES ('f','f@t.test','admin')").run(), /global admin role was retired/);
  old.close();
});

test('admin create: a person gets no API key, an agent gets one shown once', async () => {
  const human = await fetch(`${BASE}/api/users`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': ADMIN_KEY },
    body: JSON.stringify({ name: 'Pat', email: 'pat@t.test', password: 'a-long-password-1', kind: 'human' }),
  });
  assert.equal(human.status, 200);
  const hb = await human.json();
  assert.equal(hb.api_key, undefined, 'no key in the response');
  assert.deepEqual(KEY_COLS(userRow('id', hb.user.id)), NO_KEY);

  const agent = await fetch(`${BASE}/api/users`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': ADMIN_KEY },
    body: JSON.stringify({ name: 'ci-bot', email: 'bot@t.test', kind: 'agent' }),
  });
  assert.equal(agent.status, 200);
  const ab = await agent.json();
  assert.match(ab.api_key, /^dhk_user_/);
  assert.equal((await fetch(`${BASE}/api/whoami`, { headers: { 'X-API-Key': ab.api_key } })).status, 200);
  assert.ok(userRow('id', ab.user.id).api_key_expires_at, 'agent key has an expiry');
});

test('SCIM provisioning creates the account with no API key', async () => {
  const res = await fetch(`${BASE}/api/scim/v2/Users`, {
    method: 'POST', headers: { 'Content-Type': 'application/scim+json', Authorization: `Bearer ${SCIM_TOKEN}` },
    body: JSON.stringify({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: 'scim1@t.test', name: { givenName: 'Sam', familyName: 'Cim' }, emails: [{ value: 'scim1@t.test', primary: true }], active: true, externalId: 'ext-1' }),
  });
  assert.equal(res.status, 201, await res.clone().text());
  const u = userRow('email', 'scim1@t.test');
  assert.ok(u);
  assert.deepEqual(KEY_COLS(u), NO_KEY);
});

test('OIDC first sign-in auto-provisions the account with no API key', async () => {
  const start = await fetch(`${BASE}/api/auth/oidc/start`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const loc = new URL(start.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, `${IDP}/auth`);
  pendingNonce = loc.searchParams.get('nonce');
  nextClaims = { sub: 'oidc-sub-1', email: 'oidc1@t.test', email_verified: true, name: 'Olive Idc' };
  const cb = await fetch(`${BASE}/api/auth/oidc/callback?code=c1&state=${encodeURIComponent(loc.searchParams.get('state'))}`, {
    redirect: 'manual', headers: { Cookie: cookiesOf(start) },
  });
  assert.equal(cb.status, 302);
  assert.match(cb.headers.get('location'), /\/login\?.*sso_code=/, cb.headers.get('location'));
  const u = userRow('sso_sub', 'oidc-sub-1');
  assert.ok(u, 'account provisioned');
  assert.equal(u.email, 'oidc1@t.test');
  assert.deepEqual(KEY_COLS(u), NO_KEY);
});

test('SAML first sign-in auto-provisions the account with no API key', async (t) => {
  const start = await fetch(`${BASE}/api/auth/saml/start`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const req = inflateRawSync(Buffer.from(new URL(start.headers.get('location')).searchParams.get('SAMLRequest'), 'base64')).toString();
  const requestId = /\sID="([^"]+)"/.exec(req)[1];
  // The XML signature check is node-saml's, tested there; what is under test
  // here is what AppCrane does with a verified profile.
  t.mock.method(SAML.prototype, 'validatePostResponseAsync', async () => ({
    profile: { inResponseTo: requestId, nameID: 'saml1@t.test', email: 'saml1@t.test', firstName: 'Sally', lastName: 'Aml' },
  }));
  const cb = await fetch(`${BASE}/api/auth/saml/callback`, {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookiesOf(start) },
    body: new URLSearchParams({ SAMLResponse: randomBytes(8).toString('base64'), RelayState: '' }).toString(),
  });
  assert.equal(cb.status, 302);
  assert.match(cb.headers.get('location'), /\/login\?sso_code=/, cb.headers.get('location'));
  const u = userRow('saml_name_id', 'saml1@t.test');
  assert.ok(u, 'account provisioned');
  assert.deepEqual(KEY_COLS(u), NO_KEY);
});

test('keyless accounts coexist under the UNIQUE index and never match a key lookup', async () => {
  assert.ok(db.prepare('SELECT COUNT(*) n FROM users WHERE api_key_hash IS NULL').get().n >= 4);
  assert.equal((await fetch(`${BASE}/api/whoami`, { headers: { 'X-API-Key': 'dhk_user_' + 'x'.repeat(48) } })).status, 401);
});
