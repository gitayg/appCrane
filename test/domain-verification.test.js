import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import Database from 'better-sqlite3';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import crypto from 'crypto';
import express from 'express';

// DNS TXT domain verification (services/domainVerification.js) with an
// injected resolver, and OIDC sign-up honouring only verified (or legacy)
// domains, driven through the real OIDC router against a stub IdP.

const dataDir = mkdtempSync(join(tmpdir(), 'crane-domain-verify-'));
process.env.DATA_DIR = dataDir;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const dv = await import('../server/services/domainVerification.js');
const oidcRoutes = (await import('../server/routes/oidc.js')).default;
const { adminRouter } = await import('../server/routes/itSetup.js');
const { errorHandler } = await import('../server/utils/errors.js');

const adminKey = generateApiKey('dhk_admin');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('admin','admin@t.test','platform_admin',?,1,'human')").run(hashApiKey(adminKey));

const txt = (records) => async () => records;
const fail = (code) => async () => { throw Object.assign(new Error(code), { code }); };
const hang = () => new Promise(() => {});

test('TXT lookup: verified, wrong token, NXDOMAIN, timeout', async () => {
  const T = 'tok123';
  assert.equal((await dv.lookupToken('a.test', T, { resolveTxt: txt([['other=1'], [dv.TXT_PREFIX, T]]) })).result, 'verified', 'chunked record joins');
  assert.equal((await dv.lookupToken('a.test', T, { resolveTxt: txt([[dv.TXT_PREFIX + 'nope']]) })).result, 'wrong_token');
  assert.equal((await dv.lookupToken('a.test', T, { resolveTxt: fail('ENOTFOUND') })).result, 'not_found');
  assert.equal((await dv.lookupToken('a.test', T, { resolveTxt: fail('ENODATA') })).result, 'not_found');
  const t0 = Date.now();
  assert.equal((await dv.lookupToken('a.test', T, { resolveTxt: hang, timeoutMs: 60 })).result, 'timeout');
  assert.ok(Date.now() - t0 < 1000, 'bounded by the timeout');
  assert.equal((await dv.lookupToken('a.test', T, { resolveTxt: fail('ESERVFAIL') })).result, 'error');
});

test('checkDomain stores status: pending -> verified, lapse -> unverified, timeout changes nothing', async () => {
  const { row } = dv.addDomain('Lapse.Example.TEST');
  assert.equal(row.domain, 'lapse.example.test');
  assert.equal(row.status, 'pending');
  assert.ok(row.token.length >= 22);
  let r = await dv.checkDomain(row, { resolveTxt: txt([[dv.TXT_PREFIX + 'wrong']]) });
  assert.equal(r.row.status, 'pending');
  r = await dv.checkDomain(r.row, { resolveTxt: txt([[dv.TXT_PREFIX + row.token]]) });
  assert.equal(r.row.status, 'verified');
  assert.ok(r.row.verified_at);
  r = await dv.checkDomain(r.row, { resolveTxt: hang, timeoutMs: 30 });
  assert.equal(r.row.status, 'verified', 'a timeout never un-verifies');
  r = await dv.checkDomain(r.row, { resolveTxt: fail('ENOTFOUND') });
  assert.equal(r.row.status, 'unverified', 'record gone: no longer admits');
  assert.throws(() => dv.addDomain('10.0.0.1'), /Not a domain/);
  assert.throws(() => dv.addDomain('*.example.test'), /Not a domain/);
  assert.throws(() => dv.addDomain('localhost'), /Not a domain/);
});

test('migration 210 grandfathers listed domains as legacy, skipping addresses and *', () => {
  const mem = new Database(':memory:');
  mem.exec('CREATE TABLE users(id INTEGER PRIMARY KEY); CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)');
  mem.prepare("INSERT INTO settings VALUES ('oidc_allowed_domains', 'Corp.test,@b.test,pat@solo.test,*')").run();
  mem.exec(readFileSync(new URL('../server/migrations/210-sso-domains.sql', import.meta.url), 'utf8'));
  assert.deepEqual(mem.prepare('SELECT domain, status FROM sso_domains ORDER BY domain').all(), [
    { domain: 'b.test', status: 'legacy' }, { domain: 'corp.test', status: 'legacy' },
  ]);
  mem.close();
});


// --- OIDC sign-up through the real router ----------------------------------
const CLIENT_ID = 'crane-domain-test';
let nonce; let claims = {}; let idpBase;
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
function idToken() {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = enc({ iss: idpBase, aud: CLIENT_ID, nonce, exp: Math.floor(Date.now() / 1000) + 300, ...claims });
  return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`;
}
const idp = http.createServer((req, res) => {
  const json = (o) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (req.url.startsWith('/.well-known/openid-configuration')) return json({ issuer: idpBase, authorization_endpoint: `${idpBase}/authorize`, token_endpoint: `${idpBase}/token`, jwks_uri: `${idpBase}/jwks` });
  if (req.url === '/jwks') return json({ keys: [jwk] });
  if (req.url === '/token') { req.resume(); return req.on('end', () => json({ id_token: idToken(), token_type: 'Bearer' })); }
  res.writeHead(404); res.end();
});
await new Promise((r) => idp.listen(0, '127.0.0.1', r));
idpBase = `http://127.0.0.1:${idp.address().port}`;

const api = express();
api.use(express.json());
api.use('/api/auth/oidc', oidcRoutes);
api.use('/api', adminRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { for (const s of [server, idp]) { s.closeAllConnections?.(); s.close(); } rmSync(dataDir, { recursive: true, force: true }); });

const call = (method, path, body) => fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', 'X-API-Key': adminKey }, body: body ? JSON.stringify(body) : undefined });

async function signIn(who) {
  claims = who;
  const start = await fetch(`${BASE}/api/auth/oidc/start`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const loc = new URL(start.headers.get('location'));
  nonce = loc.searchParams.get('nonce');
  const cookie = start.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  const cb = await fetch(`${BASE}/api/auth/oidc/callback?${new URLSearchParams({ code: 'c', state: loc.searchParams.get('state') })}`, { redirect: 'manual', headers: { Cookie: cookie } });
  assert.equal(cb.status, 302);
  return new URL(cb.headers.get('location')).searchParams.get('sso_error');
}
const userCount = (email) => db.prepare('SELECT COUNT(*) AS n FROM users WHERE email = ?').get(email).n;

test('a domain added to the allowed list is pending and does not auto-join until verified', async () => {
  const r = await call('PUT', '/api/auth/oidc/config', { enabled: true, discovery_url: idpBase, client_id: CLIENT_ID, auto_provision: true, allowed_domains: 'fresh.example.test, solo@one.example.test' });
  assert.equal(r.status, 200);
  const row = db.prepare("SELECT * FROM sso_domains WHERE domain = 'fresh.example.test'").get();
  assert.equal(row.status, 'pending');

  const cfg = await (await call('GET', '/api/auth/oidc/admin-config')).json();
  assert.deepEqual(cfg.domain_warnings.map((w) => [w.domain, w.status]), [['fresh.example.test', 'pending']]);

  assert.equal(await signIn({ sub: 's-1', email: 'pat@fresh.example.test', email_verified: true, name: 'Pat' }), 'pending_approval');
  assert.equal(userCount('pat@fresh.example.test'), 0, 'no account for an unverified domain');
  assert.equal(await signIn({ sub: 's-solo', email: 'solo@one.example.test', email_verified: true, name: 'Solo' }), null, 'a single-address entry is unaffected');
  assert.equal(userCount('solo@one.example.test'), 1);

  const v = await dv.checkDomain(row, { resolveTxt: txt([[dv.TXT_PREFIX + row.token]]) });
  assert.equal(v.row.status, 'verified');
  assert.equal(await signIn({ sub: 's-2', email: 'kim@fresh.example.test', email_verified: true, name: 'Kim' }), null);
  assert.equal(userCount('kim@fresh.example.test'), 1, 'verified domain auto-joins');
});

test('a list whose only domain is unverified admits nobody (it does not turn into "no list")', async () => {
  await call('PUT', '/api/auth/oidc/config', { enabled: true, discovery_url: idpBase, client_id: CLIENT_ID, auto_provision: true, allowed_domains: 'only.example.test' });
  assert.equal(await signIn({ sub: 's-3', email: 'lee@elsewhere.example.test', email_verified: true, name: 'Lee' }), 'pending_approval');
  assert.equal(userCount('lee@elsewhere.example.test'), 0);
});

test('a legacy (grandfathered) domain keeps auto-joining, with a warning', async () => {
  db.prepare("INSERT INTO sso_domains (domain, token, status) VALUES ('old.example.test', 'x', 'legacy')").run();
  await call('PUT', '/api/auth/oidc/config', { enabled: true, discovery_url: idpBase, client_id: CLIENT_ID, auto_provision: true, allowed_domains: 'old.example.test' });
  assert.equal(db.prepare("SELECT status FROM sso_domains WHERE domain = 'old.example.test'").get().status, 'legacy', 'saving does not reset it');
  const cfg = await (await call('GET', '/api/auth/oidc/admin-config')).json();
  assert.equal(cfg.domain_warnings[0].status, 'legacy');
  assert.equal(await signIn({ sub: 's-4', email: 'max@old.example.test', email_verified: true, name: 'Max' }), null);
  assert.equal(userCount('max@old.example.test'), 1);
});

test('admin domain API: add, verify on demand (real resolver, bounded), delete; platform admin only', async () => {
  const anon = await fetch(`${BASE}/api/sso-domains`);
  assert.equal(anon.status, 401);
  const add = await call('POST', '/api/sso-domains', { domain: 'nx-appcrane-test.invalid' });
  assert.equal(add.status, 201);
  const { domain } = await add.json();
  assert.equal(domain.txt_value.startsWith(dv.TXT_PREFIX), true);
  const ver = await call('POST', `/api/sso-domains/${domain.id}/verify`);
  const body = await ver.json();
  assert.equal(ver.status, 200);
  assert.ok(['not_found', 'timeout', 'error'].includes(body.result), body.result);
  assert.equal(body.domain.status, 'pending');
  const audit = db.prepare("SELECT action FROM audit_log WHERE action LIKE 'sso-domain.%' ORDER BY id").all().map((a) => a.action);
  assert.deepEqual(audit, ['sso-domain.add', 'sso-domain.check']);
  assert.equal((await call('DELETE', `/api/sso-domains/${domain.id}`)).status, 200);
});

test('the job pass checks rows and records what changed', async () => {
  const { row } = dv.addDomain('job.example.test');
  const r = await dv.runDomainChecks({ resolveTxt: async (name) => (name === 'job.example.test' ? [[dv.TXT_PREFIX + row.token]] : []) });
  assert.ok(r.checked >= 1);
  assert.ok(r.changed.some((c) => c.domain === 'job.example.test' && c.to === 'verified'));
});
