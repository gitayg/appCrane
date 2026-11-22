import { test, after, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import https from 'https';
import http from 'http';
import { createVerify, generateKeyPairSync } from 'crypto';
import express from 'express';

// Connections gateway (migration 230, services/connections). Real routers on
// 127.0.0.1:0 and a real https upstream on 127.0.0.1 with its own CA. Names
// resolve through the upstream test seam: api.upstream.t.test and
// www.googleapis.com are operator-listed private hosts (so they may resolve to
// 127.0.0.1), evil.t.test is not, so the guard must refuse it at connect time.

const H = await import('./capability-harness.mjs');
const { db, mkUser, mkApp, assign, ROOT } = H;

process.env.APPCRANE_CONNECTIONS_PRIVATE_HOSTS = 'api.upstream.t.test,www.googleapis.com';

const certDir = join(ROOT, 'tls');
execFileSync('mkdir', ['-p', certDir]);
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=api.upstream.t.test',
  '-addext', 'subjectAltName=DNS:api.upstream.t.test,DNS:evil.t.test,DNS:www.googleapis.com',
  '-keyout', join(certDir, 'key.pem'), '-out', join(certDir, 'cert.pem')], { stdio: 'pipe' });
const CERT = readFileSync(join(certDir, 'cert.pem'));
const KEY = readFileSync(join(certDir, 'key.pem'));

const { _setUpstreamForTests } = await import('../server/services/connections/upstream.js');
const { _setGoogleTokenUriForTests } = await import('../server/services/connections/credentials.js');
const { _resetRateLimitsForTests } = await import('../server/services/connections/usage.js');
const { issueServiceToken } = await import('../server/services/appServiceToken.js');
const { identitySecretFor, signIdentity, signIdentityV2 } = await import('../server/services/identitySignature.js');
const { signActing } = await import('../server/services/connections/gateway.js');

_setUpstreamForTests({ ca: CERT, resolve: async () => [{ address: '127.0.0.1', family: 4 }] });

// ── the upstream ─────────────────────────────────────────────────────────────
const hits = [];
const google = generateKeyPairSync('rsa', { modulusLength: 2048 });
const GOOGLE_TOKEN = 'ya29.google-access-token-for-tests';
const upstream = https.createServer({ cert: CERT, key: KEY }, (req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    hits.push({ method: req.method, url: req.url, host: req.headers.host, headers: req.headers, body });
    if (req.url === '/token') {
      const assertion = new URLSearchParams(body).get('assertion') || '';
      const [h, c, s] = assertion.split('.');
      const ok = createVerify('RSA-SHA256').update(`${h}.${c}`).verify(google.publicKey, Buffer.from(s || '', 'base64url'));
      res.writeHead(ok ? 200 : 401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(ok ? { access_token: GOOGLE_TOKEN, expires_in: 3600 } : { error: 'invalid_grant' }));
    }
    if (req.url.startsWith('/api/redirect-away')) { res.writeHead(302, { location: 'https://elsewhere.t.test/steal' }); return res.end(); }
    if (req.url.startsWith('/api/redirect-home')) { res.writeHead(302, { location: '/api/repos/acme/moved?x=1' }); return res.end(); }
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'up=1', 'x-echo-auth': String(req.headers.authorization || '') });
    res.end(JSON.stringify({ path: req.url, method: req.method, headers: req.headers, body }));
  });
});
await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
const UP_PORT = upstream.address().port;
_setGoogleTokenUriForTests(`https://www.googleapis.com:${UP_PORT}/token`);

// ── AppCrane ─────────────────────────────────────────────────────────────────
const api = express();
api.use('/api/service/connections', (await import('../server/routes/connections.js')).default);
api.use(express.json());
api.use('/api/connections', (await import('../server/routes/connections.js')).adminRouter);
api.use('/api/apps', (await import('../server/routes/connections.js')).appRouter);
api.use('/api', (await import('../server/routes/capabilities.js')).default);
api.use((await import('../server/utils/errors.js')).errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  server.closeAllConnections?.(); server.close();
  upstream.closeAllConnections?.(); upstream.close();
  await H.stopServer();
});

async function call(who, method, path, body, { as = 'key' } = {}) {
  const h = { 'Content-Type': 'application/json' };
  if (as === 'session') h.Authorization = `Bearer ${who.session}`; else h['X-API-Key'] = who.key;
  const r = await fetch(`${BASE}${path}`, { method, headers: h, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: r.status, body: await r.json().catch(() => null) };
}

/** A raw request, so the path reaches the server byte for byte (fetch normalizes '..'). */
function gw(token, method, path, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: server.address().port, path: `/api/service/connections${path}`,
      method, headers: { ...(token ? { 'X-AppCrane-Service-Token': token } : {}), ...headers, ...(body ? { 'content-length': Buffer.byteLength(body) } : {}) },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null; try { json = JSON.parse(text); } catch (_) {}
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    req.end(body || undefined);
  });
}

const UPSTREAM_TOKEN = 'ghp_UpstreamCredentialNeverShownToApps0001';
const admin = mkUser({ name: 'Admin One', role: 'platform_admin' });
const approver = mkUser({ name: 'Admin Two', role: 'platform_admin' });
const owner = mkUser({ name: 'Owner' });
const member = mkUser({ name: 'Member' });
const appA = mkApp('conn-a');
const appB = mkApp('conn-b');
assign(appA, owner, 'owner'); assign(appB, owner, 'owner'); assign(appA, member, 'user');
const tokenA = issueServiceToken(appA.id);
const tokenB = issueServiceToken(appB.id);

async function grant(app, capability, scope) {
  const r = await call(owner, 'POST', `/api/apps/${app.slug}/capability-requests`, { capability, scope, reason: 'the app reads repositories' });
  assert.ok([200, 201].includes(r.status), JSON.stringify(r.body));
  const a = await call(approver, 'POST', `/api/capability-requests/${r.body.request.id}/approve`, {}, { as: 'session' });
  assert.equal(a.status, 200, JSON.stringify(a.body));
  return a.body.request;
}

before(async () => {
  const r = await call(admin, 'POST', '/api/connections', {
    name: 'acme-api', provider: 'generic', base_url: `https://api.upstream.t.test:${UP_PORT}/api`,
    auth_type: 'bearer', credentials: { token: UPSTREAM_TOKEN },
  });
  assert.equal(r.status, 201, JSON.stringify(r.body));
});

test('registering: the credential never comes back, and a private, http or credentialed base_url is refused', async () => {
  const list = await call(admin, 'GET', '/api/connections');
  const one = await call(admin, 'GET', '/api/connections/acme-api');
  assert.equal(list.status, 200);
  assert.equal(one.status, 200);
  for (const body of [list.body, one.body]) assert.ok(!JSON.stringify(body).includes(UPSTREAM_TOKEN));
  assert.equal(one.body.connection.has_credentials, true);
  const stored = db.prepare('SELECT credentials_enc FROM api_connections WHERE name = ?').get('acme-api').credentials_enc;
  assert.ok(!stored.includes(UPSTREAM_TOKEN), 'stored encrypted');
  for (const base_url of ['https://10.0.0.5/api', 'http://api.upstream.t.test/api', 'https://u:p@api.upstream.t.test/', 'https://[::1]/']) {
    const r = await call(admin, 'POST', '/api/connections', { name: 'bad-one', base_url, credentials: { token: 'x'.repeat(10) } });
    assert.equal(r.status, 400, base_url);
  }
  const notAdmin = await call(owner, 'GET', '/api/connections');
  assert.equal(notAdmin.status, 403);
});

test('an app without a grant is refused and the upstream is never called', async () => {
  const n = hits.length;
  const r = await gw(tokenA, 'GET', '/acme-api/repos/acme/x');
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, 'CAPABILITY_APPROVAL_REQUIRED');
  assert.equal(hits.length, n);
});

test('with a grant: only its methods and path prefixes; the credential is injected and never visible to the app', async () => {
  await grant(appA, 'connection:acme-api', { methods: ['GET'], path_prefixes: ['/repos/acme'] });
  const n = hits.length;
  const ok = await gw(tokenA, 'GET', '/acme-api/repos/acme/issues?state=open', {
    headers: {
      Authorization: 'Bearer app-own-token', Cookie: 'sid=1', 'X-AppCrane-User-Id': '7', 'X-Forwarded-Proto': 'https', 'X-Custom': 'kept',
      // A GET the grant allows must not become a DELETE at an upstream that honours these.
      'X-HTTP-Method-Override': 'DELETE', 'X-HTTP-Method': 'DELETE', 'X-Method-Override': 'DELETE',
    },
  });
  assert.equal(ok.status, 200, ok.text);
  const hit = hits[n];
  assert.equal(hit.url, '/api/repos/acme/issues?state=open');
  assert.equal(hit.headers.authorization, `Bearer ${UPSTREAM_TOKEN}`, 'credential injected upstream');
  assert.equal(hit.headers.cookie, undefined);
  assert.equal(hit.headers['x-appcrane-service-token'], undefined);
  assert.equal(hit.headers['x-appcrane-user-id'], undefined);
  assert.equal(hit.headers['x-forwarded-proto'], undefined);
  assert.equal(hit.headers['x-custom'], 'kept');
  for (const h of ['x-http-method-override', 'x-http-method', 'x-method-override']) assert.equal(hit.headers[h], undefined, h);
  assert.ok(!ok.text.includes(UPSTREAM_TOKEN), 'echoed credential scrubbed from the body');
  assert.ok(ok.text.includes('[redacted]'));
  assert.ok(!JSON.stringify(ok.headers).includes(UPSTREAM_TOKEN), 'and from the headers');
  assert.equal(ok.headers['set-cookie'], undefined);

  for (const [method, path] of [['POST', '/acme-api/repos/acme/issues'], ['GET', '/acme-api/repos/acme-evil'], ['GET', '/acme-api/orgs/acme']]) {
    const r = await gw(tokenA, method, path, method === 'POST' ? { body: '{}' } : {});
    assert.equal(r.status, 403, `${method} ${path}`);
  }
  for (const path of ['/acme-api/repos/acme/../../orgs', '/acme-api/repos/acme/%2e%2e/x', '/acme-api/repos/acme%2fx', '/acme-api/repos//acme']) {
    const r = await gw(tokenA, 'GET', path);
    assert.equal(r.status, 400, path);
  }
  assert.equal(hits.length, n + 1, 'nothing outside the grant reached the upstream');
});

test("another app's token, a bad token and a proxied request are refused", async () => {
  const n = hits.length;
  const b = await gw(tokenB, 'GET', '/acme-api/repos/acme/x');
  assert.equal(b.status, 403);
  const none = await gw('not-a-token', 'GET', '/acme-api/repos/acme/x');
  assert.equal(none.status, 401);
  const proxied = await gw(tokenA, 'GET', '/acme-api/repos/acme/x', { headers: { Via: '1.1 caddy' } });
  assert.equal(proxied.status, 403);
  assert.equal(proxied.json.error.code, 'NOT_INTERNAL');
  assert.equal(hits.length, n);
});

test('an upstream redirect to another host is refused; one under the base path is rewritten to the gateway', async () => {
  await grant(appA, 'connection:acme-api', { methods: ['GET'], path_prefixes: ['/redirect-away', '/redirect-home'] });
  const away = await gw(tokenA, 'GET', '/acme-api/redirect-away');
  assert.equal(away.status, 502);
  assert.equal(away.json.error.code, 'CONNECTION_REDIRECT_REFUSED');
  assert.equal(away.headers.location, undefined);
  const home = await gw(tokenA, 'GET', '/acme-api/redirect-home');
  assert.equal(home.status, 302);
  assert.equal(home.headers.location, '/api/service/connections/acme-api/repos/acme/moved?x=1');
});

test('an upstream that resolves to a private address is refused at connect time', async () => {
  const c = await call(admin, 'POST', '/api/connections', { name: 'evil', base_url: `https://evil.t.test:${UP_PORT}`, credentials: { token: 'evil-token-123' } });
  assert.equal(c.status, 201, JSON.stringify(c.body));
  await grant(appA, 'connection:evil', { methods: ['GET'], path_prefixes: ['/'] });
  const n = hits.length;
  const r = await gw(tokenA, 'GET', '/evil/anything');
  assert.equal(r.status, 502);
  assert.equal(r.json.error.code, 'CONNECTION_UPSTREAM_BLOCKED');
  assert.equal(hits.length, n);
});

test('every call is logged with method, path, status, bytes and latency, and no body or credential; owners see it, members do not', async () => {
  const marker = 'BODY-MARKER-never-logged';
  await grant(appA, 'connection:acme-api', { methods: ['POST'], path_prefixes: ['/repos/acme/issues'] });
  const r = await gw(tokenA, 'POST', '/acme-api/repos/acme/issues?secret=q', { body: JSON.stringify({ title: marker }), headers: { 'content-type': 'application/json' } });
  assert.equal(r.status, 200, r.text);
  const rows = db.prepare("SELECT * FROM events WHERE kind = 'connection.call' AND app_id = ? ORDER BY id").all(appA.id);
  const last = JSON.parse(rows.at(-1).data);
  assert.equal(last.connection, 'acme-api');
  assert.equal(last.method, 'POST');
  assert.equal(last.path, 'repos/acme/issues');
  assert.equal(rows.at(-1).summary.includes('acme-api/repos/acme/issues'), true);
  assert.equal(last.status, 200);
  assert.ok(last.bytes_in > 0 && last.bytes_out > 0 && Number.isInteger(last.latency_ms));
  const all = JSON.stringify(rows);
  assert.ok(!all.includes(marker), 'no body');
  assert.ok(!all.includes(UPSTREAM_TOKEN), 'no credential');
  assert.ok(!all.includes('secret=q'), 'no query string');
  assert.ok(rows.some((e) => JSON.parse(e.data).outcome === 'refused'), 'refusals are logged too');

  const seen = await call(owner, 'GET', `/api/apps/${appA.slug}/connections`);
  assert.equal(seen.status, 200);
  assert.ok(seen.body.usage.totals.some((t) => t.connection === 'acme-api' && t.outcome === 'ok' && t.calls >= 1));
  assert.ok(seen.body.connections.find((c) => c.name === 'acme-api').grants.length >= 1);
  assert.equal(seen.body.usage.recent[0].path, '/repos/acme/issues');
  const denied = await call(member, 'GET', `/api/apps/${appA.slug}/connections`);
  assert.equal(denied.status, 403);
  const other = await call(owner, 'GET', `/api/apps/${appB.slug}/connections`);
  assert.equal(other.status, 200);
  assert.ok(other.body.usage.recent.length >= 1);
  assert.ok(other.body.usage.recent.every((c) => c.app === appB.slug), "app B does not see app A's calls");
});

test('per-app rate limit', async () => {
  _resetRateLimitsForTests();
  const u = await call(admin, 'PUT', '/api/connections/acme-api', { rate_per_minute: 2 });
  assert.equal(u.status, 200);
  const codes = [];
  for (let i = 0; i < 3; i++) codes.push((await gw(tokenA, 'GET', '/acme-api/repos/acme/x')).status);
  assert.deepEqual(codes, [200, 200, 429]);
  await call(admin, 'PUT', '/api/connections/acme-api', { rate_per_minute: 120 });
  _resetRateLimitsForTests();
});

test('forward_identity: a signed identity becomes a signed acting-user header; a forged one is refused', async () => {
  const c = await call(admin, 'POST', '/api/connections', {
    name: 'acting', base_url: `https://api.upstream.t.test:${UP_PORT}/api`, credentials: { token: 'acting-token-1234' }, forward_identity: true,
  });
  assert.equal(c.status, 201);
  const secret = c.body.identity_secret;
  assert.ok(secret && secret.length > 30, 'shown once at creation');
  assert.ok(!JSON.stringify((await call(admin, 'GET', '/api/connections/acting')).body).includes(secret), 'never again');
  await grant(appA, 'connection:acting', { methods: ['GET'], path_prefixes: ['/'] });

  const ts = Math.floor(Date.now() / 1000);
  const h = { 'X-AppCrane-User-Id': String(owner.id), 'X-AppCrane-User-Email': owner.email, 'X-AppCrane-User': owner.email, 'X-AppCrane-Identity-Ts': String(ts) };
  const appSecret = identitySecretFor(db, appA.id, 'production');
  h['X-AppCrane-Identity-Sig'] = signIdentity(appSecret, ts, (n) => h[n]);
  h['X-AppCrane-Identity-Sig-V2'] = signIdentityV2(appSecret, ts, (n) => h[n]);
  const n = hits.length;
  const ok = await gw(tokenA, 'GET', '/acting/me', { headers: h });
  assert.equal(ok.status, 200, ok.text);
  const up = hits[n].headers;
  assert.equal(up['x-appcrane-acting-user-id'], String(owner.id));
  assert.equal(up['x-appcrane-acting-app'], appA.slug);
  assert.equal(up['x-appcrane-acting-sig'], signActing(secret, { ts: up['x-appcrane-acting-ts'], app: appA.slug, userId: String(owner.id), email: owner.email }));
  assert.equal(up['x-appcrane-user-id'], undefined, "the app's own identity headers are not forwarded");

  const forged = await gw(tokenA, 'GET', '/acting/me', { headers: { ...h, 'X-AppCrane-User-Id': '999' } });
  assert.equal(forged.status, 403);
  assert.equal(forged.json.error.code, 'IDENTITY_INVALID');
  const plain = await gw(tokenA, 'GET', '/acting/me');
  assert.equal(plain.status, 200);
  assert.equal(hits.at(-1).headers['x-appcrane-acting-user-id'], undefined, 'no identity passed on, none asserted');
});

test('a revoked grant refuses the next call; deleting the connection ends its grants', async () => {
  const g = await grant(appB, 'connection:acme-api', { methods: ['GET'], path_prefixes: ['/repos/acme'] });
  assert.equal((await gw(tokenB, 'GET', '/acme-api/repos/acme/x')).status, 200);
  const rv = await call(approver, 'POST', `/api/capability-requests/${g.id}/revoke`, {}, { as: 'session' });
  assert.equal(rv.status, 200, JSON.stringify(rv.body));
  assert.equal((await gw(tokenB, 'GET', '/acme-api/repos/acme/x')).status, 403);

  const d = await call(admin, 'DELETE', '/api/connections/evil');
  assert.equal(d.status, 200);
  assert.ok(d.body.grants_ended >= 1);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM capability_requests WHERE capability = 'connection:evil' AND status = 'approved'").get().n, 0);
  const req = await call(owner, 'POST', `/api/apps/${appA.slug}/capability-requests`, { capability: 'connection:nope', scope: { methods: ['GET'], path_prefixes: ['/'] }, reason: 'x' });
  assert.equal(req.status, 404, 'cannot request a connection that does not exist');
});

test('google service account: the JWT is exchanged for an access token, which is injected and scrubbed', async () => {
  const sa = { type: 'service_account', client_email: 'svc@project.iam.t.test', private_key: google.privateKey.export({ type: 'pkcs8', format: 'pem' }), private_key_id: 'k1' };
  const c = await call(admin, 'POST', '/api/connections', {
    name: 'gdrive', provider: 'google', base_url: `https://www.googleapis.com:${UP_PORT}/drive/v3`,
    credentials: { service_account_json: JSON.stringify(sa) }, scopes: ['https://www.googleapis.com/auth/drive.readonly'],
  });
  assert.equal(c.status, 201, JSON.stringify(c.body));
  assert.ok(!JSON.stringify(c.body).includes('PRIVATE KEY'));
  await grant(appA, 'connection:gdrive', { methods: ['GET'], path_prefixes: ['/files'] });
  const n = hits.length;
  const r = await gw(tokenA, 'GET', '/gdrive/files');
  assert.equal(r.status, 200, r.text);
  assert.equal(hits[n].url, '/token');
  assert.equal(hits[n + 1].headers.authorization, `Bearer ${GOOGLE_TOKEN}`);
  assert.ok(!r.text.includes(GOOGLE_TOKEN));
  const bad = await call(admin, 'POST', '/api/connections', { name: 'gbad', provider: 'google', base_url: 'https://evil.t.test', credentials: { service_account_json: JSON.stringify(sa) }, scopes: ['https://www.googleapis.com/auth/x'] });
  assert.equal(bad.status, 400, 'a google connection points only at googleapis.com');
});
