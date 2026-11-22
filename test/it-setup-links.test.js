import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// IT setup links: a platform admin issues a scoped, expiring link; the IT
// contact trades it for a cookie session scoped to /api/it-setup, stages
// changes, tests SSO, confirms; admins are mailed on completion and can roll
// the last change back. Real routers on 127.0.0.1:0.

const dataDir = mkdtempSync(join(tmpdir(), 'crane-it-setup-'));
process.env.DATA_DIR = dataDir;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, hashPassword } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const it = await import('../server/routes/itSetup.js');
const oidcRoutes = (await import('../server/routes/oidc.js')).default;
const identityRoutes = (await import('../server/routes/identity.js')).default;
const scim = await import('../server/routes/scim.js');
const siemRoutes = (await import('../server/routes/siem.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const conn = await import('../server/services/itSetup/connectionTest.js');
const dv = await import('../server/services/domainVerification.js');

const adminKey = generateApiKey('dhk_admin');
const ADMIN_PW = 'correct horse battery staple 1';
db.prepare("INSERT INTO users (name,email,role,api_key_hash,password_hash,active,kind) VALUES ('admin','admin@t.test','platform_admin',?,?,1,'human')")
  .run(hashApiKey(adminKey), hashPassword(ADMIN_PW, { iterations: 100000 }));

const api = express();
api.use(express.json({ type: ['application/json', 'application/scim+json'] }));
api.use('/api/auth/oidc', oidcRoutes);
api.use('/api/identity', identityRoutes);
api.use('/api/auth/scim', scim.scimAdminRouter);
api.use('/api/scim/v2', scim.default);
api.use('/api/settings', siemRoutes);
api.use('/api/it-setup', it.itRouter);
api.use('/api', it.adminRouter);
api.use(it.pageRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { conn._resetConnectionTestDeps(); server.closeAllConnections?.(); server.close(); rmSync(dataDir, { recursive: true, force: true }); });

const admin = (method, path, body) => fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', 'X-API-Key': adminKey }, body: body ? JSON.stringify(body) : undefined });

async function newLink(scopes, extra = {}) {
  const r = await admin('POST', '/api/it-setup-links', { label: 'Example Org IT', scopes, ...extra });
  assert.equal(r.status, 201);
  const body = await r.json();
  const token = new URL(body.url).hash.replace(/^#t=/, '');
  return { id: body.link.id, token, url: body.url };
}

/** Open a link the way the page does; returns a client bound to the session. */
async function open(token) {
  it._resetItSetupLimitsForTests();
  const r = await fetch(`${BASE}/api/it-setup/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  const body = await r.json();
  if (r.status !== 200) return { status: r.status, body };
  const setCookie = r.headers.getSetCookie()[0];
  const cookie = setCookie.split(';')[0];
  const session = cookie.split('=')[1];
  const c = (method, path, b, { csrf = body.csrf } = {}) => fetch(`${BASE}/api/it-setup${path}`, {
    method, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(csrf && { 'X-IT-Setup-CSRF': csrf }) }, body: b ? JSON.stringify(b) : undefined,
  });
  return { status: 200, body, setCookie, cookie, session, c };
}

const goodIdp = { fetchJson: async (url) => (url.endsWith('/jwks')
  ? { keys: [{ kty: 'RSA', kid: 'k' }] }
  : { issuer: 'https://idp.example.test', authorization_endpoint: 'https://idp.example.test/a', token_endpoint: 'https://idp.example.test/t', jwks_uri: 'https://idp.example.test/jwks' }) };
const audits = (linkId) => db.prepare("SELECT action, detail FROM audit_log WHERE action LIKE 'it-setup.%' ORDER BY id").all()
  .filter((a) => JSON.parse(a.detail).link_id === linkId).map((a) => a.action);
const setting = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? null;

test('link creation is platform admin only, validated, and the token lives in the fragment, stored hashed', async () => {
  assert.equal((await fetch(`${BASE}/api/it-setup-links`, { method: 'POST' })).status, 401);
  assert.equal((await admin('POST', '/api/it-setup-links', { label: 'x', scopes: ['oidc', 'billing'] })).status, 400);
  assert.equal((await admin('POST', '/api/it-setup-links', { label: 'x', scopes: [] })).status, 400);
  assert.equal((await admin('POST', '/api/it-setup-links', { label: 'x', scopes: ['scim'], expires_in_days: 90 })).status, 400);
  const { id, token, url } = await newLink(['scim']);
  assert.match(url, /\/it-setup#t=acits_/);
  assert.ok(token.length > 40);
  const row = db.prepare('SELECT * FROM it_setup_links WHERE id = ?').get(id);
  assert.equal(row.token_hash, hashApiKey(token));
  assert.ok(!JSON.stringify(row).includes(token));
  const days = (Date.parse(row.expires_at) - Date.now()) / 86400_000;
  assert.ok(days > 6.9 && days <= 7, 'defaults to 7 days');
  const list = await (await admin('GET', '/api/it-setup-links')).json();
  assert.ok(!JSON.stringify(list).includes(token));
});

test('opening sets an HttpOnly SameSite=Strict cookie scoped to /api/it-setup; writes need the CSRF header', async () => {
  const { token } = await newLink(['domains']);
  const s = await open(token);
  assert.equal(s.status, 200);
  assert.match(s.setCookie, /HttpOnly/i);
  assert.match(s.setCookie, /SameSite=Strict/i);
  assert.match(s.setCookie, /Path=\/api\/it-setup/);
  assert.equal((await s.c('POST', '/domains', { domain: 'csrf.example.test' }, { csrf: null })).status, 403);
  assert.equal((await s.c('POST', '/domains', { domain: 'csrf.example.test' }, { csrf: 'x'.repeat(43) })).status, 403);
  const cross = await fetch(`${BASE}/api/it-setup/domains`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: s.cookie, 'X-IT-Setup-CSRF': s.body.csrf, 'Sec-Fetch-Site': 'cross-site' }, body: '{"domain":"csrf.example.test"}' });
  assert.equal(cross.status, 403);
  assert.equal((await s.c('POST', '/domains', { domain: 'csrf.example.test' })).status, 201);
});

test('scopes are enforced: a SCIM-only link cannot read or change OIDC, SAML, SIEM or domains', async () => {
  const { id, token } = await newLink(['scim']);
  const s = await open(token);
  const state = await (await s.c('GET', '/state')).json();
  assert.deepEqual(Object.keys(state.sections), ['scim']);
  assert.equal(state.domains, undefined);
  for (const [m, p, b] of [['POST', '/oidc', { enabled: false }], ['POST', '/saml', {}], ['POST', '/siem', {}], ['GET', '/domains'], ['POST', '/domains', { domain: 'a.example.test' }], ['POST', '/domains/1/verify']]) {
    const r = await s.c(m, p, b);
    assert.equal(r.status, 403, `${m} ${p}`);
    assert.equal((await r.json()).error.code, 'SCOPE');
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM it_setup_changes WHERE link_id = ? AND scope <> 'scim'").get(id).n, 0);
  assert.ok(audits(id).includes('it-setup.scope-refused'));
  // A change of another link's scope is not reachable by id either.
  const other = await newLink(['oidc']);
  const o = await open(other.token);
  const staged = await (await o.c('POST', '/oidc', { enabled: false, discovery_url: 'https://idp.example.test', client_id: 'c' })).json();
  assert.equal((await s.c('POST', `/changes/${staged.change.id}/confirm`)).status, 404);
});

test('expired, revoked and completed links are refused; revoking ends live sessions', async () => {
  const a = await newLink(['domains']);
  db.prepare("UPDATE it_setup_links SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(a.id);
  const r = await open(a.token);
  assert.equal(r.status, 410);
  assert.equal(r.body.error.code, 'LINK_EXPIRED');
  assert.ok(audits(a.id).includes('it-setup.open-refused'));

  const b = await newLink(['domains']);
  const s = await open(b.token);
  assert.equal((await s.c('GET', '/state')).status, 200);
  assert.equal((await admin('POST', `/api/it-setup-links/${b.id}/revoke`)).status, 200);
  assert.equal((await s.c('GET', '/state')).status, 401, 'live session ends');
  assert.equal((await open(b.token)).body.error.code, 'LINK_REVOKED');

  assert.equal((await open('acits_' + 'A'.repeat(43))).status, 401);
  assert.equal((await open('not-a-link')).status, 401);
});

test('the setup session and link reach no other API', async () => {
  const { token } = await newLink(['oidc', 'saml', 'scim', 'domains', 'siem']);
  const s = await open(token);
  const routes = [['GET', '/api/auth/oidc/admin-config'], ['PUT', '/api/auth/oidc/config'], ['GET', '/api/auth/scim/config'], ['POST', '/api/auth/scim/token'],
    ['GET', '/api/settings/siem'], ['GET', '/api/it-setup-links'], ['POST', '/api/it-setup-links'], ['GET', '/api/sso-domains'], ['GET', '/api/identity/me']];
  for (const value of [s.session, token]) {
    for (const headers of [{ Cookie: `cc_token=${value}; cc_itsetup=${value}` }, { Authorization: `Bearer ${value}` }, { 'X-API-Key': value }]) {
      for (const [m, p] of routes) {
        const r = await fetch(BASE + p, { method: m, headers: { 'Content-Type': 'application/json', ...headers }, body: m === 'GET' ? undefined : '{}' });
        assert.ok([401, 403].includes(r.status), `${m} ${p} with ${Object.keys(headers)[0]} -> ${r.status}`);
      }
    }
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM identity_sessions').get().n, 0, 'no identity session was ever created');
});

test('OIDC: staged, needs a passing test, cannot switch SSO-only on, password sign-in still works; audited; admin rolls back', async () => {
  // An admin explicitly stored "Require SSO sign-in" on before any provider existed.
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auth_sso_only', 'true')").run();
  const { id, token } = await newLink(['oidc']);
  const s = await open(token);
  const SECRET = 'client-secret-PLAINTEXT-123';
  let r = await s.c('POST', '/oidc', { enabled: true, discovery_url: 'https://idp.example.test', client_id: 'crane', client_secret: SECRET, provider_name: 'Corp' });
  assert.equal(r.status, 201);
  const text = await r.text();
  assert.ok(!text.includes(SECRET), 'stage response masks the secret');
  const change = JSON.parse(text).change;
  assert.equal(setting('oidc_enabled'), null, 'nothing applied while staged');

  r = await s.c('POST', `/changes/${change.id}/confirm`);
  assert.equal(r.status, 409);
  assert.equal((await r.json()).error.code, 'TEST_REQUIRED');

  conn._setConnectionTestDeps({ fetchJson: async () => { throw new Error('connect ECONNREFUSED'); } });
  r = await (await s.c('POST', `/changes/${change.id}/test`)).json();
  assert.equal(r.ok, false);
  assert.equal((await s.c('POST', `/changes/${change.id}/confirm`)).status, 409, 'a failed test does not unlock confirm');

  conn._setConnectionTestDeps(goodIdp);
  r = await (await s.c('POST', `/changes/${change.id}/test`)).json();
  assert.equal(r.ok, true, JSON.stringify(r.steps));
  r = await s.c('POST', `/changes/${change.id}/confirm`);
  assert.equal(r.status, 200);
  const applied = await r.json();
  assert.equal(applied.change.sso_only_turned_off, true);
  assert.equal(setting('oidc_enabled'), '1');
  assert.equal(setting('oidc_client_id'), 'crane');
  assert.notEqual(setting('oidc_client_secret_enc'), SECRET);
  assert.equal(setting('auth_sso_only'), 'false', 'the link left SSO-only off');

  const login = await fetch(`${BASE}/api/identity/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ login: 'admin@t.test', password: ADMIN_PW }) });
  // The password is accepted; the admin MFA policy asks for the second step
  // next. What must not happen is 403 SSO_REQUIRED.
  const lb = await login.json();
  assert.notEqual(lb.error?.code, 'SSO_REQUIRED', 'password (break-glass) sign-in is not refused');
  assert.ok(lb.mfa_token || lb.token, JSON.stringify(lb));

  const state = await (await s.c('GET', '/state')).text();
  assert.ok(!state.includes(SECRET));
  assert.equal(JSON.parse(state).sections.oidc.client_secret_set, true);

  assert.deepEqual(audits(id), ['it-setup.link-create', 'it-setup.open', 'it-setup.stage', 'it-setup.test', 'it-setup.test', 'it-setup.apply']);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'sso-enforce-set' AND detail LIKE '%it-setup%'").get());

  const detail = await (await admin('GET', `/api/it-setup-links/${id}`)).text();
  assert.ok(!detail.includes(SECRET));
  r = await admin('POST', `/api/it-setup-links/${id}/rollback`);
  assert.equal(r.status, 200);
  assert.equal(setting('oidc_enabled'), null);
  assert.equal(setting('oidc_client_secret_enc'), null);
  assert.equal(setting('auth_sso_only'), 'true', 'rolled back to what the admin stored');
  assert.equal((await admin('POST', `/api/it-setup-links/${id}/rollback`)).status, 404, 'nothing left to roll back');
  db.prepare("DELETE FROM settings WHERE key = 'auth_sso_only'").run();
});

test('rollback refuses when the settings changed since, unless forced', async () => {
  const { id, token } = await newLink(['saml']);
  const s = await open(token);
  const cert = (await import('../server/services/dbPki.js')).generateCa({ commonName: 'IdP Test' }).certPem;
  const st = await (await s.c('POST', '/saml', { enabled: false, idp_sso_url: 'https://idp.example.test/sso', idp_cert: cert, provider_name: 'Okta' })).json();
  const t = await (await s.c('POST', `/changes/${st.change.id}/test`)).json();
  assert.equal(t.ok, true, JSON.stringify(t.steps));
  assert.equal((await s.c('POST', `/changes/${st.change.id}/confirm`)).status, 200);
  db.prepare("UPDATE settings SET value = 'https://other.example.test/sso' WHERE key = 'saml_idp_sso_url'").run();
  let r = await admin('POST', `/api/it-setup-links/${id}/rollback`);
  assert.equal(r.status, 409);
  assert.equal((await r.json()).error.code, 'CHANGED_SINCE');
  r = await admin('POST', `/api/it-setup-links/${id}/rollback`, { force: true });
  assert.equal(r.status, 200);
  assert.equal(setting('saml_idp_sso_url'), null);
});

test('SCIM: rotate on confirm (token shown once, works), requests logged and listed, rollback restores the old token', async () => {
  const { id, token } = await newLink(['scim']);
  const s = await open(token);
  const st = await (await s.c('POST', '/scim', { enabled: true, rotate_token: true })).json();
  assert.equal(setting('scim_token_hash'), null);
  const conf = await (await s.c('POST', `/changes/${st.change.id}/confirm`)).json();
  assert.match(conf.scim_token, /^scim_/);
  assert.equal(setting('scim_token_hash'), hashApiKey(conf.scim_token));
  const users = await fetch(`${BASE}/api/scim/v2/Users?filter=${encodeURIComponent('userName eq "pat@t.test"')}`, { headers: { Authorization: `Bearer ${conf.scim_token}` } });
  assert.equal(users.status, 200);
  assert.equal((await fetch(`${BASE}/api/scim/v2/Users`, { headers: { Authorization: 'Bearer scim_wrong' } })).status, 401);
  const log = await (await s.c('GET', '/scim/requests')).json();
  assert.deepEqual(log.requests.slice(0, 2).map((q) => [q.method, q.path, q.status]), [['GET', '/api/scim/v2/Users', 401], ['GET', '/api/scim/v2/Users', 200]]);
  assert.ok(!JSON.stringify(log).includes('pat@t.test'), 'query string not logged');
  const state = await (await s.c('GET', '/state')).text();
  assert.ok(!state.includes(conf.scim_token) && !state.includes(setting('scim_token_hash')));

  const second = await (await s.c('POST', '/scim', { enabled: true, rotate_token: true })).json();
  const conf2 = await (await s.c('POST', `/changes/${second.change.id}/confirm`)).json();
  assert.equal((await admin('POST', `/api/it-setup-links/${id}/rollback`)).status, 200);
  assert.equal((await fetch(`${BASE}/api/scim/v2/Users`, { headers: { Authorization: `Bearer ${conf2.scim_token}` } })).status, 401, 'rolled-back token is dead');
  assert.equal((await fetch(`${BASE}/api/scim/v2/Users`, { headers: { Authorization: `Bearer ${conf.scim_token}` } })).status, 200, 'previous token works again');
});

test('domains via the link: add, verify; completion mails the platform admins and closes the link', async () => {
  const { id, token } = await newLink(['domains', 'siem']);
  const s = await open(token);
  const add = await (await s.c('POST', '/domains', { domain: 'it.example.test' })).json();
  assert.equal(add.domain.status, 'pending');
  assert.equal(db.prepare('SELECT created_by_link FROM sso_domains WHERE id = ?').get(add.domain.id).created_by_link, id);
  assert.equal(setting('oidc_allowed_domains'), null, 'the link does not edit the join list');
  const row = dv.getDomain(add.domain.id);
  await dv.checkDomain(row, { resolveTxt: async () => [[dv.TXT_PREFIX + row.token]] });
  assert.equal(dv.getDomain(add.domain.id).status, 'verified');

  const tls = await s.c('POST', '/siem', { name: 'S', type: 'https', preset: 'splunk', config: { url: 'https://siem.example.test/hec' }, secrets: { token: 't' }, tls_skip_verify: true });
  assert.equal(tls.status, 400, 'a link cannot turn TLS verification off');
  const sink = await (await s.c('POST', '/siem', { name: 'Splunk', type: 'https', preset: 'splunk', config: { url: 'https://siem.example.test/hec' }, secrets: { token: 'hec-SECRET-999' } })).json();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM siem_sinks').get().n, 0);
  const sc = await s.c('POST', `/changes/${sink.change.id}/confirm`);
  assert.equal(sc.status, 200);
  assert.ok(!(await sc.text()).includes('hec-SECRET-999'));
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM siem_sinks').get().n, 1);

  const before = db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE source = 'it-setup'").get().n;
  assert.equal((await s.c('POST', '/complete')).status, 200);
  await new Promise((r) => setTimeout(r, 100));
  const mail = db.prepare("SELECT to_email, subject, body_text FROM email_queue WHERE source = 'it-setup' ORDER BY id DESC").all();
  assert.equal(mail.length - before, 1);
  assert.equal(mail[0].to_email, 'admin@t.test');
  assert.match(mail[0].body_text, /SIEM/);
  assert.equal((await s.c('GET', '/state')).status, 401);
  assert.equal((await open(token)).body.error.code, 'LINK_COMPLETED');
  const acts = audits(id);
  for (const a of ['it-setup.open', 'it-setup.domain-add', 'it-setup.stage', 'it-setup.apply', 'it-setup.complete']) assert.ok(acts.includes(a), a);

  assert.equal((await admin('POST', `/api/it-setup-links/${id}/rollback`)).status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM siem_sinks').get().n, 0, 'rolling back removes the SIEM destination');
});

test('the connection test refuses plain http and private addresses (no SSRF from the setup page)', async () => {
  conn._resetConnectionTestDeps();
  for (const url of ['http://idp.example.test', 'https://127.0.0.1:1', 'https://169.254.169.254', 'https://[::1]']) {
    const r = await conn.testOidc({ discovery_url: url, client_id: 'c' });
    assert.equal(r.ok, false, url);
    assert.match(r.steps.find((x) => x.step === 'discovery').detail, /https|private|loopback|link-local/, url);
  }
});

test('opening is rate limited per client address', async () => {
  it._resetItSetupLimitsForTests();
  const statuses = [];
  for (let i = 0; i < 11; i++) {
    const r = await fetch(`${BASE}/api/it-setup/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'acits_guess' + i }) });
    statuses.push(r.status);
  }
  assert.deepEqual(statuses, [...Array(10).fill(401), 429]);
  it._resetItSetupLimitsForTests();
});

test('the page is minimal: own CSP, no inline script, no referrer', async () => {
  const r = await fetch(`${BASE}/it-setup`);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  const html = await r.text();
  assert.ok(!/<script>[^<]/.test(html), 'no inline script');
  assert.equal((await fetch(`${BASE}/it-setup/app.js`)).status, 200);
});
