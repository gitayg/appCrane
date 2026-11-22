import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { inflateRawSync } from 'zlib';
import http from 'http';
import net from 'net';
import crypto from 'crypto';
import { SignedXml } from 'xml-crypto';

// Step-up authentication (services/stepUp.js), driven against the real server:
// every gated action refused to a stale dashboard session and allowed after a
// step-up; TOTP, password, OIDC (prompt=login + max_age=0, checked against
// auth_time from a stub IdP) and SAML (ForceAuthn, AuthnInstant) step-ups; the
// window expiring; keys and MCP agents needing a person's grant; the signed v3
// identity headers; and the hosted-app return URL.

const REPO = fileURLToPath(new URL('..', import.meta.url));
const ENCRYPTION_KEY = 'b'.repeat(64);
const CRANE_DOMAIN = 'crane.example.test';
const BASE_URL = `https://${CRANE_DOMAIN}`;
const CLIENT_ID = 'crane-step-up-test';
let recoveryCodes;
let child, base, dataDir, idp, idpBase, keyPem, certPem, db, totpLib, mfaSecret, hashApiKey, stepUp;
const codes = new Map();
const U = {};
const APPS = {};

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const { privateKey: oidcKey, publicKey: oidcPub } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...oidcPub.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
function idToken({ sub, nonce, authTime }) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = enc({ iss: idpBase, aud: CLIENT_ID, sub, email: `${sub}@t.test`, email_verified: true, nonce, auth_time: authTime, exp: Math.floor(Date.now() / 1000) + 300 });
  return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), oidcKey).toString('base64url')}`;
}
function startIdp() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const url = new URL(req.url, idpBase);
      const json = (o) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (url.pathname === '/.well-known/openid-configuration') {
        return json({ issuer: idpBase, authorization_endpoint: `${idpBase}/authorize`, token_endpoint: `${idpBase}/token`, jwks_uri: `${idpBase}/jwks` });
      }
      if (url.pathname === '/jwks') return json({ keys: [jwk] });
      if (url.pathname === '/token' && req.method === 'POST') {
        let body = '';
        req.on('data', (d) => { body += d; });
        return req.on('end', () => json({ id_token: idToken(codes.get(new URLSearchParams(body).get('code'))), token_type: 'Bearer' }));
      }
      res.writeHead(404); res.end();
    });
    srv.listen(0, '127.0.0.1', () => { idpBase = `http://127.0.0.1:${srv.address().port}`; resolve(srv); });
  });
}

// The IdP's authorize step. One that honours prompt=login re-authenticates and
// reports auth_time = now; one that ignores it reports the old login.
function idpAuthorize(location, { sub, honour = true }) {
  const loc = new URL(location);
  const reauth = honour && loc.searchParams.get('prompt') === 'login';
  const code = crypto.randomBytes(8).toString('hex');
  codes.set(code, { sub, nonce: loc.searchParams.get('nonce'), authTime: Math.floor(Date.now() / 1000) - (reauth ? 0 : 3600) });
  return `/api/auth/oidc/callback?${new URLSearchParams({ code, state: loc.searchParams.get('state') })}`;
}

function signXml(xml, refXpath, afterXpath) {
  const sig = new SignedXml({
    privateKey: keyPem, publicCert: certPem,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: refXpath,
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.computeSignature(xml, { location: { reference: afterXpath, action: 'after' } });
  return sig.getSignedXml();
}
function samlResponse(nameId, inResponseTo, authnAgeMs) {
  const iso = (ms) => new Date(Date.now() + ms).toISOString();
  const acs = `${BASE_URL}/api/auth/saml/callback`;
  const id = crypto.randomBytes(8).toString('hex');
  const irt = ` InResponseTo="${inResponseTo}"`;
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${id}" Version="2.0" IssueInstant="${iso(0)}" Destination="${acs}"${irt}>`
    + '<saml:Issuer>http://idp.example.test</saml:Issuer>'
    + '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    + `<saml:Assertion ID="_a${id}" Version="2.0" IssueInstant="${iso(0)}">`
    + '<saml:Issuer>http://idp.example.test</saml:Issuer>'
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>`
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${iso(300000)}" Recipient="${acs}"${irt}/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${iso(-60000)}" NotOnOrAfter="${iso(300000)}"><saml:AudienceRestriction><saml:Audience>${BASE_URL}/api/auth/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${iso(-authnAgeMs)}" SessionIndex="_s${id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + '</saml:Assertion></samlp:Response>';
  const assertionSigned = signXml(xml, "//*[local-name(.)='Assertion']", "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']");
  return Buffer.from(signXml(assertionSigned, "/*[local-name(.)='Response']", "/*[local-name(.)='Response']/*[local-name(.)='Issuer']")).toString('base64');
}

before(async () => {
  process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;
  dataDir = mkdtempSync(join(tmpdir(), 'crane-step-up-'));
  process.env.DATA_DIR = dataDir;
  process.env.LOG_LEVEL = 'error';
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=idp.example.test',
    '-keyout', join(dataDir, 'idp.key'), '-out', join(dataDir, 'idp.crt')], { stdio: 'ignore' });
  keyPem = readFileSync(join(dataDir, 'idp.key'), 'utf8');
  certPem = readFileSync(join(dataDir, 'idp.crt'), 'utf8');
  idp = await startIdp();
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO,
    env: {
      ...process.env, DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY, CRANE_DOMAIN, LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  for (let i = 0; i < 160; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const { initDb, getDb } = await import('../server/db.js');
  initDb();
  db = getDb();
  const enc = await import('../server/services/encryption.js');
  hashApiKey = enc.hashApiKey;
  stepUp = await import('../server/services/stepUp.js');
  const mkUser = (name, role, extra = {}) => {
    const key = enc.generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
    const id = Number(db.prepare(`INSERT INTO users (name,email,role,active,kind,api_key_hash,password_hash,sso_sub,saml_name_id)
      VALUES (?,?,?,1,'human',?,?,?,?)`).run(name, `${name}@t.test`, role, hashApiKey(key),
      extra.password ? enc.hashPassword(extra.password) : null, extra.sso_sub || null, extra.saml || null).lastInsertRowid);
    return { id, key, password: extra.password };
  };
  U.admin = mkUser('admin', 'platform_admin', { password: 'admin-password-123' });
  U.owner = mkUser('owner', 'user', { password: 'owner-password-123' });
  U.totp = mkUser('totp', 'user', { password: 'totp-password-123' });
  U.oidc = mkUser('oidc', 'user', { sso_sub: 'oidc-sub' });
  U.other = mkUser('otheroidc', 'user', { sso_sub: 'someone-else' });
  U.saml = mkUser('saml', 'user', { saml: 'saml@t.test' });
  U.target = mkUser('target', 'user');
  const mkApp = (slug, slot) => Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug.toUpperCase(), slug, slot).lastInsertRowid);
  APPS.shop = mkApp('shop', 1);
  APPS.other = mkApp('other', 2);
  APPS.gone = mkApp('gone', 3);
  const role = db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)');
  for (const u of [U.owner, U.totp, U.oidc, U.saml]) { role.run(APPS.shop, u.id, 'owner'); role.run(APPS.other, u.id, 'owner'); }
  role.run(APPS.shop, U.admin.id, 'user');
  role.run(APPS.gone, U.admin.id, 'user');
  for (const [app, env] of [[APPS.shop, 'production'], [APPS.shop, 'sandbox'], [APPS.other, 'production']]) {
    db.prepare('INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?,?,?,?)').run(app, env, 'API_TOKEN', enc.encrypt(`secret-${app}-${env}`));
  }
  const set = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
  set.run('auth_sso_only', 'false');
  set.run('oidc_enabled', '1');
  set.run('oidc_discovery_url', idpBase);
  set.run('oidc_client_id', CLIENT_ID);
  set.run('saml_enabled', '1');
  set.run('saml_idp_sso_url', 'http://idp.example.test/sso');
  set.run('saml_idp_cert_enc', enc.encrypt(certPem.trim()));

  totpLib = await import('../server/services/totp.js');
  const mfa = await import('../server/services/mfa.js');
  const tu = db.prepare('SELECT * FROM users WHERE id = ?').get(U.totp.id);
  mfaSecret = mfa.startEnrollment(db, tu).secret;
  const enrolled = mfa.activateEnrollment(db, tu, totpLib.totp(totpLib.base32Decode(mfaSecret), Date.now() - 30_000));
  assert.equal(enrolled.ok, true);
  recoveryCodes = enrolled.recovery_codes;
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { idp?.close(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

/** A dashboard session that signed in `ageMin` minutes ago. */
function session(userId, ageMin = 30) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(userId, hashApiKey(token));
  db.prepare(`UPDATE identity_sessions SET created_at = datetime('now', '-${ageMin} minutes') WHERE token_hash = ?`).run(hashApiKey(token));
  return token;
}
const ageStepUp = (token, min) => db.prepare(`UPDATE identity_sessions SET step_up_at = strftime('%Y-%m-%d %H:%M:%SZ', 'now', '-${min} minutes') WHERE token_hash = ?`).run(hashApiKey(token));

async function call(auth, method, path, body) {
  const headers = { 'Content-Type': 'application/json', ...(auth.bearer ? { Authorization: `Bearer ${auth.bearer}` } : { 'X-API-Key': auth.key }) };
  const r = await fetch(`${base}${path}`, { method, headers, ...(body !== undefined && { body: JSON.stringify(body) }) });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* not json */ }
  return { status: r.status, body: json, headers: r.headers, text };
}
const bearer = (t) => ({ bearer: t });
let rpcId = 0;
async function mcp(auth, name, args) {
  const r = await call(auth, 'POST', '/api/mcp', { jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: { name, arguments: args } });
  return r.body;
}
const mcpText = (b) => JSON.stringify(b);

function browser() {
  const jar = new Map();
  return {
    jar,
    fetch: async (path, init = {}) => {
      const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      const r = await fetch(path.startsWith('http') ? path : `${base}${path}`, { redirect: 'manual', ...init, headers: { ...(init.headers || {}), ...(cookie && { Cookie: cookie }) } });
      for (const c of r.headers.getSetCookie()) {
        const [pair, ...attrs] = c.split(';');
        const eq = pair.indexOf('=');
        const gone = attrs.some((a) => /^\s*max-age=0\b/i.test(a) || /^\s*expires=thu, 01 jan 1970/i.test(a));
        if (gone) jar.delete(pair.slice(0, eq)); else jar.set(pair.slice(0, eq), pair.slice(eq + 1));
      }
      return r;
    },
  };
}

const freshCode = () => totpLib.totp(totpLib.base32Decode(mfaSecret));
const isStepUp = (r) => r.body?.error?.code === 'STEP_UP_REQUIRED';

// ── every gated action ──────────────────────────────────────────────────────

const GATED = () => [
  ['reveal_production_secret', 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal'],
  ['reveal_production_secret', 'GET', '/api/apps/shop/env/production?reveal=true'],
  ['promote_production', 'POST', '/api/apps/shop/promote', {}],
  ['delete_app', 'DELETE', '/api/apps/gone?confirm=true'],
  ['manage_api_keys', 'POST', '/api/me/api-key/rotate', {}],
  ['manage_api_keys', 'POST', '/api/me/mcp-keys', { label: 'step-up-test' }],
  ['manage_api_keys', 'POST', `/api/users/${U.target.id}/mcp-keys`, { label: 'step-up-test' }],
  ['manage_api_keys', 'POST', `/api/users/${U.target.id}/regenerate-key?confirm=true`, {}],
  ['manage_api_keys', 'POST', '/api/me/app-keys', { slug: 'shop', label: 'step-up-test' }],
  ['security_settings', 'PUT', '/api/auth/scim/config', { enabled: false }],
  ['security_settings', 'POST', '/api/auth/scim/token', {}],
  ['security_settings', 'PUT', '/api/identity/mfa/policy', {}],
  ['security_settings', 'PUT', '/api/settings/auth_sso_only', { value: 'false' }],
  ['security_settings', 'PUT', '/api/api-key-policy', {}],
  ['security_settings', 'PUT', '/api/settings/role-permissions', { matrix: {} }],
  ['security_settings', 'PUT', '/api/identity/step-up/policy', { window_minutes: 10 }],
  ['security_settings', 'PUT', '/api/auth/oidc/config', { enabled: true, discovery_url: idpBase, client_id: CLIENT_ID }],
  ['disable_mfa', 'POST', `/api/identity/mfa/users/${U.target.id}/reset`, {}],
  ['grant_platform_admin', 'PUT', `/api/users/${U.target.id}/role`, { role: 'platform_admin' }],
];

test('every gated action is refused to a session that signed in 30 minutes ago, then allowed after a password step-up', async () => {
  const t = session(U.admin.id, 30);
  for (const [action, method, path, body] of GATED()) {
    const r = await call(bearer(t), method, path, body);
    assert.equal(r.status, 401, `${method} ${path}: ${r.status} ${r.text.slice(0, 200)}`);
    assert.equal(r.body.error.code, 'STEP_UP_REQUIRED', `${method} ${path}`);
    assert.equal(r.body.error.step_up.action, action, `${method} ${path}`);
    assert.deepEqual(r.body.error.step_up.methods, ['password'], `${method} ${path}`);
    assert.equal(r.body.error.step_up.window_minutes, 10);
  }
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'gone'").get().n, 1, 'a refused delete deleted the app');
  assert.equal(db.prepare('SELECT role FROM users WHERE id = ?').get(U.target.id).role, 'user', 'a refused grant made a platform admin');

  const wrong = await call(bearer(t), 'POST', '/api/identity/step-up/password', { password: 'not-it-at-all' });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.error.code, 'INVALID_PASSWORD');
  assert.equal((await call(bearer(t), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 401, 'a wrong password stepped up');
  const ok = await call(bearer(t), 'POST', '/api/identity/step-up/password', { password: U.admin.password });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.body.fresh, true);

  for (const [, method, path, body] of GATED()) {
    const r = await call(bearer(t), method, path, body);
    assert.ok(!isStepUp(r) && r.status !== 401, `${method} ${path} still refused after step-up: ${r.status} ${r.text.slice(0, 200)}`);
  }
  assert.equal(db.prepare('SELECT role FROM users WHERE id = ?').get(U.target.id).role, 'platform_admin');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'gone'").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'step-up' AND user_id = ?").get(U.admin.id).n, 1);
});

test('a session that just signed in counts as recent; the window expires; the window is a platform setting', async () => {
  const t = session(U.owner.id, 0);
  assert.equal((await call(bearer(t), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 200);
  const old = session(U.owner.id, 30);
  assert.equal((await call(bearer(old), 'POST', '/api/identity/step-up/password', { password: U.owner.password })).status, 200);
  assert.equal((await call(bearer(old), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 200);
  ageStepUp(old, 11);
  const expired = await call(bearer(old), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal');
  assert.equal(expired.status, 401, 'an 11-minute-old step-up still counted');
  assert.ok(isStepUp(expired));
  ageStepUp(old, 9);
  assert.equal((await call(bearer(old), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 200, 'a 9-minute-old step-up was refused');

  const admin = session(U.admin.id, 0);
  assert.equal((await call(bearer(admin), 'PUT', '/api/identity/step-up/policy', { window_minutes: 0 })).status, 400);
  assert.equal((await call(bearer(admin), 'PUT', '/api/settings/step_up_window_minutes', { value: '60' })).status, 403, 'the window was writable around its own gate');
  assert.equal((await call(bearer(admin), 'PUT', '/api/identity/step-up/policy', { window_minutes: 30 })).status, 200);
  ageStepUp(old, 20);
  assert.equal((await call(bearer(old), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 200, 'a 30-minute window did not apply');
  assert.equal((await call(bearer(admin), 'PUT', '/api/identity/step-up/policy', { window_minutes: 10 })).status, 200);
  assert.equal((await call(bearer(old), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 401);
});

test('TOTP: an enrolled person steps up with their code only, never with a weaker factor', async () => {
  const t = session(U.totp.id, 30);
  const r = await call(bearer(t), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal');
  assert.equal(r.status, 401);
  assert.deepEqual(r.body.error.step_up.methods, ['totp']);
  const pw = await call(bearer(t), 'POST', '/api/identity/step-up/password', { password: U.totp.password });
  assert.equal(pw.status, 400);
  assert.equal(pw.body.error.code, 'STEP_UP_METHOD_UNAVAILABLE');
  const bad = await call(bearer(t), 'POST', '/api/identity/step-up/totp', { code: '000000' === freshCode() ? '111111' : '000000' });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error.code, 'INVALID_CODE');
  const ok = await call(bearer(t), 'POST', '/api/identity/step-up/totp', { code: freshCode() });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.body.mfa, 'totp');
  const after = await call(bearer(t), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal');
  assert.equal(after.status, 200);
  assert.match(after.body.value, /secret-.*-production/);
});

// ── OIDC and SAML re-login ──────────────────────────────────────────────────

// The popup runs in the dashboard's browser, which holds the session cookie.
function sessionBrowser(cookieToken) {
  const b = browser();
  if (cookieToken) b.jar.set('cc_token', cookieToken);
  return b;
}

async function oidcStepUp(t, { sub, honour = true, cookie = t } = {}) {
  const b = sessionBrowser(cookie);
  const s = await call(bearer(t), 'POST', '/api/identity/step-up/sso', {});
  assert.equal(s.status, 200, s.text);
  assert.equal(s.body.method, 'oidc');
  const go = await b.fetch(s.body.url);
  assert.equal(go.status, 302, `go: ${go.status}`);
  const loc = go.headers.get('location');
  assert.ok(loc.startsWith(`${idpBase}/authorize?`), loc);
  const q = new URL(loc).searchParams;
  assert.equal(q.get('prompt'), 'login');
  assert.equal(q.get('max_age'), '0');
  const cbPath = idpAuthorize(loc, { sub, honour });
  const cb = await b.fetch(cbPath);
  return { cb, html: await cb.text(), b, cbPath, url: s.body.url };
}

test('OIDC: re-login with prompt=login and max_age=0; refused when the IdP did not re-authenticate, or for another account', async () => {
  const t = session(U.oidc.id, 30);
  const st = await call(bearer(t), 'GET', '/api/identity/step-up');
  assert.deepEqual(st.body.methods, ['oidc']);
  assert.equal(st.body.fresh, false);

  const stale = await oidcStepUp(t, { sub: 'oidc-sub', honour: false });
  assert.equal(stale.cb.status, 200);
  assert.match(stale.html, /did not ask you to sign in again/);
  assert.equal((await call(bearer(t), 'GET', '/api/identity/step-up')).body.fresh, false, 'an old IdP login stepped up');

  const wrong = await oidcStepUp(t, { sub: 'someone-else' });
  assert.match(wrong.html, /different account/);
  assert.equal((await call(bearer(t), 'GET', '/api/identity/step-up')).body.fresh, false, 'another account stepped up');

  const ok = await oidcStepUp(t, { sub: 'oidc-sub' });
  assert.match(ok.html, /Signed in/);
  assert.equal((await call(bearer(t), 'GET', '/api/identity/step-up')).body.fresh, true);
  assert.equal((await call(bearer(t), 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 200);

  ageStepUp(t, 30);
  const again = await ok.b.fetch(ok.url);
  assert.equal(again.status, 200, 'a used step-up link started another IdP round');
  assert.equal((await call(bearer(t), 'GET', '/api/identity/step-up')).body.fresh, false);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'step-up-refused' AND user_id = ?").get(U.oidc.id).n, 2);
});

async function samlStepUp(t, nameId, authnAgeMs, cookie = t) {
  const b = sessionBrowser(cookie);
  const s = await call(bearer(t), 'POST', '/api/identity/step-up/sso', {});
  assert.equal(s.body.method, 'saml', s.text);
  const go = await b.fetch(s.body.url);
  assert.equal(go.status, 302);
  const loc = new URL(go.headers.get('location'));
  const request = inflateRawSync(Buffer.from(loc.searchParams.get('SAMLRequest'), 'base64')).toString();
  assert.match(request, /ForceAuthn="true"/);
  const fields = { SAMLResponse: samlResponse(nameId, / ID="([^"]+)"/.exec(request)[1], authnAgeMs), RelayState: loc.searchParams.get('RelayState') };
  const cb = await b.fetch('/api/auth/saml/callback', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields) });
  return { cb, html: await cb.text() };
}

test('SAML: re-login with ForceAuthn; refused when AuthnInstant predates the request', async () => {
  const t = session(U.saml.id, 30);
  const stale = await samlStepUp(t, 'saml@t.test', 3600_000);
  assert.equal(stale.cb.status, 200);
  assert.match(stale.html, /did not ask you to sign in again/);
  assert.equal((await call(bearer(t), 'GET', '/api/identity/step-up')).body.fresh, false);
  const ok = await samlStepUp(t, 'saml@t.test', 0);
  assert.match(ok.html, /Signed in/, ok.html.slice(0, 300));
  assert.equal((await call(bearer(t), 'GET', '/api/identity/step-up')).body.fresh, true);
});

test('IdP step-up finishes only in the browser holding the session that asked for it', async () => {
  const t = session(U.oidc.id, 30);
  const fresh = async () => (await call(bearer(t), 'GET', '/api/identity/step-up')).body.fresh;

  // A browser without the session cookie (someone sent the link elsewhere).
  const s1 = await call(bearer(t), 'POST', '/api/identity/step-up/sso', {});
  const go1 = await browser().fetch(s1.body.url);
  assert.equal(go1.status, 200, 'the IdP round started in a browser without the session');
  assert.match(await go1.text(), /same browser/);

  // A browser holding a different session of the same user.
  const other = session(U.oidc.id, 30);
  const s2 = await call(bearer(t), 'POST', '/api/identity/step-up/sso', {});
  const go2 = await sessionBrowser(other).fetch(s2.body.url);
  assert.equal(go2.status, 200, 'the IdP round started under another session');

  // The cookie changes between the start and the callback.
  const s3 = await call(bearer(t), 'POST', '/api/identity/step-up/sso', {});
  const b3 = sessionBrowser(t);
  const go3 = await b3.fetch(s3.body.url);
  assert.equal(go3.status, 302);
  const cbPath = idpAuthorize(go3.headers.get('location'), { sub: 'oidc-sub' });
  b3.jar.set('cc_token', other);
  const cb3 = await b3.fetch(cbPath);
  assert.match(await cb3.text(), /same browser/);
  assert.equal(await fresh(), false, 'a step-up finished under another session');

  const st = session(U.saml.id, 30);
  const ss = await call(bearer(st), 'POST', '/api/identity/step-up/sso', {});
  assert.equal(ss.body.method, 'saml');
  const sgo = await browser().fetch(ss.body.url);
  assert.equal(sgo.status, 200, 'the SAML round started in a browser without the session');
  assert.match(await sgo.text(), /same browser/);
  assert.equal((await call(bearer(st), 'GET', '/api/identity/step-up')).body.fresh, false, 'SAML stepped up without the session cookie');

  const ok = await oidcStepUp(t, { sub: 'oidc-sub' });
  assert.match(ok.html, /Signed in/);
  assert.equal(await fresh(), true);
});

// ── keys and agents ─────────────────────────────────────────────────────────

test('API keys and MCP agents: production reveal and delete need a person\'s grant; promote does not', async () => {
  const key = { key: U.owner.key };
  const r = await call(key, 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal');
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'STEP_UP_REQUIRED');
  assert.equal(r.body.error.step_up.mode, 'grant');
  assert.equal(r.body.error.step_up.grant_url, `${BASE_URL}/step-up?grant=reveal_production_secret&app=shop`);
  assert.equal((await call(key, 'POST', '/api/apps/shop/env/sandbox/API_TOKEN/reveal')).status, 200, 'sandbox reveal changed');
  assert.ok(!isStepUp(await call(key, 'POST', '/api/apps/shop/promote', {})), 'promote by key needs a step-up');
  const selfRotate = await call(key, 'POST', '/api/me/api-key/rotate', {});
  assert.ok(!isStepUp(selfRotate) && selfRotate.status === 200, 'a key rotating itself needs a step-up');
  const restKey = { key: selfRotate.body.api_key };

  const mcpKey = `dhk_mcp_${crypto.randomBytes(16).toString('hex')}`;
  db.prepare('INSERT INTO user_mcp_keys (user_id, key_hash, label) VALUES (?, ?, ?)').run(U.owner.id, hashApiKey(mcpKey), 'agent');
  const agent = { key: mcpKey };
  assert.match(mcpText(await mcp(agent, 'appcrane_reveal_secret', { slug: 'shop', env: 'production', key: 'API_TOKEN' })), /STEP_UP_REQUIRED/);
  assert.match(mcpText(await mcp(agent, 'appcrane_reveal_secret', { slug: 'shop', env: 'sandbox', key: 'API_TOKEN' })), /secret-.*-sandbox/);
  assert.match(mcpText(await mcp(agent, 'appcrane_delete_app', { slug: 'other', confirm_slug: 'other' })), /STEP_UP_REQUIRED/);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM apps WHERE slug = 'other'").get().n, 1);
  // Reading a production container's files is a production-secret read too.
  const catProd = { slug: 'shop', env: 'production', path: '/app/.env' };
  assert.match(mcpText(await mcp(agent, 'appcrane_cat', catProd)), /STEP_UP_REQUIRED/);
  const viewerKey = `dhk_user_${crypto.randomBytes(16).toString('hex')}`;
  const viewer = Number(db.prepare("INSERT INTO users (name,email,role,active,kind,api_key_hash) VALUES ('catviewer','catviewer@t.test','user',1,'human',?)").run(hashApiKey(viewerKey)).lastInsertRowid);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(APPS.shop, viewer);
  assert.match(mcpText(await mcp({ key: viewerKey }, 'appcrane_cat', catProd)), /Forbidden: reading a production container/);

  // The grant: from a dashboard session, itself behind a fresh step-up.
  const stale = session(U.owner.id, 30);
  const g0 = await call(bearer(stale), 'POST', '/api/identity/step-up/grants', { action: 'reveal_production_secret', slug: 'shop' });
  assert.equal(g0.status, 401);
  assert.ok(isStepUp(g0));
  assert.equal((await call(restKey, 'POST', '/api/identity/step-up/grants', { action: 'reveal_production_secret', slug: 'shop' })).body.error.code, 'STEP_UP_SESSION_ONLY');
  const t = session(U.owner.id, 0);
  assert.equal((await call(bearer(t), 'POST', '/api/identity/step-up/grants', { action: 'promote_production', slug: 'shop' })).status, 400, 'a grant for an allowed action');
  const g = await call(bearer(t), 'POST', '/api/identity/step-up/grants', { action: 'reveal_production_secret', slug: 'shop' });
  assert.equal(g.status, 200, g.text);
  assert.equal(g.body.minutes, 10);

  assert.equal((await call(restKey, 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 200, 'the grant did not reach the REST key');
  assert.match(mcpText(await mcp(agent, 'appcrane_reveal_secret', { slug: 'shop', env: 'production', key: 'API_TOKEN' })), /secret-.*-production/);
  assert.match(mcpText(await mcp(agent, 'appcrane_reveal_secret', { slug: 'other', env: 'production', key: 'API_TOKEN' })), /STEP_UP_REQUIRED/, 'a grant for shop opened other');
  assert.doesNotMatch(mcpText(await mcp(agent, 'appcrane_cat', catProd)), /STEP_UP_REQUIRED|Forbidden/, 'the grant did not reach appcrane_cat');
  assert.equal((await call({ key: U.totp.key }, 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 403, 'one person\'s grant opened another\'s key');

  db.prepare("UPDATE step_up_grants SET expires_at = strftime('%Y-%m-%d %H:%M:%SZ', 'now', '-1 minutes') WHERE id = ?").run(g.body.id);
  assert.equal((await call(restKey, 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 403, 'an expired grant still worked');
  const g2 = await call(bearer(t), 'POST', '/api/identity/step-up/grants', { action: 'reveal_production_secret', slug: 'shop' });
  assert.equal((await call(bearer(t), 'DELETE', `/api/identity/step-up/grants/${g2.body.id}`)).status, 200);
  assert.equal((await call(restKey, 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal')).status, 403, 'a revoked grant still worked');

  // A dashboard session talking MCP is a session: it steps up like one.
  assert.match(mcpText(await mcp(bearer(stale), 'appcrane_reveal_secret', { slug: 'shop', env: 'production', key: 'API_TOKEN' })), /signed in within the last 10 minutes/);
  assert.match(mcpText(await mcp(bearer(t), 'appcrane_reveal_secret', { slug: 'shop', env: 'production', key: 'API_TOKEN' })), /secret-.*-production/);
});

// ── hosted apps: signed auth time ───────────────────────────────────────────

test('verify signs X-AppCrane-Auth-Time and -Auth-Mfa with v3; tampering is detected; v1 and v2 are unchanged', async () => {
  const { verifyIdentity } = await import('../packages/tenant/index.js');
  const { identitySecretFor } = await import('../server/services/identitySignature.js');
  const secret = identitySecretFor(db, APPS.shop, 'production');
  const t = session(U.totp.id, 30);
  const before = await call(bearer(t), 'GET', '/api/identity/verify?app=shop');
  assert.equal(before.status, 200, before.text);
  const created = Math.floor(stepUp.rowAuthTimeMs(db.prepare('SELECT * FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(t))) / 1000);
  const h0 = Object.fromEntries(before.headers);
  assert.equal(h0['x-appcrane-auth-time'], String(created));
  assert.equal(h0['x-appcrane-auth-mfa'], 'none');
  const id0 = verifyIdentity(h0, { secret, requireV3: true });
  assert.equal(id0.authTime, created);

  // The TOTP step was spent by the TOTP test; a recovery code is the other factor.
  const su = await call(bearer(t), 'POST', '/api/identity/step-up/totp', { code: recoveryCodes[0] });
  assert.equal(su.status, 200, su.text);
  const h = Object.fromEntries((await call(bearer(t), 'GET', '/api/identity/verify?app=shop')).headers);
  const id = verifyIdentity(h, { secret, requireV3: true });
  assert.ok(Math.abs(id.authTime - Math.floor(Date.now() / 1000)) <= 5, `auth time ${id.authTime} is not the step-up`);
  assert.equal(id.mfa, 'recovery_code');

  assert.throws(() => verifyIdentity({ ...h0, 'x-appcrane-auth-time': String(Math.floor(Date.now() / 1000)) }, { secret }), /signature/);
  assert.throws(() => verifyIdentity({ ...h0, 'x-appcrane-auth-mfa': 'totp' }, { secret }), /signature/);
  const v2 = { ...h };
  delete v2['x-appcrane-identity-sig-v3'];
  assert.equal(verifyIdentity(v2, { secret }).authTime, null);
  const v1 = { ...v2 };
  delete v1['x-appcrane-identity-sig-v2'];
  assert.equal(verifyIdentity(v1, { secret }).userId, String(U.totp.id));

  const byKey = Object.fromEntries((await call({ key: U.totp.key }, 'GET', '/api/identity/verify?app=shop')).headers);
  assert.equal(byKey['x-appcrane-auth-time'], undefined, 'a key claimed an interactive authentication');
  assert.equal(verifyIdentity(byKey, { secret, requireV3: true }).authTime, null);
});

test('an app-host session (per-app origins) reports the auth time of the platform session it came from', () => {
  const parent = session(U.owner.id, 30);
  const appToken = crypto.randomBytes(32).toString('base64url');
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at, scope, app_env, parent_token_hash)
    VALUES (?, ?, ?, datetime('now', '+1 hour'), 'app', 'production', ?)`).run(U.owner.id, hashApiKey(appToken), APPS.shop, hashApiKey(parent));
  const before = stepUp.sessionAuth(db, hashApiKey(appToken)).authTimeMs;
  assert.ok(Date.now() - before > 25 * 60_000, 'the app session reported its own creation time');
  stepUp.recordStepUp(db, hashApiKey(parent), 'password');
  assert.ok(Date.now() - stepUp.sessionAuth(db, hashApiKey(appToken)).authTimeMs < 5000, 'a platform step-up did not reach the app session');
});

test('the Caddy identity strip and copy cover the new headers', () => {
  const src = readFileSync(join(REPO, 'server/services/caddy.js'), 'utf8');
  const list = src.slice(src.indexOf('const IDENTITY_HEADERS = ['), src.indexOf('];', src.indexOf('const IDENTITY_HEADERS = [')));
  for (const hdr of ['X-AppCrane-Auth-Time', 'X-AppCrane-Auth-Mfa', 'X-AppCrane-Identity-Sig-V3']) assert.ok(list.includes(`'${hdr}'`), hdr);
});

// ── hosted apps: step-up with a return URL ──────────────────────────────────

test('app step-up: the return URL must be the app\'s own; the person comes back only after a step-up begun after the app asked', async () => {
  const t = session(U.owner.id, 0);
  const b = browser();
  b.jar.set('cc_token', t);
  const go = (ret, app = 'shop') => b.fetch(`/api/identity/step-up/app?${new URLSearchParams({ app, return: ret })}`);
  for (const bad of ['//evil.test/shop/', 'https://evil.test/shop/', `https://${CRANE_DOMAIN}.evil.test/shop/`, '/other/pay', '/shop/../settings',
    '/shop%2f..%2fsettings/../../settings', '/shopx/a', 'javascript:alert(1)', '/\\evil.test', `https://u:p@${CRANE_DOMAIN}/shop/`, 'shop/pay', '/settings']) {
    const r = await go(bad);
    assert.equal(r.status, 400, `accepted return ${bad}: ${r.status} ${r.headers.get('location')}`);
  }
  assert.equal((await go('/shop/pay', 'nope')).status, 400);
  const anon = await fetch(`${base}/api/identity/step-up/app?${new URLSearchParams({ app: 'shop', return: '/shop/pay' })}`, { redirect: 'manual' });
  assert.equal(anon.status, 302);
  assert.match(anon.headers.get('location'), /^\/login\?redirect=%2Fapi%2Fidentity%2Fstep-up%2Fapp/);

  const r = await go(`https://${CRANE_DOMAIN}/shop-sandbox/pay?x=1`);
  assert.equal(r.status, 302);
  const handle = new URL(r.headers.get('location'), base).searchParams.get('h');
  assert.ok(handle && handle.length >= 32, 'handle is not opaque');
  assert.equal(new URL(r.headers.get('location'), base).pathname, '/step-up');
  const d = await call(bearer(t), 'POST', '/api/identity/step-up/app/describe', { h: handle });
  assert.equal(d.body.env, 'sandbox');
  assert.equal((await call(bearer(session(U.admin.id, 0)), 'POST', '/api/identity/step-up/app/complete', { h: handle })).status, 404, 'another person used the handle');
  const early = await call(bearer(t), 'POST', '/api/identity/step-up/app/complete', { h: handle });
  assert.equal(early.status, 401, 'a session from before the app asked went straight back');
  assert.ok(isStepUp(early));
  assert.equal((await call(bearer(t), 'POST', '/api/identity/step-up/password', { password: U.owner.password })).status, 200);
  const done = await call(bearer(t), 'POST', '/api/identity/step-up/app/complete', { h: handle });
  assert.equal(done.status, 200, done.text);
  assert.equal(done.body.return_url, '/shop-sandbox/pay?x=1');
  assert.equal((await call(bearer(t), 'POST', '/api/identity/step-up/app/complete', { h: handle })).status, 404, 'a handle was used twice');
});

test('app step-up return URL with per-app origins and a custom domain', () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('app_isolation_domain', 'apps.example.test')").run();
  db.prepare("UPDATE apps SET domain = 'shop.example.test', custom_domain_auth = 1 WHERE slug = 'shop'").run();
  try {
    const v = (u) => stepUp.validateAppReturn(db, 'shop', u);
    assert.equal(v('https://shop.apps.example.test/pay').env, 'production');
    assert.equal(v('https://shop-sandbox.apps.example.test/x').env, 'sandbox');
    assert.equal(v('https://shop.example.test/x').env, 'production');
    for (const bad of ['https://other.apps.example.test/', 'https://shop.apps.example.test.evil.test/', 'http://shop.apps.example.test/',
      '/shop/pay', 'https://u:p@shop.apps.example.test/', 'http://shop.example.test/x', 'https://evil.shop.apps.example.test/', `https://${CRANE_DOMAIN}/shop/`]) {
      assert.equal(v(bad), null, `accepted ${bad}`);
    }
  } finally {
    db.prepare("DELETE FROM settings WHERE key = 'app_isolation_domain'").run();
    db.prepare("UPDATE apps SET domain = NULL, custom_domain_auth = 0 WHERE slug = 'shop'").run();
  }
});
