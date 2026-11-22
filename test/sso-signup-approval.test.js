import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import net from 'net';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { isPublicProvider, parseAllowedDomains, signupRefusal, publicProviderVouches, GOOGLE_DISCOVERY_URL } from '../server/services/ssoSignupDomains.js';

// SSO sign-up (auto-provision) with a "join without approval" list: a verified
// email on the list gets an account at once; anyone else is queued for a
// platform admin, who approves (account created, next sign-in works) or
// denies. Driven against the real server with a stub OIDC IdP.

const REPO = fileURLToPath(new URL('..', import.meta.url));
const ENCRYPTION_KEY = 'f'.repeat(64);
const CLIENT_ID = 'crane-signup-test';
let child, base, dataDir, idp, idpBase, nonce;
let claims = {};

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const ADMIN_SESS = `sess_${crypto.randomBytes(16).toString('hex')}`;
const USER_SESS = `sess_${crypto.randomBytes(16).toString('hex')}`;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const { privateKey: oidcKey, publicKey: oidcPub } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...oidcPub.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
function idToken() {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = enc({ iss: idpBase, aud: CLIENT_ID, nonce, exp: Math.floor(Date.now() / 1000) + 300, ...claims });
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
        req.resume();
        return req.on('end', () => json({ id_token: idToken(), access_token: 'at', token_type: 'Bearer' }));
      }
      res.writeHead(404); res.end();
    });
    srv.listen(0, '127.0.0.1', () => { idpBase = `http://127.0.0.1:${srv.address().port}`; resolve(srv); });
  });
}

const dbw = () => new Database(join(dataDir, 'deployhub.db'));
function q(sql, ...args) { const db = dbw(); try { return db.prepare(sql).get(...args); } finally { db.close(); } }

async function call(method, path, { token, body } = {}) {
  const h = { 'Content-Type': 'application/json' };
  if (token) h.Authorization = `Bearer ${token}`;
  const res = await fetch(base + path, { method, headers: h, redirect: 'manual', body: body === undefined ? undefined : JSON.stringify(body) });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json };
}

/** One SSO sign-in as `who`; returns { error, session }. */
async function signIn(who) {
  claims = who;
  const start = await fetch(`${base}/api/auth/oidc/start`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const loc = new URL(start.headers.get('location'));
  nonce = loc.searchParams.get('nonce');
  const cookie = start.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  const cb = await fetch(`${base}/api/auth/oidc/callback?${new URLSearchParams({ code: 'c', state: loc.searchParams.get('state') })}`, { redirect: 'manual', headers: { Cookie: cookie } });
  assert.equal(cb.status, 302);
  return {
    error: new URL(cb.headers.get('location')).searchParams.get('sso_error'),
    session: cb.headers.getSetCookie().some((c) => c.startsWith('cc_token=')),
  };
}

const saveConfig = (allowed_domains) => call('PUT', '/api/auth/oidc/config', {
  token: ADMIN_SESS,
  body: { enabled: true, discovery_url: idpBase, client_id: CLIENT_ID, provider_name: 'Test', auto_provision: true, allowed_domains },
});

const OK = { sub: 'sub-ok', email: 'pat@allowed.example', email_verified: true, name: 'Pat Allowed' };
const LISTED = { sub: 'sub-listed', email: 'kim@gmail.example', email_verified: true, name: 'Kim Listed' };
const OUTSIDER = { sub: 'sub-out', email: 'sam@other.example', email_verified: true, name: 'Sam Outsider' };
const DENIED = { sub: 'sub-deny', email: 'lee@other.example', email_verified: true, name: 'Lee Denied' };
const UNVERIFIED = { sub: 'sub-unv', email: 'max@allowed.example', email_verified: false, name: 'Max Unverified' };

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-sso-signup-'));
  idp = await startIdp();
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO,
    env: {
      ...process.env, DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY, CRANE_DOMAIN: 'app.example.com', LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const db = dbw();
  const ins = db.prepare("INSERT INTO users (name,email,role,active,kind) VALUES (?,?,?,1,'human')");
  const admin = ins.run('admin', 'admin@example.com', 'platform_admin').lastInsertRowid;
  const user = ins.run('plain', 'plain@example.com', 'user').lastInsertRowid;
  const sess = db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))");
  sess.run(admin, sha(ADMIN_SESS));
  sess.run(user, sha(USER_SESS));
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { idp?.close(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

test('with a public provider a domain entry needs the hosted-domain claim; a single address does not', () => {
  const allowed = parseAllowedDomains('allowed.example, kim@gmail.example');
  const g = { emailVerified: true, allowed, requireHostedDomain: true };
  // A consumer Google account made on a work address: verified, but no hd.
  assert.equal(signupRefusal({ ...g, email: 'ex@allowed.example' }), 'domain_not_allowed');
  assert.equal(signupRefusal({ ...g, email: 'ex@allowed.example', hostedDomain: 'other.example' }), 'domain_not_allowed');
  assert.equal(signupRefusal({ ...g, email: 'pat@allowed.example', hostedDomain: 'Allowed.Example' }), null);
  assert.equal(signupRefusal({ ...g, email: 'kim@gmail.example' }), null);
  assert.equal(signupRefusal({ ...g, email: 'ex@allowed.example', emailVerified: false, hostedDomain: 'allowed.example' }), 'email_unverified');
  // Other IdPs keep matching on the verified email's domain.
  assert.equal(signupRefusal({ email: 'ex@allowed.example', emailVerified: true, allowed }), null);
});

test('Google links an existing account by email only for gmail.com or a matching hd claim', () => {
  assert.equal(publicProviderVouches({ email: 'Kim@Gmail.com' }), true);
  assert.equal(publicProviderVouches({ email: 'kim@googlemail.com' }), true);
  assert.equal(publicProviderVouches({ email: 'pat@work.example', hostedDomain: 'Work.Example' }), true);
  // A consumer Google account on a work address: verified, but no hd.
  assert.equal(publicProviderVouches({ email: 'admin@work.example' }), false);
  assert.equal(publicProviderVouches({ email: 'admin@work.example', hostedDomain: 'other.example' }), false);
  assert.equal(publicProviderVouches({ email: 'admin@sub.work.example', hostedDomain: 'work.example' }), false);
  assert.equal(publicProviderVouches({ email: '' }), false);
});

test('the OIDC callback links by email for Google only when Google vouches for the address', () => {
  const src = readFileSync(join(REPO, 'server/routes/oidc.js'), 'utf8');
  assert.match(src, /linkByEmail: !isPublicProvider\(cfg\.discovery_url\) \|\| publicProviderVouches\(\{ email, hostedDomain: claims\.hd \}\)/);
});

test('the domain list: domains, single addresses, * and the public-provider check', () => {
  assert.deepEqual(parseAllowedDomains(' Allowed.Example, @x.example\nkim@Gmail.example ,,'), ['allowed.example', 'x.example', 'kim@gmail.example']);
  const allowed = parseAllowedDomains('allowed.example, kim@gmail.example');
  assert.equal(signupRefusal({ email: 'a@allowed.example', emailVerified: true, allowed }), null);
  assert.equal(signupRefusal({ email: 'kim@gmail.example', emailVerified: true, allowed }), null);
  assert.equal(signupRefusal({ email: 'jo@gmail.example', emailVerified: true, allowed }), 'domain_not_allowed');
  assert.equal(signupRefusal({ email: 'a@allowed.example.evil', emailVerified: true, allowed }), 'domain_not_allowed');
  assert.equal(signupRefusal({ email: 'a@allowed.example', emailVerified: false, allowed }), 'email_unverified');
  assert.equal(signupRefusal({ email: 'any@where.example', emailVerified: false, allowed: ['*'] }), 'email_unverified');
  assert.equal(signupRefusal({ emailVerified: true, allowed: ['*'] }), 'email_unverified');
  assert.equal(signupRefusal({ email: 'any@where.example', emailVerified: true, allowed: [] }), null);
  assert.equal(isPublicProvider(GOOGLE_DISCOVERY_URL), true);
  assert.equal(isPublicProvider('https://example.okta.com/.well-known/openid-configuration'), false);
});

test('admin config hands back the redirect URI and the saved list; non-admins cannot read it', async () => {
  assert.equal((await saveConfig('allowed.example, kim@gmail.example')).status, 200);
  const r = await call('GET', '/api/auth/oidc/admin-config', { token: ADMIN_SESS });
  assert.equal(r.status, 200);
  assert.equal(r.body.redirect_uri, 'https://app.example.com/api/auth/oidc/callback');
  assert.equal(r.body.allowed_domains, 'allowed.example, kim@gmail.example');
  assert.equal((await call('GET', '/api/auth/oidc/admin-config', { token: USER_SESS })).status, 403);
});

test('OIDC turned on with no client ID is refused, and a stored one neither shows a button nor requires SSO', async () => {
  const half = await call('PUT', '/api/auth/oidc/config', {
    token: ADMIN_SESS,
    body: { enabled: true, discovery_url: 'https://accounts.google.com/.well-known/openid-configuration', client_id: '', provider_name: 'Google', auto_provision: true },
  });
  assert.equal(half.status, 400);
  assert.equal(half.body.error.code, 'VALIDATION');
  assert.equal(q("SELECT value FROM settings WHERE key='oidc_client_id'").value, CLIENT_ID, 'a refused save changed nothing');

  // A half setup saved before this check existed (what locked an admin out).
  const db = dbw();
  db.prepare("UPDATE settings SET value='' WHERE key='oidc_client_id'").run();
  db.close();
  try {
    assert.equal((await call('GET', '/api/auth/oidc/config')).body.enabled, false, 'login page offers a button that cannot work');
    const { ssoProviderConfigured } = await import('../server/services/authPolicy.js');
    const ro = dbw();
    try { assert.equal(ssoProviderConfigured(ro), false, 'a provider with no client ID puts SSO-only in force'); } finally { ro.close(); }
  } finally {
    assert.equal((await saveConfig('allowed.example, kim@gmail.example')).status, 200);
  }
  assert.equal((await call('GET', '/api/auth/oidc/config')).body.enabled, true);
});

test('turning on the first SSO provider leaves password sign-in on; later saves keep the admin\'s choice', async () => {
  const set = (k, v) => { const db = dbw(); try {
    if (v === null) db.prepare('DELETE FROM settings WHERE key = ?').run(k);
    else db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
  } finally { db.close(); } };
  const ssoOnly = () => q("SELECT value FROM settings WHERE key='auth_sso_only'")?.value ?? null;

  // No provider yet and the switch at its default (no row = on).
  set('oidc_enabled', '0'); set('saml_enabled', null); set('auth_sso_only', null);
  const first = await saveConfig('allowed.example, kim@gmail.example');
  assert.equal(first.status, 200);
  assert.equal(first.body.sso_only_turned_off, true);
  assert.equal(ssoOnly(), 'false', 'the first provider put SSO-only in force before anyone tried it');

  // The admin turns it on after checking SSO works; saving OIDC again keeps it.
  set('auth_sso_only', 'true');
  const again = await saveConfig('allowed.example, kim@gmail.example');
  assert.equal(again.body.sso_only_turned_off, false);
  assert.equal(ssoOnly(), 'true', 'a later save undid the admin\'s choice');

  assert.ok(q("SELECT 1 FROM audit_log WHERE action='sso-enforce-set' AND detail LIKE '%first-provider%'"), 'the change was not audited');

  // An admin who chose SSO-only, turned every provider off and then OIDC back on keeps their choice.
  set('oidc_enabled', '0'); set('auth_sso_only', 'true');
  assert.equal((await saveConfig('allowed.example, kim@gmail.example')).body.sso_only_turned_off, false);
  assert.equal(ssoOnly(), 'true', 'a stored choice was overwritten');

  // SAML already in force: adding OIDC does not loosen it.
  set('oidc_enabled', '0'); set('saml_enabled', '1');
  assert.equal((await saveConfig('allowed.example, kim@gmail.example')).body.sso_only_turned_off, false);
  assert.equal(ssoOnly(), 'true');
  set('saml_enabled', null);
});

test('the login page is told when the provider is Google, so it can show the G mark', async () => {
  assert.equal((await call('GET', '/api/auth/oidc/config')).body.google, false);
  const g = await call('PUT', '/api/auth/oidc/config', {
    token: ADMIN_SESS,
    body: { enabled: true, discovery_url: 'https://accounts.google.com/.well-known/openid-configuration', client_id: 'x.apps.googleusercontent.com', provider_name: 'Google', auto_provision: true, allowed_domains: '' },
  });
  try {
    assert.equal(g.status, 200);
    assert.equal((await call('GET', '/api/auth/oidc/config')).body.google, true);
  } finally {
    assert.equal((await saveConfig('allowed.example, kim@gmail.example')).status, 200);
  }
});

test('a verified email on the list signs up at once, by domain or by address', async () => {
  // A domain entry admits only once DNS-verified (services/domainVerification.js).
  const db = dbw();
  try { db.prepare("UPDATE sso_domains SET status = 'verified' WHERE domain = 'allowed.example'").run(); } finally { db.close(); }
  for (const who of [OK, LISTED]) {
    const r = await signIn(who);
    assert.equal(r.error, null, who.email);
    assert.ok(r.session, who.email);
    assert.ok(q('SELECT id FROM users WHERE sso_sub = ?', who.sub), `${who.email} has no account`);
  }
});

test('an unverified email on a listed domain gets no account and is not queued', async () => {
  const r = await signIn(UNVERIFIED);
  assert.equal(r.error, 'email_unverified');
  assert.equal(r.session, false);
  assert.equal(q('SELECT id FROM users WHERE sso_sub = ?', UNVERIFIED.sub), undefined);
  assert.equal(q('SELECT id FROM sso_signup_requests WHERE subject = ?', UNVERIFIED.sub), undefined);
});

test('someone outside the list is queued, then gets in once an admin approves', async () => {
  let r = await signIn(OUTSIDER);
  assert.equal(r.error, 'pending_approval');
  assert.equal(r.session, false);
  assert.equal(q('SELECT id FROM users WHERE sso_sub = ?', OUTSIDER.sub), undefined, 'an account was created before approval');
  r = await signIn(OUTSIDER);
  assert.equal(r.error, 'pending_approval', 'a second sign-in still waits');
  assert.equal(q('SELECT COUNT(*) n FROM sso_signup_requests WHERE subject = ?', OUTSIDER.sub).n, 1, 'a second sign-in made a second request');

  const list = await call('GET', '/api/auth/oidc/signup-requests', { token: ADMIN_SESS });
  const req = list.body.requests.find((x) => x.email === OUTSIDER.email);
  assert.ok(req, 'the request is not listed');
  assert.equal((await call('POST', `/api/auth/oidc/signup-requests/${req.id}/approve`, { token: USER_SESS, body: { email: req.email } })).status, 403, 'a non-admin approved');
  assert.equal(q('SELECT id FROM users WHERE sso_sub = ?', OUTSIDER.sub), undefined);

  const ok = await call('POST', `/api/auth/oidc/signup-requests/${req.id}/approve`, { token: ADMIN_SESS, body: { email: req.email } });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  const u = q('SELECT role, email FROM users WHERE sso_sub = ?', OUTSIDER.sub);
  assert.deepEqual({ ...u }, { role: 'user', email: OUTSIDER.email });
  assert.ok(q("SELECT id FROM audit_log WHERE action = 'sso-signup-approved'"), 'approval not audited');

  r = await signIn(OUTSIDER);
  assert.equal(r.error, null);
  assert.ok(r.session, 'approved person got no session');
  assert.equal((await call('POST', `/api/auth/oidc/signup-requests/${req.id}/approve`, { token: ADMIN_SESS, body: { email: req.email } })).status, 409);
});

test('a denied person stays out until an admin approves them after all', async () => {
  assert.equal((await signIn(DENIED)).error, 'pending_approval');
  const id = q('SELECT id FROM sso_signup_requests WHERE subject = ?', DENIED.sub).id;
  assert.equal((await call('POST', `/api/auth/oidc/signup-requests/${id}/deny`, { token: ADMIN_SESS })).status, 200);
  const r = await signIn(DENIED);
  assert.equal(r.error, 'signup_denied');
  assert.equal(r.session, false);
  assert.equal(q('SELECT id FROM users WHERE sso_sub = ?', DENIED.sub), undefined);
  const denied = await call('GET', '/api/auth/oidc/signup-requests?status=denied', { token: ADMIN_SESS });
  assert.ok(denied.body.requests.some((x) => x.email === DENIED.email));
  assert.equal((await call('POST', `/api/auth/oidc/signup-requests/${id}/approve`, { token: ADMIN_SESS, body: { email: DENIED.email } })).status, 200);
  assert.ok((await signIn(DENIED)).session);
});

test('* lets anyone with a verified email sign up, and no one with an unverified one', async () => {
  assert.equal((await saveConfig('*')).status, 200);
  const unv = await signIn({ sub: 'sub-star-unv', email: 'claim@anything.example', email_verified: false, name: 'Unverified' });
  assert.equal(unv.error, 'email_unverified');
  assert.equal(unv.session, false);
  assert.equal(q('SELECT id FROM users WHERE sso_sub = ?', 'sub-star-unv'), undefined);
  const r = await signIn({ sub: 'sub-star', email: 'new@anything.example', email_verified: true, name: 'Star' });
  assert.equal(r.error, null);
  assert.ok(r.session);
});
