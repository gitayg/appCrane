import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { inflateRawSync } from 'zlib';
import http from 'http';
import net from 'net';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { SignedXml } from 'xml-crypto';

// SSO login CSRF. An attacker starts a login, completes it at the IdP as
// themselves, and hands the victim the last step: the OIDC callback URL, or an
// auto-submitting form with the SAMLResponse. The victim's browser then holds the
// attacker's session, and whatever they do lands in the attacker's account.
//
// Reproduced before the fix in real Chrome against the real server behind TLS,
// from an attacker's page on another site, for both protocols. These tests drive
// the same steps against the real server process, with a stub IdP and one cookie
// jar per browser; a jar does not apply SameSite, so what the attributes do in a
// browser (popup, iframe, cross-site POST) was measured in Chrome and is not
// proven here. No external network.

const ENCRYPTION_KEY = 'e'.repeat(64);
const CRANE_DOMAIN = 'app.example.com';
const BASE_URL = `https://${CRANE_DOMAIN}`;
const CLIENT_ID = 'crane-csrf-test';
const OIDC_COOKIE = '__Host-cc_oidc_bind';
const SAML_COOKIE = '__Host-cc_saml_bind';
const USERS = {
  alice: { sub: 'alice-sub', email: 'alice@example.com', email_verified: true, name: 'Alice Example' },
  mallory: { sub: 'mallory-sub', email: 'mallory@example.com', email_verified: true, name: 'Mallory Example' },
};
let child, base, dataDir, idp, idpBase, keyPem, certPem;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// ---- stub OIDC IdP: a code remembers who signed in and the nonce they were sent
const { privateKey: oidcKey, publicKey: oidcPub } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...oidcPub.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
const codes = new Map();
const nonceOverride = { active: false, value: undefined };

function idToken(user, nonce) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const claimed = nonceOverride.active ? nonceOverride.value : nonce;
  const h = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = enc({ iss: idpBase, aud: CLIENT_ID, ...USERS[user], ...(claimed !== undefined && { nonce: claimed }), exp: Math.floor(Date.now() / 1000) + 300 });
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
        return req.on('end', () => {
          const c = codes.get(new URLSearchParams(body).get('code'));
          if (!c) { res.writeHead(400); return res.end('bad code'); }
          json({ id_token: idToken(c.user, c.nonce), access_token: 'at', token_type: 'Bearer' });
        });
      }
      res.writeHead(404); res.end();
    });
    srv.listen(0, '127.0.0.1', () => { idpBase = `http://127.0.0.1:${srv.address().port}`; resolve(srv); });
  });
}

// ---- signed SAML responses
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

function samlResponse(user, inResponseTo) {
  const iso = (ms) => new Date(Date.now() + ms).toISOString();
  const acs = `${BASE_URL}/api/auth/saml/callback`;
  const id = crypto.randomBytes(8).toString('hex');
  const irt = inResponseTo ? ` InResponseTo="${inResponseTo}"` : '';
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${id}" Version="2.0" IssueInstant="${iso(0)}" Destination="${acs}"${irt}>`
    + '<saml:Issuer>http://idp.example.com</saml:Issuer>'
    + '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    + `<saml:Assertion ID="_a${id}" Version="2.0" IssueInstant="${iso(0)}">`
    + '<saml:Issuer>http://idp.example.com</saml:Issuer>'
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${USERS[user].email}</saml:NameID>`
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${iso(300000)}" Recipient="${acs}"${irt}/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${iso(-60000)}" NotOnOrAfter="${iso(300000)}"><saml:AudienceRestriction><saml:Audience>${BASE_URL}/api/auth/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="_s${id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + '</saml:Assertion></samlp:Response>';
  const assertionSigned = signXml(xml, "//*[local-name(.)='Assertion']", "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']");
  return Buffer.from(signXml(assertionSigned, "/*[local-name(.)='Response']", "/*[local-name(.)='Response']/*[local-name(.)='Issuer']")).toString('base64');
}

before(async () => {
  process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;
  const { encrypt } = await import('../server/services/encryption.js');
  dataDir = mkdtempSync(join(tmpdir(), 'crane-sso-csrf-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=idp.example.com',
    '-keyout', join(dataDir, 'idp.key'), '-out', join(dataDir, 'idp.crt')], { stdio: 'ignore' });
  keyPem = readFileSync(join(dataDir, 'idp.key'), 'utf8');
  certPem = readFileSync(join(dataDir, 'idp.crt'), 'utf8');

  idp = await startIdp();
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY, CRANE_DOMAIN, LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const db = new Database(join(dataDir, 'deployhub.db'));
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('admin','admin@example.com','platform_admin','x',1)").run();
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('Alice Example','alice@example.com','user','y',1)").run();
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('Mallory Example','mallory@example.com','user','z',1)").run();
  const set = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
  set.run('oidc_enabled', '1');
  set.run('oidc_discovery_url', idpBase);
  set.run('oidc_client_id', CLIENT_ID);
  set.run('saml_enabled', '1');
  set.run('saml_idp_sso_url', 'http://idp.example.com/sso');
  set.run('saml_idp_cert_enc', encrypt(certPem.trim()));
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { idp?.close(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

// ---- one browser: a cookie jar, and no redirects followed
function browser() {
  const jar = new Map();
  const b = {
    jar,
    fetch: async (path, init = {}) => {
      const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      const r = await fetch(`${base}${path}`, { redirect: 'manual', ...init, headers: { ...(init.headers || {}), ...(cookie && { Cookie: cookie }) } });
      for (const c of r.headers.getSetCookie()) {
        const [pair, ...attrs] = c.split(';');
        const eq = pair.indexOf('=');
        const gone = attrs.some((a) => /^\s*max-age=0\b/i.test(a) || /^\s*expires=thu, 01 jan 1970/i.test(a));
        if (gone) jar.delete(pair.slice(0, eq)); else jar.set(pair.slice(0, eq), pair.slice(eq + 1));
      }
      return r;
    },
  };
  return b;
}
const signedInAs = async (b) => {
  if (!b.jar.has('cc_token')) return null;
  const r = await fetch(`${base}/api/me`, { headers: { Cookie: `cc_token=${b.jar.get('cc_token')}` } });
  return r.ok ? (await r.json()).user.email : null;
};
const sessionCount = () => {
  const db = new Database(join(dataDir, 'deployhub.db'), { readonly: true });
  const n = db.prepare('SELECT COUNT(*) n FROM identity_sessions').get().n;
  db.close();
  return n;
};
const setCookieNamed = (r, name) => r.headers.getSetCookie().find((c) => c.startsWith(`${name}=`)) || null;

// ---- OIDC: /start in a browser, then the IdP step as `user`
async function oidcAuthorize(b, user, query = { redirect: '/launch' }) {
  const r = await b.fetch(`/api/auth/oidc/start?${new URLSearchParams(query)}`);
  assert.equal(r.status, 302, `oidc start did not redirect: ${r.status}`);
  const loc = new URL(r.headers.get('location'));
  const code = crypto.randomBytes(8).toString('hex');
  codes.set(code, { user, nonce: loc.searchParams.get('nonce') ?? undefined });
  return { startResponse: r, loc, callback: `/api/auth/oidc/callback?${new URLSearchParams({ code, state: loc.searchParams.get('state') })}` };
}

function assertRefused(r, label, param = 'sso_error') {
  assert.equal(r.status, 302, `${label}: expected a redirect, got ${r.status}`);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/login', `${label}: went to ${loc.pathname}`);
  assert.ok(loc.searchParams.get(param), `${label}: no ${param} in ${loc}`);
  assert.equal(loc.searchParams.get('sso_code'), null, `${label}: code issued`);
  assert.equal(loc.searchParams.get('oidc_token'), null, `${label}: token issued`);
  assert.equal(setCookieNamed(r, 'cc_token'), null, `${label}: set a session cookie`);
}

test('oidc: the attack. A callback the attacker completed does not sign in a browser with no binding cookie', async () => {
  const attacker = browser();
  const { callback } = await oidcAuthorize(attacker, 'mallory');
  const victim = browser();
  const n0 = sessionCount();
  assertRefused(await victim.fetch(callback), 'victim opening the attacker callback');
  assert.equal(sessionCount(), n0, 'a session was created for the attacker');
  assert.equal(await signedInAs(victim), null);
});

test('oidc: the attack, on a victim who has a binding cookie of their own', async () => {
  const attacker = browser();
  const { callback } = await oidcAuthorize(attacker, 'mallory');
  const victim = browser();
  await oidcAuthorize(victim, 'alice');
  assert.ok(victim.jar.get(OIDC_COOKIE), 'the victim should hold a binding cookie');
  const n0 = sessionCount();
  assertRefused(await victim.fetch(callback), 'victim with own cookie');
  assert.equal(sessionCount(), n0);
});

test('oidc: the browser that started the login finishes it, and the binding cookie has the promised attributes', async () => {
  const b = browser();
  const { startResponse, callback } = await oidcAuthorize(b, 'alice', { redirect: '/product-roadmap-v2' });
  const c = setCookieNamed(startResponse, OIDC_COOKIE);
  assert.ok(c, `no ${OIDC_COOKIE} at /start: ${startResponse.headers.getSetCookie()}`);
  assert.match(c, /; HttpOnly/i);
  assert.match(c, /; Secure/i);
  assert.match(c, /; SameSite=Lax/i);
  assert.match(c, /; Path=\//i);
  assert.match(c, /; Max-Age=600/i);
  assert.doesNotMatch(c, /; Domain=/i);
  const r = await b.fetch(callback);
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/login', r.headers.get('location'));
  assert.ok(loc.searchParams.get('sso_code'));
  assert.equal(loc.searchParams.get('redirect'), '/product-roadmap-v2');
  assert.equal(await signedInAs(b), 'alice@example.com');
});

test('oidc: the state carries a hash of the binding, never the cookie value', async () => {
  const b = browser();
  const { loc } = await oidcAuthorize(b, 'alice');
  const value = b.jar.get(OIDC_COOKIE);
  const state = loc.searchParams.get('state');
  const decoded = Buffer.from(state.slice(0, state.lastIndexOf('.')), 'base64url').toString();
  assert.ok(!decoded.includes(value) && !loc.href.includes(value), 'the cookie value left for the IdP');
});

test('oidc: two sign-ins open in one browser both finish, in either order', async () => {
  const b = browser();
  const first = await oidcAuthorize(b, 'alice');
  const value = b.jar.get(OIDC_COOKIE);
  const second = await oidcAuthorize(b, 'alice');
  assert.equal(b.jar.get(OIDC_COOKIE), value, 'a second /start replaced the binding and orphaned the first tab');
  assert.ok(new URL((await b.fetch(first.callback)).headers.get('location')).searchParams.get('sso_code'), 'first tab failed');
  assert.ok(new URL((await b.fetch(second.callback)).headers.get('location')).searchParams.get('sso_code'), 'second tab failed');
});

test('oidc: a junk binding cookie the browser already holds is replaced, not adopted', async () => {
  const b = browser();
  b.jar.set(OIDC_COOKIE, 'short');
  await oidcAuthorize(b, 'alice');
  assert.notEqual(b.jar.get(OIDC_COOKIE), 'short');
  assert.match(b.jar.get(OIDC_COOKIE), /^[A-Za-z0-9_-]{32}$/);
});

test('oidc: a nonce is sent, is different per login, and must come back in the id_token', async (t) => {
  t.after(() => { nonceOverride.active = false; nonceOverride.value = undefined; });
  const b = browser();
  const one = await oidcAuthorize(b, 'alice');
  const two = await oidcAuthorize(b, 'alice');
  const nonce = one.loc.searchParams.get('nonce');
  assert.match(nonce || '', /^[0-9a-f]{32}$/, 'no nonce in the authorization request');
  assert.notEqual(nonce, two.loc.searchParams.get('nonce'));

  const n0 = sessionCount();
  nonceOverride.active = true;
  for (const [label, value] of [['missing', undefined], ['wrong', 'f'.repeat(32)], ['wrong length', 'abc'], ['not a string', 12345]]) {
    nonceOverride.value = value;
    const flow = await oidcAuthorize(b, 'alice');
    assertRefused(await b.fetch(flow.callback), `id_token nonce ${label}`);
  }
  assert.equal(sessionCount(), n0, 'a bad nonce still produced a session');
});

test('oidc popup: the opener browser completes, and a handed-over popup state gets the failure page and no session', async () => {
  const b = browser();
  const own = await oidcAuthorize(b, 'alice', { redirect: '/product-roadmap-v2', mode: 'popup' });
  const done = await b.fetch(own.callback);
  assert.equal(done.status, 200);
  assert.match(await done.text(), /popup\/complete\.js/);
  assert.equal(await signedInAs(b), 'alice@example.com');

  const attacker = browser();
  const { callback } = await oidcAuthorize(attacker, 'mallory', { mode: 'popup' });
  const victim = browser();
  const n0 = sessionCount();
  const r = await victim.fetch(callback);
  assert.equal(r.status, 200);
  assert.match(await r.text(), /popup\/failed\.js/);
  assert.equal(setCookieNamed(r, 'cc_token'), null);
  assert.equal(sessionCount(), n0);
});

// ---- SAML: /start in a browser, then the IdP step as `user`
async function samlStart(b, query = { redirect: '/launch' }) {
  const r = await b.fetch(`/api/auth/saml/start?${new URLSearchParams(query)}`);
  assert.equal(r.status, 302, `saml start did not redirect: ${r.status}`);
  const loc = new URL(r.headers.get('location'));
  const request = inflateRawSync(Buffer.from(loc.searchParams.get('SAMLRequest'), 'base64')).toString();
  return { startResponse: r, relay: loc.searchParams.get('RelayState') ?? undefined, requestId: / ID="([^"]+)"/.exec(request)[1] };
}
const samlPost = (b, fields) => b.fetch('/api/auth/saml/callback', {
  method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields),
});

test('saml: the attack. A response the attacker obtained does not sign in a browser with no binding cookie', async () => {
  const attacker = browser();
  const { requestId } = await samlStart(attacker);
  const victim = browser();
  const n0 = sessionCount();
  assertRefused(await samlPost(victim, { SAMLResponse: samlResponse('mallory', requestId), RelayState: '/launch' }), 'saml victim', 'saml_error');
  assert.equal(sessionCount(), n0);
  assert.equal(await signedInAs(victim), null);
});

test('saml: the attack, on a victim who has a binding cookie of their own', async () => {
  const attacker = browser();
  const { requestId } = await samlStart(attacker);
  const victim = browser();
  await samlStart(victim);
  assert.ok(victim.jar.get(SAML_COOKIE));
  const n0 = sessionCount();
  assertRefused(await samlPost(victim, { SAMLResponse: samlResponse('mallory', requestId) }), 'saml victim with cookie', 'saml_error');
  assert.equal(sessionCount(), n0);
});

test('saml: a request id AppCrane did not issue is refused even with a binding cookie', async () => {
  const b = browser();
  await samlStart(b);
  const n0 = sessionCount();
  for (const id of ['_0123456789abcdef0123456789abcdef0123456789abcdef0', '_x', 'nonsense']) {
    assertRefused(await samlPost(b, { SAMLResponse: samlResponse('alice', id) }), `saml forged request id ${id}`, 'saml_error');
  }
  assert.equal(sessionCount(), n0);
});

test('saml: the browser that started the login finishes it, and the cookie survives a cross-site POST by being SameSite=None', async () => {
  const b = browser();
  const { startResponse, requestId } = await samlStart(b, { redirect: '/product-roadmap-v2' });
  const c = setCookieNamed(startResponse, SAML_COOKIE);
  assert.ok(c, `no ${SAML_COOKIE} at /start`);
  assert.match(c, /; HttpOnly/i);
  assert.match(c, /; Secure/i);
  assert.match(c, /; SameSite=None/i);
  assert.match(c, /; Path=\//i);
  assert.doesNotMatch(c, /; Domain=/i);
  const r = await samlPost(b, { SAMLResponse: samlResponse('alice', requestId), RelayState: '/product-roadmap-v2' });
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/login', r.headers.get('location'));
  assert.ok(loc.searchParams.get('sso_code'));
  assert.equal(loc.searchParams.get('redirect'), '/product-roadmap-v2');
  assert.equal(await signedInAs(b), 'alice@example.com');
});

test('saml: two sign-ins open in one browser both finish', async () => {
  const b = browser();
  const first = await samlStart(b);
  const second = await samlStart(b);
  for (const flow of [first, second]) {
    const r = await samlPost(b, { SAMLResponse: samlResponse('alice', flow.requestId) });
    assert.ok(new URL(r.headers.get('location')).searchParams.get('sso_code'), r.headers.get('location'));
  }
});

test('saml popup: the opener browser completes, and a handed-over response gets the failure page and no session', async () => {
  const b = browser();
  const own = await samlStart(b, { mode: 'popup' });
  const done = await samlPost(b, { SAMLResponse: samlResponse('alice', own.requestId), RelayState: own.relay });
  assert.equal(done.status, 200);
  assert.match(await done.text(), /popup\/complete\.js/);

  const attacker = browser();
  const stolen = await samlStart(attacker, { mode: 'popup' });
  const victim = browser();
  const n0 = sessionCount();
  const r = await samlPost(victim, { SAMLResponse: samlResponse('mallory', stolen.requestId), RelayState: stolen.relay });
  assert.equal(r.status, 200);
  assert.match(await r.text(), /popup\/failed\.js/);
  assert.equal(sessionCount(), n0);
});

test('saml: an unsolicited response (IdP tile) creates no session and restarts as a login of this browser', async () => {
  const b = browser();
  const n0 = sessionCount();
  const r = await samlPost(b, { SAMLResponse: samlResponse('mallory'), RelayState: '/product-roadmap-v2' });
  assert.equal(r.status, 303);
  assert.equal(setCookieNamed(r, 'cc_token'), null);
  assert.equal(sessionCount(), n0, 'an unsolicited response created a session');
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/api/auth/saml/start');
  assert.equal(loc.searchParams.get('redirect'), '/product-roadmap-v2');

  const { requestId } = await samlStart(b, { redirect: loc.searchParams.get('redirect') });
  const done = await samlPost(b, { SAMLResponse: samlResponse('alice', requestId), RelayState: '/product-roadmap-v2' });
  assert.ok(new URL(done.headers.get('location')).searchParams.get('sso_code'), done.headers.get('location'));
  assert.equal(await signedInAs(b), 'alice@example.com');
  assert.equal(b.jar.has(`${SAML_COOKIE}_restart`), false, 'the restart marker outlived the login');
});

test('saml: an unsafe RelayState does not survive the restart', async () => {
  const r = await samlPost(browser(), { SAMLResponse: samlResponse('alice'), RelayState: 'https://attacker.example/x' });
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/api/auth/saml/start');
  assert.equal(loc.searchParams.get('redirect'), null);
});

test('saml: an IdP that never echoes the request id fails after one restart instead of looping', async () => {
  const b = browser();
  const first = await samlPost(b, { SAMLResponse: samlResponse('alice') });
  assert.equal(new URL(first.headers.get('location')).pathname, '/api/auth/saml/start');
  assertRefused(await samlPost(b, { SAMLResponse: samlResponse('alice') }), 'second unsolicited response', 'saml_error');
});

test('saml: an unsolicited response with a broken signature is an error, not a restart', async () => {
  const tampered = Buffer.from(Buffer.from(samlResponse('alice'), 'base64').toString().replace('alice@example.com', 'mallory@example.com')).toString('base64');
  assertRefused(await samlPost(browser(), { SAMLResponse: tampered }), 'tampered unsolicited', 'saml_error');
});

// ---- the SPA's token: never in a URL. A code, single use, redeemable only by the
// browser that holds the binding cookie the login was made with.
const redeem = (b, code) => b.fetch('/api/auth/oidc/handoff', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }),
});
const codeFrom = (r) => new URL(r.headers.get('location')).searchParams.get('sso_code');
const asUser = async (token) => {
  const r = await fetch(`${base}/api/apps`, { headers: { Authorization: `Bearer ${token}` } });
  const me = await fetch(`${base}/api/me`, { headers: { Authorization: `Bearer ${token}` } });
  return { apps: r.status, email: me.ok ? (await me.json()).user.email : null };
};

test('handoff: neither callback puts a session token in the redirect, only an opaque code', async () => {
  const b = browser();
  const flow = await oidcAuthorize(b, 'alice');
  const oidc = await b.fetch(flow.callback);
  const s = await samlStart(b);
  const saml = await samlPost(b, { SAMLResponse: samlResponse('alice', s.requestId) });
  for (const r of [oidc, saml]) {
    const loc = r.headers.get('location');
    assert.equal(new URL(loc).searchParams.get('oidc_token'), null, loc);
    assert.match(codeFrom(r), /^[A-Za-z0-9_-]{22}$/);
    const session = decodeURIComponent(setCookieNamed(r, 'cc_token').split(';')[0].slice('cc_token='.length));
    assert.ok(!loc.includes(session), 'the session token is in the Location header');
  }
});

for (const [proto, finish] of [
  ['oidc', async (b, user) => { const f = await oidcAuthorize(b, user); return b.fetch(f.callback); }],
  ['saml', async (b, user) => { const s = await samlStart(b); return samlPost(b, { SAMLResponse: samlResponse(user, s.requestId) }); }],
]) {
  test(`handoff ${proto}: the browser that signed in gets a working API token, once`, async () => {
    const b = browser();
    const code = codeFrom(await finish(b, 'alice'));
    const r = await redeem(b, code);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('cache-control'), 'no-store');
    const { token } = await r.json();
    assert.deepEqual(await asUser(token), { apps: 200, email: 'alice@example.com' });
    const again = await redeem(b, code);
    assert.equal(again.status, 401, 'a code worked twice');
    assert.equal((await again.json()).token, undefined);
  });

  test(`handoff ${proto}: the attack. An attacker's code does not work in the victim's browser, with or without a binding of their own`, async () => {
    const attacker = browser();
    const code = codeFrom(await finish(attacker, 'mallory'));
    const bare = browser();
    const refused = await redeem(bare, code);
    assert.equal(refused.status, 401);
    assert.equal((await refused.json()).token, undefined);

    const victim = browser();
    await finish(victim, 'alice');
    const refused2 = await redeem(victim, code);
    assert.equal(refused2.status, 401);
    assert.equal((await refused2.json()).token, undefined);

    assert.equal((await redeem(attacker, code)).status, 200, 'someone else trying a code must not burn it');
  });
}

test('handoff: a code in the query string, or a guessed one, gets nothing; GET is not a route', async () => {
  const b = browser();
  const flow = await oidcAuthorize(b, 'alice');
  const code = codeFrom(await b.fetch(flow.callback));
  const viaQuery = await b.fetch(`/api/auth/oidc/handoff?code=${code}`, { method: 'POST' });
  assert.equal(viaQuery.status, 401);
  assert.equal((await b.fetch(`/api/auth/oidc/handoff?code=${code}`)).status === 200, false);
  for (const bad of ['nope', '', null, 7, { $ne: 1 }]) assert.equal((await redeem(b, bad)).status, 401);
  assert.equal((await redeem(b, code)).status, 200, 'the failed attempts should not have used the code up');
});

test('handoff: the callback still sets the session cookie itself, for a browser the SPA never runs in', async () => {
  const b = browser();
  const flow = await oidcAuthorize(b, 'alice');
  const r = await b.fetch(flow.callback);
  assert.ok(setCookieNamed(r, 'cc_token'), 'the callback still sets the session cookie itself');
  assert.equal(await signedInAs(b), 'alice@example.com');
});

test('handoff store: a code expires after 60 seconds and the store is bounded', async (t) => {
  const { issueSsoHandoff, redeemSsoHandoff, SSO_HANDOFF_TTL_MS, SSO_HANDOFF_MAX } = await import('../server/routes/oidc.js');
  assert.equal(SSO_HANDOFF_TTL_MS, 60_000);
  const req = { headers: { cookie: 'bind=' + 'v'.repeat(32) } };
  const realNow = Date.now;
  t.after(() => { Date.now = realNow; });
  const code = issueSsoHandoff('tok', 'bind', 'v'.repeat(32));
  const late = issueSsoHandoff('tok2', 'bind', 'v'.repeat(32));
  assert.equal(redeemSsoHandoff(req, code), 'tok');
  Date.now = () => realNow() + SSO_HANDOFF_TTL_MS + 1;
  assert.equal(redeemSsoHandoff(req, late), null, 'an expired code worked');
  Date.now = realNow;

  const first = issueSsoHandoff('oldest', 'bind', 'v'.repeat(32));
  for (let i = 0; i < SSO_HANDOFF_MAX; i++) issueSsoHandoff('x', 'bind', 'v'.repeat(32));
  assert.equal(redeemSsoHandoff(req, first), null, 'the store grew past its bound');
});
