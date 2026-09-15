import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import net from 'net';
import vm from 'vm';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { SignedXml } from 'xml-crypto';

// Popup sign-in for a framed sign-in page (the IdP refuses to be framed).
//
// /start?mode=popup must carry popup mode through the IdP inside state that
// AppCrane signed — the OIDC `state`, or a signed SAML RelayState — and the
// callback must then answer with a top-level-only completion page that sets
// the session exactly as the normal callback does. A `mode` added to the
// callback request, a tampered state, or a forged RelayState must all fall
// back to the normal forward.
//
// Driven against the real server process with a stub OIDC IdP and SAML
// responses signed by a throwaway key. No external network.

const ENCRYPTION_KEY = 'e'.repeat(64);
const CRANE_DOMAIN = 'app.example.com';
const BASE_URL = `https://${CRANE_DOMAIN}`;
const CLIENT_ID = 'crane-popup-test';
let child, base, dataDir, idp, idpBase, keyPem, certPem, ssoPopup;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// ---- stub OIDC IdP --------------------------------------------------------
const { privateKey: oidcKey, publicKey: oidcPub } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...oidcPub.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };

function idToken(issuer) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = enc({ iss: issuer, aud: CLIENT_ID, sub: 'alice-sub', email: 'alice@example.com', name: 'Alice Example', exp: Math.floor(Date.now() / 1000) + 300 });
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
        return req.on('end', () => json({ id_token: idToken(idpBase), access_token: 'at', token_type: 'Bearer' }));
      }
      res.writeHead(404); res.end();
    });
    srv.listen(0, '127.0.0.1', () => { idpBase = `http://127.0.0.1:${srv.address().port}`; resolve(srv); });
  });
}

// ---- signed SAML responses -------------------------------------------------
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

function samlResponse() {
  const now = new Date();
  const iso = (ms) => new Date(now.getTime() + ms).toISOString();
  const acs = `${BASE_URL}/api/auth/saml/callback`;
  const id = crypto.randomBytes(8).toString('hex');
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${id}" Version="2.0" IssueInstant="${iso(0)}" Destination="${acs}">`
    + '<saml:Issuer>http://idp.example.com</saml:Issuer>'
    + '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    + `<saml:Assertion ID="_a${id}" Version="2.0" IssueInstant="${iso(0)}">`
    + '<saml:Issuer>http://idp.example.com</saml:Issuer>'
    + '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>'
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${iso(300000)}" Recipient="${acs}"/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${iso(-60000)}" NotOnOrAfter="${iso(300000)}"><saml:AudienceRestriction><saml:Audience>${BASE_URL}/api/auth/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="_s${id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + '</saml:Assertion></samlp:Response>';
  const assertionSigned = signXml(xml, "//*[local-name(.)='Assertion']", "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']");
  const signed = signXml(assertionSigned, "/*[local-name(.)='Response']", "/*[local-name(.)='Response']/*[local-name(.)='Issuer']");
  return Buffer.from(signed).toString('base64');
}

before(async () => {
  process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;
  const { encrypt } = await import('../server/services/encryption.js');
  ssoPopup = await import('../server/utils/ssoPopup.js');

  dataDir = mkdtempSync(join(tmpdir(), 'crane-sso-popup-'));
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
  db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('Roadmap','product-roadmap-v2',9001,'github')").run();
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

const noFollow = (url, init = {}) => fetch(url, { redirect: 'manual', ...init });
const statePayload = (state) => JSON.parse(Buffer.from(state.slice(0, state.lastIndexOf('.')), 'base64url').toString());
const ccToken = (r) => (r.headers.getSetCookie().find((c) => c.startsWith('cc_token=')) || null);
const frameAncestors = (r) => (r.headers.get('content-security-policy') || '').match(/frame-ancestors ([^;]+)/)?.[1] ?? null;
const sessionCount = () => { const db = new Database(join(dataDir, 'deployhub.db'), { readonly: true }); const n = db.prepare('SELECT COUNT(*) n FROM identity_sessions').get().n; db.close(); return n; };

async function oidcStart(query) {
  const r = await noFollow(`${base}/api/auth/oidc/start?${new URLSearchParams(query)}`);
  assert.equal(r.status, 302, `oidc start did not redirect: ${r.status}`);
  const loc = new URL(r.headers.get('location'));
  return { loc, state: loc.searchParams.get('state') };
}
const oidcCallback = (state, extra = {}) => noFollow(`${base}/api/auth/oidc/callback?${new URLSearchParams({ code: 'c1', state, ...extra })}`);

async function assertPopupComplete(r, label) {
  assert.equal(r.status, 200, `${label}: expected the completion page, got ${r.status} ${r.headers.get('location')}`);
  assert.match(r.headers.get('content-type') || '', /text\/html/);
  const cookie = ccToken(r);
  assert.ok(cookie, `${label}: completion page did not set cc_token`);
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Lax/i);
  assert.equal(frameAncestors(r), "'none'", `${label}: completion page is frameable`);
  assert.equal(r.headers.get('x-frame-options'), 'DENY', `${label}: completion page lacks X-Frame-Options DENY`);
  const body = await r.text();
  const token = decodeURIComponent(cookie.split(';')[0].slice('cc_token='.length));
  assert.ok(!body.includes(token), `${label}: completion page leaks the session token`);
  assert.doesNotMatch(body, /oidc_token|<script>(?!<\/script>)[^<]/, `${label}: token param or inline script in completion page`);
  assert.match(body, /<script src="\/api\/auth\/popup\/complete\.js"><\/script>/);
  return { token, body };
}

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

test('oidc start: mode=popup is carried in the signed state, and only the exact value', async () => {
  const popup = await oidcStart({ redirect: '/product-roadmap-v2', mode: 'popup' });
  assert.equal(popup.loc.origin + popup.loc.pathname, `${idpBase}/authorize`);
  assert.equal(statePayload(popup.state).m, 'popup');
  assert.equal(statePayload(popup.state).r, '/product-roadmap-v2');
  assert.equal(popup.loc.searchParams.get('mode'), null, 'mode leaked into the IdP request instead of state');

  for (const q of [{ redirect: '/product-roadmap-v2' }, { redirect: '/product-roadmap-v2', mode: 'POPUP' }, { redirect: '/x', mode: 'evil' }]) {
    const { state } = await oidcStart(q);
    assert.equal(statePayload(state).m, undefined, `mode ${q.mode} was accepted`);
  }
});

test('oidc popup callback serves the top-level completion page and sets the session like the normal callback', async () => {
  const { state } = await oidcStart({ redirect: '/product-roadmap-v2', mode: 'popup' });
  const n0 = sessionCount();
  const r = await oidcCallback(state);
  const { token } = await assertPopupComplete(r, 'oidc popup');
  assert.equal(sessionCount(), n0 + 1, 'popup callback did not create an identity session');

  const me = await fetch(`${base}/api/me`, { headers: { Cookie: `cc_token=${encodeURIComponent(token)}` } });
  assert.equal(me.status, 200, 'the popup session cookie does not authenticate /api/me');
  assert.equal((await me.json()).user.email, 'alice@example.com');
});

test('oidc normal callback still forwards through /login with the deep link', async () => {
  const { state } = await oidcStart({ redirect: '/product-roadmap-v2' });
  const r = await oidcCallback(state);
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/login');
  assert.ok(loc.searchParams.get('oidc_token'));
  assert.equal(loc.searchParams.get('redirect'), '/product-roadmap-v2');
  assert.ok(ccToken(r));
});

test('oidc: mode=popup on the callback request is ignored', async () => {
  const { state } = await oidcStart({ redirect: '/product-roadmap-v2' });
  const r = await oidcCallback(state, { mode: 'popup' });
  assert.equal(r.status, 302, 'popup mode was trusted from the callback query');
  assert.equal(new URL(r.headers.get('location')).pathname, '/login');
});

test('oidc: a state tampered into popup mode fails the signature check', async () => {
  const { state } = await oidcStart({ redirect: '/product-roadmap-v2' });
  const data = statePayload(state);
  const forged = Buffer.from(JSON.stringify({ ...data, m: 'popup' })).toString('base64url') + state.slice(state.lastIndexOf('.'));
  const r = await oidcCallback(forged);
  assert.equal(r.status, 302);
  assert.ok(new URL(r.headers.get('location')).searchParams.get('sso_error'), 'tampered state was accepted');
  assert.equal(ccToken(r), null, 'tampered state set a session cookie');
});

test('oidc popup: an unsafe redirect is dropped from state and never reaches the completion page', async () => {
  const { state } = await oidcStart({ redirect: '//attacker.example/x', mode: 'popup' });
  assert.equal(statePayload(state).r, '');
  const r = await oidcCallback(state);
  const { body } = await assertPopupComplete(r, 'oidc popup unsafe redirect');
  assert.doesNotMatch(body, /attacker/);
  assert.equal(r.headers.get('location'), null);
});

// ---------------------------------------------------------------------------
// SAML
// ---------------------------------------------------------------------------

async function samlStart(query) {
  const r = await noFollow(`${base}/api/auth/saml/start?${new URLSearchParams(query)}`);
  assert.equal(r.status, 302, `saml start did not redirect: ${r.status}`);
  return new URL(r.headers.get('location')).searchParams.get('RelayState');
}
const samlCallback = (RelayState) => noFollow(`${base}/api/auth/saml/callback`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ SAMLResponse: samlResponse(), ...(RelayState !== undefined && { RelayState }) }),
});

test('saml start: mode=popup yields a signed RelayState within the 80-byte SAML limit', async () => {
  const relay = await samlStart({ redirect: '/product-roadmap-v2', mode: 'popup' });
  assert.match(relay, /^popup\./);
  assert.ok(Buffer.byteLength(relay) <= 80, `RelayState is ${Buffer.byteLength(relay)} bytes`);
  assert.equal(ssoPopup.isPopupRelayState(relay), true);
  assert.equal(await samlStart({ redirect: '/product-roadmap-v2' }), '/product-roadmap-v2');
  assert.equal(await samlStart({ redirect: '/product-roadmap-v2', mode: 'nope' }), '/product-roadmap-v2');
});

test('saml popup callback serves the completion page and sets the session', async () => {
  const relay = await samlStart({ redirect: '/product-roadmap-v2', mode: 'popup' });
  const n0 = sessionCount();
  const r = await samlCallback(relay);
  const { token } = await assertPopupComplete(r, 'saml popup');
  assert.equal(sessionCount(), n0 + 1);
  const me = await fetch(`${base}/api/me`, { headers: { Cookie: `cc_token=${encodeURIComponent(token)}` } });
  assert.equal(me.status, 200);
});

test('saml normal callback still forwards through /login', async () => {
  const r = await samlCallback('/product-roadmap-v2');
  assert.equal(r.status, 302, `saml callback failed: ${r.headers.get('location')}`);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.pathname, '/login');
  assert.ok(loc.searchParams.get('oidc_token'));
  assert.equal(loc.searchParams.get('redirect'), '/product-roadmap-v2');
});

test('saml: a forged or unsigned popup RelayState is not popup mode, and the redirect stays validated', async () => {
  const genuine = await samlStart({ redirect: '/x', mode: 'popup' });
  const flipped = genuine.slice(0, -1) + (genuine.endsWith('A') ? 'B' : 'A');
  for (const relay of ['popup', 'popup.a.b.c', flipped, 'https://attacker.example/popup']) {
    const r = await samlCallback(relay);
    assert.equal(r.status, 302, `RelayState ${relay} selected popup mode`);
    const loc = new URL(r.headers.get('location'));
    assert.equal(loc.pathname, '/login');
    assert.equal(loc.searchParams.get('redirect'), null, `RelayState ${relay} was forwarded`);
  }
});

test('saml popup RelayState expires after 10 minutes', (t) => {
  const relay = ssoPopup.makePopupRelayState();
  assert.equal(ssoPopup.isPopupRelayState(relay), true);
  const realNow = Date.now;
  t.after(() => { Date.now = realNow; });
  Date.now = () => realNow() + 11 * 60 * 1000;
  assert.equal(ssoPopup.isPopupRelayState(relay), false);
});

// ---------------------------------------------------------------------------
// Completion script
// ---------------------------------------------------------------------------

test('the completion script broadcasts only { type: "signed-in" } and closes the popup', async () => {
  const r = await fetch(`${base}/api/auth/popup/complete.js`);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type') || '', /javascript/);
  const src = await r.text();

  const posted = [];
  let closed = 0;
  const timers = [];
  class FakeChannel {
    constructor(name) { this.name = name; }
    postMessage(m) { posted.push({ name: this.name, m: structuredClone(m) }); }
    close() {}
  }
  const window = { close: () => { closed++; } };
  vm.runInNewContext(src, { BroadcastChannel: FakeChannel, window, setTimeout: (fn, ms) => timers.push({ fn, ms }) });
  for (const tmr of timers) tmr.fn();

  const { SSO_CHANNEL } = await import('../studio-web/src/utils/popupSignIn.ts');
  assert.deepEqual(posted, [{ name: SSO_CHANNEL, m: { type: 'signed-in' } }],
    'the popup must post exactly { type: "signed-in" } on the channel the SPA listens to, and nothing else');
  assert.equal(closed, 1, 'the popup does not close itself');
});
