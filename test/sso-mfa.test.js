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
import Database from 'better-sqlite3';
import { SignedXml } from 'xml-crypto';

// AppCrane MFA after SSO. A user who enrolled AppCrane's own second factor got a
// session straight from the OIDC or SAML callback, so signing in through SSO
// skipped it. Now the callback hands the browser the same second step password
// sign-in uses (an mfa_token for POST /api/identity/mfa/verify) and no session,
// unless the IdP's id_token says it already did MFA (amr). Driven against the
// real server with a stub OIDC IdP and signed SAML responses; one cookie jar per
// browser, no redirects followed.

const REPO = fileURLToPath(new URL('..', import.meta.url));
const ENCRYPTION_KEY = 'a'.repeat(64);
const CRANE_DOMAIN = 'app.example.com';
const BASE_URL = `https://${CRANE_DOMAIN}`;
const CLIENT_ID = 'crane-sso-mfa-test';
const USERS = {
  mfa: { sub: 'mfa-sub', email: 'mfa@example.com', email_verified: true, name: 'Mfa User' },
  plain: { sub: 'plain-sub', email: 'plain@example.com', email_verified: true, name: 'Plain User' },
};
let child, base, dataDir, idp, idpBase, keyPem, certPem, mfaSecret, totp, db;
const codes = new Map();

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const { privateKey: oidcKey, publicKey: oidcPub } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...oidcPub.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
function idToken({ user, nonce, amr }) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = enc({ iss: idpBase, aud: CLIENT_ID, ...USERS[user], nonce, ...(amr !== undefined && { amr }), exp: Math.floor(Date.now() / 1000) + 300 });
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
  const irt = ` InResponseTo="${inResponseTo}"`;
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
  dataDir = mkdtempSync(join(tmpdir(), 'crane-sso-mfa-'));
  process.env.DATA_DIR = dataDir;
  process.env.LOG_LEVEL = 'error';
  const { encrypt } = await import('../server/services/encryption.js');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=idp.example.com',
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
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const { initDb, getDb } = await import('../server/db.js');
  initDb();
  db = getDb();
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('admin','admin@example.com','platform_admin','x',1)").run();
  const ins = db.prepare("INSERT INTO users (name,email,role,active,kind,sso_sub,saml_name_id) VALUES (?,?,'user',1,'human',?,?)");
  for (const u of Object.values(USERS)) ins.run(u.name, u.email, u.sub, u.email);
  const set = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
  set.run('oidc_enabled', '1');
  set.run('oidc_discovery_url', idpBase);
  set.run('oidc_client_id', CLIENT_ID);
  set.run('saml_enabled', '1');
  set.run('saml_idp_sso_url', 'http://idp.example.com/sso');
  set.run('saml_idp_cert_enc', encrypt(certPem.trim()));

  totp = await import('../server/services/totp.js');
  const mfa = await import('../server/services/mfa.js');
  const user = db.prepare('SELECT * FROM users WHERE sso_sub = ?').get(USERS.mfa.sub);
  mfaSecret = mfa.startEnrollment(db, user).secret;
  assert.equal(mfa.activateEnrollment(db, user, totp.totp(totp.base32Decode(mfaSecret), Date.now() - 30_000)).ok, true);
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { idp?.close(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

function browser() {
  const jar = new Map();
  return {
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
}
const json = (o) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(o) });
const userId = (who) => db.prepare('SELECT id FROM users WHERE sso_sub = ?').get(USERS[who].sub).id;
const sessions = (who) => db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?').get(userId(who)).n;
const lastLogin = (who) => {
  const r = db.prepare("SELECT detail FROM audit_log WHERE action = 'login' AND user_id = ? ORDER BY id DESC LIMIT 1").get(userId(who));
  return r ? JSON.parse(r.detail) : null;
};
const freshCode = () => totp.totp(totp.base32Decode(mfaSecret));
// A TOTP step is single-use, so a test that needs a second code waits for the next step.
async function nextStepCode() {
  await new Promise((r) => setTimeout(r, 30_000 - (Date.now() % 30_000) + 200));
  return freshCode();
}

async function oidcSignIn(b, user, { amr, mode } = {}) {
  const r = await b.fetch(`/api/auth/oidc/start?${new URLSearchParams({ redirect: '/launch', ...(mode && { mode }) })}`);
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  const code = crypto.randomBytes(8).toString('hex');
  codes.set(code, { user, nonce: loc.searchParams.get('nonce'), amr });
  return b.fetch(`/api/auth/oidc/callback?${new URLSearchParams({ code, state: loc.searchParams.get('state') })}`);
}
async function samlSignIn(b, user, { mode } = {}) {
  const r = await b.fetch(`/api/auth/saml/start?${new URLSearchParams({ redirect: '/launch', ...(mode && { mode }) })}`);
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  const request = inflateRawSync(Buffer.from(loc.searchParams.get('SAMLRequest'), 'base64')).toString();
  const fields = { SAMLResponse: samlResponse(user, / ID="([^"]+)"/.exec(request)[1]) };
  const relay = loc.searchParams.get('RelayState');
  if (relay) fields.RelayState = relay;
  return b.fetch('/api/auth/saml/callback', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields) });
}

/** The callback held back the session and handed over the MFA step through the handoff. */
async function assertMfaStep(b, cb, label) {
  assert.equal(cb.status, 302, `${label}: ${cb.status}`);
  assert.equal(b.jar.has('cc_token'), false, `${label}: a session cookie was set before the second step`);
  const loc = new URL(cb.headers.get('location'));
  assert.equal(loc.pathname, '/login', label);
  const code = loc.searchParams.get('sso_code');
  assert.ok(code, `${label}: no handoff code`);
  const h = await b.fetch('/api/auth/oidc/handoff', json({ code }));
  assert.equal(h.status, 200, label);
  const body = await h.json();
  assert.equal(body.token, undefined, `${label}: the handoff gave a session token`);
  assert.equal(body.mfa_required, true, `${label}: ${JSON.stringify(body)}`);
  assert.equal(body.error?.code, 'MFA_REQUIRED');
  assert.ok(body.mfa_token);
  return { loc, mfaToken: body.mfa_token };
}

test('oidc: an enrolled user gets no session from the callback, then one after the AppCrane code', async () => {
  const b = browser();
  const n0 = sessions('mfa');
  const { mfaToken } = await assertMfaStep(b, await oidcSignIn(b, 'mfa'), 'oidc redirect');
  assert.equal(sessions('mfa'), n0, 'the callback created a session');

  const bad = await b.fetch('/api/identity/mfa/verify', json({ mfa_token: mfaToken, code: '000000' }));
  assert.equal(bad.status, 400);
  const ok = await b.fetch('/api/identity/mfa/verify', json({ mfa_token: mfaToken, code: freshCode() }));
  assert.equal(ok.status, 200);
  assert.ok((await ok.json()).token);
  assert.ok(b.jar.has('cc_token'), 'no session cookie after the code');
  assert.equal(sessions('mfa'), n0 + 1);
  assert.equal(lastLogin('mfa').method, 'oidc+totp', 'audited like password MFA, naming the SSO method');
});

test('oidc: an id_token whose amr says the IdP did MFA skips the AppCrane step; amr without MFA does not', async () => {
  for (const amr of [['pwd', 'mfa'], ['hwk'], ['otp'], ['swk'], ['sc'], ['fpt']]) {
    const b = browser();
    const cb = await oidcSignIn(b, 'mfa', { amr });
    assert.equal(cb.status, 302);
    assert.ok(b.jar.has('cc_token'), `amr ${amr} still asked for the AppCrane code`);
    assert.deepEqual(lastLogin('mfa').idp_amr, amr, 'the skip is not audited');
  }
  for (const amr of [['pwd'], 'mfa', ['kba'], []]) {
    const b = browser();
    await assertMfaStep(b, await oidcSignIn(b, 'mfa', { amr }), `amr ${JSON.stringify(amr)}`);
  }
});

test('oidc popup: the popup is sent to the sign-in page for the code instead of being told signed-in', async () => {
  const b = browser();
  const cb = await oidcSignIn(b, 'mfa', { mode: 'popup' });
  assert.equal(cb.headers.get('content-type')?.includes('text/html'), false, 'the popup completion page was served');
  const { loc } = await assertMfaStep(b, cb, 'oidc popup');
  assert.equal(loc.searchParams.get('sso_popup'), '1');
  assert.equal(loc.searchParams.get('redirect'), null);
});

test('saml: an enrolled user gets the AppCrane step too, redirect and popup', async () => {
  const b = browser();
  const n0 = sessions('mfa');
  const { mfaToken } = await assertMfaStep(b, await samlSignIn(b, 'mfa'), 'saml redirect');
  assert.equal(sessions('mfa'), n0);
  const ok = await b.fetch('/api/identity/mfa/verify', json({ mfa_token: mfaToken, code: await nextStepCode() }));
  assert.equal(ok.status, 200);
  assert.equal(lastLogin('mfa').method, 'saml+totp');

  // A new sign-in replaces the user's open challenge, as it does for password sign-in.
  const p = browser();
  const { loc } = await assertMfaStep(p, await samlSignIn(p, 'mfa', { mode: 'popup' }), 'saml popup');
  assert.equal(loc.searchParams.get('sso_popup'), '1');
});

test('with "Require SSO sign-in" in force the SSO second step still finishes', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('auth_sso_only', 'true') ON CONFLICT(key) DO UPDATE SET value = 'true'").run();
  try {
    const b = browser();
    const { mfaToken } = await assertMfaStep(b, await oidcSignIn(b, 'mfa'), 'sso-only');
    const ok = await b.fetch('/api/identity/mfa/verify', json({ mfa_token: mfaToken, code: await nextStepCode() }));
    assert.equal(ok.status, 200, 'the SSO second step was refused as a password sign-in');
  } finally {
    db.prepare("DELETE FROM settings WHERE key = 'auth_sso_only'").run();
  }
});

test('a user without AppCrane MFA signs in through SSO as before', async () => {
  const b = browser();
  const cb = await oidcSignIn(b, 'plain');
  const loc = new URL(cb.headers.get('location'));
  assert.ok(b.jar.has('cc_token'));
  const h = await b.fetch('/api/auth/oidc/handoff', json({ code: loc.searchParams.get('sso_code') }));
  assert.ok((await h.json()).token);
  assert.equal(lastLogin('plain').method, 'oidc');
  const s = browser();
  await samlSignIn(s, 'plain');
  assert.ok(s.jar.has('cc_token'));
});
