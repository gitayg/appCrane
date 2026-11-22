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
import { POPUP_FAILURE_REASONS } from '../server/utils/ssoPopup.js';
import { SSO_ERROR_TEXT, ssoErrorText } from '../studio-web/src/components/sso/ssoErrorText.ts';

// Three Low findings in SSO sign-up, driven against the real server with a stub
// OIDC IdP:
//  1. one client could file unlimited new sign-up requests;
//  2. the IdP's error_description (chosen by whoever crafts the callback link)
//     and exception text were shown on /login;
//  3. approving a request approved whatever email the row held at that moment,
//     though every sign-in rewrites it.

const REPO = fileURLToPath(new URL('..', import.meta.url));
const ENCRYPTION_KEY = 'b'.repeat(64);
const CLIENT_ID = 'crane-signup-hardening';
let child, base, dataDir, idp, idpBase, nonce;
let claims = {};
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const ADMIN_SESS = `sess_${crypto.randomBytes(16).toString('hex')}`;

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
        return req.on('end', () => json({ id_token: idToken(), token_type: 'Bearer' }));
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

/** One SSO sign-in as `who` from client address `ip` (loopback is a trusted proxy). */
async function signIn(who, ip = '203.0.113.10') {
  claims = who;
  const xff = { 'X-Forwarded-For': ip };
  const start = await fetch(`${base}/api/auth/oidc/start`, { redirect: 'manual', headers: xff });
  const loc = new URL(start.headers.get('location'));
  nonce = loc.searchParams.get('nonce');
  const cookie = start.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  const cb = await fetch(`${base}/api/auth/oidc/callback?${new URLSearchParams({ code: 'c', state: loc.searchParams.get('state') })}`, { redirect: 'manual', headers: { Cookie: cookie, ...xff } });
  assert.equal(cb.status, 302);
  return new URL(cb.headers.get('location')).searchParams.get('sso_error');
}
const person = (i, extra = {}) => ({ sub: `sub-${i}`, email: `p${i}@outside.example`, email_verified: true, name: `Person ${i}`, ...extra });

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-sso-harden-'));
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
  const admin = db.prepare("INSERT INTO users (name,email,role,active,kind) VALUES ('admin','admin@example.com','platform_admin',1,'human')").run().lastInsertRowid;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(admin, sha(ADMIN_SESS));
  db.close();
  const saved = await call('PUT', '/api/auth/oidc/config', {
    token: ADMIN_SESS,
    body: { enabled: true, discovery_url: idpBase, client_id: CLIENT_ID, provider_name: 'Test', auto_provision: true, allowed_domains: 'allowed.example' },
  });
  assert.equal(saved.status, 200);
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { idp?.close(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

test('one client address files at most 5 new sign-up requests an hour; others and repeat sign-ins are unaffected', async () => {
  for (let i = 1; i <= 5; i++) assert.equal(await signIn(person(i)), 'pending_approval', `request ${i}`);
  assert.equal(await signIn(person(6)), 'signup_rate_limited');
  assert.equal(q('SELECT id FROM sso_signup_requests WHERE subject = ?', 'sub-6'), undefined, 'the refused request was recorded');
  assert.equal(await signIn(person(1)), 'pending_approval', 'an existing request was refused as new');
  assert.equal(await signIn(person(7), '203.0.113.99'), 'pending_approval', 'another address was limited too');
  assert.equal(q("SELECT COUNT(*) n FROM sso_signup_requests").n, 6);
  const audit = q("SELECT detail FROM audit_log WHERE action = 'login-failed' AND detail LIKE '%signup_rate_limited%'");
  assert.ok(audit, 'the refusal is not audited');
});

test('the IdP error_description and exception text never reach /login; the log and audit keep them', async () => {
  const evil = 'Your account is locked. Call +1-555-0100 now';
  const cases = [
    [{ error: 'access_denied', error_description: evil }, 'denied'],
    [{ error: 'server_error', error_description: evil }, 'failed'],
    [{ error: evil }, 'failed'],
    [{ code: 'c', state: 'not-a-state' }, 'failed'],
    [{}, 'failed'],
  ];
  for (const [query, code] of cases) {
    const r = await fetch(`${base}/api/auth/oidc/callback?${new URLSearchParams(query)}`, { redirect: 'manual' });
    assert.equal(r.status, 302);
    const loc = r.headers.get('location');
    assert.equal(new URL(loc).searchParams.get('sso_error'), code, `${JSON.stringify(query)} -> ${loc}`);
    assert.doesNotMatch(decodeURIComponent(loc), /locked|555|state|Missing/i, loc);
  }
  assert.ok(q("SELECT 1 FROM audit_log WHERE action = 'login-failed' AND detail LIKE '%Call +1-555-0100%'"), 'the detail was not kept in the audit');

  const saml = await fetch(`${base}/api/auth/saml/callback`, {
    method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ SAMLResponse: 'garbage' }),
  });
  assert.equal(new URL(saml.headers.get('location')).searchParams.get('saml_error'), 'failed', saml.headers.get('location'));
});

test('the login page shows fixed text for every code, and nothing it was not given', () => {
  assert.deepEqual(Object.keys(SSO_ERROR_TEXT).sort(), Object.keys(POPUP_FAILURE_REASONS).sort(), 'the page and the popup disagree on the codes');
  for (const [k, v] of Object.entries(POPUP_FAILURE_REASONS)) assert.equal(ssoErrorText(k), v, k);
  assert.equal(ssoErrorText('Your account is locked'), POPUP_FAILURE_REASONS.failed);
  assert.equal(ssoErrorText('constructor'), POPUP_FAILURE_REASONS.failed);
  const login = readFileSync(join(REPO, 'studio-web/src/components/Login.tsx'), 'utf8');
  assert.match(login, /setError\(ssoErrorText\(ssoErr\)\)/);
  assert.doesNotMatch(login, /'SSO failed: ' \+ ssoErr/);
});

test('approval names the email the admin saw, and is refused if the row changed since', async () => {
  const who = person(20, { sub: 'sub-approve', email: 'first@outside.example' });
  assert.equal(await signIn(who, '198.51.100.20'), 'pending_approval');
  const id = q('SELECT id FROM sso_signup_requests WHERE subject = ?', who.sub).id;
  const approve = (body) => call('POST', `/api/auth/oidc/signup-requests/${id}/approve`, { token: ADMIN_SESS, body });

  assert.equal((await approve({})).status, 400, 'approved without saying which email');
  // The same identity signs in again with another address before the admin clicks.
  assert.equal(await signIn({ ...who, email: 'second@outside.example' }, '198.51.100.20'), 'pending_approval');
  const stale = await approve({ email: 'first@outside.example' });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.error.code, 'EMAIL_CHANGED');
  assert.equal(q('SELECT id FROM users WHERE sso_sub = ?', who.sub), undefined, 'an account was created for an email nobody approved');
  assert.equal(q('SELECT status FROM sso_signup_requests WHERE id = ?', id).status, 'pending');

  const ok = await approve({ email: 'Second@outside.example' });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(q('SELECT email FROM users WHERE sso_sub = ?', who.sub).email, 'second@outside.example');
});

test('the Settings card sends the email it shows and reloads the list when the server says it changed', () => {
  const card = readFileSync(join(REPO, 'studio-web/src/components/sso/SignupRequestsCard.tsx'), 'utf8');
  assert.match(card, /action === 'approve' \? \{ email: r\.email \} : \{\}/);
  assert.match(card, /EMAIL_CHANGED/);
});

test('unit: the per-IP counter forgets after an hour and counts each address apart', async () => {
  const { signupLimited, noteSignup, SIGNUP_PER_IP, SIGNUP_WINDOW_MS } = await import('../server/services/ssoSignupRateLimit.js');
  const t = 1_000_000;
  for (let i = 0; i < SIGNUP_PER_IP; i++) { assert.equal(signupLimited('192.0.2.1', t), false); noteSignup('192.0.2.1', t); }
  assert.equal(signupLimited('192.0.2.1', t + 1), true);
  assert.equal(signupLimited('192.0.2.2', t + 1), false);
  assert.equal(signupLimited('192.0.2.1', t + SIGNUP_WINDOW_MS), false);
});
