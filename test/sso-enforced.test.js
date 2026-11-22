import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import net from 'net';
import crypto from 'crypto';
import Database from 'better-sqlite3';

// "Require SSO sign-in" (auth_sso_only, services/authPolicy.js): on unless a
// platform admin stored 'false', in force only while an SSO provider is on.
// While in force every non-SSO way to a dashboard session or a password is
// refused server-side with 403 SSO_REQUIRED; the OIDC callback still signs in
// and API keys still work as API credentials. Break-glass is `crane sso
// enforce off` on the host.
//
// Driven against the real server process (server/index.js) with a stub OIDC
// IdP, the database seeded directly. The login limiter allows 5 attempts a
// minute per IP and every request here comes from 127.0.0.1, so the file makes
// at most 4 POST /api/identity/login calls.

const REPO = fileURLToPath(new URL('..', import.meta.url));
const ENCRYPTION_KEY = 'e'.repeat(64);
const CRANE_DOMAIN = 'app.example.com';
const CLIENT_ID = 'crane-sso-enforced-test';
const PW = 'alice-password-0001';
const NEW_PW = 'a-brand-new-password-0002';
let child, base, dataDir, idp, idpBase, nonce, oidcCookie;

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const rnd = (p) => `${p}_${crypto.randomBytes(16).toString('hex')}`;
const K = { adminKey: rnd('dhk_admin'), adminSess: rnd('sess'), aliceKey: rnd('dhk_user'), aliceSess: rnd('sess'), bobKey: rnd('dhk_user') };
const ids = {};

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// ---- stub OIDC IdP --------------------------------------------------------
const { privateKey: oidcKey, publicKey: oidcPub } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...oidcPub.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
function idToken() {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = enc({ iss: idpBase, aud: CLIENT_ID, sub: 'alice-sub', email: 'alice@example.com', email_verified: true, name: 'Alice Example', nonce, exp: Math.floor(Date.now() / 1000) + 300 });
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
function setSetting(key, value) {
  const db = dbw();
  try {
    if (value === null) db.prepare('DELETE FROM settings WHERE key = ?').run(key);
    else db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
  } finally { db.close(); }
}
const sessions = (uid) => q('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?', uid).n;
const allSessions = () => q('SELECT COUNT(*) n FROM identity_sessions').n;
const pwHash = (uid) => q('SELECT password_hash h FROM users WHERE id = ?', uid).h;
const refusals = () => q("SELECT COUNT(*) n FROM audit_log WHERE action = 'sso-required-refused'").n;

// The three states the policy can be in.
const enforced = () => { setSetting('oidc_enabled', '1'); setSetting('auth_sso_only', null); };
const toggledOff = () => { setSetting('oidc_enabled', '1'); setSetting('auth_sso_only', 'false'); };
const noProvider = () => { setSetting('oidc_enabled', '0'); setSetting('auth_sso_only', 'true'); };

async function call(method, path, { token, apiKey, body, headers = {} } = {}) {
  const h = { 'Content-Type': 'application/json', ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (apiKey) h['X-API-Key'] = apiKey;
  const res = await fetch(base + path, { method, headers: h, redirect: 'manual', body: body === undefined ? undefined : JSON.stringify(body) });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json, res };
}
const login = () => call('POST', '/api/identity/login', { body: { login: 'alice@example.com', password: PW } });
function challenge(purpose) {
  const token = crypto.randomBytes(32).toString('base64url');
  const db = dbw();
  try {
    db.prepare('INSERT INTO mfa_challenges (token_hash, user_id, purpose, app_id, expires_at) VALUES (?, ?, ?, NULL, ?)')
      .run(sha(token), ids.alice, purpose, new Date(Date.now() + 5 * 60_000).toISOString());
  } finally { db.close(); }
  return token;
}
const assertRefused = (r, label) => {
  assert.equal(r.status, 403, `${label}: expected 403, got ${r.status} ${JSON.stringify(r.body)}`);
  assert.equal(r.body?.error?.code, 'SSO_REQUIRED', `${label}: wrong code ${JSON.stringify(r.body)}`);
};

before(async () => {
  process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;
  const { hashPassword } = await import('../server/services/encryption.js');
  dataDir = mkdtempSync(join(tmpdir(), 'crane-sso-enforced-'));
  idp = await startIdp();
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO,
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
  const db = dbw();
  const ins = db.prepare("INSERT INTO users (name,email,role,api_key_hash,password_hash,active,kind) VALUES (?,?,?,?,?,1,'human')");
  ids.admin = ins.run('admin', 'admin@example.com', 'platform_admin', sha(K.adminKey), hashPassword('admin-password-0001')).lastInsertRowid;
  ids.alice = ins.run('Alice Example', 'alice@example.com', 'user', sha(K.aliceKey), hashPassword(PW)).lastInsertRowid;
  ids.bob = ins.run('Bob Example', 'bob@example.com', 'user', sha(K.bobKey), null).lastInsertRowid;
  const sess = db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))");
  sess.run(ids.admin, sha(K.adminSess));
  sess.run(ids.alice, sha(K.aliceSess));
  const set = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
  set.run('oidc_enabled', '1');
  set.run('oidc_discovery_url', idpBase);
  set.run('oidc_client_id', CLIENT_ID);
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { idp?.close(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

// ---------------------------------------------------------------------------
// In force: provider on, the setting never written (the default)
// ---------------------------------------------------------------------------

test('default: GET /api/settings/auth_sso_only is still public, and an absent row means on', async () => {
  enforced();
  const r = await call('GET', '/api/settings/auth_sso_only');
  assert.equal(r.status, 200);
  assert.equal(r.body.value, null, 'the test expects the row absent');
});

test('in force: password login is refused, no session is issued, the refusal is audited', async () => {
  enforced();
  const s0 = allSessions();
  const a0 = refusals();
  assertRefused(await login(), 'login');
  assert.equal(allSessions(), s0, 'a session was issued');
  assert.equal(refusals(), a0 + 1, 'the refusal was not audited');
});

test('in force: the MFA second step of a password sign-in is refused', async () => {
  enforced();
  const s0 = allSessions();
  assertRefused(await call('POST', '/api/identity/mfa/verify', { body: { mfa_token: challenge('verify'), code: '123456' } }), 'mfa verify');
  assertRefused(await call('POST', '/api/identity/mfa/enroll/start', { body: { mfa_token: challenge('enroll') } }), 'mfa enroll/start');
  assertRefused(await call('POST', '/api/identity/mfa/enroll/confirm', { body: { mfa_token: challenge('enroll'), code: '123456' } }), 'mfa enroll/confirm');
  assert.equal(allSessions(), s0);
});

test('in force: set-password is refused with a session and with an API key', async () => {
  enforced();
  const before = pwHash(ids.alice);
  const n = sessions(ids.alice);
  assertRefused(await call('POST', '/api/identity/set-password', { token: K.aliceSess, body: { current_password: PW, password: NEW_PW } }), 'set-password (Bearer)');
  assert.equal(pwHash(ids.alice), before, 'the password changed');
  assert.equal(sessions(ids.alice), n, 'sessions were wiped or issued');

  assertRefused(await call('POST', '/api/identity/set-password', { apiKey: K.bobKey, body: { password: NEW_PW } }), 'set-password (API key)');
  assert.equal(pwHash(ids.bob), null, 'an API key set a password');
  assert.equal(sessions(ids.bob), 0, 'an API key got a session');
});

test('in force: a platform admin setting a user password is refused', async () => {
  enforced();
  assertRefused(await call('PUT', `/api/users/${ids.bob}/password`, { token: K.adminSess, body: { password: NEW_PW } }), 'PUT /api/users/:id/password');
  assert.equal(pwHash(ids.bob), null);
});

test('in force: API keys still work as API credentials, and an existing session still refreshes its cookie', async () => {
  enforced();
  const me = await call('GET', '/api/auth/me', { apiKey: K.aliceKey });
  assert.equal(me.status, 200, JSON.stringify(me.body));
  assert.equal(me.body.user.email, 'alice@example.com');
  const rc = await call('POST', '/api/identity/refresh-cookie', { token: K.aliceSess });
  assert.equal(rc.status, 200, JSON.stringify(rc.body));
});

test('in force: the OIDC callback still issues a session', async () => {
  enforced();
  const start = await fetch(`${base}/api/auth/oidc/start?redirect=%2Flaunch`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const loc = new URL(start.headers.get('location'));
  nonce = loc.searchParams.get('nonce');
  oidcCookie = start.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  const n = sessions(ids.alice);
  const cb = await fetch(`${base}/api/auth/oidc/callback?${new URLSearchParams({ code: 'c1', state: loc.searchParams.get('state') })}`, { redirect: 'manual', headers: { Cookie: oidcCookie } });
  assert.equal(cb.status, 302);
  assert.ok(cb.headers.getSetCookie().some((c) => c.startsWith('cc_token=')), 'callback set no session cookie');
  assert.equal(new URL(cb.headers.get('location')).searchParams.get('sso_error'), null);
  assert.equal(sessions(ids.alice), n + 1, 'callback did not create a session');
});

test('a non-admin cannot turn it off; a platform admin can', async () => {
  enforced();
  const r = await call('PUT', '/api/settings/auth_sso_only', { token: K.aliceSess, body: { value: 'false' } });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(q("SELECT value FROM settings WHERE key = 'auth_sso_only'"), undefined, 'a non-admin wrote the setting');
  const ok = await call('PUT', '/api/settings/auth_sso_only', { token: K.adminSess, body: { value: 'false' } });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(q("SELECT value FROM settings WHERE key = 'auth_sso_only'").value, 'false');
});

// ---------------------------------------------------------------------------
// Turned off, and no provider
// ---------------------------------------------------------------------------

test('toggled off: password login and set-password by API key work again', async () => {
  toggledOff();
  const r = await login();
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.token);
  const sp = await call('POST', '/api/identity/set-password', { apiKey: K.bobKey, body: { password: NEW_PW } });
  assert.equal(sp.status, 200, JSON.stringify(sp.body));
  assert.ok(pwHash(ids.bob));
  const mv = await call('POST', '/api/identity/mfa/verify', { body: { mfa_token: challenge('verify'), code: '123456' } });
  assert.notEqual(mv.body?.error?.code, 'SSO_REQUIRED');
});

test('no provider: the switch on has no effect', async () => {
  noProvider();
  const r = await login();
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const adm = await call('PUT', `/api/users/${ids.bob}/password`, { token: K.adminSess, body: { password: NEW_PW + 'x' } });
  assert.equal(adm.status, 200, JSON.stringify(adm.body));
});

// ---------------------------------------------------------------------------
// Break-glass on the host
// ---------------------------------------------------------------------------

test('crane sso enforce off on the host lifts it; on puts it back', async () => {
  setSetting('oidc_enabled', '1');
  setSetting('auth_sso_only', 'true');
  const cli = (state) => execFileSync(process.execPath, ['cli/index.js', 'sso', 'enforce', state], {
    cwd: REPO, env: { ...process.env, DATA_DIR: dataDir, ENCRYPTION_KEY, LOG_LEVEL: 'error', HOME: dataDir }, encoding: 'utf8',
  });
  assert.match(cli('status'), /Require SSO sign-in: on/);
  assert.match(cli('off'), /Require SSO sign-in: off/);
  assert.equal(q("SELECT value FROM settings WHERE key = 'auth_sso_only'").value, 'false');
  assert.ok(q("SELECT id FROM audit_log WHERE action = 'sso-enforce-cli'"), 'the CLI change was not audited');
  const r = await login();
  assert.equal(r.status, 200, JSON.stringify(r.body));
  cli('on');
  assert.equal(q("SELECT value FROM settings WHERE key = 'auth_sso_only'").value, 'true');
});

// ---------------------------------------------------------------------------
// Migration 170
// ---------------------------------------------------------------------------

test('migration 170 turns a stored false to true only where a provider is enabled', () => {
  const dir = join(REPO, 'server', 'migrations');
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  const later = files.filter((f) => f > '170-auth-sso-enforced.sql');
  assert.ok(!later.some((f) => readFileSync(join(dir, f), 'utf8').includes('auth_sso_only')), 'a later migration rewrites auth_sso_only');
  const sql = readFileSync(join(dir, '170-auth-sso-enforced.sql'), 'utf8');
  const run = (rows) => {
    const db = new Database(':memory:');
    db.exec(readFileSync(join(dir, '005-settings.sql'), 'utf8').replace(/REFERENCES users\(id\) ON DELETE SET NULL/, ''));
    const ins = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
    for (const [k, v] of rows) ins.run(k, v);
    db.exec(sql);
    const v = db.prepare("SELECT value FROM settings WHERE key = 'auth_sso_only'").get()?.value ?? null;
    db.close();
    return v;
  };
  assert.equal(run([['saml_enabled', '1'], ['auth_sso_only', 'false']]), 'true', 'saml on + false');
  assert.equal(run([['oidc_enabled', '1']]), 'true', 'oidc on + no row');
  assert.equal(run([['saml_enabled', '0'], ['oidc_enabled', '0'], ['auth_sso_only', 'false']]), 'false', 'no provider + false');
  assert.equal(run([['auth_sso_only', 'false']]), 'false', 'no provider rows + false');
  assert.equal(run([]), null, 'fresh install');
});
