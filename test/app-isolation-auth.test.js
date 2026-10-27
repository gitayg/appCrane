import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import express from 'express';

// Per-app origins, server side (services/appOrigin.js). With
// app_isolation_domain set, each app runs on its own host and is signed in by
// a one-time handoff from the platform host into an 'app'-scope session that
// is good for that one app and environment only. These tests drive the routes
// over HTTP the way the browser and Caddy do, with a real Host header (fetch
// cannot set one, so they use http.request).

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-isolation-auth-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const PLATFORM = 'crane.example.test';
const DOMAIN = 'apps.example.test';
const isolationOn = () => db.prepare("INSERT INTO settings (key, value) VALUES ('app_isolation_domain', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(DOMAIN);
const isolationOff = () => db.prepare("DELETE FROM settings WHERE key = 'app_isolation_domain'").run();
isolationOn();

const mkApp = (slug, slot) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES (?,?,?,'managed','forward_auth','private')"
).run(slug, slug, slot).lastInsertRowid;
const HUB = mkApp('hub', 1);
const OTHER = mkApp('other', 2);
mkApp('secret', 3);

const mkUser = (name, role = 'user') => db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
  .run(name, `${name}@example.test`, role, hashApiKey(`key-${name}`)).lastInsertRowid;
const alice = mkUser('alice');
mkUser('admin0', 'platform_admin');
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user'),(?,?,'owner')").run(HUB, alice, OTHER, alice);

let n = 0;
function platformSession(userId = alice) {
  const token = `plat-${++n}`;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))")
    .run(userId, hashApiKey(token));
  return token;
}

const identityRouter = (await import('../server/routes/identity.js')).default;
const handoff = await import('../server/routes/appHandoff.js');
const meRouter = (await import('../server/routes/me.js')).default;
const { requireAuth } = await import('../server/middleware/auth.js');
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/__appcrane', handoff.appHostRouter);
api.use('/api/identity', handoff.default);
api.use('/api/identity', identityRouter);
api.get('/api/probe', requireAuth, (req, res) => res.json({ id: req.user.id }));
api.use('/api', meRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const PORT = server.address().port;

function call(path, { method = 'GET', host = PLATFORM, headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const r = http.request({
      host: '127.0.0.1', port: PORT, path, method,
      headers: { Host: host, Accept: 'application/json', ...(data && { 'Content-Type': 'application/json' }), ...headers },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: text }));
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

const cookieValue = (res, name) => {
  const line = (res.headers['set-cookie'] || []).find((c) => c.startsWith(`${name}=`));
  return line ? decodeURIComponent(line.slice(name.length + 1).split(';')[0]) : null;
};

// The app host's state cookie value for "this browser", and its hash as the
// handoff URL carries it.
const STATE = 'browser-state-value';
const stateOf = (v) => hashApiKey(v);

/** Platform handoff → the code it hands to the app host. */
async function issueCode(platformToken, { app = 'hub', env = 'production', ret = '/', state = STATE } = {}) {
  const r = await call(`/api/identity/handoff?app=${app}&env=${env}&return=${encodeURIComponent(ret)}&state=${stateOf(state)}`, {
    headers: { Cookie: `__Host-cc_token=${platformToken}` },
  });
  assert.equal(r.status, 302, r.body);
  const loc = new URL(r.headers.location);
  return { code: loc.searchParams.get('code'), location: loc, res: r };
}

const land = (code, host = `hub.${DOMAIN}`, state = STATE) => call(`/__appcrane/session?code=${encodeURIComponent(code)}`, {
  host, headers: state === null ? {} : { Cookie: `__Host-cc_handoff=${state}` },
});

const verifyIsolated = (app, env, headers) => call(`/api/identity/verify?app=${app}&env=${env}&host=isolated`, {
  headers: { 'X-Forwarded-Uri': '/', 'X-Forwarded-Method': 'GET', 'X-Forwarded-Host': `${env === 'sandbox' ? `${app}-sandbox` : app}.${DOMAIN}`, ...headers },
});

async function appSession(platformToken = platformSession(), opts = {}) {
  const { code } = await issueCode(platformToken, opts);
  const host = `${opts.env === 'sandbox' ? `${opts.app || 'hub'}-sandbox` : (opts.app || 'hub')}.${DOMAIN}`;
  const r = await land(code, host);
  assert.equal(r.status, 302, r.body);
  return { token: cookieValue(r, '__Host-cc_app'), platformToken, res: r };
}

test('handoff happy path: platform cookie → code → app host cookie → verify and /api/me on the app host', async () => {
  const plat = platformSession();
  const { location, res } = await issueCode(plat, { ret: '/hub/page?x=1' });
  assert.equal(location.origin, `https://hub.${DOMAIN}`);
  assert.equal(location.pathname, '/__appcrane/session');
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.headers['referrer-policy'], 'no-referrer');
  const stored = db.prepare('SELECT * FROM app_handoff_codes WHERE code_hash = ?').get(hashApiKey(location.searchParams.get('code')));
  assert.ok(stored, 'only the hash of the code is stored');
  assert.equal(stored.parent_token_hash, hashApiKey(plat));

  const landed = await land(location.searchParams.get('code'));
  assert.equal(landed.status, 302, landed.body);
  assert.equal(landed.headers.location, '/hub/page?x=1');
  const line = landed.headers['set-cookie'].find((c) => c.startsWith('__Host-cc_app='));
  for (const attr of ['Path=/', 'Secure', 'HttpOnly', 'SameSite=Lax']) assert.ok(line.includes(attr), `${attr} in ${line}`);
  assert.doesNotMatch(line, /Domain=/i);
  const token = cookieValue(landed, '__Host-cc_app');

  const row = db.prepare('SELECT s.*, p.expires_at AS p_exp, p.absolute_expires_at AS p_abs FROM identity_sessions s JOIN identity_sessions p ON p.token_hash = s.parent_token_hash WHERE s.token_hash = ?').get(hashApiKey(token));
  assert.equal(row.scope, 'app');
  assert.equal(row.app_id, HUB);
  assert.equal(row.app_env, 'production');
  assert.ok(Date.parse(row.expires_at.replace(' ', 'T')) <= Date.parse(row.p_exp.replace(' ', 'T')), 'idle deadline no later than the parent');
  assert.ok(Date.parse(row.absolute_expires_at.replace(' ', 'T')) <= Date.parse(row.p_abs.replace(' ', 'T')), 'absolute deadline no later than the parent');

  const v = await verifyIsolated('hub', 'production', { Cookie: `__Host-cc_app=${token}` });
  assert.equal(v.status, 200, v.body);
  assert.equal(v.headers['x-appcrane-user-id'], String(alice));
  assert.equal(v.headers['x-appcrane-app-role'], 'user');

  const me = await call('/api/me?app=other', { host: `hub.${DOMAIN}`, headers: { Cookie: `__Host-cc_app=${token}`, Referer: `https://${PLATFORM}/other/` } });
  assert.equal(me.status, 200, me.body);
  const body = JSON.parse(me.body);
  assert.equal(body.app, 'hub', '?app= and Referer are ignored on an app host');
  assert.equal(body.app_role, 'user');

  const dir = await call('/api/directory', { host: `hub.${DOMAIN}`, headers: { Cookie: `__Host-cc_app=${token}` } });
  assert.equal(dir.status, 200, dir.body);
});

test('an unauthenticated browser on an app host is sent to the platform handoff with its original URI', async () => {
  const r = await verifyIsolated('hub', 'sandbox', { 'X-Forwarded-Uri': '/hub-sandbox/deep?q=1', Accept: 'text/html' });
  assert.equal(r.status, 302, r.body);
  const loc = new URL(r.headers.location);
  assert.equal(loc.origin, `https://${PLATFORM}`);
  assert.equal(loc.pathname, '/api/identity/handoff');
  assert.equal(loc.searchParams.get('app'), 'hub');
  assert.equal(loc.searchParams.get('env'), 'sandbox');
  assert.equal(loc.searchParams.get('return'), '/hub-sandbox/deep?q=1');
});

test('handoff without a platform session goes to /login and names a redirect /login accepts', async () => {
  const { isSafeRedirect } = await import('../server/utils/safeRedirect.js');
  const r = await call('/api/identity/handoff?app=hub&env=production&return=%2F');
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.location, `https://${PLATFORM}`);
  assert.equal(loc.pathname, '/login');
  const back = loc.searchParams.get('redirect');
  assert.equal(back, '/api/identity/handoff?app=hub&env=production&return=%2F');
  assert.ok(isSafeRedirect(back));

  // The legacy cookie name is not read with isolation on.
  const legacy = await call('/api/identity/handoff?app=hub&env=production', { headers: { Cookie: `cc_token=${platformSession()}` } });
  assert.equal(legacy.status, 302);
  assert.match(legacy.headers.location, /^\/login\?/);
});

test('handoff refuses a user the gate would refuse, and sanitises the return path', async () => {
  const r = await call('/api/identity/handoff?app=secret&env=production', { headers: { Cookie: `__Host-cc_token=${platformSession()}` } });
  assert.equal(r.status, 403, r.body);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM app_handoff_codes WHERE app_id = (SELECT id FROM apps WHERE slug = ?)').get('secret').c, 0);

  for (const bad of ['//evil.example', '/\\evil.example', 'https://evil.example/', '/a\\b', '/a\tb']) {
    const { code } = await issueCode(platformSession(), { ret: bad });
    assert.equal(db.prepare('SELECT return_path FROM app_handoff_codes WHERE code_hash = ?').get(hashApiKey(code)).return_path, '/', bad);
  }
});

test('a code works once', async () => {
  const { code } = await issueCode(platformSession());
  assert.equal((await land(code)).status, 302);
  const again = await land(code);
  assert.equal(again.status, 403);
  assert.equal(again.headers['set-cookie'], undefined);
});

test('an expired code is refused', async () => {
  const { code } = await issueCode(platformSession());
  db.prepare("UPDATE app_handoff_codes SET expires_at = datetime('now', '-1 second') WHERE code_hash = ?").run(hashApiKey(code));
  const r = await land(code);
  assert.equal(r.status, 403);
  assert.equal(cookieValue(r, '__Host-cc_app'), null, 'no app session');
});

test("a code for one app is refused on another app's host, and is spent", async () => {
  const { code } = await issueCode(platformSession());
  const elsewhere = await land(code, `other.${DOMAIN}`);
  assert.equal(elsewhere.status, 403);
  assert.equal(elsewhere.headers['set-cookie'], undefined);
  assert.equal((await land(code)).status, 403, 'a code shown on the wrong host cannot be replayed on the right one');
});

test('a sandbox code is refused on the production host', async () => {
  const { code, location } = await issueCode(platformSession(), { env: 'sandbox' });
  assert.equal(location.origin, `https://hub-sandbox.${DOMAIN}`);
  const r = await land(code, `hub.${DOMAIN}`);
  assert.equal(r.status, 403);
  assert.equal(cookieValue(r, '__Host-cc_app'), null, 'no app session');
});

test('an app session is refused by the platform API and by non-isolated verify', async () => {
  const { token } = await appSession();
  const bearer = { Authorization: `Bearer ${token}` };
  assert.equal((await call('/api/probe', { headers: bearer })).status, 401, 'requireAuth');
  assert.equal((await call('/api/me', { headers: bearer })).status, 401, '/api/me on the platform host');
  assert.equal((await call('/api/identity/me', { headers: bearer })).status, 401, '/api/identity/me');
  assert.equal((await call('/api/identity/refresh-cookie', { method: 'POST', headers: bearer })).status, 401, 'refresh-cookie');
  const v = await call('/api/identity/verify?app=hub&prefix=/hub', { headers: { ...bearer, 'X-Forwarded-Uri': '/' } });
  assert.equal(v.status, 401, v.body);
  const viaCookie = await call('/api/identity/verify?app=hub&prefix=/hub', {
    headers: { Cookie: `__Host-cc_token=${token}`, 'X-Forwarded-Uri': '/', Accept: 'text/html' },
  });
  assert.equal(viaCookie.status, 302, 'an app token in the platform cookie is no session');
  assert.match(viaCookie.headers.location, /\/login/);
});

test('a platform session is refused by isolated verify, and an app session only counts for its own app and env', async () => {
  const plat = platformSession();
  assert.equal((await verifyIsolated('hub', 'production', { Authorization: `Bearer ${plat}` })).status, 401);
  const asCookie = await verifyIsolated('hub', 'production', { Cookie: `__Host-cc_app=${plat}`, Accept: 'text/html' });
  assert.equal(asCookie.status, 302);
  assert.match(asCookie.headers.location, /\/api\/identity\/handoff\?/);

  const { token } = await appSession(plat);
  assert.equal((await verifyIsolated('hub', 'production', { Authorization: `Bearer ${token}` })).status, 200);
  assert.equal((await verifyIsolated('other', 'production', { Authorization: `Bearer ${token}` })).status, 401);
  assert.equal((await verifyIsolated('hub', 'sandbox', { Authorization: `Bearer ${token}` })).status, 401);
});

test('/api/me on an app host takes only that host\'s app cookie', async () => {
  const plat = platformSession();
  const host = `hub.${DOMAIN}`;
  assert.equal((await call('/api/me', { host, headers: { Cookie: `__Host-cc_token=${plat}` } })).status, 401);
  assert.equal((await call('/api/me', { host, headers: { Authorization: `Bearer ${plat}` } })).status, 401);
  const { token } = await appSession(plat, { app: 'other' });
  assert.equal((await call('/api/me', { host, headers: { Cookie: `__Host-cc_app=${token}` } })).status, 401, "another app's session");
});

test('platform sign-out ends the app sessions issued from it; app sign-out ends only its own', async () => {
  const plat = platformSession();
  const a = await appSession(plat);
  const b = await appSession(plat, { app: 'other' });
  const unrelated = await appSession();

  const out = await call('/__appcrane/logout', { host: `other.${DOMAIN}`, headers: { Cookie: `__Host-cc_app=${b.token}` } });
  assert.equal(out.status, 302);
  assert.equal(out.headers.location, `https://${PLATFORM}/`);
  assert.ok(out.headers['set-cookie'].some((c) => c.startsWith('__Host-cc_app=;') && c.includes('Secure')));
  assert.equal(db.prepare('SELECT COUNT(*) c FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(b.token)).c, 0);
  assert.equal((await verifyIsolated('hub', 'production', { Authorization: `Bearer ${a.token}` })).status, 200);

  const r = await call('/api/identity/logout', { method: 'POST', headers: { Authorization: `Bearer ${plat}` } });
  assert.equal(r.status, 200);
  assert.equal((await verifyIsolated('hub', 'production', { Authorization: `Bearer ${a.token}` })).status, 401, 'child session gone');
  assert.equal((await verifyIsolated('hub', 'production', { Authorization: `Bearer ${unrelated.token}` })).status, 200, 'another sign-in untouched');

  // logout-beacon too.
  const plat2 = platformSession();
  const c = await appSession(plat2);
  await call('/api/identity/logout-beacon', { method: 'POST', body: { token: plat2 } });
  assert.equal((await verifyIsolated('hub', 'production', { Authorization: `Bearer ${c.token}` })).status, 401);
});

test('a code issued before sign-out cannot be landed after it', async () => {
  const plat = platformSession();
  const { code } = await issueCode(plat);
  await call('/api/identity/logout', { method: 'POST', headers: { Authorization: `Bearer ${plat}` } });
  const r = await land(code);
  assert.equal(r.status, 403);
  assert.equal(cookieValue(r, '__Host-cc_app'), null, 'no app session');
});

test('tls-ask answers 200 only for an existing app host, and only to a direct loopback caller', async () => {
  assert.equal((await call(`/api/identity/tls-ask?domain=hub.${DOMAIN}`)).status, 200);
  assert.equal((await call(`/api/identity/tls-ask?domain=hub-sandbox.${DOMAIN}`)).status, 200);
  assert.equal((await call(`/api/identity/tls-ask?domain=nope.${DOMAIN}`)).status, 404);
  assert.equal((await call(`/api/identity/tls-ask?domain=${PLATFORM}`)).status, 404);
  assert.equal((await call(`/api/identity/tls-ask?domain=a.hub.${DOMAIN}`)).status, 404);
  assert.equal((await call(`/api/identity/tls-ask?domain=hub.${DOMAIN}`, { headers: { 'X-Forwarded-For': '203.0.113.9' } })).status, 404,
    'a request Caddy proxied in from outside');
});

test('isolation on: the platform cookie is __Host-cc_token, and a cookie write must be same-origin', async () => {
  const plat = platformSession();
  const r = await call('/api/identity/refresh-cookie', { method: 'POST', headers: { Authorization: `Bearer ${plat}` } });
  assert.equal(r.status, 200);
  const line = r.headers['set-cookie'].find((c) => c.startsWith('__Host-cc_token='));
  assert.ok(line && line.includes('Secure') && line.includes('Path=/') && !/Domain=/i.test(line), String(r.headers['set-cookie']));
  assert.ok(!r.headers['set-cookie'].some((c) => c.startsWith('cc_token=')));

  const put = (headers) => call('/api/me/claude-token', { method: 'DELETE', headers: { Cookie: `__Host-cc_token=${plat}`, ...headers } });
  const cross = await put({ 'Sec-Fetch-Site': 'same-site' });
  assert.equal(cross.status, 403, cross.body);
  assert.equal(JSON.parse(cross.body).error.code, 'CSRF_REFUSED');
  assert.equal((await put({ Origin: `https://hub.${DOMAIN}` })).status, 403);
  assert.equal((await put({ 'Sec-Fetch-Site': 'same-origin' })).status, 200);
  assert.equal((await put({ Origin: `https://${PLATFORM}` })).status, 200);
  // Bearer is not a cookie: no guard.
  assert.equal((await call('/api/me/claude-token', { method: 'DELETE', headers: { Authorization: `Bearer ${plat}`, 'Sec-Fetch-Site': 'cross-site' } })).status, 200);
});

test('isolation off: cc_token works exactly as before and the app routes stay out of the way', async () => {
  isolationOff();
  try {
    const plat = platformSession();
    const v = await call('/api/identity/verify?app=hub&prefix=/hub', { headers: { Cookie: `cc_token=${plat}`, 'X-Forwarded-Uri': '/' } });
    assert.equal(v.status, 200, v.body);
    assert.equal(v.headers['x-appcrane-user-id'], String(alice));
    const me = await call('/api/me?app=hub', { headers: { Cookie: `cc_token=${plat}` } });
    assert.equal(me.status, 200, me.body);
    assert.equal(JSON.parse(me.body).app_role, 'user');
    assert.equal((await call('/api/me', { headers: { Cookie: `__Host-cc_token=${plat}` } })).status, 401, 'the __Host- name is only read with isolation on');

    const r = await call('/api/identity/refresh-cookie', { method: 'POST', headers: { Authorization: `Bearer ${plat}` } });
    const line = r.headers['set-cookie'].find((c) => c.startsWith('cc_token='));
    assert.ok(line && !line.includes('Secure'), 'plain http request: no Secure, as before');
    assert.ok(!r.headers['set-cookie'].some((c) => c.startsWith('__Host-')));

    assert.equal((await call('/api/identity/handoff?app=hub&env=production', { headers: { Cookie: `cc_token=${plat}` } })).status, 400);
    assert.equal((await call('/__appcrane/session?code=x', { host: `hub.${DOMAIN}` })).status, 404);
    assert.equal((await call(`/api/identity/tls-ask?domain=hub.${DOMAIN}`)).status, 404);
    assert.equal((await call('/api/me/claude-token', { method: 'DELETE', headers: { Cookie: `cc_token=${plat}`, 'Sec-Fetch-Site': 'same-site' } })).status, 200,
      'no CSRF guard change with isolation off');
  } finally {
    isolationOn();
  }
});

test('a custom domain with AppCrane sign-in is an app host for production; without it, it is not', async () => {
  db.prepare("UPDATE apps SET domain = 'hub.example.org', custom_domain_auth = 1 WHERE id = ?").run(HUB);
  try {
    assert.deepEqual(handoff.resolveAppHost(db, 'HUB.example.org:443')?.env, 'production');
    const plat = platformSession();
    const r = await call(`/api/identity/handoff?app=hub&env=production&site=hub.example.org&state=${stateOf(STATE)}`, { headers: { Cookie: `__Host-cc_token=${plat}` } });
    assert.equal(new URL(r.headers.location).origin, 'https://hub.example.org');
    const forged = await call(`/api/identity/handoff?app=hub&env=production&site=other.${DOMAIN}&state=${stateOf(STATE)}`, { headers: { Cookie: `__Host-cc_token=${plat}` } });
    assert.equal(new URL(forged.headers.location).origin, `https://hub.${DOMAIN}`, "a site that is not this app's falls back to its own host");
    db.prepare('UPDATE apps SET custom_domain_auth = 0 WHERE id = ?').run(HUB);
    assert.equal(handoff.resolveAppHost(db, 'hub.example.org'), null);
    assert.equal(handoff.resolveAppHost(db, PLATFORM), null);
  } finally {
    db.prepare('UPDATE apps SET domain = NULL, custom_domain_auth = 0 WHERE id = ?').run(HUB);
  }
});

test('a sign-in code works only in the browser that started the sign-in (no login CSRF)', async () => {
  // An attacker asks for a code with their own browser state and sends the
  // victim the /__appcrane/session link. The victim's browser holds a different
  // state value, or none, so the code must not sign the victim in.
  const attacker = platformSession();
  for (const victimState of [null, 'victim-own-state']) {
    const { code } = await issueCode(attacker, { state: 'attacker-state' });
    const r = await land(code, `hub.${DOMAIN}`, victimState);
    assert.equal(r.status, 403, `victim state ${victimState}`);
    assert.equal(cookieValue(r, '__Host-cc_app'), null, 'no app session for the victim');
    assert.equal(db.prepare("SELECT COUNT(*) c FROM app_handoff_codes WHERE code_hash = ? AND used_at IS NOT NULL").get(hashApiKey(code)).c, 1, 'the code is spent');
  }
  const ok = await land((await issueCode(attacker, { state: 'attacker-state' })).code, `hub.${DOMAIN}`, 'attacker-state');
  assert.equal(ok.status, 302, 'the browser that started it signs in');
});

test('verify sets the state cookie on the app host and sends only its hash; handoff refuses a missing state', async () => {
  const r = await verifyIsolated('hub', 'production', {});
  assert.equal(r.status, 302);
  const state = cookieValue(r, '__Host-cc_handoff');
  assert.ok(state && state.length >= 40, 'state cookie set');
  const line = r.headers['set-cookie'].find((c) => c.startsWith('__Host-cc_handoff='));
  assert.match(line, /HttpOnly/i); assert.match(line, /Secure/i); assert.match(line, /Path=\//);
  const loc = new URL(r.headers.location);
  assert.equal(loc.searchParams.get('state'), hashApiKey(state));
  assert.ok(!r.headers.location.includes(state), 'the value itself never travels in a URL');

  const none = await call('/api/identity/handoff?app=hub&env=production&return=%2F', { headers: { Cookie: `__Host-cc_token=${platformSession()}` } });
  assert.equal(none.status, 400);
});
