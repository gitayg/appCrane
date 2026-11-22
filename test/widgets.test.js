import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import http from 'http';
import express from 'express';

// Drop-in widgets on an app's own host (routes/widgets.js): the script, the
// widget token (services/widgetTokens.js) and the endpoints it opens. Driven
// over HTTP with a real Host header, the way Caddy forwards /__appcrane/* from
// an app host.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-widgets-'));
after(() => rmSync(process.env.DATA_DIR, { recursive: true, force: true }));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('app_isolation_domain', 'apps.example.test')").run();

const mkApp = (slug, slot) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES (?,?,?,'managed','forward_auth','private')",
).run(`${slug} app`, slug, slot).lastInsertRowid;
const HUB = mkApp('hub', 1);
const OTHER = mkApp('other', 2);

const mkUser = (name, role = 'user') => db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
  .run(name, `${name}@t.test`, role, hashApiKey(`key-${name}`)).lastInsertRowid;
const owner = mkUser('olivia');
const alice = mkUser('alice');
const bob = mkUser('bob');
const carol = mkUser('carol');
const role = (app, user, r) => db.prepare(`INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)
  ON CONFLICT(app_id,user_id) DO UPDATE SET app_role = excluded.app_role`).run(app, user, r);
role(HUB, owner, 'owner');
role(HUB, alice, 'user');
role(OTHER, alice, 'owner');

let n = 0;
function platformSession(userId) {
  const token = `plat-${++n}`;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(userId, hashApiKey(token));
  return token;
}
function appSession(userId, appId, env = 'production', parent = platformSession(userId)) {
  const token = `app-${++n}`;
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at, scope, app_env, parent_token_hash)
    VALUES (?, ?, ?, datetime('now','+1 day'), 'app', ?, ?)`).run(userId, hashApiKey(token), appId, env, hashApiKey(parent));
  return token;
}

const { widgetsRouter } = await import('../server/routes/widgets.js');
const widgetSettings = (await import('../server/routes/widgetSettings.js')).default;
const { requireAuth } = await import('../server/middleware/auth.js');
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/__appcrane', widgetsRouter);
api.use('/api/apps', widgetSettings);
api.get('/api/probe', requireAuth, (req, res) => res.json({ id: req.user.id }));
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });

const HUB_HOST = 'hub.apps.example.test';
const OTHER_HOST = 'other.apps.example.test';

function call(path, { method = 'GET', host = HUB_HOST, headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const r = http.request({
      host: '127.0.0.1', port: server.address().port, path, method,
      headers: { Host: host, Accept: 'application/json', ...(data && { 'Content-Type': 'application/json' }), ...headers },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, body: text, json });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

const tokenReq = (cookie, { host = HUB_HOST, headers = {}, body = {} } = {}) => call('/__appcrane/widgets/token', {
  method: 'POST', host, body, headers: { 'X-AppCrane-Widget': '1', 'Sec-Fetch-Site': 'same-origin', ...(cookie && { Cookie: `__Host-cc_app=${cookie}` }), ...headers },
});
async function widgetToken(cookie, opts) {
  const r = await tokenReq(cookie, opts);
  assert.equal(r.status, 200, r.body);
  return r.json;
}
const w = (token, path, opts = {}) => call(`/__appcrane/widgets/api${path}`, { ...opts, headers: { Authorization: `Bearer ${token}`, ...(opts.headers || {}) } });

const SCRIPT = readFileSync(new URL('../server/assets/widgets.js', import.meta.url), 'utf8');

test('the script: on app hosts only, JavaScript, revalidated, and a content-addressed copy for SRI', async () => {
  const r = await call('/__appcrane/widgets.js');
  assert.equal(r.status, 200);
  assert.equal(r.headers['content-type'], 'application/javascript; charset=utf-8');
  assert.equal(r.headers['cache-control'], 'no-cache');
  assert.equal(r.body, SCRIPT);
  const etag = r.headers.etag;
  assert.match(etag, /^"[0-9a-f]{16}"$/);
  assert.equal((await call('/__appcrane/widgets.js', { headers: { 'If-None-Match': etag } })).status, 304);

  const m = await call('/__appcrane/widgets/manifest.json');
  assert.equal(m.status, 200);
  assert.equal(m.json.integrity, `sha384-${crypto.createHash('sha384').update(SCRIPT).digest('base64')}`);
  assert.equal(m.json.src, `/__appcrane/widgets/${etag.slice(1, -1)}.js`);
  const pinned = await call(m.json.src);
  assert.equal(pinned.status, 200);
  assert.equal(pinned.headers['cache-control'], 'public, max-age=31536000, immutable');
  assert.equal(pinned.body, SCRIPT);
  assert.equal((await call('/__appcrane/widgets/0000000000000000.js')).status, 404);

  for (const host of ['crane.example.test', 'nope.apps.example.test', 'elsewhere.test']) {
    assert.equal((await call('/__appcrane/widgets.js', { host })).status, 404, host);
    assert.equal((await call('/__appcrane/widgets/manifest.json', { host })).status, 404, host);
  }
});

test('the token comes only from this host\'s own page, with this host\'s app session', async () => {
  const cookie = appSession(alice, HUB);
  assert.equal((await tokenReq(cookie, { headers: { 'X-AppCrane-Widget': '' } })).status, 400);
  assert.equal((await tokenReq(cookie, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await tokenReq(cookie, { headers: { 'Sec-Fetch-Site': 'same-site' } })).status, 403);
  assert.equal((await tokenReq(cookie, { headers: { Origin: 'https://other.apps.example.test' } })).status, 403);
  assert.equal((await tokenReq(null)).status, 401);
  // A platform session is no app session.
  assert.equal((await tokenReq(platformSession(alice))).status, 401);
  // Another app's session cookie on this host.
  assert.equal((await tokenReq(appSession(alice, OTHER))).status, 401);
  // The sandbox session on the production host.
  assert.equal((await tokenReq(appSession(alice, HUB, 'sandbox'))).status, 401);

  const t = await widgetToken(cookie, { headers: { Origin: `https://${HUB_HOST}` } });
  assert.match(t.token, /^cwt_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(t.scopes, ['me', 'sessions', 'access'], 'members and app-keys are off until the app turns them on');
  const ttl = new Date(t.expires_at).getTime() - Date.now();
  assert.ok(ttl > 3500_000 && ttl <= 3600_000, `ttl ${ttl}`);
  const stored = db.prepare('SELECT * FROM widget_tokens WHERE token_hash = ?').get(hashApiKey(t.token));
  assert.ok(stored, 'stored by hash');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM widget_tokens WHERE token_hash = ?').get(t.token).n, 0, 'never in plaintext');

  const narrow = await widgetToken(cookie, { body: { scopes: ['me'] } });
  assert.deepEqual(narrow.scopes, ['me']);
  assert.equal((await w(narrow.token, '/sessions')).status, 403);
  assert.equal((await tokenReq(cookie, { body: { scopes: ['admin'] } })).status, 400);
});

test('a token for app A is refused on app B, on A\'s other environment and by the platform API', async () => {
  const t = (await widgetToken(appSession(alice, HUB))).token;
  const ok = await w(t, '/me');
  assert.equal(ok.status, 200, ok.body);
  assert.equal(ok.json.app.slug, 'hub');
  assert.equal(ok.json.user.id, alice);
  assert.equal(ok.json.app_role, 'user');
  assert.equal(ok.json.links.sign_out, '/__appcrane/logout');
  assert.equal(ok.json.platform_url, 'https://crane.example.test');
  assert.equal(JSON.stringify(ok.json).includes('plat-'), false);

  // alice is an OWNER of `other`, so this is a replay that would be worth something.
  for (const host of [OTHER_HOST, 'hub-sandbox.apps.example.test', 'crane.example.test']) {
    const r = await w(t, '/members', { host });
    assert.ok(r.status === 401 || r.status === 404, `${host}: ${r.status}`);
    assert.notEqual((await w(t, '/me', { host })).status, 200, host);
  }
  assert.equal((await call('/api/probe', { headers: { Authorization: `Bearer ${t}` } })).status, 401);
  assert.equal((await w('cwt_' + 'x'.repeat(43), '/me')).status, 401);
  assert.equal((await w('', '/me')).status, 401);
});

test('a token ends with its app session and with its platform session', async () => {
  const parent = platformSession(alice);
  const cookie = appSession(alice, HUB, 'production', parent);
  const t = (await widgetToken(cookie)).token;
  assert.equal((await w(t, '/me')).status, 200);
  db.prepare('DELETE FROM identity_sessions WHERE token_hash = ?').run(hashApiKey(cookie));
  assert.equal((await w(t, '/me')).status, 401);

  const t2 = (await widgetToken(appSession(alice, HUB))).token;
  db.prepare("UPDATE widget_tokens SET expires_at = datetime('now','-1 second') WHERE token_hash = ?").run(hashApiKey(t2));
  assert.equal((await w(t2, '/me')).status, 401, 'expired');

  const top = platformSession(alice);
  const t4 = (await widgetToken(appSession(alice, HUB, 'production', top))).token;
  assert.equal((await w(t4, '/me')).status, 200);
  const { revokeSession } = await import('../server/services/userSessions.js');
  revokeSession(db, alice, hashApiKey(top));
  assert.equal((await w(t4, '/me')).status, 401, 'the platform session above it was revoked');

  const t3 = (await widgetToken(appSession(bob, HUB, 'production'))).token;
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(bob);
  assert.equal((await w(t3, '/me')).status, 401, 'deactivated');
  db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(bob);
});

test('members and app-keys are off per app until an owner turns each on (audited); off again refuses live tokens', async () => {
  const cookie = appSession(owner, HUB);
  const off = await widgetToken(cookie, { body: { scopes: ['me', 'members', 'app-keys'] } });
  assert.deepEqual(off.scopes, ['me'], 'requested is not granted while off');
  assert.equal((await w(off.token, '/members')).status, 403);
  assert.equal((await w(off.token, '/app-keys')).status, 403);
  assert.deepEqual((await w(off.token, '/me')).json.scopes, ['me']);

  const settings = (key, method = 'GET', body) => call('/api/apps/hub/widget-scopes', { host: 'crane.example.test', method, body, headers: { 'X-API-Key': key } });
  assert.deepEqual((await settings('key-olivia')).json, { members: false, app_keys: false, can_change: true });
  assert.equal((await settings('key-alice')).json.can_change, false);
  const denied = await settings('key-alice', 'PUT', { members: true });
  assert.equal(denied.status, 403, 'a member cannot turn it on');
  assert.equal((await settings('key-bob', 'GET')).status, 403, 'a non-member cannot even read it');
  assert.equal((await settings('key-olivia', 'PUT', { members: 'yes' })).status, 400);
  assert.equal((await widgetToken(cookie)).scopes.includes('members'), false);

  const on = await settings('key-olivia', 'PUT', { members: true });
  assert.equal(on.status, 200, on.body);
  assert.deepEqual(on.json, { members: true, app_keys: false });
  const audit = db.prepare("SELECT * FROM audit_log WHERE action = 'app-widget-scopes-set' AND app_id = ? AND user_id = ?").get(HUB, owner);
  assert.ok(audit, 'the toggle is audited');
  assert.match(audit.detail, /"members":true/);
  const t = await widgetToken(cookie);
  assert.deepEqual(t.scopes, ['me', 'sessions', 'members', 'access']);
  assert.equal((await w(t.token, '/members')).status, 200);
  assert.equal((await w(t.token, '/app-keys')).status, 403, 'app-keys is a separate switch');
  const otherApp = await widgetToken(appSession(alice, OTHER), { host: OTHER_HOST });
  assert.deepEqual(otherApp.scopes, ['me', 'sessions', 'access'], 'turning it on for hub leaves other (owned by alice) off');

  assert.equal((await settings('key-olivia', 'PUT', { members: false })).status, 200);
  const r = await w(t.token, '/members');
  assert.equal(r.status, 403, 'a token issued while on stops working when it is turned off');
  assert.equal(r.json.error.code, 'WIDGET_SCOPE_OFF');

  assert.equal((await settings('key-olivia', 'PUT', { members: true, app_keys: true })).status, 200);
});

test('members: a member cannot list or change roles, the owner can, the last owner stays', async () => {
  const mine = (await widgetToken(appSession(alice, HUB))).token;
  assert.equal((await w(mine, '/members')).status, 403);
  assert.equal((await w(mine, `/members/${alice}`, { method: 'PUT', body: { app_role: 'owner' } })).status, 403);
  assert.equal((await w(mine, '/members', { method: 'POST', body: { email: 'bob@t.test' } })).status, 403);
  assert.equal(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(HUB, alice).app_role, 'user');
  assert.equal((await w(mine, '/me')).json.can_manage_members, false);

  const own = (await widgetToken(appSession(owner, HUB))).token;
  const list = await w(own, '/members');
  assert.equal(list.status, 200, list.body);
  assert.deepEqual(list.json.members.map((m) => [m.name, m.app_role]), [['olivia', 'owner'], ['alice', 'user']]);
  assert.equal(list.json.members.some((m) => 'password_hash' in m || 'api_key_hash' in m), false);

  const up = await w(own, `/members/${alice}`, { method: 'PUT', body: { app_role: 'admin' } });
  assert.equal(up.status, 200, up.body);
  assert.equal(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(HUB, alice).app_role, 'admin');
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'app-set-role' AND app_id = ? AND user_id = ?").get(HUB, owner));

  const last = await w(own, `/members/${owner}`, { method: 'PUT', body: { app_role: 'user' } });
  assert.equal(last.status, 400);
  assert.equal(last.json.error.code, 'LAST_OWNER');
  assert.equal(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(HUB, owner).app_role, 'owner');

  assert.equal((await w(own, '/members', { method: 'POST', body: { email: 'nobody@t.test' } })).status, 404);
  const inv = await w(own, '/members', { method: 'POST', body: { email: 'BOB@t.test', app_role: 'user' } });
  assert.equal(inv.status, 201, inv.body);
  assert.equal(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(HUB, bob).app_role, 'user');
  assert.equal((await w(own, '/members', { method: 'POST', body: { email: 'bob@t.test' } })).status, 409);

  // An app admin is still not an owner (the rule PUT /api/apps/:slug/roles has).
  const adm = (await widgetToken(appSession(alice, HUB))).token;
  assert.equal((await w(adm, `/members/${bob}`, { method: 'PUT', body: { app_role: 'none' } })).status, 403);
  role(HUB, alice, 'user');
});

test('request access: a signed-in person with no role files one, once; a member is told they have access', async () => {
  const cookie = appSession(carol, HUB);
  const t = await widgetToken(cookie);
  assert.deepEqual(t.scopes, ['me', 'access']);
  assert.equal((await w(t.token, '/sessions')).status, 403);
  assert.equal((await w(t.token, '/me')).json.app_role, 'none');

  const r = await w(t.token, '/access-request', { method: 'POST', body: { note: 'for the quarterly report' } });
  assert.equal(r.status, 201, r.body);
  const row = db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(r.json.request_id);
  assert.equal(row.kind, 'access');
  assert.equal(row.app_slug, 'hub');
  assert.equal(row.user_id, carol);
  assert.equal(row.message, 'Access request for app \u201chub app\u201d:\nfor the quarterly report');
  assert.equal((await w(t.token, '/me')).json.access_requested, true);
  const again = await w(t.token, '/access-request', { method: 'POST', body: {} });
  assert.equal(again.status, 409);
  assert.equal(again.json.error.code, 'DUPLICATE_ACCESS_REQUEST');

  const member = (await widgetToken(appSession(alice, HUB))).token;
  const m = await w(member, '/access-request', { method: 'POST', body: {} });
  assert.equal(m.status, 409);
  assert.equal(m.json.error.code, 'ALREADY_MEMBER');
});

test('sessions widget: lists mine, revokes only this app\'s, and revoking this one signs out', async () => {
  const parent = platformSession(alice);
  const cookie = appSession(alice, HUB, 'production', parent);
  const otherApp = appSession(alice, OTHER);
  const t = (await widgetToken(cookie)).token;
  const r = await w(t, '/sessions');
  assert.equal(r.status, 200, r.body);
  const current = r.json.sessions.find((s) => s.current);
  assert.equal(current.app.slug, 'hub');
  assert.equal(current.revocable_here, true);
  // Only this app's sessions; the rest is a count, so a page on this app
  // learns nothing about the visitor's other apps or platform sign-ins.
  assert.ok(r.json.sessions.every((s) => s.scope === 'app' && s.app.slug === 'hub'), JSON.stringify(r.json.sessions));
  assert.ok(r.json.other_sessions >= 2, `other_sessions ${r.json.other_sessions}`);
  assert.doesNotMatch(JSON.stringify(r.json), /"slug":"other"|other app/);
  assert.equal(JSON.stringify(r.json).includes('token_hash'), false);
  const { listSessions } = await import('../server/services/userSessions.js');
  const all = listSessions(db, alice);
  const plat = all.find((s) => s.scope === 'platform');
  const oth = all.find((s) => s.app && s.app.slug === 'other');

  assert.equal((await w(t, `/sessions/${plat.id}`, { method: 'DELETE' })).status, 403);
  assert.equal((await w(t, `/sessions/${oth.id}`, { method: 'DELETE' })).status, 403);
  assert.ok(db.prepare('SELECT 1 FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(otherApp)));

  const bobs = (await widgetToken(appSession(bob, HUB))).token;
  const bobCurrent = (await w(bobs, '/sessions')).json.sessions.find((s) => s.current);
  assert.equal((await w(t, `/sessions/${bobCurrent.id}`, { method: 'DELETE' })).status, 404);

  const out = await w(t, `/sessions/${current.id}`, { method: 'DELETE' });
  assert.equal(out.status, 200, out.body);
  assert.equal(out.json.signed_out, true);
  assert.match((out.headers['set-cookie'] || []).join(';'), /__Host-cc_app=;/);
  assert.equal((await w(t, '/me')).status, 401);
  assert.ok(db.prepare('SELECT 1 FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(parent)), 'platform session untouched');
});

test('app keys widget: issuing a key needs a recent sign-in on the platform session', async () => {
  const parent = platformSession(alice);
  db.prepare("UPDATE identity_sessions SET created_at = datetime('now', '-30 minutes') WHERE token_hash = ?").run(hashApiKey(parent));
  const t = (await widgetToken(appSession(alice, HUB, 'production', parent))).token;
  const before = db.prepare('SELECT COUNT(*) AS n FROM user_app_keys WHERE user_id = ?').get(alice).n;
  const r = await w(t, '/app-keys', { method: 'POST', body: { label: 'stale' } });
  assert.equal(r.status, 401, r.body);
  assert.equal(r.json.error.code, 'STEP_UP_REQUIRED');
  assert.match(r.json.error.step_up.url, /\/api\/identity\/step-up\/app\?app=hub$/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM user_app_keys WHERE user_id = ?').get(alice).n, before, 'a key was issued');
  assert.equal((await w(t, '/app-keys')).status, 200, 'listing keys needs no step-up');
});

test('app keys widget: this app only, short-lived, revoke stays inside this app', async () => {
  const t = (await widgetToken(appSession(alice, HUB))).token;
  const made = await w(t, '/app-keys', { method: 'POST', body: { label: 'uploader' } });
  assert.equal(made.status, 201, made.body);
  assert.match(made.json.api_key, /^dhk_uak_/);
  assert.equal(made.json.key.app_slug, 'hub');
  const days = (new Date(made.json.key.expires_at.replace(' ', 'T') + 'Z') - Date.now()) / 86400_000;
  assert.ok(days > 29 && days <= 30, `default ${days} days`);
  assert.equal((await w(t, '/app-keys', { method: 'POST', body: { expires_in_days: 91 } })).status, 400);

  const { issueKey } = await import('../server/services/userAppKeys.js');
  const otherKey = issueKey(db, db.prepare('SELECT * FROM users WHERE id = ?').get(alice), { app: 'other' });
  const list = await w(t, '/app-keys');
  assert.deepEqual(list.json.keys.map((k) => k.app_slug), ['hub']);
  assert.equal((await w(t, `/app-keys/${otherKey.key.id}`, { method: 'DELETE' })).status, 404);
  assert.equal(db.prepare('SELECT revoked_at FROM user_app_keys WHERE id = ?').get(otherKey.key.id).revoked_at, null);
  assert.equal((await w(t, `/app-keys/${made.json.key.id}`, { method: 'DELETE' })).status, 200);
  assert.ok(db.prepare('SELECT revoked_at FROM user_app_keys WHERE id = ?').get(made.json.key.id).revoked_at);
});
