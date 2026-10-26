import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Personal app sign-in keys, dhk_uak_* (v2.124.0).
//
// The Work Review uploader needed a credential a cron job can hold. The only one
// that passed forward_auth was the user's full dhk_user_* key, which also
// drives the whole AppCrane API as them. An app sign-in key opens ONE app's gate
// and nothing else, and grants only what the user's current role on that app
// grants — so removing the role, deactivating the user or revoking the key
// shuts it at once.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-uak-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkApp = (slug, slot, visibility = 'private') => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES (?,?,?,'managed','forward_auth',?)"
).run(slug, slug, slot, visibility).lastInsertRowid;
const HUB = mkApp('uak-hub', 1);
const OTHER = mkApp('uak-other', 2);
const CLOSED = mkApp('uak-closed', 3);

const userKey = generateApiKey('dhk_user');
const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('Eli','eli@acme.test','user',1,?)")
  .run(hashApiKey(userKey)).lastInsertRowid;
for (const a of [HUB, OTHER]) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(a, uid);
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))")
  .run(uid, hashApiKey('uak-browser-token'));

const identityRouter = (await import('../server/routes/identity.js')).default;
const userAppKeysRouter = (await import('../server/routes/userAppKeys.js')).default;
const { requireAuth } = await import('../server/middleware/auth.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { identitySecretFor } = await import('../server/services/identitySignature.js');
const { verifyIdentity } = await import('../packages/tenant/index.js');

const api = express();
api.use(express.json());
api.use('/api/identity', identityRouter);
api.use('/api/me/app-keys', userAppKeysRouter);
api.get('/api/some-admin-thing', requireAuth, (req, res) => res.json({ user: req.user.email }));
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const issue = (body, key = userKey) => fetch(`${BASE}/api/me/app-keys`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': key }, body: JSON.stringify(body),
});
const verify = (key, slug) => fetch(`${BASE}/api/identity/verify${slug ? `?app=${slug}&prefix=/${slug}` : ''}`, {
  headers: { 'X-API-Key': key }, redirect: 'manual',
});
async function newKey(app = 'uak-hub') {
  const r = await issue({ app, label: 'laptop uploader' });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.match(body.api_key, /^dhk_uak_[A-Za-z0-9_-]+$/);
  return body;
}

test('a key is issued only for an app its user can enter, and shown once', async () => {
  const { api_key, key } = await newKey();
  assert.equal(key.app_slug, 'uak-hub');
  assert.ok(key.expires_at, 'expires by default');
  const row = db.prepare('SELECT key_hash FROM user_app_keys WHERE id = ?').get(key.id);
  assert.equal(row.key_hash, hashApiKey(api_key), 'only the hash is stored');
  assert.equal((await issue({ app: 'uak-closed' })).status, 403, 'no role on the app → no key for it');
  assert.equal((await issue({ app: 'uak-hub', expires_in_days: 400 })).status, 400, 'expiry is capped');

  const list = await (await fetch(`${BASE}/api/me/app-keys`, { headers: { 'X-API-Key': userKey } })).json();
  assert.ok(list.keys.some(k => k.id === key.id) && !JSON.stringify(list).includes(api_key), 'listing never shows the key');
  assert.deepEqual(list.apps.map(a => a.slug).sort(), ['uak-hub', 'uak-other']);
});

test('the key signs in to its own app, says so, and the identity is signed', async () => {
  const { api_key } = await newKey();
  const r = await verify(api_key, 'uak-hub');
  assert.equal(r.status, 200);
  const h = {}; for (const [k, v] of r.headers) if (k.startsWith('x-appcrane-')) h[k] = v;
  assert.equal(h['x-appcrane-user-email'], 'eli@acme.test');
  assert.equal(h['x-appcrane-app-role'], 'user');
  assert.equal(h['x-appcrane-auth-via'], 'app-key');
  assert.equal(verifyIdentity(h, { secret: identitySecretFor(db, HUB) }).email, 'eli@acme.test',
    'Auth-Via sits outside the v1 signature, so existing apps keep verifying');

  const browser = await fetch(`${BASE}/api/identity/verify?app=uak-hub`, { headers: { Authorization: 'Bearer uak-browser-token' } });
  assert.equal(browser.status, 200);
  assert.equal(browser.headers.get('x-appcrane-auth-via'), null, 'a browser session is not marked as an app key');
});

test('the key opens no other app and no bare verify', async () => {
  const { api_key } = await newKey();
  assert.equal((await verify(api_key, 'uak-other')).status, 403, 'another app the user CAN enter is still refused');
  assert.equal((await verify(api_key, 'uak-closed')).status, 403);
  assert.equal((await verify(api_key, null)).status, 403, 'no ?app= → refused');
});

test('the key is refused by the AppCrane API, and cannot mint more keys', async () => {
  const { api_key } = await newKey();
  const r = await fetch(`${BASE}/api/some-admin-thing`, { headers: { 'X-API-Key': api_key } });
  assert.equal(r.status, 403);
  assert.equal((await r.json()).error?.code ?? 'KEY_SCOPE_RESTRICTED', 'KEY_SCOPE_RESTRICTED');
  assert.equal((await issue({ app: 'uak-hub' }, api_key)).status, 403);
  assert.equal((await fetch(`${BASE}/api/me/app-keys`, { headers: { 'X-API-Key': api_key } })).status, 403);
});

test('removing the role, deactivating, revoking or expiring shuts the key', async () => {
  const { api_key, key } = await newKey();
  assert.equal((await verify(api_key, 'uak-hub')).status, 200);

  db.prepare("UPDATE app_user_roles SET app_role = 'none' WHERE app_id = ? AND user_id = ?").run(HUB, uid);
  assert.equal((await verify(api_key, 'uak-hub')).status, 403, 'no role now → refused, no revoke needed');
  db.prepare("UPDATE app_user_roles SET app_role = 'user' WHERE app_id = ? AND user_id = ?").run(HUB, uid);

  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(uid);
  assert.equal((await verify(api_key, 'uak-hub')).status, 403, 'deactivated user → refused');
  db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(uid);

  db.prepare("UPDATE user_app_keys SET expires_at = datetime('now','-1 minute') WHERE id = ?").run(key.id);
  assert.equal((await verify(api_key, 'uak-hub')).status, 401, 'expired → refused');
  db.prepare("UPDATE user_app_keys SET expires_at = datetime('now','+1 day') WHERE id = ?").run(key.id);
  assert.equal((await verify(api_key, 'uak-hub')).status, 200);

  const del = await fetch(`${BASE}/api/me/app-keys/${key.id}`, { method: 'DELETE', headers: { 'X-API-Key': userKey } });
  assert.equal(del.status, 200);
  assert.equal((await verify(api_key, 'uak-hub')).status, 401, 'revoked → refused');
});

test('Caddy strips a client-sent Auth-Via and copies the platform one', async () => {
  // Caddy emits a forward_auth route only for an app with a live deployment.
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(HUB);
  const { generateCaddyfile } = await import('../server/services/caddy.js');
  const cf = generateCaddyfile();
  assert.ok(cf.includes('request_header -X-AppCrane-Auth-Via\n'), 'client copy stripped');
  assert.match(cf, /copy_headers [^\n]*X-AppCrane-Auth-Via/, 'platform copy forwarded');
});
