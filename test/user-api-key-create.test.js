import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import express from 'express';

// A person with no API key (accounts are created without one since 169)
// creates their first key with POST /api/me/api-key/rotate; GET reports
// "no key" cleanly; the expiry sweep and warnings skip keyless accounts; an
// admin can issue a first key for someone without signing them out.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-keycreate-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const expiry = await import('../server/services/apiKeyExpiry.js');

initDb();
const db = getDb();

const ADMIN_KEY = generateApiKey('dhk_admin');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('admin','admin@t.test','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY));

function keyless() {
  const tag = randomBytes(3).toString('hex');
  const id = db.prepare("INSERT INTO users (name,email,role,active,kind) VALUES (?,?,'user',1,'human')").run(`k${tag}`, `k${tag}@t.test`).lastInsertRowid;
  const session = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(id, hashApiKey(session));
  return { id, session, auth: { Authorization: `Bearer ${session}` } };
}

const app = express();
app.use(express.json());
app.get('/api/whoami', requireAuth, (req, res) => res.json({ id: req.user.id }));
app.use('/api', (await import('../server/routes/apiKeys.js')).default);
app.use('/api/users', (await import('../server/routes/users.js')).default);
app.use(errorHandler);
const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const daysFromNow = (iso) => (Date.parse(iso) - Date.now()) / 86400_000;
const audits = (userId, action) => db.prepare('SELECT COUNT(*) n FROM audit_log WHERE user_id = ? AND action = ?').get(userId, action).n;
const whoami = async (headers) => (await fetch(`${BASE}/api/whoami`, { headers })).status;

test('GET /api/me/api-key on a keyless account says "no key", with no dates', async () => {
  const u = keyless();
  const res = await fetch(`${BASE}/api/me/api-key`, { headers: u.auth });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual({ ...body, max_age_days: undefined }, { has_key: false, expired: false, issued_at: null, expires_at: null, last_used_at: null, max_age_days: undefined });
  assert.equal(body.max_age_days, 90);
});

test('a keyless account creates its first key: shown once, authenticates, has an expiry, audited as a create', async () => {
  const u = keyless();
  const res = await fetch(`${BASE}/api/me/api-key/rotate`, { method: 'POST', headers: u.auth });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.match(body.api_key, /^dhk_user_/);
  assert.equal(body.created, true);
  assert.equal(body.has_key, true);
  assert.ok(Math.abs(daysFromNow(body.expires_at) - 90) < 0.01, `expiry ${body.expires_at}`);
  assert.doesNotMatch(body.warning, /previous key/);
  const row = db.prepare('SELECT api_key_hash, api_key_issued_at, api_key_expires_at FROM users WHERE id = ?').get(u.id);
  assert.equal(row.api_key_hash, hashApiKey(body.api_key), 'only the hash is stored');
  assert.ok(row.api_key_issued_at && row.api_key_expires_at, 'trg_users_api_key_rotate stamped NULL -> key');

  assert.equal(await whoami({ 'X-API-Key': body.api_key }), 200);
  assert.equal(await whoami(u.auth), 200, 'creating a key does not sign the person out');
  assert.equal(audits(u.id, 'user-api-key-create'), 1);
  assert.equal(audits(u.id, 'user-api-key-rotate'), 0);

  const get = await (await fetch(`${BASE}/api/me/api-key`, { headers: u.auth })).json();
  assert.equal(get.has_key, true);
  assert.equal(get.api_key, undefined, 'GET never returns the key');

  const again = await (await fetch(`${BASE}/api/me/api-key/rotate`, { method: 'POST', headers: u.auth })).json();
  assert.equal(again.created, false);
  assert.match(again.warning, /previous key no longer works/);
  assert.equal(audits(u.id, 'user-api-key-rotate'), 1, 'the second call is a rotation');
  assert.equal(await whoami({ 'X-API-Key': body.api_key }), 401);
  assert.equal(await whoami({ 'X-API-Key': again.api_key }), 200);
});

test('keyless accounts get no expiry warning and the sweep leaves them alone, even with stale expiry columns', () => {
  db.prepare("DELETE FROM email_queue WHERE source = 'api-key-expiry'").run();
  const warnable = keyless();
  const stale = keyless();
  db.prepare('UPDATE users SET api_key_hash = ? WHERE id = ?').run(hashApiKey(generateApiKey('dhk_user')), warnable.id);
  db.prepare("UPDATE users SET api_key_expires_at = datetime('now','+10 days'), api_key_last_used_at = datetime('now') WHERE id = ?").run(warnable.id);
  db.prepare("UPDATE users SET api_key_expires_at = datetime('now','+10 days'), api_key_last_used_at = datetime('now') WHERE id = ?").run(stale.id);

  expiry.sendExpiryWarnings(db);
  const sent = db.prepare("SELECT idempotency_key FROM email_queue WHERE source = 'api-key-expiry'").all().map((r) => r.idempotency_key);
  assert.ok(sent.some((k) => k.startsWith(`api-key-expiry:user:${warnable.id}:`)), 'control: a used key in the window is warned');
  assert.ok(!sent.some((k) => k.startsWith(`api-key-expiry:user:${stale.id}:`)), 'a keyless account is not warned');

  db.prepare("UPDATE users SET api_key_expires_at = datetime('now','-1 day') WHERE id = ?").run(stale.id);
  expiry.expireDueUserKeys(db);
  const after = db.prepare('SELECT api_key_hash, api_key_expired_hash FROM users WHERE id = ?').get(stale.id);
  assert.deepEqual(after, { api_key_hash: null, api_key_expired_hash: null });
  assert.equal(audits(stale.id, 'api-key.expired'), 0);
});

test('an admin issues a first key for a keyless user without signing them out; a rotation still does', async () => {
  const u = keyless();
  const list = await (await fetch(`${BASE}/api/users`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(list.users.find((x) => x.id === u.id).has_api_key, 0);

  const first = await fetch(`${BASE}/api/users/${u.id}/regenerate-key?confirm=true`, { method: 'POST', headers: { 'X-API-Key': ADMIN_KEY } });
  assert.equal(first.status, 200);
  const fb = await first.json();
  assert.match(fb.api_key, /^dhk_user_/);
  assert.equal(await whoami({ 'X-API-Key': fb.api_key }), 200);
  assert.equal(await whoami(u.auth), 200, 'first issue keeps the session');
  const list2 = await (await fetch(`${BASE}/api/users`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(list2.users.find((x) => x.id === u.id).has_api_key, 1);

  const rot = await (await fetch(`${BASE}/api/users/${u.id}/regenerate-key?confirm=true`, { method: 'POST', headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(await whoami({ 'X-API-Key': fb.api_key }), 401);
  assert.equal(await whoami({ 'X-API-Key': rot.api_key }), 200);
  assert.equal(await whoami(u.auth), 401, 'replacing a key signs the user out, as before');
});
