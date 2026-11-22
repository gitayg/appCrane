import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// GET/DELETE /api/me/sessions (a user's own sign-in sessions) and the platform
// admin's GET/DELETE /api/users/:id/sessions, over HTTP through the real
// routers and requireAuth.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-me-sessions-'));
after(() => rmSync(process.env.DATA_DIR, { recursive: true, force: true }));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const HUB = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('hub','hub',1,'managed')").run().lastInsertRowid;
const mkUser = (name, role = 'user') => db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
  .run(name, `${name}@t.test`, role, hashApiKey(`key-${name}`)).lastInsertRowid;
const alice = mkUser('alice');
const bob = mkUser('bob');
mkUser('root', 'platform_admin');

let n = 0;
function session(userId) {
  const token = `tok-${++n}`;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(userId, hashApiKey(token));
  return token;
}
function child(userId, parent) {
  const token = `app-${++n}`;
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at, scope, app_env, parent_token_hash)
    VALUES (?, ?, ?, datetime('now','+1 day'), 'app', 'production', ?)`).run(userId, hashApiKey(token), HUB, hashApiKey(parent));
  return token;
}
const live = (token) => !!db.prepare('SELECT 1 FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(token));

const { meSessionsRouter, adminUserSessionsRouter } = await import('../server/routes/userSessions.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { sessionHandle } = await import('../server/services/userSessions.js');
const api = express();
api.use(express.json());
api.use('/api/me/sessions', meSessionsRouter);
api.use('/api/users', adminUserSessionsRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const base = `http://127.0.0.1:${server.address().port}`;

async function call(path, { method = 'GET', bearer, apiKey } = {}) {
  const headers = {};
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (apiKey) headers['X-API-Key'] = apiKey;
  const res = await fetch(base + path, { method, headers });
  return { status: res.status, headers: res.headers, json: await res.json().catch(() => null) };
}

test('lists only my own live sessions, marks the current one, carries no credential', async () => {
  const mine = session(alice);
  const other = session(alice);
  const app = child(alice, mine);
  session(bob);
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','-1 hour'))").run(alice, hashApiKey('expired'));

  const r = await call('/api/me/sessions', { bearer: mine });
  assert.equal(r.status, 200);
  assert.equal(r.json.sessions.length, 3);
  const cur = r.json.sessions.filter((s) => s.current);
  assert.equal(cur.length, 1);
  assert.equal(cur[0].scope, 'platform');
  const appRow = r.json.sessions.find((s) => s.scope === 'app');
  assert.deepEqual(appRow.app, { slug: 'hub', name: 'hub', env: 'production' });
  assert.equal(appRow.parent_id, cur[0].id);
  for (const s of r.json.sessions) assert.match(s.id, /^[A-Za-z0-9_-]{32}$/);
  const text = JSON.stringify(r.json);
  for (const secret of [mine, other, app, hashApiKey(mine), hashApiKey(other)]) assert.equal(text.includes(secret), false);
  assert.equal(text.includes('_app_id'), false);

  const byKey = await call('/api/me/sessions', { apiKey: 'key-alice' });
  assert.equal(byKey.status, 200);
  assert.equal(byKey.json.sessions.some((s) => s.current), false, 'an API key is no session');
  assert.equal((await call('/api/me/sessions')).status, 401);
});

test('revoking: another user\'s session id is 404, mine goes, the current one signs me out', async () => {
  const mine = session(alice);
  const spare = session(alice);
  const app = child(alice, mine);
  const bobs = session(bob);
  const bobId = (await call('/api/me/sessions', { bearer: bobs })).json.sessions.find((s) => s.current).id;

  const cross = await call(`/api/me/sessions/${bobId}`, { method: 'DELETE', bearer: mine });
  assert.equal(cross.status, 404);
  assert.ok(live(bobs), 'bob is still signed in');
  assert.equal((await call('/api/me/sessions/not-a-handle', { method: 'DELETE', bearer: mine })).status, 404);

  const list = (await call('/api/me/sessions', { bearer: mine })).json.sessions;
  const spareId = sessionHandle(hashApiKey(spare));
  assert.ok(list.some((s) => s.id === spareId));
  const gone = await call(`/api/me/sessions/${spareId}`, { method: 'DELETE', bearer: mine });
  assert.equal(gone.status, 200);
  assert.equal(gone.json.signed_out, false);
  assert.equal((await call('/api/me/sessions', { bearer: mine })).status, 200, 'still signed in');
  assert.equal(live(mine), true);
  assert.equal(list.length - 1, (await call('/api/me/sessions', { bearer: mine })).json.sessions.length);

  const curId = (await call('/api/me/sessions', { bearer: mine })).json.sessions.find((s) => s.current).id;
  const out = await call(`/api/me/sessions/${curId}`, { method: 'DELETE', bearer: mine });
  assert.equal(out.status, 200);
  assert.equal(out.json.signed_out, true);
  assert.equal(out.json.revoked, 2, 'the platform session and the app session it handed off');
  assert.match(out.headers.get('set-cookie') || '', /cc_token=;/);
  assert.equal(live(mine), false);
  assert.equal(live(app), false);
  assert.equal((await call('/api/me/sessions', { bearer: mine })).status, 401);
});

test('a platform admin lists and revokes a user\'s sessions; nobody else can', async () => {
  const b1 = session(bob);
  const b2 = session(bob);
  const asAlice = await call(`/api/users/${bob}/sessions`, { apiKey: 'key-alice' });
  assert.equal(asAlice.status, 403);
  assert.equal((await call(`/api/users/${bob}/sessions`, { method: 'DELETE', apiKey: 'key-alice' })).status, 403);
  assert.ok(live(b1) && live(b2));

  const r = await call(`/api/users/${bob}/sessions`, { apiKey: 'key-root' });
  assert.equal(r.status, 200);
  assert.ok(r.json.sessions.length >= 2);
  assert.equal((await call('/api/users/9999/sessions', { apiKey: 'key-root' })).status, 404);

  const aliceSession = session(alice);
  const aliceId = (await call('/api/me/sessions', { bearer: aliceSession })).json.sessions.find((s) => s.current).id;
  assert.equal((await call(`/api/users/${bob}/sessions/${aliceId}`, { method: 'DELETE', apiKey: 'key-root' })).status, 404, 'a handle of another user');
  assert.ok(live(aliceSession));

  const one = await call(`/api/users/${bob}/sessions/${r.json.sessions[0].id}`, { method: 'DELETE', apiKey: 'key-root' });
  assert.equal(one.status, 200);
  assert.equal(one.json.revoked, 1);
  const all = await call(`/api/users/${bob}/sessions`, { method: 'DELETE', apiKey: 'key-root' });
  assert.equal(all.status, 200);
  assert.equal(live(b1) || live(b2), false);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'admin-user-sessions-revoke-all'").get());
});
