import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { signedHeaders } from './helpers.js';
import { createApp } from '../server/app.js';

// The real Express app on a real port, with an in-memory stand-in for the
// database so these run with no Postgres. test/db.test.js runs the same routes
// against a real one.
const notes = [];
const fakeDb = {
  async query(sql, params = []) {
    if (sql === 'SELECT 1') return { rows: [{ '?column?': 1 }] };
    if (sql.startsWith('SELECT id, body')) return { rows: [...notes].reverse() };
    if (sql.startsWith('INSERT INTO notes')) {
      const row = { id: notes.length + 1, body: params[0], author_id: params[1], created_at: new Date().toISOString() };
      notes.push(row);
      return { rows: [row] };
    }
    if (sql.startsWith('DELETE FROM notes')) return { rowCount: 1, rows: [] };
    throw new Error(`unexpected SQL: ${sql}`);
  },
};

let server;
let base;
before(async () => {
  server = createApp({ version: '0.1.0', db: fakeDb }).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.closeAllConnections?.(); server.close(); });

const call = (path, { headers = {}, method = 'GET', body } = {}) => fetch(base + path, {
  method,
  headers: { 'content-type': 'application/json', ...headers },
  body: body === undefined ? undefined : JSON.stringify(body),
});

test('/api/health answers AppCrane\'s probe with no identity: 200, status and version', async () => {
  const res = await call('/api/health');
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.version, '0.1.0');
  assert.equal(body.database, 'ok');
});

test('/api/health is 503 when the database is configured but unreachable', async () => {
  const broken = createApp({ version: '0.1.0', db: { query: async () => { throw new Error('down'); } } }).listen(0, '127.0.0.1');
  await new Promise((r) => broken.once('listening', r));
  try {
    const res = await fetch(`http://127.0.0.1:${broken.address().port}/api/health`);
    assert.equal(res.status, 503);
    assert.equal((await res.json()).status, 'error');
  } finally { broken.close(); }
});

test('an unsigned request is refused with 401', async () => {
  const res = await call('/api/me', { headers: { 'x-appcrane-user-id': '1', 'x-appcrane-app-role': 'owner', 'x-appcrane-is-admin': '1' } });
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error.code, 'IDENTITY_UNSIGNED');
});

test('a forged signature is refused with 401', async () => {
  const forged = signedHeaders({ appRole: 'owner', secret: randomBytes(32).toString('base64url') });
  const res = await call('/api/me', { headers: forged });
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error.code, 'IDENTITY_FORGED');
});

test('a signed request reaches the route and sees who it is', async () => {
  const res = await call('/api/me', { headers: signedHeaders({ appRole: 'viewer' }) });
  assert.equal(res.status, 200);
  const { user } = await res.json();
  assert.equal(user.userId, '42');
  assert.equal(user.appRole, 'viewer');
});

test('role checks: a viewer reads but cannot write, a user writes', async () => {
  assert.equal((await call('/api/notes', { headers: signedHeaders({ appRole: 'viewer' }) })).status, 200);
  const denied = await call('/api/notes', { method: 'POST', headers: signedHeaders({ appRole: 'viewer' }), body: { body: 'hi' } });
  assert.equal(denied.status, 403);
  const ok = await call('/api/notes', { method: 'POST', headers: signedHeaders({ appRole: 'user' }), body: { body: 'hi' } });
  assert.equal(ok.status, 201);
  assert.equal((await ok.json()).note.author_id, '42');
});

test('admin routes: a user is refused, an owner passes', async () => {
  assert.equal((await call('/api/admin/notes/1', { method: 'DELETE', headers: signedHeaders({ appRole: 'user' }) })).status, 403);
  assert.equal((await call('/api/admin/notes/1', { method: 'DELETE', headers: signedHeaders({ appRole: 'owner' }) })).status, 200);
});
