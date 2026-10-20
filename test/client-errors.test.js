import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// POST /api/client-errors + GET/DELETE /api/settings/client-errors, over a real
// socket into the real routers, mounted as index.js mounts them: the report
// router at '/api' ahead of a 50 MB express.json(), so the 8 KB cap is the
// router's own and not an accident of the test harness; the admin router after
// it at '/api/settings/client-errors'.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-client-errors-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function makeUser(name, role) {
  const key = generateApiKey('dhk_admin');
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
}
const admin = makeUser('admin', 'platform_admin');
const owner = makeUser('owner', 'user');
const member = makeUser('member', 'user');
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('ce','ce-app',1,'managed')").run().lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, owner.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, member.id);

const routes = (await import('../server/routes/clientErrors.js')).default;
const { resetClientErrorRateLimit, RATE, adminRouter } = await import('../server/routes/clientErrors.js');
const svc = await import('../server/services/clientErrors.js');
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use('/api', routes);
api.use(express.json({ limit: '50mb' }));
api.use('/api/settings/client-errors', adminRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
beforeEach(() => { resetClientErrorRateLimit(); db.prepare('DELETE FROM client_errors').run(); });

const report = (body, key) => fetch(`${BASE}/api/client-errors`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...(key ? { 'X-API-Key': key } : {}) },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});
const rows = () => db.prepare('SELECT * FROM client_errors ORDER BY id').all();

const STACK = 'TypeError: x is undefined\n    at render (/docs/admin-app/assets/index-abc.js:10:20)\n    at go (/docs/admin-app/assets/index-abc.js:11:2)';

test('identical errors aggregate into one row with a count; a different one gets its own row', async () => {
  for (let i = 0; i < 3; i++) {
    const r = await report({ message: 'x is undefined', stack: STACK, page: '/dashboard', version: '2.111.3', source: 'admin' }, admin.key);
    assert.equal(r.status, 204);
  }
  await report({ message: 'x is undefined', stack: STACK, page: '/settings', version: '2.111.4' }, admin.key);
  await report({ message: 'other', stack: 'Error: other\n    at a (/x.js:1:1)', page: '/crew' });
  const all = rows();
  assert.equal(all.length, 2);
  assert.equal(all[0].count, 4);
  assert.deepEqual(JSON.parse(all[0].pages), ['/settings', '/dashboard']);
  assert.deepEqual(JSON.parse(all[0].versions), ['2.111.4', '2.111.3']);
  assert.equal(all[0].last_user_id, admin.id);
  assert.equal(all[1].last_user_id, null);
});

test('planted dhk_ key, Bearer token, query string, fragment and long hex never reach the table', async () => {
  const KEY = 'dhk_admin_' + 'Z9'.repeat(20);
  const BEARER = 'Bearer abc.def-ghi_jkl1234567';
  const HEX = 'a1'.repeat(24);
  const r = await report({
    message: `failed with ${KEY} and ${BEARER} at /api/x?token=s3cr3tQ&id=7 ${HEX}`,
    stack: `Error\n    at f (https://host.example/docs/app.js?sig=TOPSECRET#frag:1:2)\n    at g (${KEY})`,
    page: '/settings?code=AUTHCODE123#audit',
    userAgent: `UA ${BEARER}`,
  }, owner.key);
  assert.equal(r.status, 204);
  const dump = JSON.stringify(rows());
  for (const secret of [KEY, 'abc.def-ghi_jkl1234567', 's3cr3tQ', 'TOPSECRET', 'AUTHCODE123', '#audit', HEX, 'id=7']) {
    assert.ok(!dump.includes(secret), `stored: ${secret}`);
  }
  const [row] = rows();
  assert.equal(row.last_page, '/settings');
  assert.match(row.message, /dhk_\[redacted\]/);
  assert.match(row.message, /Bearer \[redacted\]/);
});

test('oversized body is refused 413 by the router itself; fields are truncated', async () => {
  const big = await report({ message: 'm', stack: 'x'.repeat(20_000) });
  assert.equal(big.status, 413);
  assert.equal(rows().length, 0);
  const ok = await report({ message: 'q '.repeat(400), stack: 'z'.repeat(4500), page: '/' + 'p'.repeat(600) });
  assert.equal(ok.status, 204);
  const [row] = rows();
  assert.ok(row.message.length <= svc.LIMITS.message);
  assert.ok(row.stack.length <= svc.LIMITS.stack);
  assert.ok(row.last_page.length <= svc.LIMITS.page);
  assert.equal((await report('{nope')).status, 400);
  assert.equal((await report({ stack: 'no message' })).status, 400);
});

test('anonymous reports are accepted but rate-limited per IP; signed-in users get their own bucket', async () => {
  for (let i = 0; i < RATE.anonPerIp; i++) {
    assert.equal((await report({ message: `anon ${i}` })).status, 204);
  }
  assert.equal((await report({ message: 'one too many' })).status, 429);
  assert.equal((await report({ message: 'signed in' }, member.key)).status, 204);
  for (let i = 1; i < RATE.userPerMin; i++) await report({ message: `m ${i}` }, member.key);
  assert.equal((await report({ message: 'member over' }, member.key)).status, 429);
  assert.equal((await report({ message: 'owner fine' }, owner.key)).status, 204);
});

test('listing and resolving are platform-admin only: owner/member 403, anonymous 401', async () => {
  await report({ message: 'listed', stack: STACK, page: '/x' }, admin.key);
  for (const who of [owner, member]) {
    assert.equal((await fetch(`${BASE}/api/settings/client-errors`, { headers: { 'X-API-Key': who.key } })).status, 403);
    assert.equal((await fetch(`${BASE}/api/settings/client-errors`, { method: 'DELETE', headers: { 'X-API-Key': who.key } })).status, 403);
  }
  assert.equal((await fetch(`${BASE}/api/settings/client-errors`)).status, 401);
  const res = await fetch(`${BASE}/api/settings/client-errors`, { headers: { 'X-API-Key': admin.key } });
  assert.equal(res.status, 200);
  const { errors } = await res.json();
  assert.equal(errors.length, 1);
  assert.equal(errors[0].message, 'listed');
  assert.deepEqual(errors[0].pages, ['/x']);
  const id = errors[0].id;
  const memberDel = await fetch(`${BASE}/api/settings/client-errors/${id}`, { method: 'DELETE', headers: { 'X-API-Key': member.key } });
  assert.equal(memberDel.status, 403);
  assert.equal(rows().length, 1);
  const del = await fetch(`${BASE}/api/settings/client-errors/${id}`, { method: 'DELETE', headers: { 'X-API-Key': admin.key } });
  assert.equal(del.status, 200);
  assert.equal(rows().length, 0);
});

test('retention drops entries not seen for 30 days; the table is capped', async () => {
  await report({ message: 'stale' });
  await report({ message: 'fresh' });
  db.prepare("UPDATE client_errors SET last_seen = datetime('now', '-31 days') WHERE message = 'stale'").run();
  assert.equal(svc.pruneClientErrors(), 1);
  assert.deepEqual(rows().map(r => r.message), ['fresh']);

  db.prepare('DELETE FROM client_errors').run();
  const insert = db.prepare("INSERT INTO client_errors (fingerprint, message, last_seen) VALUES (?, ?, datetime('now', ?))");
  for (let i = 0; i < svc.LIMITS.maxRows; i++) insert.run(`fp${i}`, `old ${i}`, `-${i + 1} minutes`);
  svc.recordClientError(svc.normalizeReport({ message: 'newest' }));
  const n = db.prepare('SELECT COUNT(*) AS n FROM client_errors').get().n;
  assert.equal(n, svc.LIMITS.maxRows);
  assert.ok(db.prepare("SELECT 1 FROM client_errors WHERE message = 'newest'").get());
  assert.ok(!db.prepare(`SELECT 1 FROM client_errors WHERE message = 'old ${svc.LIMITS.maxRows - 1}'`).get());
});
