import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// /api/admin/mcp-keys (routes/adminMcpKeys.js): a platform admin lists and
// revokes any user's personal MCP key, singly or in bulk. Driven through the
// real routers, requireAuth and the MCP endpoint, so "revoked" is proven by the
// key failing to authenticate, not by a column value.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-adminmcpkeys-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

initDb();
const db = getDb();

let seq = 0;
function mkUser(role = 'user') {
  const n = ++seq;
  const apiKey = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`u${n}`, `u${n}@t.test`, role, hashApiKey(apiKey), 'human').lastInsertRowid;
  return { id, apiKey };
}
function mkKey(userId, { label = null, lastUsedDaysAgo = null, createdDaysAgo = 0, coder = false } = {}) {
  const plain = generateApiKey('dhk_mcp');
  const id = db.prepare(`INSERT INTO user_mcp_keys (user_id,key_hash,label,coder_session_id,created_at,last_used_at)
                         VALUES (?,?,?,?,datetime('now', '-' || ? || ' days'),
                                 CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', '-' || ? || ' days') END)`)
    .run(userId, hashApiKey(plain), label, coder ? 'sess-1' : null, createdDaysAgo, lastUsedDaysAgo, lastUsedDaysAgo).lastInsertRowid;
  return { id, plain };
}
const revokedAt = (id) => db.prepare('SELECT revoked_at FROM user_mcp_keys WHERE id = ?').get(id).revoked_at;

const admin = mkUser('platform_admin');
const plainUser = mkUser('user');
const owner = mkUser('user');

const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.use('/api/admin/mcp-keys', (await import('../server/routes/adminMcpKeys.js')).default);
httpApp.use('/api', (await import('../server/routes/userMcpKeys.js')).default);
httpApp.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message, code: err.code }));
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

async function api(user, method, path, body) {
  const key = typeof user === 'string' ? user : user.apiKey;
  const r = await fetch(`${BASE}${path}`, {
    method, headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, body: await r.json() };
}
const ping = (key) => api(key, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method: 'ping' });

test('index.js mounts the admin router at /api/admin/mcp-keys', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'index.js'), 'utf8');
  assert.match(src, /app\.use\('\/api\/admin\/mcp-keys', \(await import\('\.\/routes\/adminMcpKeys\.js'\)\)\.default\)/);
});

test('a non-platform-admin gets 403 on every admin route; an MCP key is refused too', async () => {
  const k = mkKey(owner.id);
  for (const [method, path, body] of [
    ['GET', '/api/admin/mcp-keys'],
    ['DELETE', `/api/admin/mcp-keys/${k.id}`],
    ['POST', '/api/admin/mcp-keys/revoke-unused', { days: 30, dry_run: true }],
    ['POST', '/api/admin/mcp-keys/revoke-unused', { days: 30 }],
  ]) {
    const r = await api(plainUser, method, path, body);
    assert.equal(r.status, 403, `${method} ${path} -> ${r.status} ${JSON.stringify(r.body)}`);
    assert.equal(r.body.code, 'FORBIDDEN_PLATFORM_ADMIN');
  }
  const adminMcp = mkKey(admin.id);
  const viaMcpKey = await api(adminMcp.plain, 'GET', '/api/admin/mcp-keys');
  assert.equal(viaMcpKey.status, 403);
  assert.equal(revokedAt(k.id), null);
  // Baseline: the admin passes.
  assert.equal((await api(admin, 'GET', '/api/admin/mcp-keys')).status, 200);
});

test('the list carries owner and key metadata and never a hash', async () => {
  const k = mkKey(owner.id, { label: 'listed' });
  const { status, body } = await api(admin, 'GET', '/api/admin/mcp-keys?status=all');
  assert.equal(status, 200);
  const row = body.keys.find((x) => x.id === k.id);
  assert.ok(row, 'key missing from list');
  assert.deepEqual(row.owner, { id: owner.id, name: db.prepare('SELECT name FROM users WHERE id = ?').get(owner.id).name, email: db.prepare('SELECT email FROM users WHERE id = ?').get(owner.id).email });
  assert.equal(row.label, 'listed');
  for (const f of ['purpose', 'read_only', 'app_scope', 'created_at', 'last_used_at', 'expires_at', 'revoked_at', 'coder_session']) {
    assert.ok(f in row, `missing ${f}`);
  }
  const hashes = db.prepare('SELECT key_hash FROM user_mcp_keys').all().map((r) => r.key_hash);
  const text = JSON.stringify(body);
  for (const h of hashes) assert.ok(!text.includes(h), 'a key_hash value leaked into the list');
  for (const x of body.keys) {
    for (const f of Object.keys(x)) assert.doesNotMatch(f, /hash/i, `field ${f}`);
  }
});

test('status=live hides revoked and expired keys; status=all shows them', async () => {
  const live = mkKey(owner.id);
  const gone = mkKey(owner.id);
  db.prepare("UPDATE user_mcp_keys SET revoked_at = datetime('now') WHERE id = ?").run(gone.id);
  const expired = mkKey(owner.id);
  db.prepare("UPDATE user_mcp_keys SET expires_at = datetime('now', '-1 day') WHERE id = ?").run(expired.id);
  const liveIds = (await api(admin, 'GET', '/api/admin/mcp-keys')).body.keys.map((k) => k.id);
  assert.ok(liveIds.includes(live.id));
  assert.ok(!liveIds.includes(gone.id));
  assert.ok(!liveIds.includes(expired.id));
  const allIds = (await api(admin, 'GET', '/api/admin/mcp-keys?status=all')).body.keys.map((k) => k.id);
  assert.ok(allIds.includes(gone.id) && allIds.includes(expired.id));
  assert.equal((await api(admin, 'GET', '/api/admin/mcp-keys?status=bogus')).status, 400);
});

test('an admin revokes another user\'s key: it stops authenticating on /api/mcp, the revoke is idempotent and audited', async () => {
  const k = mkKey(owner.id);
  const before = await ping(k.plain);
  assert.equal(before.status, 200, `baseline ping: ${JSON.stringify(before.body)}`);
  const r = await api(admin, 'DELETE', `/api/admin/mcp-keys/${k.id}`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.message, 'Key revoked');
  assert.ok(revokedAt(k.id));
  const afterPing = await ping(k.plain);
  assert.equal(afterPing.status, 401, `revoked key still authenticates: ${JSON.stringify(afterPing.body)}`);
  const again = await api(admin, 'DELETE', `/api/admin/mcp-keys/${k.id}`);
  assert.equal(again.status, 200);
  assert.equal(again.body.message, 'Already revoked');
  const audits = db.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'user-mcp-key-revoke-admin'").all()
    .map((a) => ({ user_id: a.user_id, d: JSON.parse(a.detail) })).filter((a) => a.d.key_id === k.id);
  assert.equal(audits.length, 1, 'exactly one audit row, none for the idempotent repeat');
  assert.equal(audits[0].user_id, admin.id);
  assert.equal(audits[0].d.owner_user_id, owner.id);
  assert.equal((await api(admin, 'DELETE', '/api/admin/mcp-keys/999999')).status, 404);
});

test('revoke-unused: the preview count equals what is revoked, and only stale non-coder keys go', async () => {
  // Isolate from keys made by earlier tests.
  db.prepare("UPDATE user_mcp_keys SET revoked_at = datetime('now') WHERE revoked_at IS NULL").run();
  const u = mkUser();
  const neverUsedOld = mkKey(u.id, { createdDaysAgo: 40 });
  const usedLongAgo = mkKey(u.id, { createdDaysAgo: 90, lastUsedDaysAgo: 45 });
  const neverUsedNew = mkKey(u.id, { createdDaysAgo: 2 });
  const usedRecently = mkKey(u.id, { createdDaysAgo: 90, lastUsedDaysAgo: 3 });
  const coderOld = mkKey(u.id, { createdDaysAgo: 40, coder: true });

  const preview = await api(admin, 'POST', '/api/admin/mcp-keys/revoke-unused', { days: 30, dry_run: true });
  assert.equal(preview.status, 200, JSON.stringify(preview.body));
  assert.equal(preview.body.dry_run, true);
  assert.deepEqual(preview.body.key_ids.sort((a, b) => a - b), [neverUsedOld.id, usedLongAgo.id].sort((a, b) => a - b));
  for (const k of [neverUsedOld, usedLongAgo]) assert.equal(revokedAt(k.id), null, 'a dry run must revoke nothing');

  const done = await api(admin, 'POST', '/api/admin/mcp-keys/revoke-unused', { days: 30 });
  assert.equal(done.status, 200);
  assert.equal(done.body.count, preview.body.count);
  assert.deepEqual(done.body.key_ids, preview.body.key_ids);
  assert.ok(revokedAt(neverUsedOld.id) && revokedAt(usedLongAgo.id));
  for (const k of [neverUsedNew, usedRecently, coderOld]) assert.equal(revokedAt(k.id), null);
  assert.equal((await ping(neverUsedOld.plain)).status, 401);

  const audited = db.prepare("SELECT detail FROM audit_log WHERE action = 'user-mcp-key-revoke-admin'").all()
    .map((a) => JSON.parse(a.detail)).filter((d) => done.body.key_ids.includes(d.key_id));
  assert.equal(audited.length, done.body.count, 'one audit row per revoked key');
  for (const d of audited) assert.equal(d.owner_user_id, u.id);

  assert.equal((await api(admin, 'POST', '/api/admin/mcp-keys/revoke-unused', { days: 0 })).status, 400);
  assert.equal((await api(admin, 'POST', '/api/admin/mcp-keys/revoke-unused', { days: '30' })).status, 400);
});
