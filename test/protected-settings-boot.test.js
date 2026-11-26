import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import net from 'net';
import Database from 'better-sqlite3';

// /api/settings/protected through the real server process (server/index.js):
// it must be mounted before the generic /api/settings/:key router, or that
// router answers its GET and refuses its PUT with 409; and the Docker version
// check is started at boot, next to the host gateway check.

let child;
let base;
let dataDir;
let db;
let adminId;
const sha = (s) => createHash('sha256').update(s).digest('hex');
const adminKey = `dhk_admin_${randomBytes(12).toString('hex')}`;
const fresh = randomBytes(24).toString('base64url');
const stale = randomBytes(24).toString('base64url');

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-protected-boot-'));
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY: 'e'.repeat(64), CRANE_DOMAIN: 'crane.example.test', LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  db = new Database(join(dataDir, 'deployhub.db'));
  adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('boot admin','admin@example.test','platform_admin',?,1,'human')").run(sha(adminKey)).lastInsertRowid;
  const session = (tok, age) => db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, datetime('now','+1 day'), datetime('now', ?))`).run(adminId, sha(tok), `-${age} minutes`);
  session(fresh, 0);
  session(stale, 60);
});

after(() => {
  try { db?.close(); } catch (_) {}
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

const call = async (method, path, headers, body) => {
  const r = await fetch(`${base}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body !== undefined && { body: JSON.stringify(body) }) });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const bearer = (t) => ({ authorization: `Bearer ${t}` });
const value = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? null;

test('the protected route answers through the real mount, ahead of /api/settings/:key', async () => {
  const read = await call('GET', '/api/settings/protected/db_allowlist_mode', { 'x-api-key': adminKey });
  assert.equal(read.status, 200, JSON.stringify(read.body));
  assert.deepEqual([read.body.key, read.body.kind, read.body.effective], ['db_allowlist_mode', 'enum', 'observe']);
  const all = await call('GET', '/api/settings/protected', { 'x-api-key': adminKey });
  assert.equal(all.status, 200);
  assert.ok(all.body.settings.some((s) => s.key === 'db_allowlist_mode'));

  const generic = await call('PUT', '/api/settings/db_allowlist_mode', bearer(fresh), { value: 'off' });
  assert.equal(generic.status, 409);
  assert.equal(generic.body.error.route, 'PUT /api/settings/protected/db_allowlist_mode');

  assert.equal((await call('PUT', '/api/settings/protected/db_allowlist_mode', { 'x-api-key': adminKey }, { value: 'enforce' })).status, 403);
  const tighten = await call('PUT', '/api/settings/protected/db_allowlist_mode', bearer(stale), { value: 'enforce' });
  assert.equal(tighten.status, 200, JSON.stringify(tighten.body));
  const weaken = await call('PUT', '/api/settings/protected/db_allowlist_mode', bearer(stale), { value: 'off' });
  assert.equal(weaken.status, 401);
  assert.equal(weaken.body.error.code, 'STEP_UP_REQUIRED');
  assert.equal(value('db_allowlist_mode'), 'enforce');
  const rows = db.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'protected-setting-change'").all();
  assert.deepEqual(rows.map((r) => [r.user_id, JSON.parse(r.detail).to]), [[adminId, 'enforce']]);
});

test('the Docker version check is started at boot', async () => {
  const r = await call('GET', '/api/settings/job-health', { 'x-api-key': adminKey });
  assert.equal(r.status, 200);
  const job = r.body.jobs.find((j) => j.id === 'docker-version');
  assert.equal(job.started_in_process, true, JSON.stringify(job));
  assert.notEqual(job.status, 'disabled');
});
