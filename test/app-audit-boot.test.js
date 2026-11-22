import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import net from 'net';
import Database from 'better-sqlite3';

// App audit events through the real server process (server/index.js): the
// write path is mounted before the 50 MB parser (so its 32 KB cap holds),
// takes only a service token and refuses a request that came through the
// proxy; the read and settings routes answer behind their own guards; and the
// delivery and retention workers are registered in Job Health.

let child;
let base;
let dataDir;
const sha = (s) => createHash('sha256').update(s).digest('hex');
const adminKey = `dhk_admin_${randomBytes(12).toString('hex')}`;
const memberKey = `dhk_user_${randomBytes(12).toString('hex')}`;
const token = randomBytes(32).toString('base64url');

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-app-audit-boot-'));
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
  const db = new Database(join(dataDir, 'deployhub.db'));
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('boot admin','admin@example.test','platform_admin',?,1,'human')").run(sha(adminKey));
  const memberId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('boot member','member@example.test','user',?,1,'human')").run(sha(memberKey)).lastInsertRowid;
  const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,service_token_hash) VALUES ('Boot','boot-a',9101,'managed',?)").run(sha(token)).lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, memberId);
  db.prepare("INSERT INTO app_audit_event_types (app_id, action) VALUES (?, 'invoice.paid')").run(appId);
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

const post = (body, headers = {}) => fetch(`${base}/api/service/audit/events`, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body),
});
const get = (path, key) => fetch(`${base}${path}`, { headers: key ? { 'x-api-key': key } : {} });

test('the write path is mounted: a service token writes, a user key and a proxied request do not', async () => {
  const ok = await post({ action: 'invoice.paid', targets: [{ type: 'invoice', id: 'b1' }] }, { 'x-appcrane-service-token': token });
  assert.equal(ok.status, 201, await ok.clone().text());
  assert.equal((await ok.json()).event.app.slug, 'boot-a');
  assert.equal((await post({ action: 'invoice.paid' }, { 'x-api-key': adminKey })).status, 401);
  assert.equal((await post({ action: 'invoice.paid' }, { 'x-appcrane-service-token': token, 'x-forwarded-for': '198.51.100.4' })).status, 403);
});

test('the 32 KB cap holds in the real middleware order (not swallowed by the 50 MB parser)', async () => {
  const r = await post(JSON.stringify({ action: 'invoice.paid', pad: 'x'.repeat(40_000) }), { 'x-appcrane-service-token': token });
  assert.equal(r.status, 413);
});

test('read and settings routes answer behind their guards', async () => {
  const list = await get('/api/apps/boot-a/audit-events', adminKey);
  assert.equal(list.status, 200);
  assert.equal((await list.json()).events.length, 1);
  assert.equal((await get('/api/apps/boot-a/audit-events', memberKey)).status, 403);
  assert.equal((await get('/api/apps/boot-a/audit-events')).status, 401);
  const all = await get('/api/app-audit-events', adminKey);
  assert.equal(all.status, 200);
  assert.equal((await get('/api/app-audit-events', memberKey)).status, 403);
  const settings = await get('/api/app-audit/settings', adminKey);
  assert.equal(settings.status, 200);
  assert.deepEqual(await settings.json(), { retention_days: 365, min_days: 30, max_days: 3650, owner_streams_enabled: true, owner_streams_private: false });
  const csv = await get('/api/apps/boot-a/audit-events/export?format=csv', adminKey);
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get('content-type'), /text\/csv/);
});

test('the delivery and retention workers are registered in Job Health', async () => {
  const r = await get('/api/settings/job-health', adminKey);
  assert.equal(r.status, 200);
  const text = await r.text();
  assert.ok(text.includes('app-audit-streams'), 'app-audit-streams job');
  assert.ok(text.includes('app-audit-retention'), 'app-audit-retention job');
});
