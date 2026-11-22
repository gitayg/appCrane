import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import http from 'http';
import net from 'net';
import Database from 'better-sqlite3';

// The widget and session routers as server/index.js mounts them, against the
// real server process: nothing mounted earlier (slug fallback, /api routers
// with their own requireAuth, /api/apps routers) swallows or misroutes them.

const PLATFORM = 'crane.example.test';
const HUB_HOST = 'hub.apps.example.test';
let child;
let port;
let dataDir;
const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
const KEY = { owner: 'dhk_user_bootowner', member: 'dhk_user_bootmember', admin: 'dhk_admin_bootadmin' };
const ids = {};
let cookie;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function call(path, { method = 'GET', host = PLATFORM, headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const r = http.request({
      host: '127.0.0.1', port, path, method,
      headers: { Host: host, Accept: 'application/json', ...(data && { 'Content-Type': 'application/json' }), ...headers },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => { let json = null; try { json = JSON.parse(text); } catch (_) { /* not json */ } resolve({ status: res.statusCode, headers: res.headers, body: text, json }); });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-widgets-boot-'));
  port = await freePort();
  child = spawn(process.execPath, ['server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY: 'e'.repeat(64), CRANE_DOMAIN: PLATFORM, LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const db = new Database(join(dataDir, 'deployhub.db'));
  db.prepare("INSERT INTO settings (key, value) VALUES ('app_isolation_domain', 'apps.example.test') ON CONFLICT(key) DO UPDATE SET value = excluded.value").run();
  const user = (name, role, key) => db.prepare('INSERT INTO users (name,email,role,api_key_hash,active) VALUES (?,?,?,?,1)').run(name, `${name}@t.test`, role, sha(key)).lastInsertRowid;
  ids.owner = user('owner', 'user', KEY.owner);
  ids.member = user('member', 'user', KEY.member);
  ids.admin = user('root', 'platform_admin', KEY.admin);
  ids.hub = db.prepare("INSERT INTO apps (name,slug,slot,source_type,visibility) VALUES ('Hub','hub',9001,'managed','private')").run().lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner'),(?,?,'user')").run(ids.hub, ids.owner, ids.hub, ids.member);
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(ids.owner, sha('boot-platform'));
  cookie = 'boot-app-session';
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at, scope, app_env, parent_token_hash)
    VALUES (?, ?, ?, datetime('now','+1 day'), 'app', 'production', ?)`).run(ids.owner, sha(cookie), ids.hub, sha('boot-platform'));
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

test('the real server serves the widget script on an app host, not on the platform host', async () => {
  const js = await call('/__appcrane/widgets.js', { host: HUB_HOST });
  assert.equal(js.status, 200, js.body.slice(0, 200));
  assert.equal(js.headers['content-type'], 'application/javascript; charset=utf-8');
  assert.match(js.body, /customElements\.define/);
  assert.equal((await call('/__appcrane/widgets.js')).status, 404);
});

test('the real server: sessions API, admin sessions, widget-scopes opt-in, token and members end to end', async () => {
  const mine = await call('/api/me/sessions', { headers: { Authorization: 'Bearer boot-platform' } });
  assert.equal(mine.status, 200, mine.body);
  assert.equal(mine.json.sessions.filter((s) => s.current).length, 1);
  assert.equal((await call(`/api/users/${ids.owner}/sessions`, { headers: { 'X-API-Key': KEY.member } })).status, 403);
  const adm = await call(`/api/users/${ids.owner}/sessions`, { headers: { 'X-API-Key': KEY.admin } });
  assert.equal(adm.status, 200, adm.body);
  assert.equal(adm.json.sessions.length, 2);

  const tokenOf = async () => (await call('/__appcrane/widgets/token', {
    method: 'POST', host: HUB_HOST, body: {}, headers: { 'X-AppCrane-Widget': '1', 'Sec-Fetch-Site': 'same-origin', Cookie: `__Host-cc_app=${cookie}` },
  })).json;
  const off = await tokenOf();
  assert.deepEqual(off.scopes, ['me', 'sessions', 'access']);

  const scopes = await call('/api/apps/hub/widget-scopes', { headers: { 'X-API-Key': KEY.owner } });
  assert.equal(scopes.status, 200, scopes.body);
  assert.deepEqual(scopes.json, { members: false, app_keys: false, can_change: true });
  assert.equal((await call('/api/apps/hub/widget-scopes', { method: 'PUT', body: { members: true }, headers: { 'X-API-Key': KEY.member } })).status, 403);
  const on = await call('/api/apps/hub/widget-scopes', { method: 'PUT', body: { members: true }, headers: { 'X-API-Key': KEY.owner } });
  assert.equal(on.status, 200, on.body);

  const t = await tokenOf();
  assert.ok(t.scopes.includes('members'));
  const members = await call('/__appcrane/widgets/api/members', { host: HUB_HOST, headers: { Authorization: `Bearer ${t.token}` } });
  assert.equal(members.status, 200, members.body);
  assert.deepEqual(members.json.members.map((m) => m.name), ['owner', 'member']);
  assert.equal(members.headers['cache-control'], 'no-store');
});
