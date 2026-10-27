import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Per-app origins: every server-side place that hands a person an app's
// browser URL must give the app's own host once app_isolation_domain is set
// (services/appOrigin.js appUrl), and the /<slug> path on the platform host
// while it is not. A surface that keeps building `https://<platform>/<slug>`
// itself still works with isolation on (the platform host 308s), but it sends
// every visitor through a redirect and reads as "apps live on the platform
// host" to the next person. custom_domain_auth rides along: readable on the app
// object, writable by the owner where the domain is.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-iso-urls-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.example.com';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkUser = (name, role) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name.toLowerCase()}@example.test`, role, hashApiKey(key)).lastInsertRowid;
  return { key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const admin = mkUser('Admin', 'platform_admin');
const owner = mkUser('Owner', 'user');
const member = mkUser('Member', 'user');

const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,domain) VALUES ('Hub','hub',7,'github','https://github.com/example/hub',NULL)").run().lastInsertRowid;
for (const env of ['production', 'sandbox']) {
  db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(appId, env);
  db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(appId, env);
}
db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(appId, owner.row.id);
db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(appId, member.row.id);

const setIsolation = (domain) => db.prepare(
  `INSERT INTO settings (key, value) VALUES ('app_isolation_domain', ?)
   ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(domain);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const healthRoutes = (await import('../server/routes/health.js')).default;
const monitoringRoutes = (await import('../server/routes/monitoring.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use('/api/apps', healthRoutes);
api.use('/api', monitoringRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function req(method, path, key, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'X-API-Key': key, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* not json */ }
  return { status: res.status, text, body: json };
}
const mcp = async (user, name, args) => {
  const r = await callTool(user, name, args);
  return JSON.parse(r.content[0].text);
};

const OFF = { url: 'https://crane.example.com/hub', sandbox_url: 'https://crane.example.com/hub-sandbox' };
const ON = { url: 'https://hub.apps.example.com/', sandbox_url: 'https://hub-sandbox.apps.example.com/' };

for (const [label, domain, want] of [['off', '', OFF], ['on', 'apps.example.com', ON]]) {
  test(`isolation ${label}: the apps API carries url and sandbox_url on list, detail and update`, async () => {
    setIsolation(domain);
    const list = await req('GET', '/api/apps', admin.key);
    assert.equal(list.status, 200, list.text);
    const row = list.body.apps.find((a) => a.slug === 'hub');
    assert.equal(row.url, want.url);
    assert.equal(row.sandbox_url, want.sandbox_url);
    assert.deepEqual(row.urls, { production: want.url, sandbox: want.sandbox_url });

    const detail = await req('GET', '/api/apps/hub', owner.key);
    assert.equal(detail.status, 200, detail.text);
    assert.equal(detail.body.app.url, want.url);
    assert.equal(detail.body.app.sandbox_url, want.sandbox_url);
    assert.deepEqual(detail.body.urls, { production: want.url, sandbox: want.sandbox_url });
    // APP_BASE_PATH does not change: the app host strips the prefix.
    assert.deepEqual(detail.body.base_path, { production: '/hub/', sandbox: '/hub-sandbox/' });

    const upd = await req('PUT', '/api/apps/hub', owner.key, { description: `iso ${label}` });
    assert.equal(upd.status, 200, upd.text);
    assert.equal(upd.body.app.url, want.url);
    assert.equal(upd.body.app.sandbox_url, want.sandbox_url);
  });

  test(`isolation ${label}: MCP get_app and list_apps urls`, async () => {
    setIsolation(domain);
    const got = await mcp(admin.row, 'appcrane_get_app', { slug: 'hub' });
    assert.deepEqual(got.urls ?? got.app?.urls, { production: want.url, sandbox: want.sandbox_url });
    const listed = await mcp(admin.row, 'appcrane_list_apps', {});
    const row = (listed.apps ?? listed).find((a) => a.slug === 'hub');
    assert.deepEqual(row.urls, { production: want.url, sandbox: want.sandbox_url });
  });

  test(`isolation ${label}: health test and metrics links`, async () => {
    setIsolation(domain);
    const h = await req('POST', '/api/apps/hub/health/sandbox/test', admin.key);
    assert.equal(h.status, 200, h.text);
    const endpoint = h.body.endpoint;
    assert.equal(h.body.url, domain
      ? `https://hub-sandbox.apps.example.com${endpoint}`
      : `https://crane.example.com/hub-sandbox${endpoint}`);

    const m = await req('GET', '/api/apps/hub/metrics/production', owner.key);
    assert.equal(m.status, 200, m.text);
    assert.equal(m.body.url, want.url);
  });
}

test('MCP: a custom domain still wins for production when isolation is on', async () => {
  setIsolation('apps.example.com');
  db.prepare("UPDATE apps SET domain = 'hub.example.test' WHERE id = ?").run(appId);
  try {
    const got = await mcp(admin.row, 'appcrane_get_app', { slug: 'hub' });
    const urls = got.urls ?? got.app?.urls;
    assert.equal(urls.production, 'https://hub.example.test');
    assert.equal(urls.sandbox, ON.sandbox_url);
  } finally {
    db.prepare('UPDATE apps SET domain = NULL WHERE id = ?').run(appId);
  }
});

test('custom_domain_auth: readable on the app object, 0 by default', async () => {
  const r = await req('GET', '/api/apps/hub', member.key);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.app.custom_domain_auth, 0);
});

test('custom_domain_auth: a member cannot turn it on; echoing the current value is not a change', async () => {
  const refused = await req('PUT', '/api/apps/hub', member.key, { custom_domain_auth: true });
  assert.equal(refused.status, 403, refused.text);
  assert.equal(db.prepare('SELECT custom_domain_auth FROM apps WHERE id = ?').get(appId).custom_domain_auth, 0);
  const echo = await req('PUT', '/api/apps/hub', member.key, { custom_domain_auth: 0, description: 'echo' });
  assert.equal(echo.status, 200, echo.text);
});

test('custom_domain_auth: the owner turns it on and off; a non-boolean is refused', async () => {
  const bad = await req('PUT', '/api/apps/hub', owner.key, { custom_domain_auth: 'yes' });
  assert.equal(bad.status, 400, bad.text);
  const on = await req('PUT', '/api/apps/hub', owner.key, { custom_domain_auth: true });
  assert.equal(on.status, 200, on.text);
  assert.equal(on.body.app.custom_domain_auth, 1);
  assert.equal(db.prepare('SELECT custom_domain_auth FROM apps WHERE id = ?').get(appId).custom_domain_auth, 1);
  const off = await req('PUT', '/api/apps/hub', owner.key, { custom_domain_auth: false });
  assert.equal(off.status, 200, off.text);
  assert.equal(off.body.app.custom_domain_auth, 0);
});

test('custom_domain_auth via MCP set_app_meta: owner only, stored, returned', async () => {
  await assert.rejects(mcp(member.row, 'appcrane_set_app_meta', { slug: 'hub', custom_domain_auth: true }), /Forbidden/);
  const r = await mcp(owner.row, 'appcrane_set_app_meta', { slug: 'hub', custom_domain_auth: true });
  assert.equal(r.custom_domain_auth, true);
  assert.deepEqual(r.updated_fields, ['custom_domain_auth']);
  assert.equal(db.prepare('SELECT custom_domain_auth FROM apps WHERE id = ?').get(appId).custom_domain_auth, 1);
  await mcp(owner.row, 'appcrane_set_app_meta', { slug: 'hub', custom_domain_auth: false });
  assert.equal(db.prepare('SELECT custom_domain_auth FROM apps WHERE id = ?').get(appId).custom_domain_auth, 0);
});
