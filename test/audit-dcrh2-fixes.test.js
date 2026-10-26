import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, symlinkSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import express from 'express';

// Second Defending Code harness pass (2026-10-14): the mediums that were still
// open at v2.107.2, each driven through the surface an attacker would use.
//
//   rename     appcrane_rename_app said 'platform_admin', canUseTool knew no
//              such role and fell through to `return true`
//   owner      an app admin granted themselves owner over MCP, or demoted and
//              removed the real owner (REST was already owner-only)
//   runtime    any member set container_command / volume_paths / catalog_slug,
//              and any member restarted production
//   logs       /api/:slug/logs/:env built the container name from :env
//   probe      health probes followed redirects off the app's own port
//   skills     skill fetch-by-URL had no private-address guard
//   volumes    a planted symlink under <shared>/volumes was mkdir'd, chowned
//              and bind-mounted
//   frame      MCP stored frame_ancestors unvalidated into the Caddyfile
//   ask        the Ask Claude audit row recorded user_id NULL

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-dcrh2-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.ANTHROPIC_API_KEY = 'test-key-not-real';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkUser = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@acme.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const mkApp = (slug, slot, extra = '') => db.prepare(
  `INSERT INTO apps (name,slug,slot,source_type,branch${extra ? ',repo_backend' : ''}) VALUES (?,?,?,'managed','main'${extra ? ',?' : ''})`,
).run(...[slug, slug, slot, ...(extra ? [extra] : [])]).lastInsertRowid;
const assign = (appId, u, r) => db.prepare(
  'INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?) ON CONFLICT(app_id,user_id) DO UPDATE SET app_role=excluded.app_role',
).run(appId, u.id, r);
const roleOf = (appId, u) => db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, u.id)?.app_role;

// slot 20011: sandbox backend port 44022, far from anything a dev box runs.
const APP = mkApp('dfix', 20011);
const RENAME_APP = mkApp('dfixrn', 20012);
const ASK_APP = mkApp('dfixask', 20013, 'local');
const OWNER = mkUser('owner');
const OWNER2 = mkUser('owner2');
const APPADMIN = mkUser('appadmin');
const MEMBER = mkUser('member');
const MEMBER2 = mkUser('member2');
const PLATFORM = mkUser('platform', 'platform_admin');
for (const [u, r] of [[OWNER, 'owner'], [OWNER2, 'owner'], [APPADMIN, 'admin'], [MEMBER, 'user']]) assign(APP, u, r);
assign(RENAME_APP, MEMBER, 'user');
assign(RENAME_APP, OWNER, 'owner');
assign(ASK_APP, MEMBER, 'user');

const appsRoutes = (await import('../server/routes/apps.js')).default;
const deployRoutes = (await import('../server/routes/deploy.js')).default;
const healthRoutes = (await import('../server/routes/health.js')).default;
const logsRoutes = (await import('../server/routes/logs.js')).default;
const askRoutes = (await import('../server/routes/ask.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', appsRoutes);
  a.use('/api/apps', deployRoutes);
  a.use('/api/apps', healthRoutes);
  a.use('/api/ask', askRoutes);
  a.use('/api', logsRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
const servers = [server];
after(() => { for (const s of servers) { s.closeAllConnections?.(); s.close(); } });
const base = `http://127.0.0.1:${server.address().port}`;
const call = (method, path, who, body) => fetch(base + path, {
  method, headers: { 'x-api-key': who.key, ...(body ? { 'content-type': 'application/json' } : {}) },
  body: body ? JSON.stringify(body) : undefined,
});
const listen = (handler, port = 0, host) => new Promise((r) => {
  const s = http.createServer(handler);
  servers.push(s);
  s.listen(port, host, () => r(s));
});

test('rename: an app member cannot rename the app over MCP; the check is fail-closed', async () => {
  await assert.rejects(
    callTool(MEMBER.row, 'appcrane_rename_app', { slug: 'dfixrn', new_slug: 'dfixrn-taken', redirect: false }),
    /Forbidden: tool appcrane_rename_app requires app_admin|Only the app owner or a platform admin/,
  );
  assert.ok(db.prepare("SELECT 1 FROM apps WHERE slug = 'dfixrn'").get(), 'the app was renamed by a member');
});

test('owner: an app admin cannot make themselves owner, nor demote or remove an owner, over MCP', async () => {
  await assert.rejects(callTool(APPADMIN.row, 'appcrane_grant_app_access', { slug: 'dfix', user: String(APPADMIN.id), role: 'owner' }), /owner role/);
  assert.equal(roleOf(APP, APPADMIN), 'admin');
  await assert.rejects(callTool(APPADMIN.row, 'appcrane_grant_app_access', { slug: 'dfix', user: String(OWNER.id), role: 'user' }), /owner role/);
  assert.equal(roleOf(APP, OWNER), 'owner');
  await assert.rejects(callTool(APPADMIN.row, 'appcrane_revoke_app_access', { slug: 'dfix', user: String(OWNER.id) }), /owner role/);
  assert.equal(roleOf(APP, OWNER), 'owner');

  // The self-approval route to the same place.
  const reqId = db.prepare("INSERT INTO enhancement_requests (app_slug, user_id, user_name, message) VALUES ('dfix', ?, 'appadmin', 'Access request for app dfix')")
    .run(APPADMIN.id).lastInsertRowid;
  await assert.rejects(callTool(APPADMIN.row, 'appcrane_approve_access_request', { request_id: reqId, role: 'owner' }), /owner role/);
  assert.equal(roleOf(APP, APPADMIN), 'admin');

  // What an app admin could do before is untouched below the owner tier, and
  // an owner can still hand out owner.
  await callTool(APPADMIN.row, 'appcrane_grant_app_access', { slug: 'dfix', user: String(MEMBER2.id), role: 'admin' });
  assert.equal(roleOf(APP, MEMBER2), 'admin');
  await callTool(OWNER.row, 'appcrane_grant_app_access', { slug: 'dfix', user: String(MEMBER2.id), role: 'owner' });
  assert.equal(roleOf(APP, MEMBER2), 'owner');
  db.prepare('DELETE FROM app_user_roles WHERE app_id = ? AND user_id = ?').run(APP, MEMBER2.id);
});

test('runtime: a member cannot set what production runs or restart it', async () => {
  assert.equal((await call('PUT', '/api/apps/dfix', MEMBER, { container_command: ['sh', '-c', 'id'] })).status, 403);
  assert.equal((await call('PUT', '/api/apps/dfix', MEMBER, { volume_paths: ['/config'] })).status, 403);
  assert.equal((await call('PUT', '/api/apps/dfix', MEMBER, { catalog_slug: 'metabase' })).status, 403);
  const row = db.prepare('SELECT container_command, volume_paths, catalog_slug FROM apps WHERE id = ?').get(APP);
  assert.deepEqual(row, { container_command: null, volume_paths: null, catalog_slug: null });
  assert.equal((await call('POST', '/api/apps/dfix/restart/production', MEMBER)).status, 403);
  // Members keep the ordinary fields.
  assert.equal((await call('PUT', '/api/apps/dfix', MEMBER, { description: 'still mine to edit' })).status, 200);
});

test('logs: the :env segment cannot name another app\'s container', async () => {
  assert.equal((await call('GET', '/api/dfix/logs/x-production', OWNER)).status, 400);
  const { getAppLogs } = await import('../server/services/docker.js');
  await assert.rejects(getAppLogs('dfix', 'x-production'), /invalid env/);
});

test('probe: a health check follows a redirect on the app\'s own port only', async () => {
  let internalHits = 0;
  const internal = await listen((req, res) => { internalHits++; res.end('INTERNAL-SECRET'); }, 0, '127.0.0.1');
  const target = `http://127.0.0.1:${internal.address().port}/latest/meta-data/`;
  await listen((req, res) => {
    if (req.url === '/hop') { res.writeHead(302, { location: '/ok' }); return res.end(); }
    if (req.url === '/ok') { res.setHeader('content-type', 'application/json'); return res.end('{"status":"ok"}'); }
    res.writeHead(302, { location: target }); res.end();
  }, 44022);
  db.prepare("INSERT INTO health_configs (app_id, env, endpoint) VALUES (?, 'sandbox', '/health')").run(APP);
  const out = await (await call('POST', '/api/apps/dfix/health/sandbox/test', MEMBER)).json();
  assert.equal(internalHits, 0, 'the probe followed the app\'s redirect to another address');
  assert.equal(out.status, 302);
  assert.doesNotMatch(JSON.stringify(out), /INTERNAL-SECRET/);

  db.prepare("UPDATE health_configs SET endpoint = '/hop' WHERE app_id = ? AND env = 'sandbox'").run(APP);
  const same = await (await call('POST', '/api/apps/dfix/health/sandbox/test', MEMBER)).json();
  assert.equal(same.status, 200, 'a same-origin redirect should still be followed');
});

test('skills: fetch-by-URL refuses a private address', async () => {
  let hits = 0;
  const internal = await listen((req, res) => { hits++; res.end('# internal'); }, 0, '127.0.0.1');
  const { fetchSkillFromUrl } = await import('../server/services/skills.js');
  await assert.rejects(fetchSkillFromUrl(`http://127.0.0.1:${internal.address().port}/SKILL.md`), /fetch failed/);
  assert.equal(hits, 0);
});

test('volumes: a symlink planted under the volumes tree is refused, not followed', async () => {
  const { resolveVolumeMounts } = await import('../server/services/containerRuntimeSpec.js');
  const shared = mkdtempSync(join(tmpdir(), 'crane-dcrh2-shared-'));
  const outside = mkdtempSync(join(tmpdir(), 'crane-dcrh2-etc-'));
  mkdirSync(join(shared, 'volumes', 'var'), { recursive: true });
  // What app code writes through a '/var' mount before '/var/lib' is declared.
  symlinkSync(outside, join(shared, 'volumes', 'var', 'lib'));
  assert.throws(() => resolveVolumeMounts({ sharedDir: shared, paths: ['/var/lib'] }), /not a plain directory/);
  assert.throws(() => resolveVolumeMounts({ sharedDir: shared, paths: ['/var/lib/odoo'] }), /not a plain directory/);
  assert.ok(!existsSync(join(outside, 'odoo')));
});

test('frame: MCP cannot write a Caddyfile-breaking frame_ancestors, and the generator ignores a planted one', async () => {
  const evil = 'https://a.test"\n}\nhandle /* {\n  reverse_proxy 127.0.0.1:2019\n}\n#';
  await assert.rejects(callTool(PLATFORM.row, 'appcrane_update_app', { slug: 'dfix', frame_ancestors: evil }), /invalid characters/);
  db.prepare('UPDATE apps SET frame_ancestors = ? WHERE id = ?').run(evil, APP);
  const { generateCaddyfile } = await import('../server/services/caddy.js');
  // No CRANE_DOMAIN means no app routes at all, and the embed headers are only
  // written into a LIVE environment's block.
  process.env.CRANE_DOMAIN = 'crane.test';
  const dep = db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(APP).lastInsertRowid;
  try {
    const out = generateCaddyfile();
    assert.match(out, /reverse_proxy 127\.0\.0\.1:\d+\n/, 'no live app block was generated, so this check proves nothing');
    assert.doesNotMatch(out, /127\.0\.0\.1:2019/);
  } finally {
    delete process.env.CRANE_DOMAIN;
    db.prepare('DELETE FROM deployments WHERE id = ?').run(dep);
  }
  db.prepare('UPDATE apps SET frame_ancestors = NULL WHERE id = ?').run(APP);
});

test('ask: the Ask Claude audit row names the asker', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (url, opts) => (String(url).includes('anthropic.com')
    ? Promise.resolve(new Response('{}', { status: 500 }))
    : realFetch(url, opts));
  try {
    const r = await call('POST', '/api/ask/dfixask', MEMBER, { question: 'what does this do?' });
    assert.equal(r.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  const row = db.prepare("SELECT user_id FROM audit_log WHERE action = 'ask' AND app_id = ?").get(ASK_APP);
  assert.equal(row?.user_id, MEMBER.id);
});

test('secret: appcrane_set_secret honours env.write.production like the REST route', async () => {
  // An operator narrows production env writes to owners only.
  db.prepare("UPDATE role_permissions SET granted = 0 WHERE permission = 'env.write.production' AND role = 'admin'").run();
  try {
    await assert.rejects(
      callTool(APPADMIN.row, 'appcrane_set_secret', { slug: 'dfix', env: 'production', key: 'K', value: 'v' }),
      /env\.write\.production/,
    );
    assert.equal(db.prepare("SELECT 1 FROM env_vars WHERE app_id = ? AND env = 'production' AND key = 'K'").get(APP), undefined);
    await callTool(APPADMIN.row, 'appcrane_set_secret', { slug: 'dfix', env: 'sandbox', key: 'K', value: 'v' });
    await callTool(OWNER.row, 'appcrane_set_secret', { slug: 'dfix', env: 'production', key: 'K', value: 'v' });
  } finally {
    db.prepare("UPDATE role_permissions SET granted = 1 WHERE permission = 'env.write.production' AND role = 'admin'").run();
  }
});

test('volumes: whether a nested path is skipped does not depend on declaration order', async () => {
  const { resolveVolumeMounts } = await import('../server/services/containerRuntimeSpec.js');
  const { mounts, skipped } = resolveVolumeMounts({ sharedDir: '/srv/none/shared', paths: ['/config/cache', '/config'] });
  assert.deepEqual(mounts.map((m) => m.container), ['/data', '/config']);
  assert.deepEqual(skipped, [{ path: '/config/cache', coveredBy: '/config' }]);
});
