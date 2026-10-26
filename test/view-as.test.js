import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// View as role (services/viewAs.js, middleware/viewAsGuard.js, routes/viewAs.js).
// Driven through the real routers over HTTP with the credentials the SPA sends
// (an identity session Bearer token): who may preview what, that the preview
// gets the target role's 403s, that nothing can be changed while it is active,
// that the real person stays in the audit log, and that it ends.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-viewas-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { viewAsWriteGuard } = await import('../server/middleware/viewAsGuard.js');

initDb();
const db = getDb();

const mkApp = (slug, slot) => db
  .prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES (?,?,?,'managed','local','main')")
  .run(slug, slug, slot).lastInsertRowid;
const ALPHA = mkApp('alpha', 911);
const BETA = mkApp('beta', 912);

let seq = 0;
function mkUser(role, roles = {}) {
  const n = ++seq;
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`va${n}`, `va${n}@t.test`, role, hashApiKey(generateApiKey('dhk_user')), 'human').lastInsertRowid;
  for (const [appId, r] of Object.entries(roles)) {
    db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(Number(appId), id, r);
  }
  const token = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(id, hashApiKey(token));
  return { id, token };
}
const owner = mkUser('user', { [ALPHA]: 'owner', [BETA]: 'user' });
const appAdmin = mkUser('user', { [ALPHA]: 'admin' });
const member = mkUser('user', { [ALPHA]: 'user' });
const padmin = mkUser('platform_admin', {});

const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api', viewAsWriteGuard);
httpApp.use('/api/auth', (await import('../server/routes/viewAs.js')).default);
httpApp.use('/api/apps', (await import('../server/routes/apps.js')).default);
httpApp.use('/api/apps', (await import('../server/routes/deploy.js')).default);
httpApp.use('/api/apps', (await import('../server/routes/envVars.js')).default);
httpApp.use('/api/coder', (await import('../server/routes/coder.js')).default);
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.use('/api', (await import('../server/routes/logs.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

async function api(who, method, path, body, extra = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${who.token}`, ...extra },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json };
}
const start = (who, role, app_slug) => api(who, 'POST', '/api/auth/view-as', { role, ...(app_slug ? { app_slug } : {}) });
const stop = (who) => api(who, 'POST', '/api/auth/stop-viewing-as', {});
const rpc = (who, method, params) => api(who, 'POST', '/api/mcp', { jsonrpc: '2.0', id: 1, method, params });

test('an app owner may pick only lower roles, only on an app they own', async () => {
  const opts = await api(owner, 'GET', '/api/auth/view-as-options');
  assert.equal(opts.status, 200);
  assert.deepEqual(opts.body.platform_roles, []);
  assert.deepEqual(opts.body.apps, [{ slug: 'alpha', name: 'alpha', roles: ['admin', 'user', 'none'] }]);

  for (const [role, slug] of [['owner', 'alpha'], ['user', 'beta'], ['user', undefined], ['platform_admin', 'alpha']]) {
    const r = await start(owner, role, slug);
    assert.equal(r.status, 403, `owner viewing ${slug || 'platform'} as ${role} was allowed`);
    assert.equal(r.body.error.code, 'VIEW_AS_FORBIDDEN');
  }
  const ok = await start(owner, 'admin', 'alpha');
  assert.equal(ok.status, 200);
  assert.equal(ok.body.active, true);
  assert.equal(ok.body.role, 'admin');
  await stop(owner);
});

test('app admins and members cannot view as anything', async () => {
  for (const who of [appAdmin, member]) {
    const opts = await api(who, 'GET', '/api/auth/view-as-options');
    assert.deepEqual(opts.body.apps, []);
    for (const role of ['user', 'none']) {
      const r = await start(who, role, 'alpha');
      assert.equal(r.status, 403);
    }
  }
});

test('a platform admin may pick any role on any app, or the platform as a user', async () => {
  const opts = await api(padmin, 'GET', '/api/auth/view-as-options');
  assert.deepEqual(opts.body.platform_roles, ['user']);
  assert.deepEqual(opts.body.apps.map(a => [a.slug, a.roles]), [
    ['alpha', ['owner', 'admin', 'user', 'none']], ['beta', ['owner', 'admin', 'user', 'none']],
  ]);
  for (const [role, slug] of [['owner', 'beta'], ['admin', 'alpha'], ['user', 'alpha'], ['none', 'beta'], ['user', undefined]]) {
    const r = await start(padmin, role, slug);
    assert.equal(r.status, 200, `${role} on ${slug || 'platform'}: ${JSON.stringify(r.body)}`);
  }
  const bad = await start(padmin, 'platform_admin', undefined);
  assert.equal(bad.status, 403);
  await stop(padmin);
});

test('effective permissions are the target role\'s: a member view gets the member\'s 403s', async () => {
  // Baseline: the owner reads alpha's audit trail (app.audit.view: owner yes, admin yes, user no).
  assert.equal((await api(owner, 'GET', '/api/alpha/audit')).status, 200);
  assert.equal((await api(member, 'GET', '/api/alpha/audit')).status, 403, 'a real member must be refused, or this proves nothing');

  await start(owner, 'user', 'alpha');
  const asMember = await api(owner, 'GET', '/api/alpha/audit');
  assert.equal(asMember.status, 403, 'viewing as member still read the audit trail');
  assert.equal((await api(owner, 'GET', '/api/apps/alpha')).status, 200, 'a member can still open the app');

  await start(owner, 'admin', 'alpha');
  assert.equal((await api(owner, 'GET', '/api/alpha/audit')).status, 200, 'an app admin reads the audit trail');

  await start(owner, 'none', 'alpha');
  assert.equal((await api(owner, 'GET', '/api/apps/alpha')).status, 403, 'viewing as no role still opened the app');
  await stop(owner);
  assert.equal((await api(owner, 'GET', '/api/alpha/audit')).status, 200, 'stop did not restore the owner');
});

test('a platform admin viewing the platform as a user loses the admin-only surface', async () => {
  assert.equal((await api(padmin, 'GET', '/api/mcp/catalog')).status, 200);
  await start(padmin, 'user', undefined);
  assert.equal((await api(padmin, 'GET', '/api/mcp/catalog')).status, 403);
  await stop(padmin);
  assert.equal((await api(padmin, 'GET', '/api/mcp/catalog')).status, 200);
});

test('every write is refused while viewing as, and the handler never runs', async () => {
  // Baseline: the owner can write alpha's sandbox env when not previewing.
  const base = await api(owner, 'PUT', '/api/apps/alpha/env/sandbox', { vars: { BASELINE: '1' } });
  assert.equal(base.status, 200, JSON.stringify(base.body));

  await start(owner, 'admin', 'alpha');
  const writes = [
    ['PUT', '/api/apps/alpha/env/sandbox', { vars: { BLOCKED: '1' } }],
    ['POST', '/api/apps/alpha/deploy/sandbox', {}],
    ['POST', '/api/apps/alpha/rename', { new_slug: 'alpha-renamed' }],
    ['POST', '/api/coder/alpha/session/s1/dispatch', { text: 'hi' }],
    ['POST', '/api/coder/alpha/session/s1/release', {}],
  ];
  for (const [method, path, body] of writes) {
    const r = await api(owner, method, path, body);
    assert.equal(r.status, 403, `${method} ${path} was not refused: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error.code, 'VIEW_AS_READ_ONLY');
    assert.match(r.body.error.message, /You are viewing as admin on alpha\. Stop viewing as to make changes\./);
  }
  assert.equal(db.prepare("SELECT COUNT(*) n FROM env_vars WHERE key = 'BLOCKED'").get().n, 0);
  assert.ok(db.prepare("SELECT 1 FROM apps WHERE slug = 'alpha'").get(), 'the rename ran');

  // MCP: reads still answer, a write tool is refused with the view-as reason.
  const list = await rpc(owner, 'tools/call', { name: 'appcrane_list_apps', arguments: {} });
  assert.ok(list.body.result, `read tool refused: ${JSON.stringify(list.body)}`);
  const write = await rpc(owner, 'tools/call', { name: 'appcrane_deploy', arguments: { slug: 'alpha', env: 'sandbox' } });
  assert.match(write.body.error?.message || '', /You are viewing as admin on alpha/);
  const tools = await rpc(owner, 'tools/list', {});
  assert.ok(tools.body.result.tools.length > 0);
  assert.ok(!tools.body.result.tools.some(t => t.name === 'appcrane_deploy'), 'a write tool is advertised during view-as');
  await stop(owner);
  const baseTools = await rpc(owner, 'tools/list', {});
  assert.ok(baseTools.body.result.tools.some(t => t.name === 'appcrane_deploy'), 'baseline: the owner sees appcrane_deploy outside view-as');

  // And after stopping, writes work again (the refusal was the preview, not something else).
  const again = await api(owner, 'PUT', '/api/apps/alpha/env/sandbox', { vars: { AFTER: '1' } });
  assert.equal(again.status, 200);
});

test('the audit log records the real person, the target role and the app', async () => {
  db.prepare("DELETE FROM audit_log WHERE action LIKE 'view-as-%'").run();
  await start(owner, 'user', 'alpha');
  await stop(owner);
  const rows = db.prepare("SELECT user_id, app_id, action, detail FROM audit_log WHERE action LIKE 'view-as-%' ORDER BY id").all();
  assert.deepEqual(rows.map(r => [r.user_id, r.app_id, r.action]), [[owner.id, ALPHA, 'view-as-start'], [owner.id, ALPHA, 'view-as-stop']]);
  const d = JSON.parse(rows[0].detail);
  assert.equal(d.target_role, 'user');
  assert.equal(d.app_slug, 'alpha');
  assert.equal(d.real_role, 'user');
});

test('a preview expires, and stop ends it', async () => {
  await start(owner, 'user', 'alpha');
  assert.equal((await api(owner, 'GET', '/api/auth/view-as')).body.active, true);
  db.prepare("UPDATE view_as_sessions SET expires_at = datetime('now','-1 minute')").run();
  assert.equal((await api(owner, 'GET', '/api/auth/view-as')).body.active, false);
  assert.equal((await api(owner, 'GET', '/api/alpha/audit')).status, 200, 'an expired preview still lowered permissions');
  const w = await api(owner, 'PUT', '/api/apps/alpha/env/sandbox', { vars: { EXPIRED_OK: '1' } });
  assert.equal(w.status, 200, 'an expired preview still blocked writes');

  await start(owner, 'user', 'alpha');
  const s = await stop(owner);
  assert.equal(s.body.stopped, true);
  assert.equal(s.body.active, false);
});

test('privileges can never be raised: forged inputs and stale records are refused', async () => {
  // No header names a role.
  const forged = await api(member, 'GET', '/api/alpha/audit', undefined, { 'X-View-As-Role': 'owner', 'X-View-As': 'platform_admin' });
  assert.equal(forged.status, 403);
  // A member cannot view as owner, and a body naming another user changes nothing.
  const raise = await api(member, 'POST', '/api/auth/view-as', { role: 'owner', app_slug: 'alpha', user_id: owner.id });
  assert.equal(raise.status, 403);
  // A row written straight into the table for a role above the real one is ignored and deleted.
  db.prepare("INSERT INTO view_as_sessions (credential_hash, user_id, target_role, app_id, expires_at) VALUES (?, ?, 'owner', ?, datetime('now','+1 hour'))")
    .run(hashApiKey(member.token), member.id, ALPHA);
  assert.equal((await api(member, 'GET', '/api/alpha/audit')).status, 403, 'a planted owner preview raised a member');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM view_as_sessions WHERE user_id = ?').get(member.id).n, 0);
  // An owner demoted mid-preview loses the preview.
  await start(owner, 'admin', 'alpha');
  db.prepare("UPDATE app_user_roles SET app_role = 'user' WHERE app_id = ? AND user_id = ?").run(ALPHA, owner.id);
  assert.equal((await api(owner, 'GET', '/api/auth/view-as')).body.active, false);
  assert.equal((await api(owner, 'GET', '/api/alpha/audit')).status, 403, 'the demoted owner kept an app-admin view');
  db.prepare("UPDATE app_user_roles SET app_role = 'owner' WHERE app_id = ? AND user_id = ?").run(ALPHA, owner.id);
  // A preview belongs to the credential that started it: another session of the same user is unaffected.
  const other = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(owner.id, hashApiKey(other));
  await start(owner, 'user', 'alpha');
  assert.equal((await api({ token: other }, 'GET', '/api/alpha/audit')).status, 200);
  await stop(owner);
});
