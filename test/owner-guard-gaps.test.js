import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Required owner, the paths that still had the old last-owner guard (which
// counted deactivated owners) and no immediate orphan check: PUT
// /api/apps/:slug/users, and the MCP tools appcrane_revoke_app_access,
// appcrane_grant_app_access and appcrane_approve_access_request. Plus the SCIM
// interplay: an owner who accepted (or was assigned) ownership is no longer the
// group reconciler's row, so removing the group does not re-orphan the app.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-owner-gaps-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

const SHIM_DIR = join(ROOT, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
writeFileSync(join(SHIM_DIR, 'caddy'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { checkAppOwnership } = await import('../server/services/appOwnership.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const { callTool } = await import('../server/services/mcpTools.js');

let seq = 0;
function mkUser({ role = 'user' } = {}) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name, username, email, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, ?)')
    .run(`Gap Person ${n}`, `gap${n}`, `gap${n}@t.test`, role, hashApiKey(key), 'human').lastInsertRowid;
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
function mkApp(slug) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'github')").run(`App ${slug}`, slug, getNextSlot(db)).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const grant = (app, u, role) => db.prepare(`INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
  ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role`).run(app.id, u.id, role);
const roleOf = (app, u) => db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, u.id)?.app_role ?? null;
const openOrphanRow = (app) => db.prepare('SELECT * FROM app_owner_orphans WHERE app_id = ? AND resolved_at IS NULL').get(app.id);
const deactivate = (u) => db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(u.id);
const asUser = (u) => db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);

const PA = mkUser({ role: 'platform_admin' });
const SCIM_TOKEN = generateApiKey('scim');
const setSetting = (k, v) => db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
setSetting('scim_token_hash', hashApiKey(SCIM_TOKEN));
setSetting('scim_enabled', '1');

let server;
let BASE;
before(async () => {
  checkAppOwnership(db);
  const api = express();
  api.use(express.json({ type: ['application/json', 'application/scim+json'] }));
  const scim = await import('../server/routes/scim.js');
  api.use('/api/scim/v2', scim.default);
  api.use('/api/auth/scim', scim.scimAdminRouter);
  api.use('/api/apps', (await import('../server/routes/apps.js')).default);
  api.use('/api', (await import('../server/routes/appOwnership.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  BASE = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  server?.closeAllConnections?.();
  server?.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker?.();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function call(who, method, path, body) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': who.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}
async function scim(method, path, body) {
  const r = await fetch(`${BASE}/api/scim/v2${path}`, {
    method,
    headers: { Authorization: `Bearer ${SCIM_TOKEN}`, 'Content-Type': 'application/scim+json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}

// --- PUT /api/apps/:slug/users -------------------------------------------

test('PUT /:slug/users refuses a list that keeps only a deactivated owner and drops the one active owner', async () => {
  const app = mkApp('gap-list-active');
  const active = mkUser(); const gone = mkUser(); const member = mkUser();
  grant(app, active, 'owner'); grant(app, gone, 'owner'); grant(app, member, 'user');
  deactivate(gone);
  checkAppOwnership(db);
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}/users`, { user_ids: [gone.id, member.id] });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'LAST_OWNER');
  assert.equal(roleOf(app, active), 'owner');
  assert.equal(openOrphanRow(app), undefined);
});

test('PUT /:slug/users may drop a deactivated owner of an already-orphaned app; the orphan stays open', async () => {
  const app = mkApp('gap-list-inactive');
  const gone = mkUser(); const member = mkUser();
  grant(app, gone, 'owner'); grant(app, member, 'user');
  checkAppOwnership(db);
  deactivate(gone);
  checkAppOwnership(db);
  const orphan = openOrphanRow(app);
  assert.ok(orphan);
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}/users`, { user_ids: [member.id] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(roleOf(app, gone), null);
  assert.equal(openOrphanRow(app).id, orphan.id);
});

test('PUT /:slug/users records an ownerless app at once, attributed to the member-list write', async () => {
  const app = mkApp('gap-list-immediate');
  const gone = mkUser(); const member = mkUser();
  grant(app, gone, 'owner');
  checkAppOwnership(db);
  deactivate(gone);
  assert.equal(openOrphanRow(app), undefined, 'no sweep has run since the owner went');
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}/users`, { user_ids: [gone.id, member.id] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const row = openOrphanRow(app);
  assert.ok(row, 'flagged without waiting for the sweep');
  assert.equal(row.cause, 'member-list');
});

// --- MCP tools -----------------------------------------------------------

test('appcrane_revoke_app_access refuses to remove the one active owner next to a deactivated owner', async () => {
  const app = mkApp('gap-mcp-revoke');
  const active = mkUser(); const gone = mkUser();
  grant(app, active, 'owner'); grant(app, gone, 'owner');
  deactivate(gone);
  checkAppOwnership(db);
  await assert.rejects(
    callTool(asUser(PA), 'appcrane_revoke_app_access', { slug: app.slug, user: String(active.id) }),
    /last owner/,
  );
  assert.equal(roleOf(app, active), 'owner');
  assert.equal(openOrphanRow(app), undefined);
});

test('appcrane_revoke_app_access records an ownerless app at once with cause mcp-revoke', async () => {
  const app = mkApp('gap-mcp-revoke-now');
  const gone = mkUser(); const member = mkUser();
  grant(app, gone, 'owner'); grant(app, member, 'user');
  checkAppOwnership(db);
  deactivate(gone);
  await callTool(asUser(PA), 'appcrane_revoke_app_access', { slug: app.slug, user: String(member.id) });
  assert.equal(roleOf(app, member), null);
  assert.equal(openOrphanRow(app)?.cause, 'mcp-revoke');
});

test('appcrane_grant_app_access cannot demote the last active owner', async () => {
  const app = mkApp('gap-mcp-demote');
  const owner = mkUser();
  grant(app, owner, 'owner');
  checkAppOwnership(db);
  await assert.rejects(
    callTool(asUser(owner), 'appcrane_grant_app_access', { slug: app.slug, user: String(owner.id), role: 'user' }),
    /last owner/,
  );
  assert.equal(roleOf(app, owner), 'owner');
  assert.equal(openOrphanRow(app), undefined);
});

test('appcrane_grant_app_access of owner on an orphaned app resolves the orphan at once', async () => {
  const app = mkApp('gap-mcp-restore');
  const gone = mkUser(); const heir = mkUser();
  grant(app, gone, 'owner');
  checkAppOwnership(db);
  deactivate(gone);
  checkAppOwnership(db);
  assert.ok(openOrphanRow(app));
  await callTool(asUser(PA), 'appcrane_grant_app_access', { slug: app.slug, user: String(heir.id), role: 'owner' });
  assert.equal(openOrphanRow(app), undefined);
  const row = db.prepare('SELECT * FROM app_owner_orphans WHERE app_id = ?').get(app.id);
  assert.equal(row.resolution, 'owner-restored');
  assert.equal(row.resolved_by, PA.id);
});

test('appcrane_approve_access_request cannot demote the last active owner to the requested role', async () => {
  const app = mkApp('gap-mcp-approve');
  const owner = mkUser();
  grant(app, owner, 'owner');
  checkAppOwnership(db);
  const reqId = db.prepare(`INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status)
                            VALUES (?, ?, 'owner', 'Access request for app x', 'new')`).run(app.slug, owner.id).lastInsertRowid;
  await assert.rejects(
    callTool(asUser(PA), 'appcrane_approve_access_request', { request_id: Number(reqId), role: 'user' }),
    /last owner/,
  );
  assert.equal(roleOf(app, owner), 'owner');
});

// --- SCIM group x ownership transfer -------------------------------------

async function groupGranting(app, member, name, appRole = 'user') {
  const g = await scim('POST', '/Groups', { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'], displayName: name, members: [{ value: String(member.id) }] });
  assert.equal(g.status, 201, JSON.stringify(g.body));
  const map = await call(PA, 'PUT', `/api/auth/scim/groups/${g.body.id}/apps`, { apps: [{ slug: app.slug, app_role: appRole }] });
  assert.equal(map.status, 200, JSON.stringify(map.body));
  return g.body.id;
}
const removeMember = (gid, u) => scim('PATCH', `/Groups/${gid}`, {
  schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
  Operations: [{ op: 'remove', path: `members[value eq "${u.id}"]` }],
});

function orphaned(slug) {
  const app = mkApp(slug);
  const gone = mkUser();
  grant(app, gone, 'owner');
  checkAppOwnership(db);
  deactivate(gone);
  checkAppOwnership(db);
  assert.ok(openOrphanRow(app));
  return app;
}

test('a group-granted member who accepts ownership keeps it when the IdP group is removed', async () => {
  const app = orphaned('gap-scim-accept');
  const nominee = mkUser();
  const gid = await groupGranting(app, nominee, 'gap-accept-group');
  assert.equal(roleOf(app, nominee), 'user');

  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  assert.equal(n.status, 201, JSON.stringify(n.body));
  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.equal(roleOf(app, nominee), 'owner');

  const rm = await removeMember(gid, nominee);
  assert.ok(rm.status === 200 || rm.status === 204, JSON.stringify(rm.body));
  assert.equal(roleOf(app, nominee), 'owner', 'the group no longer owns this row');
  assert.equal(openOrphanRow(app), undefined, 'the app is not re-orphaned');
  assert.equal(db.prepare('SELECT 1 FROM scim_group_access WHERE app_id = ? AND user_id = ?').get(app.id, nominee.id), undefined);
});

test('a group-granted member assigned as owner is not demoted when the group re-tiers to admin', async () => {
  const app = orphaned('gap-scim-assign');
  const heir = mkUser();
  const gid = await groupGranting(app, heir, 'gap-assign-group');
  const a = await call(PA, 'POST', `/api/apps/${app.slug}/owner`, { user_id: heir.id });
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.equal(roleOf(app, heir), 'owner');

  const map = await call(PA, 'PUT', `/api/auth/scim/groups/${gid}/apps`, { apps: [{ slug: app.slug, app_role: 'admin' }] });
  assert.equal(map.status, 200, JSON.stringify(map.body));
  assert.equal(roleOf(app, heir), 'owner');
  assert.equal(openOrphanRow(app), undefined);
});
