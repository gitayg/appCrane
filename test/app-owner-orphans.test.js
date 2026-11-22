import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import Database from 'better-sqlite3';

// Required owner (migration 176): an app whose last active owner leaves is
// flagged orphaned once, platform admins and the app's admins are mailed once,
// and a nominated person accepts (or declines) to become the new owner.
// Every change goes through the real routers: SCIM, PUT /roles, the ownership
// routes.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-owner-orphans-'));
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

let seq = 0;
function mkUser({ name, role = 'user', kind = 'human', email } = {}) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name, username, email, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, ?)')
    .run(name || `Person ${n}`, `owner${n}`, email === undefined ? `owner${n}@t.test` : email, role, hashApiKey(key), kind).lastInsertRowid;
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
const ownerMails = (u) => db.prepare("SELECT * FROM email_queue WHERE source = 'app-owner' AND to_email = ? ORDER BY id").all(u.email);

const PA = mkUser({ name: 'Pat Platform', role: 'platform_admin' });

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
  api.use('/api/apps', (await import('../server/routes/users.js')).default);
  api.use('/api/users', (await import('../server/routes/users.js')).default);
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
const deprovision = (u) => scim('PATCH', `/Users/${u.id}`, {
  schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
  Operations: [{ op: 'replace', path: 'active', value: false }],
});

test('SCIM deprovision of the last owner orphans the app, audits it and mails platform admins and app admins once', async () => {
  const app = mkApp('oo-last');
  const owner = mkUser({ name: 'Olive Owner' });
  const appAdmin = mkUser({ name: 'Adam AppAdmin' });
  const member = mkUser({ name: 'Mia Member' });
  grant(app, owner, 'owner'); grant(app, appAdmin, 'admin'); grant(app, member, 'user');
  checkAppOwnership(db);
  assert.equal(openOrphanRow(app), undefined);

  const r = await deprovision(owner);
  assert.equal(r.status, 200, JSON.stringify(r.body));

  const row = openOrphanRow(app);
  assert.ok(row, 'the app is flagged orphaned');
  assert.equal(row.cause, 'scim-user-deprovision');
  assert.deepEqual(JSON.parse(row.detail), { reason: 'owner-deactivated', former_owner_ids: [owner.id] });
  assert.ok(row.orphaned_at);
  assert.match(row.notify_note, /^mailed /);

  const paMail = ownerMails(PA).filter((m) => m.subject.includes(app.name));
  const adminMail = ownerMails(appAdmin).filter((m) => m.subject.includes(app.name));
  assert.equal(paMail.length, 1);
  assert.equal(adminMail.length, 1);
  assert.equal(paMail[0].subject, `[AppCrane] ${app.name} has no owner`);
  assert.match(paMail[0].body_text, /its owner was deactivated/);
  assert.match(paMail[0].body_text, /Detected by: scim-user-deprovision/);
  assert.equal(ownerMails(member).length, 0, 'a plain member is not mailed');

  const audit = db.prepare("SELECT * FROM audit_log WHERE action = 'app-owner-orphaned' AND app_id = ?").all(app.id);
  assert.equal(audit.length, 1);

  checkAppOwnership(db);
  checkAppOwnership(db);
  assert.equal(ownerMails(PA).filter((m) => m.subject.includes(app.name)).length, 1, 'later sweeps send nothing more');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_owner_orphans WHERE app_id = ?').get(app.id).n, 1);
});

test('SCIM deprovision of an owner who is not the last active owner does not orphan the app', async () => {
  const app = mkApp('oo-notlast');
  const a = mkUser(); const b = mkUser();
  grant(app, a, 'owner'); grant(app, b, 'owner');
  checkAppOwnership(db);
  const before = db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'app-owner'").get().n;
  const r = await deprovision(a);
  assert.equal(r.status, 200);
  assert.equal(openOrphanRow(app), undefined);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'app-owner'").get().n, before);
});

test('SCIM DELETE of the only owner orphans the app with reason owner-deleted', async () => {
  const app = mkApp('oo-deleted');
  const owner = mkUser();
  grant(app, owner, 'owner');
  checkAppOwnership(db);
  const r = await scim('DELETE', `/Users/${owner.id}`);
  assert.equal(r.status, 204);
  const row = openOrphanRow(app);
  assert.ok(row);
  assert.equal(row.cause, 'scim-user-delete');
  assert.equal(JSON.parse(row.detail).reason, 'owner-deleted');
});

test('a platform admin deleting the only owner through DELETE /api/users/:id orphans the app', async () => {
  const app = mkApp('oo-userdel');
  const owner = mkUser();
  grant(app, owner, 'owner');
  checkAppOwnership(db);
  const r = await call(PA, 'DELETE', `/api/users/${owner.id}`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const row = openOrphanRow(app);
  assert.ok(row);
  assert.equal(row.cause, 'user-delete');
  assert.equal(JSON.parse(row.detail).reason, 'owner-deleted');
  assert.equal(db.prepare("SELECT user_id FROM audit_log WHERE action = 'app-owner-orphaned' AND app_id = ?").get(app.id).user_id, PA.id);
});

test('SCIM group removal of the group-granted only owner orphans the app', async () => {
  const app = mkApp('oo-group');
  const owner = mkUser();
  const g = await scim('POST', '/Groups', { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'], displayName: 'oo-owners', members: [{ value: String(owner.id) }] });
  assert.equal(g.status, 201, JSON.stringify(g.body));
  const map = await call(PA, 'PUT', `/api/auth/scim/groups/${g.body.id}/apps`, { apps: [{ slug: app.slug, app_role: 'owner' }] });
  assert.equal(map.status, 200, JSON.stringify(map.body));
  assert.equal(roleOf(app, owner), 'owner');
  assert.equal(openOrphanRow(app), undefined);

  const rm = await scim('PATCH', `/Groups/${g.body.id}`, {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{ op: 'remove', path: `members[value eq "${owner.id}"]` }],
  });
  assert.ok(rm.status === 200 || rm.status === 204, JSON.stringify(rm.body));
  assert.equal(roleOf(app, owner), null);
  const row = openOrphanRow(app);
  assert.ok(row);
  assert.equal(row.cause, 'scim-group');
  assert.equal(JSON.parse(row.detail).reason, 'owner-removed');
});

function orphanedApp(slug) {
  const app = mkApp(slug);
  const gone = mkUser();
  grant(app, gone, 'owner');
  checkAppOwnership(db);
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(gone.id);
  checkAppOwnership(db);
  assert.ok(openOrphanRow(app));
  return app;
}

test('nomination -> accept: the nominee is mailed, becomes owner, and the orphan flag clears', async () => {
  const app = orphanedApp('oo-accept');
  const nominee = mkUser({ name: 'Nina Nominee' });

  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id, note: 'please' });
  assert.equal(n.status, 201, JSON.stringify(n.body));
  assert.equal(n.body.transfer.kind, 'orphan');
  assert.equal(n.body.transfer.status, 'pending');
  const mail = ownerMails(nominee);
  assert.equal(mail.length, 1);
  assert.equal(mail[0].subject, `[AppCrane] You were asked to own ${app.name}`);
  assert.match(mail[0].body_text, /https:\/\/crane\.test\.local\/owner-transfers/);

  const mine = await call(nominee, 'GET', '/api/owner-transfers/mine');
  assert.equal(mine.status, 200);
  assert.deepEqual(mine.body.transfers.map((t) => t.id), [n.body.transfer.id]);

  const own = await call(PA, 'GET', `/api/apps/${app.slug}/ownership`);
  assert.equal(own.body.orphaned, true);
  assert.equal(own.body.pending_transfer.nominee.id, nominee.id);

  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.equal(a.body.transfer.status, 'accepted');
  assert.equal(roleOf(app, nominee), 'owner');
  assert.equal(openOrphanRow(app), undefined);
  const resolved = db.prepare('SELECT * FROM app_owner_orphans WHERE app_id = ?').get(app.id);
  assert.equal(resolved.resolution, 'transfer-accepted');
  assert.equal(resolved.resolved_by, nominee.id);
  assert.equal(ownerMails(PA).filter((m) => m.subject === `[AppCrane] ${app.name} has a new owner`).length, 1);

  const again = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(again.status, 409);
});

test('decline: the nomination closes, the app stays orphaned, and a new nomination is possible', async () => {
  const app = orphanedApp('oo-decline');
  const nominee = mkUser();
  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  assert.equal(n.status, 201);
  const dup = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: mkUser().id });
  assert.equal(dup.status, 409);
  assert.equal(dup.body.error.code, 'TRANSFER_PENDING');

  const d = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/decline`);
  assert.equal(d.status, 200);
  assert.equal(d.body.transfer.status, 'declined');
  assert.equal(roleOf(app, nominee), null);
  assert.ok(openOrphanRow(app), 'still orphaned');
  const byEmail = mkUser();
  const n2 = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { email: byEmail.email.toUpperCase() });
  assert.equal(n2.status, 201, JSON.stringify(n2.body));
  assert.equal(n2.body.transfer.nominee.id, byEmail.id);
});

test('nobody but the nominee can accept or decline, and a non-admin member cannot nominate', async () => {
  const app = orphanedApp('oo-authz');
  const member = mkUser(); grant(app, member, 'user');
  const outsider = mkUser();
  const nominee = mkUser();

  const m = await call(member, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: member.id });
  assert.equal(m.status, 403);
  const probe = await call(member, 'POST', `/api/apps/${app.slug}/owner-transfers`, { email: 'nobody@nowhere.test' });
  assert.equal(probe.status, 403, 'refused before the nominee is looked up, so it reveals nothing about who exists');
  const o = await call(outsider, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: outsider.id });
  assert.equal(o.status, 403);

  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  assert.equal(n.status, 201);
  const id = n.body.transfer.id;
  for (const who of [outsider, member, PA]) {
    const a = await call(who, 'POST', `/api/owner-transfers/${id}/accept`);
    assert.equal(a.status, 404, `${who.name} must not accept for the nominee`);
    const d = await call(who, 'POST', `/api/owner-transfers/${id}/decline`);
    assert.equal(d.status, 404);
  }
  assert.equal(db.prepare('SELECT status FROM app_owner_transfers WHERE id = ?').get(id).status, 'pending');
  assert.equal(roleOf(app, outsider), null);
  assert.ok(openOrphanRow(app));

  const c = await call(outsider, 'POST', `/api/apps/${app.slug}/owner-transfers/${id}/cancel`);
  assert.equal(c.status, 403);
  const c2 = await call(member, 'POST', `/api/apps/${app.slug}/owner-transfers/${id}/cancel`);
  assert.equal(c2.status, 403);
  const c3 = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers/${id}/cancel`);
  assert.equal(c3.status, 200);
  assert.equal(c3.body.transfer.status, 'cancelled');
});

test('an app admin can nominate someone else while the app is orphaned, never themselves, and not when it has an owner', async () => {
  const app = orphanedApp('oo-appadmin');
  const appAdmin = mkUser(); grant(app, appAdmin, 'admin');
  const self = await call(appAdmin, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: appAdmin.id });
  assert.equal(self.status, 403);
  assert.equal(self.body.error.code, 'SELF_NOMINATION');
  const other = mkUser();
  const ok = await call(appAdmin, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: other.id });
  assert.equal(ok.status, 201, JSON.stringify(ok.body));

  const owned = mkApp('oo-appadmin-owned');
  const owner = mkUser(); grant(owned, owner, 'owner');
  const admin2 = mkUser(); grant(owned, admin2, 'admin');
  const r = await call(admin2, 'POST', `/api/apps/${owned.slug}/owner-transfers`, { user_id: mkUser().id });
  assert.equal(r.status, 403);
});

test('handover: an owner nominates a successor and steps down to admin on acceptance', async () => {
  const app = mkApp('oo-handover');
  const owner = mkUser(); grant(app, owner, 'owner');
  checkAppOwnership(db);
  const next = mkUser();
  const agent = mkUser({ kind: 'agent' });
  const bad = await call(owner, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: agent.id });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error.code, 'NOMINEE_NOT_HUMAN');
  const n = await call(owner, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: next.id, step_down: true });
  assert.equal(n.status, 201, JSON.stringify(n.body));
  assert.equal(n.body.transfer.kind, 'handover');
  const a = await call(next, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 200);
  assert.equal(roleOf(app, next), 'owner');
  assert.equal(roleOf(app, owner), 'admin');
  assert.equal(openOrphanRow(app), undefined);
});

test('a platform admin assigns an owner directly; nobody else can', async () => {
  const app = orphanedApp('oo-assign');
  const appAdmin = mkUser(); grant(app, appAdmin, 'admin');
  const target = mkUser();
  const pend = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: mkUser().id });
  assert.equal(pend.status, 201);

  const denied = await call(appAdmin, 'POST', `/api/apps/${app.slug}/owner`, { user_id: appAdmin.id });
  assert.equal(denied.status, 403);
  assert.equal(roleOf(app, appAdmin), 'admin');

  const r = await call(PA, 'POST', `/api/apps/${app.slug}/owner`, { user_id: target.id });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(roleOf(app, target), 'owner');
  assert.equal(openOrphanRow(app), undefined);
  assert.equal(db.prepare('SELECT resolution FROM app_owner_orphans WHERE app_id = ?').get(app.id).resolution, 'assigned');
  assert.equal(db.prepare('SELECT status FROM app_owner_transfers WHERE id = ?').get(pend.body.transfer.id).status, 'superseded');
});

test('the orphaned-apps list is for platform admins only and shows age; ownership needs app access', async () => {
  const app = orphanedApp('oo-list');
  db.prepare("UPDATE app_owner_orphans SET orphaned_at = datetime('now', '-3 days') WHERE app_id = ? AND resolved_at IS NULL").run(app.id);
  const outsider = mkUser();
  const no = await call(outsider, 'GET', '/api/admin/orphaned-apps');
  assert.equal(no.status, 403);
  const yes = await call(PA, 'GET', '/api/admin/orphaned-apps');
  assert.equal(yes.status, 200);
  const entry = yes.body.apps.find((a) => a.slug === app.slug);
  assert.ok(entry);
  assert.equal(entry.age_days, 3);
  assert.equal(entry.detail.reason, 'owner-deactivated');
  assert.ok(!yes.body.apps.some((a) => a.slug === 'oo-accept'), 'a resolved app is not listed');

  const own = await call(outsider, 'GET', `/api/apps/${app.slug}/ownership`);
  assert.equal(own.status, 403);
});

test('the last-owner guard counts active owners: the one active owner cannot be demoted next to an inactive one', async () => {
  const app = mkApp('oo-guard');
  const active = mkUser(); const inactive = mkUser();
  grant(app, active, 'owner'); grant(app, inactive, 'owner');
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(inactive.id);
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}/roles`, { user_id: active.id, app_role: 'admin' });
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, 'LAST_OWNER');
  assert.equal(roleOf(app, active), 'owner');
});

test('an owner granted by any other path (PUT /roles) resolves the orphan; deleting an orphaned app resolves it as app-deleted', async () => {
  const app = orphanedApp('oo-restored');
  const next = mkUser();
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}/roles`, { user_id: next.id, app_role: 'owner' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(openOrphanRow(app), undefined);
  const row = db.prepare('SELECT * FROM app_owner_orphans WHERE app_id = ?').get(app.id);
  assert.equal(row.resolution, 'owner-restored');
  assert.equal(row.resolved_by, PA.id);

  const gone = orphanedApp('oo-gone');
  db.prepare('DELETE FROM apps WHERE id = ?').run(gone.id);
  checkAppOwnership(db);
  assert.equal(db.prepare('SELECT resolution FROM app_owner_orphans WHERE app_id = ?').get(gone.id).resolution, 'app-deleted');
});

const statusOf = (id) => db.prepare('SELECT status FROM app_owner_transfers WHERE id = ?').get(id).status;

test('an orphan nomination is superseded when the orphan resolves another way, and can no longer be accepted', async () => {
  const app = orphanedApp('oo-stale-orphan');
  const nominee = mkUser();
  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  assert.equal(n.status, 201);
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}/roles`, { user_id: mkUser().id, app_role: 'owner' });
  assert.equal(r.status, 200);
  assert.equal(statusOf(n.body.transfer.id), 'superseded', 'resolving the orphan supersedes its pending nomination');
  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 409);
  assert.equal(roleOf(app, nominee), null);
});

test('accept re-checks the orphan itself: a pending orphan nomination on an app that has an owner again is refused', async () => {
  const app = orphanedApp('oo-stale-orphan2');
  const nominee = mkUser();
  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  db.prepare("UPDATE app_owner_orphans SET resolved_at = datetime('now'), resolution = 'test' WHERE app_id = ? AND resolved_at IS NULL").run(app.id);
  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 409);
  assert.equal(a.body.error.code, 'TRANSFER_STALE');
  assert.match(a.body.error.message, /has an owner again/);
  assert.equal(statusOf(n.body.transfer.id), 'superseded');
  assert.equal(roleOf(app, nominee), null);
});

test('a nomination by an app admin who has since been demoted is refused and superseded', async () => {
  const app = orphanedApp('oo-stale-admin');
  const appAdmin = mkUser(); grant(app, appAdmin, 'admin');
  const nominee = mkUser();
  const n = await call(appAdmin, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  assert.equal(n.status, 201);
  const d = await call(PA, 'PUT', `/api/apps/${app.slug}/roles`, { user_id: appAdmin.id, app_role: 'user' });
  assert.equal(d.status, 200);
  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 409);
  assert.equal(a.body.error.code, 'TRANSFER_STALE');
  assert.equal(statusOf(n.body.transfer.id), 'superseded');
  assert.equal(roleOf(app, nominee), null);
  assert.ok(openOrphanRow(app));
});

test('a handover whose nominator is no longer an owner is refused', async () => {
  const app = mkApp('oo-stale-handover');
  const a1 = mkUser(); const a2 = mkUser();
  grant(app, a1, 'owner'); grant(app, a2, 'owner');
  checkAppOwnership(db);
  const nominee = mkUser();
  const n = await call(a1, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  assert.equal(n.status, 201);
  const d = await call(a2, 'PUT', `/api/apps/${app.slug}/roles`, { user_id: a1.id, app_role: 'admin' });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 409);
  assert.equal(a.body.error.code, 'TRANSFER_STALE');
  assert.equal(statusOf(n.body.transfer.id), 'superseded');
  assert.equal(roleOf(app, nominee), null);
});

test('a nominee who has become an agent identity cannot accept', async () => {
  const app = orphanedApp('oo-stale-nominee');
  const nominee = mkUser();
  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  db.prepare("UPDATE users SET kind = 'agent' WHERE id = ?").run(nominee.id);
  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 409);
  assert.equal(a.body.error.code, 'TRANSFER_STALE');
  assert.equal(roleOf(app, nominee), null);
});

test('an expired nomination cannot be accepted', async () => {
  const app = orphanedApp('oo-expired');
  const nominee = mkUser();
  const n = await call(PA, 'POST', `/api/apps/${app.slug}/owner-transfers`, { user_id: nominee.id });
  db.prepare("UPDATE app_owner_transfers SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(n.body.transfer.id);
  const a = await call(nominee, 'POST', `/api/owner-transfers/${n.body.transfer.id}/accept`);
  assert.equal(a.status, 409);
  assert.equal(a.body.error.code, 'EXPIRED');
  assert.equal(roleOf(app, nominee), null);
});

test('migration 176 on an existing database records apps already without an active owner, without mailing', () => {
  const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');
  const files = readdirSync(DIR).filter((f) => f.endsWith('.sql')).sort();
  const old = new Database(':memory:');
  for (const f of files) { if (f >= '176-') break; old.exec(readFileSync(join(DIR, f), 'utf8')); }
  for (let i = 1; i <= 3; i++) old.prepare('INSERT INTO users (id,name,email,role,api_key_hash,active) VALUES (?,?,?,?,?,?)').run(i, `u${i}`, `u${i}@t.test`, 'user', `h${i}`, i === 2 ? 0 : 1);
  old.prepare("INSERT INTO apps (id,name,slug,slot,source_type) VALUES (1,'owned','owned',1,'managed'), (2,'inactive','inactive',2,'managed'), (3,'none','none',3,'managed')").run();
  old.prepare("INSERT INTO app_user_roles VALUES (1,1,'owner'), (2,2,'owner'), (3,3,'admin')").run();
  old.exec(readFileSync(join(DIR, files.find((f) => f.startsWith('176-'))), 'utf8'));
  const rows = old.prepare('SELECT app_id, cause, notified_at FROM app_owner_orphans ORDER BY app_id').all();
  assert.deepEqual(rows.map((r) => [r.app_id, r.cause]), [[2, 'present-at-upgrade'], [3, 'present-at-upgrade']]);
  assert.ok(rows.every((r) => r.notified_at), 'marked so the sweep does not mail them');
  assert.equal(old.prepare('SELECT COUNT(*) n FROM email_queue').get().n, 0);
  assert.equal(old.prepare("SELECT COUNT(*) n FROM app_owner_transfers").get().n, 0);
});
