import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Access to an app is recorded in ONE place: app_user_roles (v2.94.0).
//
// It used to be two tables. app_users said "is a member", app_user_roles said
// "at which tier", and they drifted. Migrations 042/048 and ownerBackfill made
// app creators owners without a membership row, so an owner, shown as owner in
// the Users dialog, was refused their own app's env vars by requireAppUser
// (which read app_users): "Admin access does not include app data/env".
// app_users is now a read-only view of app_user_roles, so the two cannot
// disagree, and nothing can write it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-access1-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const mkUser = (name, role) => db.prepare(
  'INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)'
).run(name, `${name}@t.test`, role, `hash-${name}`).lastInsertRowid;
const mkApp = (slug, slot) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')"
).run(slug, slug, slot).lastInsertRowid;

const { requireAppUser } = await import('../server/middleware/auth.js');
function gate(slug, user) {
  let out = null;
  requireAppUser({ params: { slug }, user }, {}, (err) => { out = err ? err.code : 'allowed'; });
  return out;
}

test('an owner of record can open their own app\'s data and env', () => {
  const OWNER = mkUser('owner', 'platform_admin');
  mkApp('reports', 1);
  // Exactly what ownerBackfill and migrations 042/048 wrote: a role, no membership.
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) SELECT id, ?, 'owner' FROM apps WHERE slug='reports'").run(OWNER);
  assert.equal(gate('reports', { id: OWNER, role: 'platform_admin' }), 'allowed');
});

test('membership is the role table: removing the role removes access', () => {
  const U = mkUser('member', 'user');
  const appId = mkApp('notes', 2);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, U);
  assert.equal(gate('notes', { id: U, role: 'user' }), 'allowed');
  db.prepare('DELETE FROM app_user_roles WHERE app_id = ? AND user_id = ?').run(appId, U);
  assert.equal(gate('notes', { id: U, role: 'user' }), 'FORBIDDEN');
});

test('app_users cannot be written, so a second copy can never drift', () => {
  const U = mkUser('writer', 'user');
  const appId = mkApp('wiki', 3);
  assert.throws(() => db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, U));
});

test('SCIM: a grant recorded before v2.94.0 over hand-made access drops back to plain access', async () => {
  const { reconcileGroupAccess } = await import('../server/services/scimGroupAccess.js');
  const U = mkUser('legacy', 'user');
  const appId = mkApp('legacy-app', 4);
  // Before v2.94.0: the person was a member by hand, and the group raised them
  // to admin. The ledger says SCIM created the role but not the membership.
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'admin')").run(appId, U);
  db.prepare("INSERT INTO scim_group_access (app_id,user_id,app_role,created_membership,created_role) VALUES (?,?,'admin',0,1)").run(appId, U);

  reconcileGroupAccess(db); // no group grants it any more

  assert.equal(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, U)?.app_role, 'user',
    'hand-made access was lost, or the group\'s tier was kept');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM scim_group_access WHERE app_id = ?').get(appId).n, 0);
});
