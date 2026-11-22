import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Every path that changes one person's AppCrane tier writes through
// applyAppRole (services/appRoleChange.js). Before, the MCP grant / revoke /
// approve tools wrote app_user_roles themselves: grant could demote the only
// owner, and revoke counted a DEACTIVATED owner as an owner, so the one active
// owner could be removed and the app left with nobody who can sign in to own it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-role-shared-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
after(() => rmSync(process.env.DATA_DIR, { recursive: true, force: true }));

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');

let slot = 21000;
const mkApp = (slug) => db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')").run(slug, slug, ++slot).lastInsertRowid;
const mkUser = (name, role = 'user') => {
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)').run(name, `${name}@t.test`, role, hashApiKey(`k-${name}`)).lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
};
const assign = (appId, u, r) => db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?) ON CONFLICT(app_id,user_id) DO UPDATE SET app_role=excluded.app_role').run(appId, u.id, r);
const roleOf = (appId, u) => db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, u.id)?.app_role;

const owner = mkUser('owner');
const gone = mkUser('gone');
const admin = mkUser('admin');
const root = mkUser('root', 'platform_admin');

test('MCP grant cannot demote the only active owner', async () => {
  const app = mkApp('g1');
  assign(app, owner, 'owner');
  await assert.rejects(callTool(owner, 'appcrane_grant_app_access', { slug: 'g1', user: String(owner.id), role: 'user' }), /last owner/);
  await assert.rejects(callTool(root, 'appcrane_grant_app_access', { slug: 'g1', user: String(owner.id), role: 'admin' }), /last owner/);
  assert.equal(roleOf(app, owner), 'owner');
  const ok = await callTool(owner, 'appcrane_grant_app_access', { slug: 'g1', user: String(admin.id), role: 'admin' });
  assert.equal(ok.role ?? JSON.parse(ok.content?.[0]?.text || '{}').role, 'admin');
  assert.equal(roleOf(app, admin), 'admin');
});

test('MCP revoke counts ACTIVE owners: a deactivated co-owner does not keep the app owned', async () => {
  const app = mkApp('r1');
  assign(app, owner, 'owner');
  assign(app, gone, 'owner');
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(gone.id);
  await assert.rejects(callTool(root, 'appcrane_revoke_app_access', { slug: 'r1', user: String(owner.id) }), /last owner/);
  assert.equal(roleOf(app, owner), 'owner');
  db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(gone.id);
  await callTool(root, 'appcrane_revoke_app_access', { slug: 'r1', user: String(gone.id) });
  assert.equal(roleOf(app, gone), undefined, 'with two active owners one may go');
});

test('MCP approve-access writes through the same guard; a refused approval leaves the request open', async () => {
  const app = mkApp('a1');
  assign(app, owner, 'owner');
  const reqId = db.prepare("INSERT INTO enhancement_requests (app_slug,user_id,user_name,message,status,kind) VALUES ('a1',?,?,'Access request for app “a1”','new','access')")
    .run(owner.id, owner.name).lastInsertRowid;
  await assert.rejects(callTool(owner, 'appcrane_approve_access_request', { request_id: Number(reqId), role: 'user' }), /last owner/);
  assert.equal(roleOf(app, owner), 'owner');
  assert.notEqual(db.prepare('SELECT status FROM enhancement_requests WHERE id = ?').get(reqId).status, 'done', 'a refused approval leaves the request open');

  const app2 = mkApp('a2');
  const req2 = db.prepare("INSERT INTO enhancement_requests (app_slug,user_id,user_name,message,status,kind) VALUES ('a2',?,?,'Access request for app “a2”','new','access')")
    .run(admin.id, admin.name).lastInsertRowid;
  await callTool(root, 'appcrane_approve_access_request', { request_id: Number(req2), role: 'owner' });
  assert.equal(roleOf(app2, admin), 'owner');
});
