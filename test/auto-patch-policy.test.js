import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The auto-patch policy toggle: ON by default, platform-admin switch, per-app
// opt-out by the owner or a platform admin, and opt-back-in follows who opted out.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-auto-patch-policy-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getPolicy, setPolicy, effectiveForApp, setAppOptOut } = await import('../server/services/autoPatch/policy.js');

const user = (name, role = 'user') => {
  const id = Number(db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES (?,?,?,1,?, 'human')").run(name, `${name}@acme.test`, role, `h-${name}`).lastInsertRowid);
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
};
const admin = user('admin', 'platform_admin');
const owner = user('owner');
const member = user('member');
const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend) VALUES ('p','p',901,'managed','local')").run().lastInsertRowid);
const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, owner.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, member.id);

test('the platform setting is ON with no row, with a 24h cooldown', () => {
  assert.equal(db.prepare("SELECT COUNT(*) n FROM settings WHERE key = 'auto_approve_rce_fixes'").get().n, 0);
  const p = getPolicy(db);
  assert.equal(p.enabled, true);
  assert.equal(p.cooldown_hours, 24);
  assert.equal(effectiveForApp(db, app).enabled, true);
});

test('only a platform admin changes the platform setting, and it is audited', () => {
  assert.throws(() => setPolicy(db, { enabled: false }, owner), /platform admin/);
  setPolicy(db, { enabled: false, cooldown_hours: 48 }, admin);
  assert.equal(getPolicy(db).enabled, false);
  assert.equal(effectiveForApp(db, app).enabled, false);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'auto-patch-policy-change'").get().n, 1);
  setPolicy(db, { enabled: true, cooldown_hours: 24 }, admin);
  assert.throws(() => setPolicy(db, { cooldown_hours: 500 }, admin), /between/);
});

test('owner opts the app out; a member cannot; the owner can opt back in', () => {
  assert.throws(() => setAppOptOut(db, app, { opted_out: true }, member), /owner or a platform admin/);
  assert.equal(setAppOptOut(db, app, { opted_out: true, reason: 'we patch by hand' }, owner).enabled, false);
  assert.equal(setAppOptOut(db, app, { opted_out: false }, owner).enabled, true);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action IN ('auto-patch-opt-out','auto-patch-opt-in')").get().n, 2);
});

test('a platform admin opt-out can only be reversed by a platform admin', () => {
  setAppOptOut(db, app, { opted_out: true }, admin);
  assert.match(effectiveForApp(db, app).reason, /platform admin/);
  assert.throws(() => setAppOptOut(db, app, { opted_out: false }, owner), /only a platform admin can opt it back in/);
  assert.equal(effectiveForApp(db, app).enabled, false);
  assert.equal(setAppOptOut(db, app, { opted_out: false }, admin).enabled, true);
});
