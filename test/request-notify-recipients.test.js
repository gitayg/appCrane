import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Who is e-mailed about a new request on an app. Read off the real email_queue,
// because the claim is about who RECEIVES it:
//   - an access request reaches the app's admins only (owners, then platform
//     admins, only when there is no app admin)
//   - every other request reaches the app's owners only (platform admins only
//     when the app has no owner)

const ROOT = mkdtempSync(join(tmpdir(), 'crane-reqnotify-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { notifyAppAdminsOfNewRequest } = await import('../server/services/requestNotify.js');
after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

let seq = 0;
function user(role = 'user') {
  const n = ++seq;
  const email = `p${n}@example.com`;
  const id = db.prepare("INSERT INTO users (name,email,role,active,kind) VALUES (?,?,?,1,'human')").run(`P${n}`, email, role).lastInsertRowid;
  return { id, email };
}
let slot = 700;
function app(slug) {
  return db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')").run(slug, slug, slot++).lastInsertRowid;
}
const role = (appId, u, r) => db.prepare('INSERT OR REPLACE INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, u.id, r);
function request(slug, message, kind = null) {
  return db.prepare("INSERT INTO enhancement_requests (app_slug, user_name, message, status, kind) VALUES (?, 'Requester', ?, 'new', ?)")
    .run(slug, message, kind).lastInsertRowid;
}
const mailedTo = (source) => db.prepare('SELECT to_email FROM email_queue WHERE source = ? ORDER BY to_email').all(source).map((r) => r.to_email).sort();

const platformAdmin = user('platform_admin');
beforeEach(() => db.prepare('DELETE FROM email_queue').run());

test('an access request goes to the app admins only, not the owner or platform admins', () => {
  const id = app('acc');
  const owner = user(); const admin = user(); const member = user();
  role(id, owner, 'owner'); role(id, admin, 'admin'); role(id, member, 'user');
  notifyAppAdminsOfNewRequest(request('acc', 'Access request for app acc', 'access'));
  assert.deepEqual(mailedTo('access-request'), [admin.email]);
});

test('an access request on an app with no admin falls back to its owners', () => {
  const id = app('acc-owner');
  const owner = user(); role(id, owner, 'owner');
  notifyAppAdminsOfNewRequest(request('acc-owner', 'Access request for app acc-owner', 'access'));
  assert.deepEqual(mailedTo('access-request'), [owner.email]);
});

test('an access request on an app with neither falls back to platform admins', () => {
  app('acc-none');
  notifyAppAdminsOfNewRequest(request('acc-none', 'Access request for app acc-none', 'access'));
  assert.deepEqual(mailedTo('access-request'), [platformAdmin.email]);
});

test('any other request goes to the app owners only, not app admins or platform admins', () => {
  const id = app('feat');
  const owner = user(); const admin = user();
  role(id, owner, 'owner'); role(id, admin, 'admin');
  notifyAppAdminsOfNewRequest(request('feat', 'Please add dark mode'));
  assert.deepEqual(mailedTo('new-request'), [owner.email]);
});

test('any other request on an app with no owner falls back to platform admins', () => {
  app('feat-none');
  notifyAppAdminsOfNewRequest(request('feat-none', 'Please add dark mode'));
  assert.deepEqual(mailedTo('new-request'), [platformAdmin.email]);
});
