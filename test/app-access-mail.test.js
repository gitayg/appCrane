import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// App access change e-mail (v2.137.0). Triggers on app_user_roles record every
// change; services/appAccessMail.js mails the person a net change once it has
// settled. Changes are made through the real writers (PUT /api/apps/:slug/roles,
// POST /api/apps, MCP tools, SCIM group reconcile, access-review decisions, app
// deletion) to prove the triggers see them, not only raw INSERTs.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-access-mail-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
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
db.prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { processAppAccessChanges } = await import('../server/services/appAccessMail.js');
const { reconcileGroupAccess } = await import('../server/services/scimGroupAccess.js');
const { setAppRole } = await import('../server/services/accessReviews/decisions.js');
const { deleteApp } = await import('../server/services/appDelete.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');

let seq = 0;
function mkUser({ name, role = 'user', email, active = 1, kind = 'human' } = {}) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name, username, email, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(name || `Person ${n}`, `person${n}`, email === undefined ? `person${n}@t.test` : email, role, hashApiKey(key), active, kind).lastInsertRowid;
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}

const admin = mkUser({ name: 'Ada Admin', role: 'platform_admin' });

function mkApp(slug, name = slug) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'github')").run(name, slug, getNextSlot(db)).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

// Debounce 0: every settled change is due. The debounce has its own test.
const tick = (o = {}) => processAppAccessChanges(db, { debounceSeconds: 0, ...o });
const mails = (u) => db.prepare("SELECT * FROM email_queue WHERE source = 'app-access-change' AND to_email = ? ORDER BY id").all(u.email);
const pending = () => db.prepare('SELECT COUNT(*) n FROM app_access_changes WHERE processed_at IS NULL').get().n;

let server;
let BASE;
before(async () => {
  const api = express();
  api.use(express.json());
  api.use('/api/apps', (await import('../server/routes/apps.js')).default);
  api.use('/api/apps', (await import('../server/routes/users.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  BASE = `http://127.0.0.1:${server.address().port}`;
  tick();
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
const setRole = async (slug, user, role) => {
  const r = await call(admin, 'PUT', `/api/apps/${slug}/roles`, { user_id: user.id, app_role: role });
  assert.equal(r.status, 200, JSON.stringify(r.body));
};

test('a grant (none -> user) through the dashboard route mails the person once, and a second tick sends nothing more', async () => {
  const app = mkApp('am-grant', 'Grant App');
  const u = mkUser({ name: 'Gina' });
  await setRole(app.slug, u, 'user');

  const r = tick();
  assert.equal(r.sent, 1);
  const m = mails(u);
  assert.equal(m.length, 1);
  assert.match(m[0].subject, /^\[AppCrane\] You have been given access to Grant App$/);
  assert.match(m[0].body_text, /Your role: no access -> user/);
  assert.match(m[0].body_text, /A user can open and use the app\./);
  assert.match(m[0].body_text, /Changed by: Ada Admin/, 'the actor comes from the app-set-role audit row');
  assert.match(m[0].body_html, /https:\/\/crane\.test\.local\/launch\/am-grant/);
  assert.equal(m[0].app_id, null);

  assert.deepEqual(tick(), { sent: 0, skipped: 0, failed: 0, waiting: 0 });
  assert.equal(mails(u).length, 1, 'a processed change is never mailed again');
  assert.equal(pending(), 0);
});

test('a role change (user -> admin) mails the new role', async () => {
  const app = mkApp('am-promote', 'Promote App');
  const u = mkUser();
  await setRole(app.slug, u, 'user');
  tick();
  await setRole(app.slug, u, 'admin');
  assert.equal(tick().sent, 1);
  const m = mails(u);
  assert.equal(m.length, 2);
  assert.match(m[1].subject, /Your role on Promote App is now admin/);
  assert.match(m[1].body_text, /Your role: user -> admin/);
  assert.match(m[1].body_text, /An admin can use the app/);
});

test('removal through an access-review decision mails a removal with no link', async () => {
  const app = mkApp('am-remove', 'Remove App');
  const u = mkUser();
  await setRole(app.slug, u, 'user');
  tick();
  await setAppRole(db, app.id, u.id, 'none');
  assert.equal(tick().sent, 1);
  const m = mails(u).at(-1);
  assert.match(m.subject, /Your access to Remove App was removed/);
  assert.match(m.body_text, /Your role: user -> no access/);
  assert.match(m.body_text, /You can no longer open the app\./);
  assert.doesNotMatch(m.body_html, /\/launch\//);
  assert.doesNotMatch(m.body_text, /Open the app/);
});

test('MCP grant names the actor from its audit row', async () => {
  const app = mkApp('am-mcp', 'Mcp App');
  const owner = mkUser({ name: 'Owen Owner' });
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(app.id, owner.id);
  tick();
  const u = mkUser();
  await callTool(owner, 'appcrane_grant_app_access', { slug: app.slug, user: u.email, role: 'user' });
  assert.equal(tick().sent, 1);
  assert.match(mails(u)[0].body_text, /Changed by: Owen Owner/);
});

test('a raw write with no audit row omits who made the change', () => {
  const app = mkApp('am-raw');
  const u = mkUser();
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(app.id, u.id);
  assert.equal(tick().sent, 1);
  assert.doesNotMatch(mails(u)[0].body_text, /Changed by/);
});

test('changes wait for the debounce, and a grant undone inside it sends nothing', async () => {
  const app = mkApp('am-debounce');
  const u = mkUser();
  await setRole(app.slug, u, 'user');
  const early = processAppAccessChanges(db);
  assert.equal(early.sent, 0);
  assert.equal(early.waiting, 1, 'a change younger than the debounce waits');
  assert.equal(mails(u).length, 0);

  await setRole(app.slug, u, 'none');
  assert.equal(processAppAccessChanges(db).waiting, 1);
  const settled = tick();
  assert.equal(settled.sent, 0);
  assert.equal(mails(u).length, 0, 'grant then revoke is no net change');
  assert.equal(pending(), 0, 'the undone pair is marked processed');

  const v = mkUser();
  await setRole(app.slug, v, 'user');
  assert.equal(processAppAccessChanges(db).waiting, 1);
  assert.equal(tick().sent, 1, 'once settled the grant is mailed');
});

test('deleting the app sends nothing, and the cascade still records the change', async () => {
  const app = mkApp('am-delete');
  const u = mkUser();
  await setRole(app.slug, u, 'user');
  await deleteApp(app);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM apps WHERE id = ?').get(app.id).n, 0);
  const rows = db.prepare('SELECT old_role, new_role FROM app_access_changes WHERE app_id = ? AND user_id = ? ORDER BY id').all(app.id, u.id);
  assert.deepEqual(rows.map((r) => `${r.old_role}>${r.new_role}`), ['none>user', 'user>none']);
  tick();
  assert.equal(mails(u).length, 0);

  const app2 = mkApp('am-delete2');
  const v = mkUser();
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(app2.id, v.id);
  tick();
  db.prepare("UPDATE app_user_roles SET app_role = 'admin' WHERE app_id = ? AND user_id = ?").run(app2.id, v.id);
  db.prepare('DELETE FROM apps WHERE id = ?').run(app2.id);
  assert.equal(tick().sent, 0, 'a change to an app deleted before the tick is not mailed');
  assert.equal(mails(v).length, 1, 'only the earlier grant');
});

test('SCIM group grants mail an active human and nobody inactive, without e-mail or non-human', () => {
  const app = mkApp('am-scim');
  const human = mkUser();
  const inactive = mkUser({ active: 0 });
  const noEmail = mkUser({ email: null });
  const agent = mkUser({ kind: 'agent' });
  const g = db.prepare("INSERT INTO scim_groups (display_name) VALUES ('Access Mail Group')").run().lastInsertRowid;
  for (const u of [human, inactive, noEmail, agent]) db.prepare('INSERT INTO scim_group_members (group_id, user_id) VALUES (?, ?)').run(g, u.id);
  db.prepare("INSERT INTO scim_group_app_roles (group_id, app_id, app_role) VALUES (?, ?, 'user')").run(g, app.id);
  reconcileGroupAccess(db);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM app_user_roles WHERE app_id = ?').get(app.id).n, 4, 'SCIM granted all four');

  const r = tick();
  assert.equal(r.sent, 1);
  assert.equal(mails(human).length, 1);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'app-access-change' AND to_email IN (?, ?)").get(inactive.email, agent.email).n, 0);
  assert.equal(pending(), 0, 'skipped people are marked processed');
});

test('the creator owner row at app creation sends nothing; a later owner grant does', async () => {
  const creator = mkUser({ name: 'Cora Creator', role: 'platform_admin' });
  const r = await call(creator, 'POST', '/api/apps', { name: 'Made Here', slug: 'am-made', source_type: 'github', github_url: 'https://github.com/acme-co/made' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  await callTool(creator, 'appcrane_create_app', { name: 'Made Mcp', slug: 'am-made-mcp', github_url: 'https://github.com/acme-co/mcp' });
  assert.equal(db.prepare("SELECT COUNT(*) n FROM app_access_changes WHERE user_id = ? AND new_role = 'owner'").get(creator.id).n, 2);
  tick();
  assert.equal(mails(creator).length, 0, 'the creator is not told they own the app they just created');

  const co = mkUser();
  await setRole('am-made', co, 'owner');
  assert.equal(tick().sent, 1, 'another owner is mailed');

  await setRole('am-made', creator, 'none');
  tick();
  await setRole('am-made', creator, 'owner');
  tick();
  assert.equal(mails(creator).length, 2, 'removal and re-grant of the creator are mailed');
});

test('the platform setting off sends nothing and does not mail those changes later', async () => {
  const app = mkApp('am-off');
  const u = mkUser();
  db.prepare("INSERT INTO settings (key, value) VALUES ('app_access_mail_enabled', '0')").run();
  try {
    await setRole(app.slug, u, 'user');
    assert.equal(tick().sent, 0);
    assert.equal(pending(), 0);
  } finally {
    db.prepare("UPDATE settings SET value = '1' WHERE key = 'app_access_mail_enabled'").run();
  }
  tick();
  assert.equal(mails(u).length, 0);
  await setRole(app.slug, u, 'admin');
  assert.equal(tick().sent, 1, 'on again, the next change is mailed');
});

test('the HTML escapes an app name containing markup', async () => {
  const app = mkApp('am-xss', '<script>alert(1)</script>');
  const u = mkUser();
  await setRole(app.slug, u, 'user');
  tick();
  const m = mails(u)[0];
  assert.ok(m.body_html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!m.body_html.includes('<script>'));
});

test('a queue failure leaves the change for the next tick, and a duplicate key is not sent twice', async () => {
  const app = mkApp('am-retry');
  const u = mkUser();
  await setRole(app.slug, u, 'user');
  db.exec(`CREATE TRIGGER t_fail_access_mail BEFORE INSERT ON email_queue WHEN NEW.source = 'app-access-change'
           BEGIN SELECT RAISE(ABORT, 'queue down'); END`);
  try {
    assert.equal(tick().failed, 1);
  } finally {
    db.exec('DROP TRIGGER t_fail_access_mail');
  }
  assert.equal(pending(), 1, 'the change stays unprocessed');
  assert.equal(tick().sent, 1);
  assert.equal(mails(u).length, 1);

  const v = mkUser();
  await setRole(app.slug, v, 'user');
  const id = db.prepare('SELECT id FROM app_access_changes WHERE processed_at IS NULL').get().id;
  db.prepare("INSERT INTO email_queue (to_email, subject, body_text, idempotency_key, source) VALUES (?, 'earlier', 'x', ?, 'app-access-change')")
    .run(v.email, `app-access-change:${app.id}:${v.id}:${id}-${id}:1`);
  assert.equal(tick().skipped, 1);
  assert.equal(mails(v).length, 1, 'the earlier queued mail only');
  assert.equal(pending(), 0);
});
