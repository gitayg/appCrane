import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Tasks: hosted apps assign work to people, one inbox per person.
//   - the app is identified by its service token only, and only touches its own tasks;
//   - requester and assignee must be active users with access to the app;
//   - assignee comments and moves status, requester also deletes, everyone else gets 404;
//   - the inbox spans apps and filters; one e-mail per event and recipient;
//   - input is plain text, validated, and escaped where AppCrane renders it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tasks-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, { role = 'user', active = 1 } = {}) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,?,'human')")
    .run(name, `${name.toLowerCase()}@example.com`, role, hashApiKey(key), active).lastInsertRowid;
  return { id: Number(id), name, email: `${name.toLowerCase()}@example.com`, key };
}
let slot = 1;
function mkApp(slug) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug.toUpperCase(), slug, slot++).lastInsertRowid);
  return { id, slug };
}
const grant = (app, u, role = 'user') => db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(app.id, u.id, role);

const dana = mkUser('Dana');      // requester
const lior = mkUser('Lior');      // assignee
const sam = mkUser('Sam');        // another member of the app
const out = mkUser('Outsider');   // no access to the app
const gone = mkUser('Gone', { active: 0 });
const admin = mkUser('Admin', { role: 'platform_admin' });

const crm = mkApp('crm');
const hr = mkApp('hr');
for (const u of [dana, lior, sam, gone]) grant(crm, u);
grant(hr, dana); grant(hr, lior);

const { issueServiceToken } = await import('../server/services/appServiceToken.js');
let crmToken = issueServiceToken(crm.id);
const hrToken = issueServiceToken(hr.id);

const tasksServiceRoutes = (await import('../server/routes/tasksService.js')).default;
const tasksRoutes = (await import('../server/routes/tasks.js')).default;
const crewRoutes = (await import('../server/routes/crew.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/service/tasks', tasksServiceRoutes);
api.use('/api/tasks', tasksRoutes);
api.use('/api/crew', crewRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); });

async function call(method, path, { headers = {}, body } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
const asApp = (token, method, path, body) => call(method, `/api/service/tasks${path}`, { headers: { 'X-AppCrane-Service-Token': token }, body });
const asUser = (u, method, path, body) => call(method, `/api/tasks${path}`, { headers: { 'X-API-Key': u.key }, body });
const mails = (u) => db.prepare("SELECT * FROM email_queue WHERE source = 'tasks' AND to_email = ? ORDER BY id").all(u.email);

let t1;
test('the app creates a task for its own app with its service token', async () => {
  const r = await asApp(crmToken, 'POST', '/', {
    subject: 'Approve the Q3 invoice', body: 'Line 1\nLine 2', requester_user_id: dana.id, assignee_email: lior.email,
    due_date: '2026-11-01', external_ref: 'inv-42', url: 'https://crm.example.com/inv/42',
  });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  t1 = r.body.task;
  assert.match(t1.id, /^[A-Za-z0-9_-]{22}$/, 'opaque id');
  assert.equal(t1.app.slug, 'crm');
  assert.equal(t1.status, 'open');
  assert.equal(t1.requester.id, dana.id);
  assert.equal(t1.assignee.id, lior.id);
  assert.equal(t1.body, 'Line 1\nLine 2');
  const row = db.prepare('SELECT app_id FROM tasks WHERE id = ?').get(t1.id);
  assert.equal(row.app_id, crm.id);
});

test('the app is identified by its token only: no token, a bad token, or a proxied request are refused', async () => {
  assert.equal((await call('GET', '/api/service/tasks')).status, 401);
  assert.equal((await asApp('nope', 'GET', '/')).status, 401);
  const proxied = await call('GET', '/api/service/tasks', { headers: { 'X-AppCrane-Service-Token': crmToken, 'X-Forwarded-For': '203.0.113.9' } });
  assert.equal(proxied.status, 403);
  assert.equal(proxied.body.error.code, 'NOT_INTERNAL');
});

test("another app's token cannot see, comment on, move or delete crm's task", async () => {
  assert.equal((await asApp(hrToken, 'GET', `/${t1.id}`)).status, 404);
  assert.equal((await asApp(hrToken, 'POST', `/${t1.id}/comments`, { body: 'x' })).status, 404);
  assert.equal((await asApp(hrToken, 'PATCH', `/${t1.id}`, { status: 'done' })).status, 404);
  assert.equal((await asApp(hrToken, 'DELETE', `/${t1.id}`)).status, 404);
  const list = await asApp(hrToken, 'GET', '/');
  assert.deepEqual(list.body.tasks, []);
  const feed = await asApp(hrToken, 'GET', '/events');
  assert.deepEqual(feed.body.events, []);
  assert.equal(db.prepare('SELECT status, deleted_at FROM tasks WHERE id = ?').get(t1.id).status, 'open');
});

test('the service token opens no other route', async () => {
  for (const headers of [{ 'X-API-Key': crmToken }, { Authorization: `Bearer ${crmToken}` }, { 'X-AppCrane-Service-Token': crmToken }]) {
    assert.equal((await call('GET', '/api/tasks', { headers })).status, 401, JSON.stringify(headers));
    assert.equal((await call('GET', '/api/crew/roster', { headers })).status, 401, JSON.stringify(headers));
  }
});

test('requester and assignee must be active users with access to the app', async () => {
  const base = { subject: 's' };
  const cases = [
    [{ requester_user_id: out.id, assignee_user_id: lior.id }, 'REQUESTER_NO_ACCESS'],
    [{ requester_user_id: dana.id, assignee_user_id: out.id }, 'ASSIGNEE_NO_ACCESS'],
    [{ requester_user_id: dana.id, assignee_user_id: gone.id }, 'ASSIGNEE_NO_ACCESS'],
    [{ requester_user_id: dana.id, assignee_email: 'nobody@example.com' }, 'ASSIGNEE_NO_ACCESS'],
    [{ requester_user_id: dana.id, assignee_user_id: admin.id }, 'ASSIGNEE_NO_ACCESS'],
    [{ assignee_user_id: lior.id }, 'INVALID_TASK'],
  ];
  for (const [who, code] of cases) {
    const r = await asApp(crmToken, 'POST', '/', { ...base, ...who });
    assert.equal(r.status, 400, JSON.stringify(who));
    assert.equal(r.body.error.code, code, JSON.stringify(who));
  }
});

test('the assignee can comment and change status but not delete or reopen a closed task', async () => {
  const c = await asUser(lior, 'POST', `/${t1.id}/comments`, { body: 'On it' });
  assert.equal(c.status, 201, JSON.stringify(c.body));
  assert.equal(c.body.comment.author.id, lior.id);
  assert.equal(c.body.comment.via, 'dashboard');
  const s = await asUser(lior, 'PATCH', `/${t1.id}`, { status: 'in_progress' });
  assert.equal(s.status, 200, JSON.stringify(s.body));
  assert.equal(s.body.task.status, 'in_progress');
  assert.deepEqual(s.body.task.allowed_statuses, ['open', 'done', 'declined']);
  assert.equal(s.body.task.can_delete, false);
  const d = await asUser(lior, 'DELETE', `/${t1.id}`);
  assert.equal(d.status, 403);
  assert.equal((await asUser(lior, 'PATCH', `/${t1.id}`, { status: 'done' })).status, 200);
  const reopen = await asUser(lior, 'PATCH', `/${t1.id}`, { status: 'open' });
  assert.equal(reopen.status, 403);
  assert.equal(reopen.body.error.code, 'STATUS_NOT_ALLOWED');
});

test('the requester can comment, change status (including reopen) and delete', async () => {
  assert.equal((await asUser(dana, 'POST', `/${t1.id}/comments`, { body: 'Thanks' })).status, 201);
  const r = await asUser(dana, 'PATCH', `/${t1.id}`, { status: 'open' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.task.can_delete, true);
  const detail = await asUser(dana, 'GET', `/${t1.id}`);
  assert.deepEqual(detail.body.task.comments.map((c) => c.body), ['On it', 'Thanks']);
  assert.deepEqual(detail.body.task.history.map((h) => h.to_status), ['open', 'in_progress', 'done', 'open']);

  const t = (await asApp(crmToken, 'POST', '/', { subject: 'to delete', requester_user_id: dana.id, assignee_user_id: lior.id })).body.task;
  const del = await asUser(dana, 'DELETE', `/${t.id}`);
  assert.equal(del.status, 200);
  assert.equal((await asUser(dana, 'GET', `/${t.id}`)).status, 404, 'hidden from the requester');
  assert.equal((await asUser(lior, 'GET', `/${t.id}`)).status, 404, 'hidden from the assignee');
  assert.equal((await asApp(crmToken, 'GET', `/${t.id}`)).status, 404, 'hidden from the app');
  const row = db.prepare('SELECT deleted_at, deleted_by_user_id, deleted_via FROM tasks WHERE id = ?').get(t.id);
  assert.ok(row.deleted_at, 'soft delete keeps the row');
  assert.equal(row.deleted_by_user_id, dana.id);
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'task-delete'").all();
  assert.equal(audit.length, 1);
  assert.doesNotMatch(audit[0].detail, /to delete/, 'audit carries ids, not the subject');
});

test('outsiders, other members of the app and platform admins get 404', async () => {
  for (const u of [out, sam, admin]) {
    assert.equal((await asUser(u, 'GET', `/${t1.id}`)).status, 404, u.name);
    assert.equal((await asUser(u, 'POST', `/${t1.id}/comments`, { body: 'hi' })).status, 404, u.name);
    assert.equal((await asUser(u, 'PATCH', `/${t1.id}`, { status: 'done' })).status, 404, u.name);
    assert.equal((await asUser(u, 'DELETE', `/${t1.id}`)).status, 404, u.name);
    assert.deepEqual((await asUser(u, 'GET', '/')).body.tasks, [], u.name);
  }
});

test('a party who loses access to the app stops seeing the task', async () => {
  const t = (await asApp(crmToken, 'POST', '/', { subject: 'access check', requester_user_id: dana.id, assignee_user_id: sam.id })).body.task;
  assert.equal((await asUser(sam, 'GET', `/${t.id}`)).status, 200);
  db.prepare("UPDATE app_user_roles SET app_role = 'none' WHERE app_id = ? AND user_id = ?").run(crm.id, sam.id);
  assert.equal((await asUser(sam, 'GET', `/${t.id}`)).status, 404);
  assert.ok(!(await asUser(sam, 'GET', '/')).body.tasks.some((x) => x.id === t.id), 'gone from the inbox too');
  db.prepare("UPDATE app_user_roles SET app_role = 'user' WHERE app_id = ? AND user_id = ?").run(crm.id, sam.id);
});

test('the inbox lists across apps and filters by box, status and app; counts unread and open', async () => {
  const h = (await asApp(hrToken, 'POST', '/', { subject: 'Sign the policy', requester_user_id: dana.id, assignee_user_id: lior.id })).body.task;
  const all = (await asUser(lior, 'GET', '/?box=assigned')).body.tasks;
  assert.ok(all.some((t) => t.id === h.id && t.app.slug === 'hr'));
  assert.ok(all.some((t) => t.id === t1.id && t.app.slug === 'crm'));
  const hrOnly = (await asUser(lior, 'GET', '/?app=hr')).body.tasks;
  assert.deepEqual(hrOnly.map((t) => t.id), [h.id]);
  assert.deepEqual((await asUser(lior, 'GET', '/?box=requested')).body.tasks, []);
  const danaReq = (await asUser(dana, 'GET', '/?box=requested&status=active')).body.tasks;
  assert.ok(danaReq.every((t) => ['open', 'in_progress'].includes(t.status)));
  assert.ok(danaReq.some((t) => t.id === h.id));
  assert.equal((await asUser(lior, 'GET', '/?status=bogus')).status, 400);

  const before = (await asUser(lior, 'GET', '/count')).body;
  assert.ok(before.unread >= 1);
  assert.ok(before.open_assigned >= 2);
  await asUser(lior, 'GET', `/${h.id}`);
  const afterRead = (await asUser(lior, 'GET', '/count')).body;
  assert.equal(afterRead.unread, before.unread - 1, 'opening a task marks it read');
  assert.equal(all.find((t) => t.id === h.id).unread, true);
});

test('e-mail: one per event and recipient, never to the actor, idempotent on re-notify', async () => {
  db.prepare("DELETE FROM email_queue WHERE source = 'tasks'").run();
  const t = (await asApp(crmToken, 'POST', '/', { subject: 'Mail me', requester_user_id: dana.id, assignee_user_id: lior.id })).body.task;
  assert.equal(mails(lior).length, 1, 'assignee told about the new task');
  assert.match(mails(lior)[0].subject, /new task "Mail me"/);
  assert.match(mails(lior)[0].body_text, /https:\/\/crane\.example\.com\/tasks\?task=/);
  assert.equal(mails(dana).length, 0);

  await asUser(lior, 'POST', `/${t.id}/comments`, { body: 'question?' });
  assert.equal(mails(dana).length, 1, 'requester told about the reply');
  assert.equal(mails(lior).length, 1, 'the actor is not mailed');
  await asUser(dana, 'PATCH', `/${t.id}`, { status: 'declined' });
  assert.equal(mails(lior).length, 2);
  assert.match(mails(lior)[1].subject, /is now Declined/);

  const { queueTaskMail } = await import('../server/services/tasksMail.js');
  const ev = db.prepare("SELECT id FROM task_events WHERE task_id = ? AND kind = 'status'").get(t.id);
  assert.equal(queueTaskMail(db, ev.id), 0, 're-notifying the same event queues nothing');
  assert.equal(mails(lior).length, 2);
});

test('input validation, plain text, and escaping in the e-mail', async () => {
  const bad = [
    [{ subject: '' }, /subject is required/],
    [{ subject: 'x'.repeat(201) }, /at most 200/],
    [{ subject: 'a\u0007b' }, /plain text/],
    [{ subject: 'ok', body: 'y'.repeat(10_001) }, /at most 10000/],
    [{ subject: 'ok', url: 'javascript:alert(1)' }, /http\(s\) URL/],
    [{ subject: 'ok', due_date: '2026-02-30' }, /real date/],
    [{ subject: 'ok', due_date: 'tomorrow' }, /YYYY-MM-DD/],
  ];
  for (const [body, re] of bad) {
    const r = await asApp(crmToken, 'POST', '/', { requester_user_id: dana.id, assignee_user_id: lior.id, ...body });
    assert.equal(r.status, 400, JSON.stringify(body).slice(0, 80));
    assert.match(r.body.error.message, re);
  }
  assert.equal((await asUser(lior, 'POST', `/${t1.id}/comments`, { body: '   ' })).status, 400);
  assert.equal((await asUser(lior, 'POST', `/${t1.id}/comments`, { body: 'z'.repeat(5001) })).status, 400);
  assert.equal((await asUser(dana, 'PATCH', `/${t1.id}`, { status: 'archived' })).status, 400);
  assert.equal((await asUser(dana, 'GET', '/not a valid id')).status, 404);

  db.prepare("DELETE FROM email_queue WHERE source = 'tasks'").run();
  const xss = '<script>alert(1)</script>';
  const r = await asApp(crmToken, 'POST', '/', { subject: xss, body: `<img src=x onerror=alert(2)>`, requester_user_id: dana.id, assignee_user_id: lior.id });
  assert.equal(r.status, 201);
  assert.equal(r.body.task.subject, xss, 'stored and returned verbatim as plain text');
  const m = mails(lior)[0];
  assert.doesNotMatch(m.body_html, /<script>|<img src=x/);
  assert.match(m.body_html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test('the app reads, lists and polls its own events with a cursor', async () => {
  const list = await asApp(crmToken, 'GET', '/?external_ref=inv-42');
  assert.deepEqual(list.body.tasks.map((t) => t.id), [t1.id]);
  const first = await asApp(crmToken, 'GET', '/events?limit=1');
  assert.equal(first.body.events.length, 1);
  assert.equal(first.body.has_more, true);
  assert.equal(first.body.events[0].type, 'task.created');
  const rest = await asApp(crmToken, 'GET', `/events?since=${first.body.cursor}`);
  assert.ok(rest.body.events.every((e) => Number(e.cursor) > Number(first.body.cursor)));
  const reply = rest.body.events.find((e) => e.type === 'task.comment' && e.via === 'dashboard');
  assert.equal(reply.comment.body, 'On it');
  assert.equal(reply.actor.id, lior.id);
  assert.equal((await asApp(crmToken, 'GET', '/events?since=-1')).status, 400);

  const c = await asApp(crmToken, 'POST', `/${t1.id}/comments`, { body: 'Reminder from the app' });
  assert.equal(c.status, 201);
  assert.equal(c.body.comment.author, null);
  assert.equal(c.body.comment.via, 'app');
  const s = await asApp(crmToken, 'PATCH', `/${t1.id}`, { status: 'done' });
  assert.equal(s.body.task.status, 'done');
});

test('rotation retires the old token, and deleting the app retires the token and its tasks', async () => {
  const old = crmToken;
  crmToken = issueServiceToken(crm.id);
  assert.equal((await asApp(old, 'GET', '/')).status, 401, 'old token refused after rotation');
  assert.equal((await asApp(crmToken, 'GET', '/')).status, 200);

  const tmp = mkApp('tmp');
  grant(tmp, dana); grant(tmp, lior);
  const tok = issueServiceToken(tmp.id);
  const t = (await asApp(tok, 'POST', '/', { subject: 'doomed', requester_user_id: dana.id, assignee_user_id: lior.id })).body.task;
  db.prepare('DELETE FROM app_user_roles WHERE app_id = ?').run(tmp.id);
  db.prepare('DELETE FROM audit_log WHERE app_id = ?').run(tmp.id);
  db.prepare('DELETE FROM apps WHERE id = ?').run(tmp.id);
  assert.equal((await asApp(tok, 'GET', '/')).status, 401, 'token refused once the app is deleted');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM tasks WHERE id = ?').get(t.id).n, 0, 'tasks go with the app');
});
