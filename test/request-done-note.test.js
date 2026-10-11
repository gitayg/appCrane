/**
 * The request-completed email says WHAT was done, not only that something was.
 *
 * Whoever closes a request (bucket route, set-status route, or the MCP tool) can
 * attach a note. It is stored on the row, mailed to the requester and the
 * platform-admin copy, and shown back to the requester in My Requests.
 *
 * Mail is read from the real email_queue rows enqueueEmail writes, not from a
 * spy, so what is asserted is the body that would actually be sent.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-done-note-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, email, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, email, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, email, role };
}

const requester = mkUser('Requester', 'req@example.test', 'user');
const otherUser = mkUser('Other', 'other@example.test', 'user');
const admin = mkUser('Admin', 'admin@example.test', 'platform_admin');

const appId = db.prepare('INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,?,?)')
  .run('Widget', 'widget', 1, 'managed', 'main').lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, admin.id);

function mkRequest(message) {
  return Number(db.prepare(
    "INSERT INTO enhancement_requests (app_slug,user_id,user_name,message,status) VALUES ('widget',?,?,?,'in_progress')"
  ).run(requester.id, 'Requester', message).lastInsertRowid);
}

const enhancementsRoutes = (await import('../server/routes/enhancements.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const api = express();
api.use(express.json());
api.use('/api/enhancements', enhancementsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

async function call(method, path, key, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'X-API-Key': key, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

const lastMailId = () => db.prepare('SELECT COALESCE(MAX(id),0) AS m FROM email_queue').get().m;
function mailSince(id) {
  const rows = db.prepare("SELECT to_email, subject, body_text FROM email_queue WHERE id > ? AND source = 'request-fulfilled'").all(id);
  return {
    requester: rows.find((r) => r.to_email === requester.email),
    adminCopy: rows.find((r) => r.to_email === admin.email),
    all: rows,
  };
}

test('bucket route: shipped with a note mails it to the requester and the admin copy', async () => {
  const id = mkRequest('Make the header sticky');
  const since = lastMailId();
  const r = await call('PUT', `/api/enhancements/${id}/bucket`, admin.key,
    { bucket: 'shipped', note: 'The header now stays at the top while you scroll.\nAlso on mobile.' });
  assert.equal(r.status, 200, JSON.stringify(r.body));

  const m = mailSince(since);
  assert.ok(m.requester, 'no email queued for the requester');
  assert.ok(m.adminCopy, 'no admin copy queued');
  assert.match(m.requester.body_text, /What was done:\n  The header now stays at the top while you scroll\.\n  Also on mobile\./);
  assert.match(m.adminCopy.body_text, /What was done:\n  The header now stays at the top/);
  // After the quoted request, not before it.
  assert.ok(m.requester.body_text.indexOf('Make the header sticky') < m.requester.body_text.indexOf('What was done:'));
  assert.doesNotMatch(m.requester.subject, /header now stays/, 'the note must not go into the subject');
  assert.equal(db.prepare('SELECT done_note FROM enhancement_requests WHERE id = ?').get(id).done_note,
    'The header now stays at the top while you scroll.\nAlso on mobile.');
});

test('set-status: done and won\'t-do carry the note, labelled for each', async () => {
  const done = mkRequest('Add CSV export');
  let since = lastMailId();
  let r = await call('POST', `/api/enhancements/${done}/set-status`, admin.key, { status: 'done', note: 'Export is under the ... menu.' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  let m = mailSince(since);
  assert.match(m.requester.body_text, /What was done:\n  Export is under the \.\.\. menu\./);
  assert.match(m.adminCopy.body_text, /What was done:\n  Export is under/);

  const wont = mkRequest('Rewrite it in Rust');
  since = lastMailId();
  r = await call('POST', `/api/enhancements/${wont}/set-status`, admin.key, { status: 'no_changes_needed', note: 'Out of scope for this app.' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  m = mailSince(since);
  assert.match(m.requester.body_text, /Note:\n  Out of scope for this app\./);
  assert.doesNotMatch(m.requester.body_text, /What was done/);
  assert.match(m.adminCopy.body_text, /Note:\n  Out of scope/);
});

test('MCP appcrane_set_request_status passes the note through to the email', async () => {
  const id = mkRequest('Dark mode please');
  const since = lastMailId();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(admin.id);
  await callTool(user, 'appcrane_set_request_status', { id, bucket: 'shipped', note: 'Dark mode follows your system setting now.' });
  const m = mailSince(since);
  assert.ok(m.requester, 'no email queued for the requester');
  assert.match(m.requester.body_text, /What was done:\n  Dark mode follows your system setting now\./);
  assert.match(m.adminCopy.body_text, /What was done:\n  Dark mode follows/);
});

test('MCP tool rejects a note over 2000 characters', async () => {
  const id = mkRequest('Too long via MCP');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(admin.id);
  await assert.rejects(
    callTool(user, 'appcrane_set_request_status', { id, bucket: 'shipped', note: 'x'.repeat(2001) }),
    /at most 2000/,
  );
  assert.equal(db.prepare('SELECT status FROM enhancement_requests WHERE id = ?').get(id).status, 'in_progress');
});

test('no note: the email reads exactly as before, with no "What was done" section', async () => {
  const id = mkRequest('Bigger buttons');
  const since = lastMailId();
  const r = await call('PUT', `/api/enhancements/${id}/bucket`, admin.key, { bucket: 'shipped' });
  assert.equal(r.status, 200);
  const m = mailSince(since);
  assert.equal(m.requester.body_text,
    'Hi Requester,\n\nGood news — a request you submitted for Widget has been completed:\n\n' +
    '  "Bigger buttons"\n\nYou\'ll see it the next time you open the app.\n\n— Admin');
  assert.equal(m.adminCopy.body_text,
    'Request #' + id + ' from Requester for Widget was completed by Admin.\n\n  "Bigger buttons"\n\n— Admin');

  // Whitespace-only counts as no note too.
  const id2 = mkRequest('Smaller buttons');
  const since2 = lastMailId();
  await call('PUT', `/api/enhancements/${id2}/bucket`, admin.key, { bucket: 'shipped', note: '   \n  ' });
  assert.doesNotMatch(mailSince(since2).requester.body_text, /What was done/);
});

test('a note over 2000 characters is a 400 and changes nothing', async () => {
  const id = mkRequest('Long note');
  const since = lastMailId();
  const r1 = await call('PUT', `/api/enhancements/${id}/bucket`, admin.key, { bucket: 'shipped', note: 'y'.repeat(2001) });
  assert.equal(r1.status, 400);
  const r2 = await call('POST', `/api/enhancements/${id}/set-status`, admin.key, { status: 'done', note: 'y'.repeat(2001) });
  assert.equal(r2.status, 400);
  assert.equal(db.prepare('SELECT status FROM enhancement_requests WHERE id = ?').get(id).status, 'in_progress');
  assert.equal(mailSince(since).all.length, 0);

  // Exactly 2000 is allowed.
  const ok = await call('PUT', `/api/enhancements/${id}/bucket`, admin.key, { bucket: 'shipped', note: 'y'.repeat(2000) });
  assert.equal(ok.status, 200);
});

test('control characters are stripped, newlines kept', async () => {
  const id = mkRequest('Control chars');
  const since = lastMailId();
  await call('PUT', `/api/enhancements/${id}/bucket`, admin.key,
    { bucket: 'shipped', note: 'Fixed\u0007 the\u001b[31m bug\r\nSecond\u0000 line\u007f' });
  const stored = db.prepare('SELECT done_note FROM enhancement_requests WHERE id = ?').get(id).done_note;
  assert.equal(stored, 'Fixed the[31m bug\nSecond line');
  const body = mailSince(since).requester.body_text;
  assert.match(body, /What was done:\n  Fixed the\[31m bug\n  Second line\n/);
  assert.doesNotMatch(body, /[\u0000-\u0009\u000B-\u001F\u007F]/);
});

test('GET /api/enhancements/my returns done_note to the requester only', async () => {
  const id = mkRequest('Show my note');
  await call('PUT', `/api/enhancements/${id}/bucket`, admin.key, { bucket: 'shipped', note: 'Visible in My Requests.' });

  const mine = await call('GET', '/api/enhancements/my', requester.key);
  assert.equal(mine.status, 200);
  const row = mine.body.requests.find((x) => x.id === id);
  assert.ok(row, 'requester cannot see their own request');
  assert.equal(row.done_note, 'Visible in My Requests.');

  // /my is scoped to user_id: another user sees none of the requester's rows.
  const theirs = await call('GET', '/api/enhancements/my', otherUser.key);
  assert.equal(theirs.status, 200);
  assert.equal(theirs.body.requests.length, 0);
});

test('re-marking done with a new note replaces it; an empty re-mark keeps it', async () => {
  const id = mkRequest('Replace note');
  await call('POST', `/api/enhancements/${id}/set-status`, admin.key, { status: 'done', note: 'First.' });
  await call('POST', `/api/enhancements/${id}/set-status`, admin.key, { status: 'done', note: 'Second.' });
  assert.equal(db.prepare('SELECT done_note FROM enhancement_requests WHERE id = ?').get(id).done_note, 'Second.');
  await call('POST', `/api/enhancements/${id}/set-status`, admin.key, { status: 'done' });
  assert.equal(db.prepare('SELECT done_note FROM enhancement_requests WHERE id = ?').get(id).done_note, 'Second.');
});
