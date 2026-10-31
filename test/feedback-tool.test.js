import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// appcrane_submit_feedback, driven through callTool with the user shapes the
// MCP route hands it, so the read-only gate, the role gate and the audit
// write all run as they do in production.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-feedback-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getNextSlot } = await import('../server/services/portAllocator.js');
const { callTool, listTools } = await import('../server/services/mcpTools.js');
const { notifyAdminsOfFeedback } = await import('../server/services/feedback/mail.js');
const { RATE_LIMIT_PER_HOUR } = await import('../server/services/feedback/submit.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

let n = 0;
function mkUser(role = 'user', kind = 'human') {
  n++;
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`fb${n}`, `fb${n}@example.test`, role, `fbh${n}`, kind).lastInsertRowid;
  return { id, role, name: `fb${n}`, email: `fb${n}@example.test`, kind };
}
function mkApp(slug, roles = []) {
  db.prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)').run(slug, slug, getNextSlot(db));
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  for (const [user, role] of roles) {
    db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, user.id, role);
  }
  return app;
}
const send = async (user, args, key = null) => JSON.parse((await callTool(user, 'appcrane_submit_feedback', args, key)).content[0].text);
const request = (id) => db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(id);
const feedbackMails = () => db.prepare("SELECT * FROM email_queue WHERE source = 'feedback' ORDER BY id").all();

const padminA = mkUser('platform_admin');
const padminB = mkUser('platform_admin');
const owner = mkUser();
const member = mkUser();
const stranger = mkUser();

test('app target: lands in that app\'s request queue, visible to appcrane_list_requests', async () => {
  mkApp('fb-app', [[owner, 'owner'], [member, 'user']]);
  const out = await send(member, {
    message: 'The deploy error did not name the missing env var',
    slug: 'fb-app', env: 'sandbox',
    context: { tool: 'appcrane_deploy', task: 'deploy to sandbox', deploy_id: 42, error: 'Missing required env', client: 'TestAgent 1.0' },
  });
  assert.equal(out.target, 'app');
  assert.match(out.where, new RegExp(`/requests/${out.id}$`));
  const row = request(out.id);
  assert.equal(row.app_slug, 'fb-app');
  assert.equal(row.user_id, member.id);
  assert.equal(row.kind, 'feedback');
  assert.equal(row.status, 'new');
  assert.match(row.message, /^\[Feedback: bug\] The deploy error did not name the missing env var/);
  assert.match(row.message, /- Tool: appcrane_deploy/);
  assert.match(row.message, /- Deploy: 42/);
  assert.match(row.message, /- Environment: sandbox/);
  assert.match(row.message, /- Client: TestAgent 1\.0/);
  assert.match(row.message, /\(human\) on AppCrane v\d+\.\d+\.\d+/);
  const listed = JSON.parse((await callTool(owner, 'appcrane_list_requests', { slug: 'fb-app' })).content[0].text);
  assert.ok(listed.requests.some((r) => r.id === out.id), 'owner sees it in the app queue');
  const audit = db.prepare("SELECT * FROM audit_log WHERE action = 'feedback-submitted' ORDER BY id DESC LIMIT 1").get();
  assert.equal(audit.user_id, member.id);
  assert.equal(audit.actor_kind, 'human');
  assert.equal(JSON.parse(audit.detail).id, out.id);
});

test('app target: a caller without access to the app is refused and nothing is stored', async () => {
  mkApp('fb-private', [[owner, 'owner']]);
  const before = db.prepare("SELECT COUNT(*) AS c FROM enhancement_requests WHERE app_slug = 'fb-private'").get().c;
  await assert.rejects(send(stranger, { message: 'hello', slug: 'fb-private' }), /Forbidden/);
  await assert.rejects(send(stranger, { message: 'hello', slug: 'no-such-app' }), /App not found/);
  const scoped = { ...owner, mcp_app_scope: JSON.stringify(['fb-app']) };
  await assert.rejects(send(scoped, { message: 'hello', slug: 'fb-private' }), /outside this key's MCP scope/);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM enhancement_requests WHERE app_slug = 'fb-private'").get().c, before);
});

test('AppCrane target: goes to the platform list, and each admin gets one mail per hour', async () => {
  const agent = mkUser('user', 'agent');
  const a = await send(agent, { message: 'First idea', kind: 'feature' });
  const b = await send(agent, { message: 'Second idea', slug: 'appcrane' });
  for (const out of [a, b]) {
    assert.equal(out.target, 'appcrane');
    assert.equal(request(out.id).app_slug, '_platform');
  }
  assert.match(request(a.id).message, /^\[Feedback: feature\] First idea/);
  assert.match(request(a.id).message, /\(agent\)/);
  const mails = feedbackMails();
  assert.deepEqual(mails.map((m) => m.to_email).sort(), [padminA.email, padminB.email].sort());
  assert.ok(mails.every((m) => m.app_id === null && /First idea/.test(m.body_text)));
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM email_queue WHERE source = 'platform-request'").get().c, 0,
    'no per-request platform mail on top');
  const nextHour = new Date(Date.now() + 3600_000);
  notifyAdminsOfFeedback(db, { id: b.id, kind: 'bug', who: 'x', message: 'later', now: nextHour });
  assert.equal(feedbackMails().length, 4, 'a new hour sends again');
  const listed = db.prepare("SELECT id FROM enhancement_requests WHERE app_slug = '_platform' AND kind = 'feedback'").all().map((r) => r.id);
  assert.ok(listed.includes(a.id) && listed.includes(b.id));
});

test('secrets in message and error are redacted before they are stored or audited', async () => {
  const token = 'ghp_' + 'A1b2C3d4E5'.repeat(4);
  const out = await send(member, {
    message: `clone failed with https://bob:hunter2pass@git.example.test/x.git and token=${token}`,
    slug: 'fb-app',
    context: { error: `401 Authorization: Bearer abc.def.ghi dhk_user_0123456789abcdef AKIAABCDEFGHIJKLMNOP mail me at ops@example.test` },
  });
  const msg = request(out.id).message;
  for (const s of [token, 'hunter2pass', 'bob:', 'abc.def.ghi', 'dhk_user_0123456789abcdef', 'AKIAABCDEFGHIJKLMNOP', 'ops@example.test']) {
    assert.ok(!msg.includes(s), `stored text still contains ${s}`);
  }
  assert.match(msg, /\[redacted\]/);
  const mcpAudit = db.prepare("SELECT detail FROM audit_log WHERE action = 'mcp.appcrane_submit_feedback' ORDER BY id DESC LIMIT 1").get().detail;
  for (const s of [token, 'hunter2pass', 'AKIAABCDEFGHIJKLMNOP']) assert.ok(!mcpAudit.includes(s), `MCP audit row contains ${s}`);
});

test(`rate limit: ${RATE_LIMIT_PER_HOUR} per user per hour`, async () => {
  const busy = mkUser();
  for (let i = 0; i < RATE_LIMIT_PER_HOUR; i++) await send(busy, { message: `note ${i}` });
  await assert.rejects(send(busy, { message: 'one too many' }), /RATE_LIMITED/);
  const other = mkUser();
  await send(other, { message: 'someone else is not limited' });
  db.prepare("UPDATE enhancement_requests SET created_at = datetime('now', '-2 hours') WHERE user_id = ?").run(busy.id);
  await send(busy, { message: 'an hour later' });
});

test('schema: unknown keys and oversized fields are refused', async () => {
  const bad = [
    [{ message: 'x', extra: 1 }, /unknown field/],
    [{ message: 'x', context: { tool: 'a', secret_dump: 'y' } }, /unknown context field/],
    [{ message: 'x'.repeat(4001) }, /over the 4000-character limit/],
    [{ message: '   ' }, /message is empty/],
    [{}, /message is required/],
    [{ message: 'x', kind: 'rant' }, /kind must be/],
    [{ message: 'x', env: 'staging' }, /env must be/],
    [{ message: 'x', context: { task: 't'.repeat(1001) } }, /context\.task/],
    [{ message: 'x', context: 'nope' }, /context must be an object/],
  ];
  for (const [args, re] of bad) await assert.rejects(send(member, args), re, JSON.stringify(args).slice(0, 80));
  const out = await send(member, { message: 'long error', context: { error: 'e'.repeat(10000) } });
  const stored = request(out.id).message;
  assert.ok(stored.length < 4096 + 1000, 'error text is capped');
  assert.match(stored, /\[cut\]/);
});

test('read-only keys may send feedback; View as previews and the coder key may not', async () => {
  const ro = { ...member, mcp_read_only: true };
  const roKey = { id: 9, read_only: true };
  assert.ok(listTools(ro, roKey).some((t) => t.name === 'appcrane_submit_feedback'));
  const out = await send(ro, { message: 'from a read-only key' }, roKey);
  assert.equal(out.target, 'appcrane');
  const preview = { ...member, role: 'user', mcp_read_only: true, view_as: { role: 'user', app_id: null, app_slug: null } };
  await assert.rejects(send(preview, { message: 'preview' }), /read-only/);
  assert.ok(!listTools(preview).some((t) => t.name === 'appcrane_submit_feedback'));
  const coder = { ...owner, mcp_read_only: true, coder_key: { slug: 'fb-app' } };
  await assert.rejects(send(coder, { message: 'coder' }, { id: 10, read_only: true, coder: { slug: 'fb-app' } }), /Forbidden/);
});

test('feedback text never carries the sender\'s e-mail, even when they have no name', async () => {
  const { composeFeedbackText } = await import('../server/services/feedback/submit.js');
  const src = (await import('fs')).readFileSync(new URL('../server/services/feedback/submit.js', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /user\.name \|\| user\.email/, 'the e-mail must not stand in for a missing name');
  const text = composeFeedbackText({ message: 'm', kind: 'bug', env: null, context: {} }, { who: 'user 7', actorKind: 'agent', at: 'now' });
  assert.match(text, /Sent over MCP by user 7 \(agent\)/);
});

test('feedback is never mirrored to the app\'s GitHub issues (a read-only key may file it)', async () => {
  const fs = await import('fs');
  const submit = fs.readFileSync(new URL('../server/services/feedback/submit.js', import.meta.url), 'utf8');
  const create = fs.readFileSync(new URL('../server/services/requestCreate.js', import.meta.url), 'utf8');
  assert.match(submit, /announceRequest\(db, id, appSlug, \{ platformMail: false, mirror: false \}\)/);
  assert.match(create, /if \(mirror && app\?\.github_url\)/);
});
