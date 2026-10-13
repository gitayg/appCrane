import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';
import express from 'express';

// Crew, phase 1 (v2.105.0): the platform-wide agent hub.
//
// What these tests pin, in the order a reviewer would ask about them:
//   - an agent acts only through its owner (no one, not even a platform admin,
//     can send or read as someone else's agent);
//   - same-owner traffic flows; cross-owner traffic is held on first contact
//     and the receiving person gets exactly ONE e-mail per (agent, person);
//   - allow / allow once / refuse / block do what the dashboard says;
//   - blocks are silent: rejected for the sender, nothing at all for the owner;
//   - flood limits answer 429, secrets are refused, audit rows never carry a
//     title or body, and retention deletes history but not audit rows.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';
process.env.LOG_LEVEL = 'error';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const email = `${name.toLowerCase()}@example.com`;
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, email, role, hashApiKey(key)).lastInsertRowid;
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
const dana = mkUser('Dana');
const lior = mkUser('Lior');
const sam = mkUser('Sam');
const priya = mkUser('Priya');
const alex = mkUser('Alex');
const rita = mkUser('Rita');
const admin = mkUser('Admin', 'platform_admin');

const { callTool, listTools } = await import('../server/services/mcpTools.js');
const crewRoutes = (await import('../server/routes/crew.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { purgeExpiredCrewHistory, CREW_LIMITS } = await import('../server/services/crew.js');

const api = express();
api.use(express.json());
api.use('/api/crew', crewRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

async function rest(user, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': user.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json() };
}

async function mcp(user, tool, args) {
  const r = await callTool(user, tool, args);
  return JSON.parse(r.content[0].text);
}

const emailsTo = (u) => db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE to_email = ? AND source = 'crew-first-contact'").get(u.email).n;
const taskState = (id) => db.prepare('SELECT state, held FROM crew_tasks WHERE id = ?').get(id);

const BODY_MARK = 'ZEBRA-BODY-MARKER-7731';
const TITLE_MARK = 'OCELOT-TITLE-MARKER';

test('registration: the agent belongs to the caller, names are unique platform-wide', async () => {
  const a = await mcp(dana, 'appcrane_crew_register', { name: 'dana-laptop', description: 'Dana on a laptop', skills: [{ id: 'fix-bug' }] });
  assert.equal(a.name, 'dana-laptop');
  assert.equal(a.owner, 'Dana');
  assert.equal(a.created, true);
  await mcp(dana, 'appcrane_crew_register', { name: 'dana-helper' });
  await mcp(lior, 'appcrane_crew_register', { name: 'qa-runner', skills: [{ id: 'e2e-tests' }] });
  await mcp(sam, 'appcrane_crew_register', { name: 'db-steward', skills: [{ id: 'migrate' }] });
  await mcp(priya, 'appcrane_crew_register', { name: 'docs-writer' });
  await mcp(alex, 'appcrane_crew_register', { name: 'growth-scraper' });
  await mcp(rita, 'appcrane_crew_register', { name: 'rita-bot' });

  // Re-registering your own name updates it; someone else's is refused.
  const again = await mcp(dana, 'appcrane_crew_register', { name: 'dana-laptop', description: 'updated' });
  assert.equal(again.created, false);
  await assert.rejects(mcp(lior, 'appcrane_crew_register', { name: 'dana-laptop' }), /already registered by another person/);
  await assert.rejects(mcp(dana, 'appcrane_crew_register', { name: 'Bad Name!' }), /lowercase letters/);
});

test('an agent acts only through its owner: another person, and a platform admin, get 403', async () => {
  await assert.rejects(
    mcp(dana, 'appcrane_crew_send', { as_agent: 'qa-runner', to_agent: 'dana-laptop', title: 't', message: 'm' }),
    /Forbidden: agent "qa-runner" belongs to another person/);
  await assert.rejects(mcp(admin, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' }), /Forbidden/);
  await assert.rejects(mcp(lior, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' }), /Forbidden/);
  // REST: removing someone else's agent is a 403 too.
  const r = await rest(dana, 'DELETE', '/api/crew/agents/qa-runner');
  assert.equal(r.status, 403, JSON.stringify(r.body));
  // But the roster is visible to everyone, with owners, yours marked.
  const roster = await rest(dana, 'GET', '/api/crew/roster');
  assert.equal(roster.status, 200);
  const qa = roster.body.agents.find((x) => x.name === 'qa-runner');
  assert.equal(qa.owner, 'Lior');
  assert.equal(qa.is_mine, false);
  assert.equal(roster.body.agents.find((x) => x.name === 'dana-laptop').is_mine, true);
});

test('same-owner tasks are delivered at once, with no e-mail', async () => {
  const s = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'dana-helper', title: 'tidy logs', message: 'please' });
  assert.equal(s.state, 'submitted');
  assert.equal(s.note, undefined);
  const inbox = await mcp(dana, 'appcrane_crew_inbox', { as_agent: 'dana-helper' });
  assert.equal(inbox.received.length, 1);
  assert.equal(inbox.received[0].messages[0].body, 'please');
  assert.equal(emailsTo(dana), 0);
});

let firstHeld;
test('first contact holds the task and sends exactly one e-mail per (agent, person)', async () => {
  const s1 = await mcp(lior, 'appcrane_crew_send', { as_agent: 'qa-runner', to_agent: 'dana-laptop', title: 'run the regression suite on sandbox', message: 'after your fix lands' });
  firstHeld = s1.task_id;
  assert.equal(s1.state, 'submitted');
  assert.match(s1.note, /held until they decide/);
  assert.deepEqual(taskState(s1.task_id), { state: 'submitted', held: 1 });
  assert.equal(emailsTo(dana), 1, 'one e-mail on first contact');
  const mail = db.prepare("SELECT subject, body_text FROM email_queue WHERE source = 'crew-first-contact'").get();
  assert.match(mail.subject, /Lior's agent wants to work with your agent/);
  assert.match(mail.body_text, /run the regression suite on sandbox/);
  assert.match(mail.body_text, /https:\/\/crane\.example\.com\/crew#log/);

  // The receiver's agent cannot see a held task.
  assert.equal((await mcp(dana, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' })).received.length, 0);

  // A second task from the same agent — to the same or another of Dana's agents — sends no second e-mail.
  await mcp(lior, 'appcrane_crew_send', { as_agent: 'qa-runner', to_agent: 'dana-laptop', title: 'second', message: 'two' });
  await mcp(lior, 'appcrane_crew_send', { as_agent: 'qa-runner', to_agent: 'dana-helper', title: 'third', message: 'three' });
  assert.equal(emailsTo(dana), 1, 'still exactly one e-mail');

  // Dana's Crew log offers the decision on each held task.
  const log = await rest(dana, 'GET', '/api/crew/log');
  const pending = log.body.entries.filter((e) => e.awaiting_your_decision);
  assert.equal(pending.length, 3);
  assert.ok(pending.every((e) => e.connection_id === pending[0].connection_id));
});

test('only the receiving person can decide; Allow releases held tasks and no e-mail follows', async () => {
  const log = await rest(dana, 'GET', '/api/crew/log');
  const connId = log.body.entries.find((e) => e.awaiting_your_decision).connection_id;
  // The sender, and a platform admin, cannot decide for Dana.
  assert.equal((await rest(lior, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow' })).status, 404);
  assert.equal((await rest(admin, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow' })).status, 404);

  const r = await rest(dana, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.released, 3);
  assert.deepEqual(taskState(firstHeld), { state: 'submitted', held: 0 });
  assert.equal((await mcp(dana, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' })).received.length, 2);

  const s = await mcp(lior, 'appcrane_crew_send', { as_agent: 'qa-runner', to_agent: 'dana-laptop', title: 'fourth', message: 'four' });
  assert.equal(s.note, undefined, 'delivered directly');
  assert.equal(taskState(s.task_id).held, 0);
  assert.equal(emailsTo(dana), 1, 'no e-mail after the connection is allowed');

  // The receiver works the task and returns an artifact; the sender sees it.
  await mcp(dana, 'appcrane_crew_reply', { as_agent: 'dana-laptop', task_id: s.task_id, message: 'done', state: 'completed', artifact: { name: 'report.md', body: 'all green' } });
  const sent = (await mcp(lior, 'appcrane_crew_inbox', { as_agent: 'qa-runner' })).sent.find((t) => t.task_id === s.task_id);
  assert.equal(sent.state, 'completed');
  assert.equal(sent.messages.at(-1).artifact.name, 'report.md');
  await assert.rejects(mcp(dana, 'appcrane_crew_reply', { as_agent: 'dana-laptop', task_id: s.task_id, message: 'again' }), /already completed/);
  // A task id is not probeable by an agent that is neither party.
  await assert.rejects(mcp(dana, 'appcrane_crew_reply', { as_agent: 'dana-helper', task_id: s.task_id, message: 'x' }), /No task/);
});

test('Allow once releases one task; the next is held again without another e-mail', async () => {
  const a = await mcp(sam, 'appcrane_crew_send', { as_agent: 'db-steward', to_agent: 'dana-laptop', title: 'migrate', message: 'plan' });
  assert.equal(emailsTo(dana), 2, 'a new connection is a new first contact');
  const connId = (await rest(dana, 'GET', '/api/crew/log')).body.entries.find((e) => e.task_id === a.task_id).connection_id;
  const r = await rest(dana, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow_once', task_id: a.task_id });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.state, 'pending');
  assert.equal(taskState(a.task_id).held, 0);
  const b = await mcp(sam, 'appcrane_crew_send', { as_agent: 'db-steward', to_agent: 'dana-laptop', title: 'migrate again', message: 'plan 2' });
  assert.equal(taskState(b.task_id).held, 1);
  assert.equal(emailsTo(dana), 2, 'no second e-mail for the same connection');
});

test('Refuse rejects what is waiting and every later task, silently', async () => {
  const a = await mcp(priya, 'appcrane_crew_send', { as_agent: 'docs-writer', to_agent: 'dana-laptop', title: 'changelog', message: 'x' });
  const emails = emailsTo(dana);
  const connId = (await rest(dana, 'GET', '/api/crew/log')).body.entries.find((e) => e.task_id === a.task_id).connection_id;
  const r = await rest(dana, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'refuse' });
  assert.equal(r.body.rejected, 1);
  assert.equal(taskState(a.task_id).state, 'rejected');
  const b = await mcp(priya, 'appcrane_crew_send', { as_agent: 'docs-writer', to_agent: 'dana-helper', title: 'again', message: 'y' });
  assert.equal(b.state, 'rejected');
  assert.equal(b.note, undefined, 'no reason given');
  assert.equal(emailsTo(dana), emails);
  // Rejections never show in the receiver's log; refused agents are listed for an Allow later.
  const log = (await rest(dana, 'GET', '/api/crew/log')).body.entries;
  assert.ok(!log.some((e) => e.task_id === b.task_id));
  assert.ok((await rest(dana, 'GET', '/api/crew/blocks')).body.refused.some((x) => x.agent === 'docs-writer'));
});

test('Block from a first contact: rejected now and later, no e-mail, no notification', async () => {
  const a = await mcp(alex, 'appcrane_crew_send', { as_agent: 'growth-scraper', to_agent: 'dana-laptop', title: 'enrich', message: 'leads' });
  const emails = emailsTo(dana);
  const connId = (await rest(dana, 'GET', '/api/crew/log')).body.entries.find((e) => e.task_id === a.task_id).connection_id;
  await rest(dana, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'block' });
  const b = await mcp(alex, 'appcrane_crew_send', { as_agent: 'growth-scraper', to_agent: 'dana-laptop', title: 'enrich 2', message: 'leads' });
  assert.equal(b.state, 'rejected');
  assert.equal(emailsTo(dana), emails);
  const blocks = (await rest(dana, 'GET', '/api/crew/blocks')).body.blocks;
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].agent, 'growth-scraper');
  // The held task the Block rejected, plus the one sent afterwards.
  assert.equal(blocks[0].refused_since, 2);
  // Platform admins see how often an agent is blocked.
  const adminRoster = (await rest(admin, 'GET', '/api/crew/roster')).body.agents;
  assert.equal(adminRoster.find((x) => x.name === 'growth-scraper').blocked_by_count, 1);
});

test('a block placed before any contact is silent: rejected, and the owner gets nothing', async () => {
  const r = await rest(rita, 'POST', '/api/crew/blocks', { agent: 'qa-runner' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const s = await mcp(lior, 'appcrane_crew_send', { as_agent: 'qa-runner', to_agent: 'rita-bot', title: 'hello', message: 'hi' });
  assert.equal(s.state, 'rejected');
  assert.equal(emailsTo(rita), 0, 'no e-mail');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM crew_connections WHERE to_owner_id = ?').get(rita.id).n, 0, 'no first-contact request created');
  assert.equal((await rest(rita, 'GET', '/api/crew/log')).body.entries.length, 0, 'nothing in her log');
  // Unblock is the owner's alone.
  const blockId = (await rest(rita, 'GET', '/api/crew/blocks')).body.blocks[0].id;
  assert.equal((await rest(dana, 'DELETE', `/api/crew/blocks/${blockId}`)).status, 404);
  assert.equal((await rest(rita, 'DELETE', `/api/crew/blocks/${blockId}`)).status, 200);
});

test('a message carrying a credential is refused and nothing is stored', async () => {
  const before = db.prepare('SELECT COUNT(*) AS n FROM crew_tasks').get().n;
  await assert.rejects(
    mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'dana-helper', title: 'creds', message: 'use AKIAABCDEFGHIJKLMNOP for s3' }),
    /looks like a credential \(aws-access-key\)/);
  await assert.rejects(
    mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'dana-helper', title: 'key', message: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc' }),
    /private-key/);
  await assert.rejects(
    mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'dana-helper', title: 'k', message: `my key ${generateApiKey('dhk_mcp')}` }),
    /appcrane-key/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM crew_tasks').get().n, before);
});

test('audit rows carry actor_kind and never a title or body', async () => {
  const s = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'dana-helper', title: TITLE_MARK, message: BODY_MARK });
  await mcp(dana, 'appcrane_crew_reply', { as_agent: 'dana-helper', task_id: s.task_id, message: BODY_MARK, state: 'working' });
  const send = db.prepare("SELECT * FROM audit_log WHERE action = 'crew.task.send' AND detail LIKE ?").get(`%${s.task_id}%`);
  assert.equal(send.actor_kind, 'agent');
  assert.equal(JSON.parse(send.detail).title_len, TITLE_MARK.length);
  const decisions = db.prepare("SELECT actor_kind FROM audit_log WHERE action LIKE 'crew.connection.%'").all();
  assert.ok(decisions.length >= 4);
  assert.ok(decisions.every((d) => d.actor_kind === 'human'));
  assert.equal(db.prepare("SELECT actor_kind FROM audit_log WHERE action = 'crew.first_contact'").get().actor_kind, 'agent');
  // Not in the crew rows, and not in the generic mcp.* rows either.
  const leaks = db.prepare('SELECT action FROM audit_log WHERE detail LIKE ? OR detail LIKE ?').all(`%${BODY_MARK}%`, `%${TITLE_MARK}%`);
  assert.deepEqual(leaks, []);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'mcp.appcrane_crew_send'").get(), 'the MCP call itself is still audited');
});

test('flood control: per-agent task limit and per-owner pending first-contact cap answer 429', async () => {
  await mcp(dana, 'appcrane_crew_register', { name: 'dana-flood' });
  const sent = db.prepare("SELECT COUNT(*) AS n FROM crew_tasks WHERE from_agent_id = (SELECT id FROM crew_agents WHERE name = 'dana-flood')").get().n;
  for (let i = sent; i < CREW_LIMITS.TASKS_PER_HOUR; i++) {
    await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-flood', to_agent: 'dana-helper', title: `t${i}`, message: 'm' });
  }
  await assert.rejects(
    mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-flood', to_agent: 'dana-helper', title: 'one more', message: 'm' }),
    (e) => /RATE|limit is 60/.test(e.message) && e.status === 429);
  const r = await rest(dana, 'POST', '/api/crew/agents', { name: 'dana-flood-2' });
  assert.equal(r.status, 201);

  // 20 first contacts of Rita's still pending → the 21st is refused.
  const ritaAgent = db.prepare("SELECT id FROM crew_agents WHERE name = 'rita-bot'").get().id;
  for (let i = 0; i < CREW_LIMITS.PENDING_FIRST_CONTACTS; i++) {
    const u = mkUser(`Pending${i}`);
    db.prepare("INSERT INTO crew_connections (from_agent_id, from_owner_id, to_owner_id, state) VALUES (?, ?, ?, 'pending')").run(ritaAgent, rita.id, u.id);
  }
  const emails = emailsTo(dana);
  await assert.rejects(
    mcp(rita, 'appcrane_crew_send', { as_agent: 'rita-bot', to_agent: 'dana-laptop', title: 'hi', message: 'hi' }),
    (e) => /first-contact requests still waiting/.test(e.message) && e.status === 429);
  assert.equal(emailsTo(dana), emails, 'the refused send queued no e-mail');
});

test('retention deletes tasks and messages older than 30 days, never audit rows', () => {
  const agent = db.prepare("SELECT id FROM crew_agents WHERE name = 'dana-helper'").get().id;
  db.prepare("INSERT INTO crew_tasks (id, from_agent_id, to_agent_id, title, state, created_at, updated_at) VALUES ('old-task', ?, ?, 'old', 'completed', datetime('now','-40 days'), datetime('now','-31 days'))").run(agent, agent);
  db.prepare("INSERT INTO crew_messages (task_id, from_agent_id, body, created_at) VALUES ('old-task', ?, 'old body', datetime('now','-40 days'))").run(agent);
  const auditBefore = db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n;
  const recent = db.prepare("SELECT COUNT(*) AS n FROM crew_tasks WHERE updated_at >= datetime('now','-1 day')").get().n;
  const r = purgeExpiredCrewHistory();
  assert.equal(r.tasks, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM crew_tasks WHERE id = 'old-task'").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM crew_messages WHERE task_id = 'old-task'").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM crew_tasks WHERE updated_at >= datetime('now','-1 day')").get().n, recent);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n, auditBefore);
});

test('the Crew MCP tools are wired and advertised', () => {
  const names = listTools(dana).map((t) => t.name).filter((n) => n.startsWith('appcrane_crew_'));
  // Phase 3 (crew-rules.test.js) added appcrane_crew_rules, read-only.
  assert.deepEqual(names.sort(), [
    'appcrane_crew_inbox', 'appcrane_crew_register', 'appcrane_crew_reply',
    'appcrane_crew_roster', 'appcrane_crew_rules', 'appcrane_crew_send', 'appcrane_crew_who_is_on',
  ]);
});

test('who_is_on finds open work by its title', async () => {
  const r = await mcp(sam, 'appcrane_crew_who_is_on', { query: 'regression suite' });
  assert.ok(r.working_on.some((x) => x.agent === 'dana-laptop' && /regression suite/.test(x.task_title)));
});

test('hosted agents register from a pasted card; there is no card URL fetch', async () => {
  const card = JSON.stringify({ name: 'release-bot', description: 'Writes release notes', skills: [{ id: 'release-notes', description: 'notes' }], capabilities: { streaming: true } });
  const r = await rest(sam, 'POST', '/api/crew/agents', { card_json: card, knows_about: 'release process' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.agent.kind, 'hosted');
  assert.deepEqual(r.body.agent.skills, [{ id: 'release-notes', description: 'notes' }]);
  assert.equal((await rest(sam, 'DELETE', '/api/crew/agents/release-bot')).status, 200);
});

test('scripts/check-route-authz.mjs --strict stays green', () => {
  const r = spawnSync(process.execPath, [join(ROOT, 'scripts', 'check-route-authz.mjs'), '--strict'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
