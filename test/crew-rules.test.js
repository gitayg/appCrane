import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Crew, phase 3: people in the loop. What these pin:
//   - a standing rule matches only its exact (person, agent, action, scope),
//     live and unexpired, and never production or a deletion — not when the
//     fields say so, not when only the title says so, not when a field is
//     simply left out;
//   - rules never reach past a block or a first contact (gate order);
//   - an INPUT_REQUIRED question goes to exactly one person, and nobody else
//     (the other owner, a platform admin, a stranger) can answer it;
//   - Approve / Approve and always allow / Reply / Decline do what they say,
//     a reply arrives as a HUMAN message, and none of it sends e-mail;
//   - every rule create / revoke / use and every decision is audited, without
//     a body.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-rules-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';
process.env.LOG_LEVEL = 'error';
process.env.CREW_A2A_BLOCKING_WAIT_MS = '0';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name.toLowerCase()}@example.com`, role, hashApiKey(key)).lastInsertRowid;
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
const dana = mkUser('Dana');   // sends tasks
const sam = mkUser('Sam');     // owns db-steward, receives them
const lior = mkUser('Lior');   // a stranger to Sam
const admin = mkUser('Admin', 'platform_admin');

const { callTool } = await import('../server/services/mcpTools.js');
const crewRoutes = (await import('../server/routes/crew.js')).default;
const a2aRoutes = (await import('../server/routes/a2a.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { matchRule, alwaysAskReason } = await import('../server/services/crewRules.js');

const app = express();
app.use('/a2a', a2aRoutes);
app.use(express.json());
app.use('/api/crew', crewRoutes);
app.use(errorHandler);
const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
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
let rpcId = 0;
async function rpc(token, method, params) {
  const res = await fetch(`${BASE}/a2a`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'A2A-Version': '1.0', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  return res.json();
}
const msg = (text, extra = {}) => ({ messageId: `m-${++rpcId}`, role: 'ROLE_AGENT', parts: [{ text }], ...extra });
const task = (id) => db.prepare('SELECT * FROM crew_tasks WHERE id = ?').get(id);
const agentId = (name) => db.prepare('SELECT id FROM crew_agents WHERE name = ?').get(name).id;
const emailCount = () => db.prepare('SELECT COUNT(*) AS n FROM email_queue').get().n;
const nonFirstContactEmails = () => db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE source <> 'crew-first-contact'").get().n;
const auditRows = (action) => db.prepare('SELECT * FROM audit_log WHERE action = ? ORDER BY id').all(action);
const logEntry = async (user, taskId) => (await rest(user, 'GET', '/api/crew/log')).body.entries.find((e) => e.task_id === taskId);

const QUESTION_MARK = 'HERON-QUESTION-MARKER-5521';
const REPLY_MARK = 'IBIS-REPLY-MARKER-9034';

// Agents: Dana's local agent and a second one, Sam's hosted db-steward (A2A),
// Lior's local agent. Dana's agent gets a first contact with Sam, allowed.
await mcp(dana, 'appcrane_crew_register', { name: 'dana-laptop' });
await mcp(dana, 'appcrane_crew_register', { name: 'dana-two' });
await mcp(lior, 'appcrane_crew_register', { name: 'lior-bot' });
const stewardToken = (await rest(sam, 'POST', '/api/crew/agents', { name: 'db-steward', skills: 'migrate, backup' })).body.a2a_token;
{
  const first = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title: 'hello', message: 'first contact' });
  const conn = (await logEntry(sam, first.task_id)).connection_id;
  assert.equal((await rest(sam, 'POST', `/api/crew/connections/${conn}/decision`, { decision: 'allow' })).status, 200);
}
// From here on, the only e-mail allowed is a first contact.
const EMAILS_AFTER_SETUP = emailCount();

test('a rule matches only its exact person + agent + action + scope, live and unexpired', async () => {
  const r = await rest(sam, 'POST', '/api/crew/rules', { agent: 'dana-laptop', action: 'migrate', scope: 'sandbox' });
  assert.equal(r.status, 201);
  const ruleId = r.body.rule.id;
  assert.match(ruleId, /^[A-Za-z0-9_-]{22}$/, 'opaque base64url id');
  const base = { ownerId: sam.id, agentId: agentId('dana-laptop'), action: 'migrate', scope: 'sandbox' };
  assert.equal(matchRule(db, base)?.id, ruleId);
  assert.equal(matchRule(db, { ...base, ownerId: dana.id }), null, 'another person');
  assert.equal(matchRule(db, { ...base, agentId: agentId('dana-two') }), null, 'another agent of the same person');
  assert.equal(matchRule(db, { ...base, action: 'backup' }), null, 'another action');
  assert.equal(matchRule(db, { ...base, scope: 'sandbox-2' }), null, 'no prefix matching');
  assert.equal(matchRule(db, { ...base, action: null }), null, 'action omitted');
  assert.equal(matchRule(db, { ...base, scope: null }), null, 'scope omitted');

  db.prepare("UPDATE crew_rules SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(ruleId);
  assert.equal(matchRule(db, base), null, 'expired');
  const edited = await rest(sam, 'PATCH', `/api/crew/rules/${ruleId}`, { expires_in_days: 7 });
  assert.equal(edited.status, 200);
  assert.equal(edited.body.rule.expired, false);
  assert.equal(matchRule(db, base)?.id, ruleId, 'an edited expiry brings it back');
  // Only its owner sees or changes it — a platform admin included.
  assert.equal((await rest(admin, 'GET', '/api/crew/rules')).body.rules.length, 0);
  assert.equal((await rest(admin, 'DELETE', `/api/crew/rules/${ruleId}`)).status, 404);
  assert.equal((await rest(dana, 'PATCH', `/api/crew/rules/${ruleId}`, { expires_in_days: 1 })).status, 404);
  // The agent's read-only view lists its owner's rules.
  assert.equal((await mcp(sam, 'appcrane_crew_rules', {})).rules[0].id, ruleId);
  assert.equal((await mcp(dana, 'appcrane_crew_rules', {})).rules.length, 0);
});

test('production and deletions are never covered: by field, by title, or by leaving a field out', async () => {
  for (const bad of [{ scope: 'production' }, { scope: 'prod-eu' }, { action: 'delete-rows' }, { action: 'drop' }]) {
    const r = await rest(sam, 'POST', '/api/crew/rules', { agent: 'dana-laptop', action: 'migrate', scope: 'sandbox', ...bad });
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.equal(r.body.error.code, 'ALWAYS_ASKS');
  }
  assert.equal(alwaysAskReason({ action: 'migrate', scope: 'sandbox', texts: ['then DROP the old table'] }), 'deletion');
  assert.equal(alwaysAskReason({ action: 'migrate', scope: 'sandbox', texts: ['run it on prod tonight'] }), 'production');
  assert.equal(alwaysAskReason({ action: 'migrate', scope: 'sandbox', texts: ['add a column'] }), null);

  // Sam's rule (from the test above) covers dana-laptop / migrate / sandbox.
  const covered = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title: 'add reorder_point', message: 'add a column', action: 'migrate', scope: 'sandbox' });
  assert.equal(covered.state, 'submitted');
  assert.ok(covered.approved_by_rule, 'exact match is pre-approved');

  const viaTitle = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title: 'migrate the production database', message: 'same plan', action: 'migrate', scope: 'sandbox' });
  assert.equal(viaTitle.state, 'input_required', 'a title naming production always asks, whatever the fields say');
  assert.equal(viaTitle.approved_by_rule, undefined);
  const viaBody = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title: 'tidy up', message: 'truncate the items table', action: 'migrate', scope: 'sandbox' });
  assert.equal(viaBody.state, 'input_required', 'a deletion in the body always asks');

  const noScope = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title: 'add column', message: 'm', action: 'migrate' });
  assert.equal(noScope.state, 'input_required', 'scope left out: no rule, the person is asked');
  const noAction = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title: 'add column', message: 'm', scope: 'sandbox' });
  assert.equal(noAction.state, 'input_required', 'action left out: no rule, the person is asked');

  // The receiving person's Crew log offers no "always allow" for production.
  const e = await logEntry(sam, viaTitle.task_id);
  assert.equal(e.input_required.always_asks, 'production');
  assert.equal(e.input_required.can_always_allow, false);
  const r = await rest(sam, 'POST', `/api/crew/decisions/${e.input_required.decision_id}`, { decision: 'approve_always' });
  assert.equal(r.status, 400);
  assert.equal(task(viaTitle.task_id).state, 'input_required', 'a refused "always allow" changed nothing');
});

test('rules never bypass first contact or a block', async () => {
  // Sam trusts lior-bot to migrate sandbox before Lior's agent ever wrote.
  assert.equal((await rest(sam, 'POST', '/api/crew/rules', { agent: 'lior-bot', action: 'migrate', scope: 'sandbox' })).status, 201);
  const t = await mcp(lior, 'appcrane_crew_send', { as_agent: 'lior-bot', to_agent: 'db-steward', title: 'add column', message: 'm', action: 'migrate', scope: 'sandbox' });
  assert.equal(t.state, 'submitted');
  assert.equal(task(t.task_id).held, 1, 'still a first contact: held');
  assert.equal(task(t.task_id).rule_id, null, 'the rule was not consulted before first contact');
  assert.equal((await rpc(stewardToken, 'GetTask', { id: t.task_id })).error?.code, -32001, 'the receiver cannot see it');
  const rule = db.prepare('SELECT * FROM crew_rules WHERE owner_user_id = ? AND agent_id = ?').get(sam.id, agentId('lior-bot'));
  assert.equal(rule.use_count, 0);

  // Allowing the first contact runs the rule stage, then.
  const conn = (await logEntry(sam, t.task_id)).connection_id;
  assert.equal((await rest(sam, 'POST', `/api/crew/connections/${conn}/decision`, { decision: 'allow_once', task_id: t.task_id })).status, 200);
  assert.equal(task(t.task_id).rule_id, rule.id);
  assert.equal(task(t.task_id).state, 'submitted');

  // Blocking lior-bot ends the rule, and a rule row that somehow survived a
  // block still never matches.
  assert.equal((await rest(sam, 'POST', '/api/crew/blocks', { agent: 'lior-bot' })).status, 201);
  assert.ok(db.prepare('SELECT revoked_at FROM crew_rules WHERE id = ?').get(rule.id).revoked_at, 'block revoked the rule');
  assert.ok(auditRows('crew.rule.revoke').some((a) => JSON.parse(a.detail).rule_id === rule.id && JSON.parse(a.detail).reason === 'blocked'));
  db.prepare('UPDATE crew_rules SET revoked_at = NULL WHERE id = ?').run(rule.id);
  assert.equal(matchRule(db, { ownerId: sam.id, agentId: agentId('lior-bot'), action: 'migrate', scope: 'sandbox' }), null);
  const blocked = await mcp(lior, 'appcrane_crew_send', { as_agent: 'lior-bot', to_agent: 'db-steward', title: 'add column', message: 'm', action: 'migrate', scope: 'sandbox' });
  assert.equal(blocked.state, 'rejected');
  db.prepare("UPDATE crew_rules SET revoked_at = datetime('now') WHERE id = ?").run(rule.id);
  // Rules cannot be created for an agent you blocked.
  assert.equal((await rest(sam, 'POST', '/api/crew/rules', { agent: 'lior-bot', action: 'backup', scope: 'sandbox' })).status, 409);
});

/** dana-laptop sends a plain task; db-steward (A2A) asks a question about it. */
async function askedTask({ ask, action = 'migrate', scope = 'sandbox', title = 'stock count fix' } = {}) {
  const t = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title, message: 'please migrate' });
  const metadata = { taskState: 'TASK_STATE_INPUT_REQUIRED', ...(ask ? { ask } : {}), ...(action ? { action } : {}), ...(scope ? { scope } : {}) };
  const r = await rpc(stewardToken, 'SendMessage', { message: msg(`${QUESTION_MARK}: back up, add column, backfill 18240 rows. Approve?`, { taskId: t.task_id, metadata }) });
  assert.ok(r.result, JSON.stringify(r.error));
  return { id: t.task_id, a2a: r.result.task };
}

test('INPUT_REQUIRED goes to the sender\'s owner by default, and only they can decide', async () => {
  const before = emailCount();
  const { id, a2a } = await askedTask({});
  assert.equal(a2a.status.state, 'TASK_STATE_INPUT_REQUIRED');
  assert.equal(task(id).state, 'input_required');

  const danaEntry = await logEntry(dana, id);
  assert.ok(danaEntry.input_required.decision_id, 'Dana (the sender\'s owner) is asked');
  assert.equal(danaEntry.input_required.waiting_for, 'you');
  assert.ok(danaEntry.input_required.question.includes(QUESTION_MARK));
  assert.equal(danaEntry.input_required.can_always_allow, true);
  const samEntry = await logEntry(sam, id);
  assert.equal(samEntry.input_required.decision_id, undefined, 'Sam sees the question but is not offered a decision');
  assert.equal(samEntry.input_required.waiting_for, 'Dana');
  assert.ok((await rest(dana, 'GET', '/api/crew/waiting')).body.questions.some((q) => q.task_id === id), 'Dana\'s notification');
  assert.ok(!(await rest(sam, 'GET', '/api/crew/waiting')).body.questions.some((q) => q.task_id === id));

  const decisionId = danaEntry.input_required.decision_id;
  for (const who of [sam, admin, lior]) {
    const r = await rest(who, 'POST', `/api/crew/decisions/${decisionId}`, { decision: 'approve' });
    assert.equal(r.status, 404, `${who.name} decided a question routed to Dana`);
  }
  assert.equal(task(id).state, 'input_required');

  const ok = await rest(dana, 'POST', `/api/crew/decisions/${decisionId}`, { decision: 'approve' });
  assert.equal(ok.status, 200);
  assert.equal(task(id).state, 'working', 'Approve resumes the task');
  assert.equal((await rest(dana, 'POST', `/api/crew/decisions/${decisionId}`, { decision: 'decline' })).status, 409, 'answered once');
  const got = await rpc(stewardToken, 'GetTask', { id });
  const last = got.result.history.at(-1);
  assert.equal(last.role, 'ROLE_USER');
  assert.equal(last.metadata?.actorKind, 'human');
  assert.match(last.parts[0].text, /Approved by Dana/);
  assert.equal(emailCount(), before, 'no e-mail for a question or a decision');
});

test('ask: my_owner goes to the receiving agent\'s own owner', async () => {
  // Sam's own rule (first test: dana-laptop may migrate sandbox) answers a
  // my_owner question about a task from dana-laptop: the rule names the sender.
  const covered = await askedTask({ ask: 'my_owner' });
  assert.equal(covered.a2a.status.state, 'TASK_STATE_WORKING', 'Sam\'s rule for the sender covered it');
  const { id } = await askedTask({ ask: 'my_owner', scope: 'staging' });
  const samEntry = await logEntry(sam, id);
  assert.ok(samEntry.input_required.decision_id);
  const danaEntry = await logEntry(dana, id);
  assert.equal(danaEntry.input_required.decision_id, undefined);
  assert.equal((await rest(dana, 'POST', `/api/crew/decisions/${samEntry.input_required.decision_id}`, { decision: 'approve' })).status, 404);
  assert.equal((await rest(sam, 'POST', `/api/crew/decisions/${samEntry.input_required.decision_id}`, { decision: 'decline' })).status, 200);
  assert.equal(task(id).state, 'rejected', 'Decline sets rejected');
  assert.equal(task(id).declined, 1);
  // The asking agent sees the outcome (a person declined it), unlike a silent block.
  assert.equal((await rpc(stewardToken, 'GetTask', { id })).result.status.state, 'TASK_STATE_REJECTED');
  const sent = (await mcp(dana, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' })).sent.find((x) => x.task_id === id);
  assert.equal(sent.state, 'rejected');
});

test('Reply arrives as a message from a person, and the task resumes', async () => {
  const { id } = await askedTask({});
  const decisionId = (await logEntry(dana, id)).input_required.decision_id;
  assert.equal((await rest(dana, 'POST', `/api/crew/decisions/${decisionId}`, { decision: 'reply' })).status, 400, 'a reply needs text');
  const r = await rest(dana, 'POST', `/api/crew/decisions/${decisionId}`, { decision: 'reply', message: `${REPLY_MARK} use the replica first` });
  assert.equal(r.status, 200);
  assert.equal(task(id).state, 'working');
  const m = db.prepare('SELECT * FROM crew_messages WHERE task_id = ? ORDER BY id DESC LIMIT 1').get(id);
  assert.equal(m.actor_kind, 'human');
  assert.equal(m.from_user_id, dana.id);
  assert.ok(m.body.includes(REPLY_MARK));
  const hist = (await rpc(stewardToken, 'GetTask', { id })).result.history;
  assert.equal(hist.at(-1).role, 'ROLE_USER');
  assert.equal(hist.at(-1).metadata.actorKind, 'human');
  // The MCP inbox labels it as the person's, not the agent's.
  const sent = (await mcp(dana, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' })).sent.find((x) => x.task_id === id);
  const human = sent.messages.find((x) => x.body.includes(REPLY_MARK));
  assert.equal(human.actor_kind, 'human');
  assert.equal(human.from_person, 'Dana');
  assert.equal(human.from_agent, undefined);
});

test('Approve and always allow creates a rule; the next matching question is answered by it and marked', async () => {
  const { id } = await askedTask({});
  const decisionId = (await logEntry(dana, id)).input_required.decision_id;
  const r = await rest(dana, 'POST', `/api/crew/decisions/${decisionId}`, { decision: 'approve_always', expires_in_days: 7 });
  assert.equal(r.status, 200);
  assert.equal(task(id).state, 'working');
  const ruleId = r.body.rule.id;
  const rule = db.prepare('SELECT * FROM crew_rules WHERE id = ?').get(ruleId);
  assert.equal(rule.owner_user_id, dana.id);
  assert.equal(rule.agent_id, agentId('db-steward'), 'the rule names the agent that asked');
  assert.equal(rule.from_decision_id, decisionId);
  assert.ok(rule.expires_at);
  const listed = (await rest(dana, 'GET', '/api/crew/rules')).body.rules.find((x) => x.id === ruleId);
  assert.equal(listed.from_decision, true);

  // Next time db-steward asks Dana the same thing, nobody is asked.
  const next = await askedTask({});
  assert.equal(next.a2a.status.state, 'TASK_STATE_WORKING', 'answered by the rule at once');
  assert.equal(task(next.id).state, 'working');
  const e = await logEntry(dana, next.id);
  assert.equal(e.input_required, undefined);
  assert.equal(e.ran_under_rule.id, ruleId, 'the Crew log marks the rule that allowed it');
  assert.equal(db.prepare('SELECT use_count FROM crew_rules WHERE id = ?').get(ruleId).use_count, 1);
  // A different scope still asks.
  const other = await askedTask({ scope: 'staging' });
  assert.equal(other.a2a.status.state, 'TASK_STATE_INPUT_REQUIRED');
  // Revoked in one click; then it asks again.
  assert.equal((await rest(dana, 'DELETE', `/api/crew/rules/${ruleId}`)).status, 200);
  assert.equal((await askedTask({})).a2a.status.state, 'TASK_STATE_INPUT_REQUIRED');
});

test('a declared task waits for the receiving person; the receiving agent cannot start it itself', async () => {
  const t = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'db-steward', title: 'reindex', message: 'm', action: 'reindex', scope: 'sandbox' });
  assert.equal(t.state, 'input_required');
  for (const taskState of ['TASK_STATE_WORKING', 'TASK_STATE_COMPLETED', 'TASK_STATE_INPUT_REQUIRED']) {
    const r = await rpc(stewardToken, 'SendMessage', { message: msg('starting anyway', { taskId: t.task_id, metadata: { taskState, ask: 'sender_owner' } }) });
    assert.ok(r.error, `receiver moved a declared task to ${taskState} without its person`);
  }
  const e = await logEntry(sam, t.task_id);
  assert.equal(e.input_required.ask, 'declared');
  assert.equal((await rest(dana, 'POST', `/api/crew/decisions/${e.input_required.decision_id}`, { decision: 'approve' })).status, 404, 'the sender\'s owner cannot approve it');
  assert.equal((await rest(sam, 'POST', `/api/crew/decisions/${e.input_required.decision_id}`, { decision: 'approve' })).status, 200);
  assert.equal(task(t.task_id).state, 'working');
});

test('a block ends a pending question: it can no longer be decided', async () => {
  await mcp(lior, 'appcrane_crew_register', { name: 'lior-two' });
  const first = await mcp(lior, 'appcrane_crew_send', { as_agent: 'lior-two', to_agent: 'db-steward', title: 'x', message: 'm' });
  const conn = (await logEntry(sam, first.task_id)).connection_id;
  await rest(sam, 'POST', `/api/crew/connections/${conn}/decision`, { decision: 'allow' });
  const r = await rpc(stewardToken, 'SendMessage', { message: msg('ok?', { taskId: first.task_id, metadata: { taskState: 'TASK_STATE_INPUT_REQUIRED' } }) });
  assert.equal(r.result.task.status.state, 'TASK_STATE_INPUT_REQUIRED');
  const decisionId = (await logEntry(lior, first.task_id)).input_required.decision_id;
  assert.ok(decisionId);
  await rest(sam, 'POST', '/api/crew/blocks', { agent: 'lior-two' });
  assert.equal(task(first.task_id).state, 'rejected', 'v2.106.1: block ends every open task');
  assert.equal((await rest(lior, 'POST', `/api/crew/decisions/${decisionId}`, { decision: 'approve' })).status, 409);
  assert.equal(task(first.task_id).state, 'rejected');
});

test('no e-mail for any of this, and audit rows for every rule and decision, without bodies', () => {
  // lior-bot's first contact e-mailed Sam; lior-two's did not (one first-contact
  // e-mail per pair of people per 24 hours, v2.106.0).
  assert.equal(emailCount(), EMAILS_AFTER_SETUP + 1, 'only a first contact made inside these tests e-mailed');
  assert.equal(nonFirstContactEmails(), 0, 'nothing but first contacts was e-mailed');
  for (const action of ['crew.rule.create', 'crew.rule.revoke', 'crew.rule.use', 'crew.rule.update',
    'crew.decision.ask', 'crew.decision.by_rule', 'crew.decision.approve', 'crew.decision.approve_always',
    'crew.decision.reply', 'crew.decision.decline']) {
    assert.ok(auditRows(action).length > 0, `no audit row for ${action}`);
  }
  for (const a of auditRows('crew.decision.approve')) assert.equal(a.actor_kind, 'human');
  for (const a of auditRows('crew.decision.by_rule')) assert.equal(a.actor_kind, 'agent');
  for (const a of auditRows('crew.rule.create')) assert.equal(a.actor_kind, 'human');
  const crewAudit = db.prepare("SELECT detail FROM audit_log WHERE action LIKE 'crew.%' OR action LIKE 'mcp.%'").all().map((r) => r.detail).join('\n');
  assert.ok(!crewAudit.includes(QUESTION_MARK), 'a question body reached audit_log');
  assert.ok(!crewAudit.includes(REPLY_MARK), 'a person\'s reply reached audit_log');
});
