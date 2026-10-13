import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Security fixes to Crew phase 1 (review of v2.105.0), pinned so they cannot
// regress. Each test below FAILED against v2.105.0:
//   1. a read-only MCP key changed state through appcrane_crew_inbox
//      (last_seen_at), though the tool is marked readOnly;
//   2. an app-scoped MCP key (mcp_app_scope) and an agent identity
//      (users.kind = 'agent') had full platform-wide Crew;
//   3. a blocked/refused person removed their agent, registered the same name
//      again and got a fresh first contact and a fresh e-mail;
//   4. first-contact e-mail was capped per sending AGENT, so registering agent
//      after agent sent the same person one e-mail each.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-sec-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, { kind = 'human', scope = null } = {}) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind,mcp_app_scope) VALUES (?,?,?,?,1,?,?)')
    .run(name, `${name.toLowerCase()}@example.com`, 'user', hashApiKey(key), kind, scope).lastInsertRowid;
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
const dana = mkUser('Dana');
const lior = mkUser('Lior');
const rita = mkUser('Rita');
const alex = mkUser('Alex');
const scoped = mkUser('Scoped', { scope: '["some-app"]' });
const bot = mkUser('Botty', { kind: 'agent' });

const { callTool, listTools } = await import('../server/services/mcpTools.js');
const crewRoutes = (await import('../server/routes/crew.js')).default;
const a2aRoutes = (await import('../server/routes/a2a.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

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
async function mcp(user, tool, args, key = null) {
  const r = await callTool(user, tool, args, key);
  return JSON.parse(r.content[0].text);
}
const emailsTo = (u) => db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE to_email = ? AND source = 'crew-first-contact'").get(u.email).n;
const lastSeen = (name) => db.prepare('SELECT last_seen_at FROM crew_agents WHERE name = ?').get(name).last_seen_at;

await mcp(dana, 'appcrane_crew_register', { name: 'dana-laptop' });
await mcp(rita, 'appcrane_crew_register', { name: 'rita-bot' });

test('fix 1: a read-only MCP key changes nothing, appcrane_crew_inbox included', async () => {
  const ro = { id: 1, label: 'ro', read_only: true };
  db.prepare("UPDATE crew_agents SET last_seen_at = '2020-01-01 00:00:00' WHERE name = 'dana-laptop'").run();
  const inbox = await mcp({ ...dana, mcp_read_only: true }, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' }, ro);
  assert.equal(inbox.agent, 'dana-laptop', 'the read still works');
  assert.equal(lastSeen('dana-laptop'), '2020-01-01 00:00:00', 'a read-only key wrote last_seen_at');
  // A full key still refreshes it.
  await mcp(dana, 'appcrane_crew_inbox', { as_agent: 'dana-laptop' });
  assert.notEqual(lastSeen('dana-laptop'), '2020-01-01 00:00:00');
  for (const [tool, args] of [
    ['appcrane_crew_register', { name: 'dana-ro' }],
    ['appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'rita-bot', title: 't', message: 'm' }],
    ['appcrane_crew_reply', { as_agent: 'dana-laptop', task_id: 'x', message: 'm' }],
  ]) {
    await assert.rejects(mcp({ ...dana, mcp_read_only: true }, tool, args, ro), /read-only/, tool);
  }
});

test('fix 2: an app-scoped key and an agent identity get no Crew over MCP, A2A or (identity) the dashboard', async () => {
  for (const tool of ['appcrane_crew_register', 'appcrane_crew_roster', 'appcrane_crew_who_is_on', 'appcrane_crew_send', 'appcrane_crew_inbox', 'appcrane_crew_reply']) {
    await assert.rejects(mcp(scoped, tool, { name: 'scoped-bot', query: 'anything', as_agent: 'x', to_agent: 'y', title: 't', message: 'm', task_id: 'z' }), /MCP app scope/, `${tool} (scoped)`);
    await assert.rejects(mcp(bot, tool, { name: 'botty-bot', query: 'anything', as_agent: 'x', to_agent: 'y', title: 't', message: 'm', task_id: 'z' }), /agent identity/, `${tool} (agent identity)`);
  }
  assert.deepEqual(listTools(scoped).filter((t) => t.name.startsWith('appcrane_crew_')), [], 'the catalogue hides them too');
  assert.deepEqual(listTools(bot).filter((t) => t.name.startsWith('appcrane_crew_')), []);
  assert.equal(listTools(dana).filter((t) => t.name.startsWith('appcrane_crew_')).length, 6);
  assert.equal((await rest(bot, 'POST', '/api/crew/agents', { name: 'botty-hosted' })).status, 403);
  assert.equal((await rest(bot, 'GET', '/api/crew/roster')).status, 403);
  // A2A: a token whose owner is later limited to some apps stops working.
  const r = await rest(lior, 'POST', '/api/crew/agents', { name: 'lior-hosted' });
  const call = () => fetch(`${BASE}/a2a`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'A2A-Version': '1.0', Authorization: `Bearer ${r.body.a2a_token}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ListTasks', params: {} }) });
  assert.equal((await call()).status, 200);
  db.prepare("UPDATE users SET mcp_app_scope = '[\"some-app\"]' WHERE id = ?").run(lior.id);
  assert.equal((await call()).status, 401);
  db.prepare('UPDATE users SET mcp_app_scope = NULL WHERE id = ?').run(lior.id);
});

test('fix 3: a block survives the blocked person removing and re-registering the agent', async () => {
  await mcp(lior, 'appcrane_crew_register', { name: 'lior-runner' });
  assert.equal((await rest(rita, 'POST', '/api/crew/blocks', { agent: 'lior-runner' })).status, 201);
  const emails = emailsTo(rita);
  await mcp(lior, 'appcrane_crew_reply', { as_agent: 'lior-runner', task_id: 'none', message: 'x' }).catch(() => {});
  assert.equal((await rest(lior, 'DELETE', '/api/crew/agents/lior-runner')).status, 200);
  await mcp(lior, 'appcrane_crew_register', { name: 'lior-runner' });
  const s = await mcp(lior, 'appcrane_crew_send', { as_agent: 'lior-runner', to_agent: 'rita-bot', title: 'hello again', message: 'hi' });
  assert.equal(s.state, 'rejected', 'the block was evaded by delete + re-register');
  assert.equal(emailsTo(rita), emails, 'and it produced no e-mail');
  assert.ok((await rest(rita, 'GET', '/api/crew/blocks')).body.blocks.some((b) => b.agent === 'lior-runner'), 'Rita still sees her block');
  // A different person who takes the freed name later inherits nothing.
  await rest(lior, 'DELETE', '/api/crew/agents/lior-runner');
  await mcp(alex, 'appcrane_crew_register', { name: 'lior-runner' });
  const fresh = await mcp(alex, 'appcrane_crew_send', { as_agent: 'lior-runner', to_agent: 'rita-bot', title: 'hi', message: 'hi' });
  assert.equal(fresh.state, 'submitted');
  await rest(alex, 'DELETE', '/api/crew/agents/lior-runner');
});

test('fix 3: a refusal survives it too', async () => {
  await mcp(lior, 'appcrane_crew_register', { name: 'lior-docs' });
  const a = await mcp(lior, 'appcrane_crew_send', { as_agent: 'lior-docs', to_agent: 'dana-laptop', title: 'docs', message: 'x' });
  const connId = (await rest(dana, 'GET', '/api/crew/log')).body.entries.find((e) => e.task_id === a.task_id).connection_id;
  assert.equal((await rest(dana, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'refuse' })).status, 200);
  const emails = emailsTo(dana);
  await rest(lior, 'DELETE', '/api/crew/agents/lior-docs');
  await mcp(lior, 'appcrane_crew_register', { name: 'lior-docs' });
  const b = await mcp(lior, 'appcrane_crew_send', { as_agent: 'lior-docs', to_agent: 'dana-laptop', title: 'docs again', message: 'y' });
  assert.equal(b.state, 'rejected');
  assert.equal(emailsTo(dana), emails);
});

test('fix 4: at most one first-contact e-mail per sending person per receiving person per day', async () => {
  // A sender who has not contacted Rita yet (Alex already did, in fix 3).
  const alex = mkUser('Morgan');
  const before = emailsTo(rita);
  await mcp(alex, 'appcrane_crew_register', { name: 'alex-one' });
  await mcp(alex, 'appcrane_crew_register', { name: 'alex-two' });
  await mcp(alex, 'appcrane_crew_register', { name: 'alex-three' });
  const t1 = await mcp(alex, 'appcrane_crew_send', { as_agent: 'alex-one', to_agent: 'rita-bot', title: 'one', message: 'm' });
  const t2 = await mcp(alex, 'appcrane_crew_send', { as_agent: 'alex-two', to_agent: 'rita-bot', title: 'two', message: 'm' });
  // Remove and re-register: no new e-mail either.
  await rest(alex, 'DELETE', '/api/crew/agents/alex-three');
  await mcp(alex, 'appcrane_crew_register', { name: 'alex-three' });
  const t3 = await mcp(alex, 'appcrane_crew_send', { as_agent: 'alex-three', to_agent: 'rita-bot', title: 'three', message: 'm' });
  assert.equal(emailsTo(rita), before + 1, 'one e-mail per (sending person, receiving person) per 24 h');
  // Every request still waits for Rita in her Crew log.
  const pending = (await rest(rita, 'GET', '/api/crew/log')).body.entries.filter((e) => e.awaiting_your_decision).map((e) => e.task_id);
  for (const t of [t1, t2, t3]) assert.ok(pending.includes(t.task_id), 'the request is still offered for a decision');
  // A different sending person still gets their own first e-mail.
  await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'rita-bot', title: 'hi', message: 'm' });
  assert.equal(emailsTo(rita), before + 2);
  // And the window is per day: an e-mail older than 24 h no longer counts.
  db.prepare("UPDATE crew_first_contact_emails SET sent_at = datetime('now', '-25 hours') WHERE from_owner_id = ?").run(alex.id);
  await mcp(alex, 'appcrane_crew_register', { name: 'alex-four' });
  await mcp(alex, 'appcrane_crew_send', { as_agent: 'alex-four', to_agent: 'rita-bot', title: 'four', message: 'm' });
  assert.equal(emailsTo(rita), before + 3);
});

test('task ids are not a capability: a guessed or leaked id reads and replies to nothing', async () => {
  const t = await mcp(dana, 'appcrane_crew_send', { as_agent: 'dana-laptop', to_agent: 'rita-bot', title: 'private', message: 'secret plan' });
  await mcp(lior, 'appcrane_crew_register', { name: 'lior-snoop' });
  await assert.rejects(mcp(lior, 'appcrane_crew_reply', { as_agent: 'lior-snoop', task_id: t.task_id, message: 'x' }), /No task/);
  await assert.rejects(mcp(lior, 'appcrane_crew_reply', { as_agent: 'lior-snoop', task_id: t.task_id, state: 'canceled' }), /No task/);
  const inbox = await mcp(lior, 'appcrane_crew_inbox', { as_agent: 'lior-snoop' });
  assert.ok(!JSON.stringify(inbox).includes('secret plan'));
  // The held receiver cannot act on it before Rita decides, either.
  await assert.rejects(mcp(rita, 'appcrane_crew_reply', { as_agent: 'rita-bot', task_id: t.task_id, message: 'x', state: 'working' }), /No task/);
});
