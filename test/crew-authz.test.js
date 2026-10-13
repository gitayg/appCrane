import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Authorization fixes to Crew (review of v2.106.0), pinned so they cannot
// regress. Each test below FAILED against v2.106.0:
//   1. a sender cancelling its own HELD task cleared `held`, which made the
//      never-approved title and body visible to the receiver's agents over
//      A2A (GetTask / ListTasks) — first contact bypassed by send + cancel;
//   2. a sender could add messages to a HELD task, so "Allow once" released
//      content the receiving person never saw when deciding;
//   3. Block / Refuse rejected only held tasks: a sender that had been allowed
//      kept its open tasks and kept writing into them after being blocked.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-authz-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';
process.env.LOG_LEVEL = 'error';
process.env.CREW_A2A_BLOCKING_WAIT_MS = '0';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,'user',?,1,'human')")
    .run(name, `${name.toLowerCase()}@example.com`, hashApiKey(key)).lastInsertRowid;
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
const sam = mkUser('Sam');   // sender
const ruth = mkUser('Ruth'); // receiver

const { callTool } = await import('../server/services/mcpTools.js');
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
const msg = (text, extra = {}) => ({ messageId: `m-${++rpcId}`, role: 'ROLE_USER', parts: [{ text }], ...extra });
const connectionOf = async (taskId) => (await rest(ruth, 'GET', '/api/crew/log')).body.entries.find((e) => e.task_id === taskId)?.connection_id;

// Ruth's receiving agent is hosted, so it reads over A2A with its own token.
await mcp(sam, 'appcrane_crew_register', { name: 'sam-agent' });
const ruthToken = (await rest(ruth, 'POST', '/api/crew/agents', { name: 'ruth-agent' })).body.a2a_token;
const samToken = (await rest(sam, 'POST', '/api/crew/agents', { name: 'sam-hosted' })).body.a2a_token;

test('fix 1: cancelling a held task never shows it to the receiver, and it cannot be released', async () => {
  const t = await mcp(sam, 'appcrane_crew_send', { as_agent: 'sam-agent', to_agent: 'ruth-agent', title: 'unapproved title', message: 'unapproved body' });
  assert.equal(t.state, 'submitted');
  const connId = await connectionOf(t.task_id);
  const c = await mcp(sam, 'appcrane_crew_reply', { as_agent: 'sam-agent', task_id: t.task_id, state: 'canceled' });
  assert.equal(c.state, 'canceled', 'the sender may still withdraw its request');

  const list = await rpc(ruthToken, 'ListTasks', {});
  assert.ok(!JSON.stringify(list).includes('unapproved'), 'the receiver\'s agent read a never-approved task after the sender cancelled it');
  assert.equal((await rpc(ruthToken, 'GetTask', { id: t.task_id })).error?.code, -32001, 'GetTask on a cancelled held task');

  // The withdrawn request is no longer offered, and no decision releases it.
  const entry = (await rest(ruth, 'GET', '/api/crew/log')).body.entries.find((e) => e.task_id === t.task_id);
  assert.equal(entry.awaiting_your_decision, false);
  assert.equal((await rest(ruth, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow_once', task_id: t.task_id })).status, 404);
  const allowed = await rest(ruth, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow' });
  assert.equal(allowed.body.released, 0, 'Allow released a task its sender had withdrawn');
  assert.equal((await rpc(ruthToken, 'GetTask', { id: t.task_id })).error?.code, -32001);
  // Reset for the next test: sam-agent starts with no connection to Ruth.
  db.prepare('DELETE FROM crew_connections WHERE from_agent_id = (SELECT id FROM crew_agents WHERE name = ?)').run('sam-agent');
});

test('fix 2: a sender cannot add to a held task, so "Allow once" releases exactly what was decided', async () => {
  const t = await mcp(sam, 'appcrane_crew_send', { as_agent: 'sam-agent', to_agent: 'ruth-agent', title: 'please review', message: 'the original request' });
  await assert.rejects(mcp(sam, 'appcrane_crew_reply', { as_agent: 'sam-agent', task_id: t.task_id, message: 'smuggled after the fact' }), /waiting for the receiving person/);
  await assert.rejects(mcp(sam, 'appcrane_crew_reply', { as_agent: 'sam-agent', task_id: t.task_id, state: 'canceled', message: 'smuggled with a cancel' }), /waiting for the receiving person/);
  // The A2A door reaches the same rule.
  const s = await rpc(samToken, 'SendMessage', { message: msg('x', { metadata: {} }), tenant: 'ruth-agent' });
  const a2aHeld = s.result.task.id;
  const more = await rpc(samToken, 'SendMessage', { message: msg('smuggled over a2a', { taskId: a2aHeld }) });
  assert.ok(more.error, 'A2A SendMessage continued a held task');

  const connId = await connectionOf(t.task_id);
  const once = await rest(ruth, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow_once', task_id: t.task_id });
  assert.equal(once.status, 200);
  const got = await rpc(ruthToken, 'GetTask', { id: t.task_id });
  assert.equal(got.result.history.length, 1, 'only the message Ruth decided on is released');
  assert.ok(!JSON.stringify(got).includes('smuggled'));
});

test('fix 3: Block and Refuse win over an earlier Allow for tasks already open', async () => {
  for (const decision of ['refuse', 'block']) {
    const name = `sam-${decision}`;
    await mcp(sam, 'appcrane_crew_register', { name });
    const first = await mcp(sam, 'appcrane_crew_send', { as_agent: name, to_agent: 'ruth-agent', title: 'first', message: 'm' });
    const connId = await connectionOf(first.task_id);
    assert.equal((await rest(ruth, 'POST', `/api/crew/connections/${connId}/decision`, { decision: 'allow' })).status, 200);
    // Ruth's agent picks the task up: it is open and released.
    assert.equal((await rpc(ruthToken, 'SendMessage', { message: msg('on it', { taskId: first.task_id, metadata: { taskState: 'TASK_STATE_WORKING' } }) })).result.task.status.state, 'TASK_STATE_WORKING');

    // Ruth changes her mind.
    const r = await rest(ruth, 'POST', `/api/crew/connections/${connId}/decision`, { decision });
    assert.equal(r.status, 200);
    await assert.rejects(
      mcp(sam, 'appcrane_crew_reply', { as_agent: name, task_id: first.task_id, message: `still writing after ${decision}` }),
      /already rejected/, `the sender kept writing into an open task after ${decision}`,
    );
    const sent = (await mcp(sam, 'appcrane_crew_inbox', { as_agent: name })).sent.find((x) => x.task_id === first.task_id);
    assert.equal(sent.state, 'rejected', 'silent: the sender sees rejected, no reason');
    assert.equal((await rpc(ruthToken, 'GetTask', { id: first.task_id })).error?.code, -32001, 'the task left Ruth\'s agent\'s view');
  }
});
