import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Crew, phase 2 (v2.106.0): the platform A2A endpoint.
//
// What these tests pin:
//   - JSON-RPC 2.0 dispatch and the A2A 1.0 error codes (spec §5.4, §9.5);
//   - an agent token authenticates exactly one crew agent and acts only as it;
//   - A2A reaches the SAME first-contact gate, blocks, secret scan and audit
//     as MCP (it is another door into services/crew.js, not a copy of it);
//   - SSE streams carry the task first, then its updates, and close at a
//     terminal state;
//   - the communication map returns counts only and shows a block only to the
//     person who placed it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-a2a-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
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
const dana = mkUser('Dana');
const lior = mkUser('Lior');
const rita = mkUser('Rita');
const priya = mkUser('Priya');

const a2aRoutes = (await import('../server/routes/a2a.js')).default;
const { wellKnownAgentCard } = await import('../server/routes/a2a.js');
const crewRoutes = (await import('../server/routes/crew.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const app = express();
app.use('/a2a', a2aRoutes);
app.get('/.well-known/agent-card.json', wellKnownAgentCard);
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

let rpcId = 0;
async function rpcRaw(token, payload, { version = '1.0', contentType = 'application/json' } = {}) {
  const headers = { 'Content-Type': contentType };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (version) headers['A2A-Version'] = version;
  const res = await fetch(`${BASE}/a2a`, { method: 'POST', headers, body: typeof payload === 'string' ? payload : JSON.stringify(payload) });
  return { status: res.status, headers: res.headers, body: await res.json() };
}
const rpc = (token, method, params, opts) => rpcRaw(token, { jsonrpc: '2.0', id: ++rpcId, method, ...(params === undefined ? {} : { params }) }, opts);

function msg(text, extra = {}) {
  return { messageId: `m-${++rpcId}`, role: 'ROLE_USER', parts: [{ text }], ...extra };
}

const emailsTo = (u) => db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE to_email = ? AND source = 'crew-first-contact'").get(u.email).n;
const TITLE_MARK = 'PANGOLIN-TITLE-MARKER';
const BODY_MARK = 'NARWHAL-BODY-MARKER';

// Hosted agents registered from the dashboard get their token once.
const tokens = {};
async function registerHosted(user, name) {
  const r = await rest(user, 'POST', '/api/crew/agents', { name, description: `${name} agent`, skills: 'relay, review' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.match(r.body.a2a_token, /^dhk_crew_[A-Za-z0-9_-]{43}$/);
  tokens[name] = r.body.a2a_token;
}

test('a new hosted agent gets its A2A token once; only a hash is stored', async () => {
  await registerHosted(dana, 'dana-bot');
  await registerHosted(dana, 'dana-two');
  await registerHosted(lior, 'lior-bot');
  await registerHosted(rita, 'rita-bot');
  await registerHosted(priya, 'priya-bot');
  const again = await rest(dana, 'POST', '/api/crew/agents', { name: 'dana-bot', description: 'updated' });
  assert.equal(again.status, 200);
  assert.equal(again.body.a2a_token, undefined, 're-registering never issues a token');
  const stored = db.prepare('SELECT token_hash FROM crew_agent_tokens').all().map((r) => r.token_hash);
  for (const t of Object.values(tokens)) assert.ok(!stored.includes(t) && stored.includes(hashApiKey(t)));
  const mine = await rest(dana, 'GET', '/api/crew/agents');
  assert.deepEqual(mine.body.tokens.map((t) => t.agent).sort(), ['dana-bot', 'dana-two']);
  assert.ok(!JSON.stringify(mine.body).includes(tokens['dana-bot']), 'the token is never shown again');
});

test('the public Agent Card is at the spec\'s well-known path and lists no agents', async () => {
  const res = await fetch(`${BASE}/.well-known/agent-card.json`);
  assert.equal(res.status, 200);
  const card = await res.json();
  assert.equal(card.name, 'AppCrane Crew');
  assert.deepEqual(card.supportedInterfaces, [{ url: 'https://crane.example.com/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }]);
  assert.deepEqual({ s: card.capabilities.streaming, p: card.capabilities.pushNotifications, e: card.capabilities.extendedAgentCard }, { s: true, p: true, e: true });
  assert.equal(card.securitySchemes.crewAgentToken.httpAuthSecurityScheme.scheme, 'Bearer');
  assert.deepEqual(card.securityRequirements, [{ schemes: { crewAgentToken: { list: [] } } }]);
  for (const n of ['dana-bot', 'lior-bot', 'rita-bot']) assert.ok(!JSON.stringify(card).includes(n), `${n} leaked into the public card`);
  assert.ok(res.headers.get('etag'));
  assert.match(res.headers.get('cache-control'), /max-age=/);
});

test('no anonymous access: missing, malformed, unknown and revoked tokens are one 401', async () => {
  const none = await rpc(null, 'ListTasks', {});
  assert.equal(none.status, 401);
  assert.match(none.headers.get('www-authenticate'), /^Bearer /);
  assert.equal(none.body.error.code, -31001);
  assert.equal((await rpc('dhk_crew_' + 'x'.repeat(43), 'ListTasks', {})).status, 401);
  assert.equal((await rpc(dana.key, 'ListTasks', {})).status, 401, 'a user API key is not an agent token');
  // Rotate: the old token dies at once, the new one works.
  const rot = await rest(dana, 'POST', '/api/crew/agents/dana-two/token');
  assert.equal(rot.status, 201);
  assert.equal((await rpc(tokens['dana-two'], 'ListTasks', {})).status, 401);
  tokens['dana-two'] = rot.body.token;
  assert.equal((await rpc(tokens['dana-two'], 'ListTasks', {})).status, 200);
  // Someone else cannot rotate or revoke your agent's token.
  assert.equal((await rest(lior, 'POST', '/api/crew/agents/dana-two/token')).status, 403);
  assert.equal((await rest(lior, 'DELETE', '/api/crew/agents/dana-two/token')).status, 403);
  // Revoke.
  const tmp = await rest(dana, 'POST', '/api/crew/agents', { name: 'dana-tmp' });
  assert.equal((await rpc(tmp.body.a2a_token, 'ListTasks', {})).status, 200);
  assert.equal((await rest(dana, 'DELETE', '/api/crew/agents/dana-tmp/token')).body.revoked, true);
  assert.equal((await rpc(tmp.body.a2a_token, 'ListTasks', {})).status, 401);
  // A deactivated owner's token stops working.
  const t2 = await rest(dana, 'POST', '/api/crew/agents/dana-tmp/token');
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(dana.id);
  assert.equal((await rpc(t2.body.token, 'ListTasks', {})).status, 401);
  db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(dana.id);
});

test('JSON-RPC errors follow the spec\'s codes', async () => {
  const t = tokens['dana-bot'];
  assert.equal((await rpc(t, 'NoSuchMethod', {})).body.error.code, -32601);
  assert.equal((await rpc(t, 'tasks/get', { id: 'x' })).body.error.code, -32601, 'the 0.x slash names are not 1.0 methods');
  const noId = await rpc(t, 'GetTask', {});
  assert.equal(noId.body.error.code, -32602);
  assert.equal(noId.body.error.data[0]['@type'], 'type.googleapis.com/google.rpc.BadRequest');
  assert.equal(noId.body.error.data[0].fieldViolations[0].field, 'id');
  const missing = await rpc(t, 'GetTask', { id: 'no-such-task' });
  assert.equal(missing.body.error.code, -32001);
  const info = missing.body.error.data.find((d) => d['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo');
  assert.equal(info.reason, 'TASK_NOT_FOUND');
  assert.equal(info.domain, 'a2a-protocol.org');
  assert.equal((await rpc(t, 'ListTasks', {}, { version: null })).body.error.code, -32009, 'no A2A-Version means 0.3 (spec §3.6.2)');
  assert.equal((await rpc(t, 'ListTasks', {}, { version: '0.3' })).body.error.code, -32009);
  assert.equal((await rpc(t, 'ListTasks', {}, { version: '1.0.2' })).status, 200, 'patch versions are ignored');
  assert.equal((await rpcRaw(t, '{"jsonrpc":"2.0",')).body.error.code, -32700);
  assert.equal((await rpcRaw(t, [{ jsonrpc: '2.0', id: 1, method: 'ListTasks' }])).body.error.code, -32600);
  assert.equal((await rpcRaw(t, { jsonrpc: '1.0', id: 1, method: 'ListTasks' })).body.error.code, -32600);
  const raw = await rpc(t, 'SendMessage', { tenant: 'dana-two', message: { messageId: 'r', role: 'ROLE_USER', parts: [{ url: 'https://files.example.com/x' }] } });
  assert.equal(raw.body.error.code, -32005);
  assert.equal((await rpc(t, 'SendMessage', { message: msg('no tenant') })).body.error.code, -32602);
  assert.equal((await rpc(t, 'SendMessage', { tenant: 'nobody-here', message: msg('x') })).body.error.code, -32602);
  assert.equal((await rpc(t, 'SendMessage', { tenant: 'dana-two', message: { role: 'ROLE_USER', parts: [{ text: 'x' }] } })).body.error.code, -32602, 'messageId is REQUIRED');
});

let ownTask;
test('SendMessage between one person\'s agents: delivered, visible to both, roles per a2a.proto', async () => {
  const r = await rpc(tokens['dana-bot'], 'SendMessage', {
    tenant: 'dana-two',
    message: msg('Tidy the logs\nplease do it today', { metadata: { title: 'tidy logs' } }),
    configuration: { returnImmediately: true },
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.jsonrpc, '2.0');
  const task = r.body.result.task;
  ownTask = task.id;
  assert.equal(task.status.state, 'TASK_STATE_SUBMITTED');
  assert.match(task.status.timestamp, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.equal(task.contextId, task.id);
  assert.equal(task.metadata.title, 'tidy logs');
  assert.equal(task.metadata.fromAgent, 'dana-bot');
  assert.equal(task.history[0].role, 'ROLE_USER');
  const seen = await rpc(tokens['dana-two'], 'GetTask', { id: task.id, historyLength: 0 });
  assert.equal(seen.body.result.id, task.id);
  assert.equal(seen.body.result.history, undefined, 'historyLength 0 omits history (spec §3.2.4)');
  // The receiver reports progress over A2A (Crew relay extension).
  const w = await rpc(tokens['dana-two'], 'SendMessage', { message: { messageId: 'w1', role: 'ROLE_AGENT', taskId: task.id, parts: [{ text: 'on it' }], metadata: { taskState: 'TASK_STATE_WORKING' } } });
  assert.equal(w.body.result.task.status.state, 'TASK_STATE_WORKING');
  assert.equal(w.body.result.task.history.at(-1).role, 'ROLE_AGENT');
  assert.equal(w.body.result.task.history.at(-1).messageId, 'w1');
  // contextId mismatch is refused (spec §3.4.3).
  const mm = await rpc(tokens['dana-two'], 'SendMessage', { message: { messageId: 'w2', role: 'ROLE_AGENT', taskId: task.id, contextId: 'other', parts: [{ text: 'x' }] } });
  assert.equal(mm.body.error.code, -32602);
});

test('a token acts only as its own agent — not as another agent of the same owner', async () => {
  // dana-two → lior-bot is dana-two's task. dana-bot has the same owner and
  // must still not see it.
  db.prepare("INSERT INTO crew_connections (from_agent_id, from_owner_id, to_owner_id, state) VALUES ((SELECT id FROM crew_agents WHERE name='dana-two'), ?, ?, 'allowed')").run(dana.id, lior.id);
  const r = await rpc(tokens['dana-two'], 'SendMessage', { tenant: 'lior-bot', message: msg('review my PR'), configuration: { returnImmediately: true } });
  const id = r.body.result.task.id;
  assert.equal(r.body.result.task.metadata.fromAgent, 'dana-two', 'the task is sent as the token\'s own agent');
  assert.equal((await rpc(tokens['dana-bot'], 'GetTask', { id })).body.error.code, -32001);
  assert.equal((await rpc(tokens['dana-bot'], 'CancelTask', { id })).body.error.code, -32001);
  assert.equal((await rpc(tokens['priya-bot'], 'GetTask', { id })).body.error.code, -32001);
  assert.equal((await rpc(tokens['lior-bot'], 'GetTask', { id })).body.result.id, id, 'the receiver sees it');
  const listed = (await rpc(tokens['dana-bot'], 'ListTasks', {})).body.result.tasks.map((t) => t.id);
  assert.ok(listed.includes(ownTask));
  assert.ok(!listed.includes(id));
});

test('first contact over A2A is held and e-mails the receiving person exactly once', async () => {
  const before = emailsTo(rita);
  const r = await rpc(tokens['lior-bot'], 'SendMessage', { tenant: 'rita-bot', message: msg(`please ${BODY_MARK}`, { metadata: { title: TITLE_MARK } }), configuration: { returnImmediately: true } });
  const task = r.body.result.task;
  assert.equal(task.status.state, 'TASK_STATE_SUBMITTED');
  assert.equal(task.metadata.waitingForApproval, true);
  assert.equal(emailsTo(rita), before + 1);
  // The receiver's agent cannot see a held task, by id or in a list.
  assert.equal((await rpc(tokens['rita-bot'], 'GetTask', { id: task.id })).body.error.code, -32001);
  assert.ok(!(await rpc(tokens['rita-bot'], 'ListTasks', {})).body.result.tasks.some((t) => t.id === task.id));
  await rpc(tokens['lior-bot'], 'SendMessage', { tenant: 'rita-bot', message: msg('second'), configuration: { returnImmediately: true } });
  assert.equal(emailsTo(rita), before + 1, 'still one e-mail');
  // Audited as the agent, without the title or body.
  const row = db.prepare("SELECT actor_kind, detail FROM audit_log WHERE action = 'crew.task.send' AND detail LIKE ?").get(`%${task.id}%`);
  assert.equal(row.actor_kind, 'agent');
  assert.ok(!row.detail.includes(TITLE_MARK) && !row.detail.includes(BODY_MARK));
});

test('a blocked sender gets TASK_STATE_REJECTED and nothing else', async () => {
  const r = await rest(priya, 'POST', '/api/crew/blocks', { agent: 'lior-bot' });
  assert.equal(r.status, 201);
  const s = await rpc(tokens['lior-bot'], 'SendMessage', { tenant: 'priya-bot', message: msg('hello') });
  const task = s.body.result.task;
  assert.equal(task.status.state, 'TASK_STATE_REJECTED');
  assert.deepEqual(task.history || [], [], 'a rejected task carries no history');
  assert.equal(emailsTo(priya), 0);
  assert.equal((await rpc(tokens['priya-bot'], 'GetTask', { id: task.id })).body.error.code, -32001);
});

test('secrets are refused over A2A too, by the same scanner', async () => {
  const r = await rpc(tokens['dana-bot'], 'SendMessage', { tenant: 'dana-two', message: msg('use AKIAABCDEFGHIJKLMNOP for s3') });
  assert.equal(r.body.error.code, -32602);
  assert.match(r.body.error.message, /credential \(aws-access-key\)/);
});

test('replies, artifacts, terminal states and CancelTask', async () => {
  const r = await rpc(tokens['dana-bot'], 'SendMessage', { tenant: 'dana-two', message: msg('write notes'), configuration: { returnImmediately: true } });
  const id = r.body.result.task.id;
  const done = await rpc(tokens['dana-two'], 'SendMessage', { message: { messageId: 'd1', role: 'ROLE_AGENT', taskId: id, parts: [{ text: 'done' }, { text: '# Notes', filename: 'notes.md' }], metadata: { taskState: 'TASK_STATE_COMPLETED' } } });
  const t = done.body.result.task;
  assert.equal(t.status.state, 'TASK_STATE_COMPLETED');
  assert.equal(t.artifacts[0].name, 'notes.md');
  assert.equal(t.artifacts[0].parts[0].text, '# Notes');
  const again = await rpc(tokens['dana-two'], 'SendMessage', { message: { messageId: 'd2', role: 'ROLE_AGENT', taskId: id, parts: [{ text: 'more' }] } });
  assert.equal(again.body.error.code, -32004, 'messages to a terminal task: UnsupportedOperationError (spec §3.1.1)');
  assert.equal((await rpc(tokens['dana-bot'], 'CancelTask', { id })).body.error.code, -32002);
  const bad = await rpc(tokens['dana-two'], 'SendMessage', { message: { messageId: 'd3', role: 'ROLE_AGENT', taskId: ownTask, parts: [{ text: 'x' }], metadata: { taskState: 'TASK_STATE_AUTH_REQUIRED' } } });
  assert.equal(bad.body.error.code, -32602, 'Crew has no AUTH_REQUIRED state');

  const c = await rpc(tokens['dana-bot'], 'SendMessage', { tenant: 'dana-two', message: msg('maybe'), configuration: { returnImmediately: true } });
  const cid = c.body.result.task.id;
  assert.equal((await rpc(tokens['dana-two'], 'CancelTask', { id: cid })).body.error.code, -32002, 'only the sender cancels');
  const canceled = await rpc(tokens['dana-bot'], 'CancelTask', { id: cid });
  assert.equal(canceled.body.result.status.state, 'TASK_STATE_CANCELED');
  assert.equal((await rpc(tokens['dana-bot'], 'CancelTask', { id: cid })).body.error.code, -32002);
});

test('ListTasks: newest first, cursor pages, artifacts omitted unless asked', async () => {
  const t = tokens['dana-bot'];
  const p1 = (await rpc(t, 'ListTasks', { pageSize: 1 })).body.result;
  assert.equal(p1.tasks.length, 1);
  assert.equal(p1.pageSize, 1);
  assert.ok(p1.totalSize >= 3);
  assert.ok(p1.nextPageToken);
  assert.ok(!('artifacts' in p1.tasks[0]), 'includeArtifacts defaults to false: field omitted (spec §3.1.4)');
  const p2 = (await rpc(t, 'ListTasks', { pageSize: 1, pageToken: p1.nextPageToken })).body.result;
  assert.notEqual(p2.tasks[0].id, p1.tasks[0].id);
  const all = (await rpc(t, 'ListTasks', { pageSize: 100, includeArtifacts: true })).body.result;
  assert.equal(all.nextPageToken, '', 'last page: empty string, never absent');
  assert.ok(all.tasks.every((x) => Array.isArray(x.artifacts)));
  const stamps = all.tasks.map((x) => x.status.timestamp);
  assert.deepEqual([...stamps].sort().reverse(), stamps);
  const completed = (await rpc(t, 'ListTasks', { status: 'TASK_STATE_COMPLETED' })).body.result.tasks;
  assert.ok(completed.length >= 1 && completed.every((x) => x.status.state === 'TASK_STATE_COMPLETED'));
  assert.equal((await rpc(t, 'ListTasks', { pageToken: 'garbage' })).body.error.code, -32602);
  assert.equal((await rpc(t, 'ListTasks', { pageSize: 0 })).body.error.code, -32602);
});

/** Read an SSE response until it ends; returns the parsed `data:` payloads. */
async function readSse(res) {
  const text = await res.text();
  return text.split('\n\n').filter((b) => b.startsWith('data: ')).map((b) => JSON.parse(b.slice(6)));
}

test('SendStreamingMessage: the Task first, then status/artifact updates, closed at a terminal state', async () => {
  const res = await fetch(`${BASE}/a2a`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokens['dana-bot']}`, 'A2A-Version': '1.0' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'stream-1', method: 'SendStreamingMessage', params: { tenant: 'dana-two', message: msg('stream me') } }),
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /^text\/event-stream/);
  const eventsP = readSse(res);
  // Find the task and work it from the receiver's side.
  await new Promise((r) => setTimeout(r, 50));
  const id = db.prepare("SELECT t.id FROM crew_tasks t JOIN crew_messages m ON m.task_id = t.id WHERE m.body = 'stream me'").get().id;
  await rpc(tokens['dana-two'], 'SendMessage', { message: { messageId: 's1', role: 'ROLE_AGENT', taskId: id, parts: [{ text: 'working' }], metadata: { taskState: 'TASK_STATE_WORKING' } } });
  await rpc(tokens['dana-two'], 'SendMessage', { message: { messageId: 's2', role: 'ROLE_AGENT', taskId: id, parts: [{ text: 'result', filename: 'out.txt' }], metadata: { taskState: 'TASK_STATE_COMPLETED' } } });
  const events = await eventsP;
  assert.ok(events.every((e) => e.jsonrpc === '2.0' && e.id === 'stream-1'));
  assert.equal(events[0].result.task.id, id);
  assert.equal(events[0].result.task.status.state, 'TASK_STATE_SUBMITTED');
  const kinds = events.slice(1).map((e) => Object.keys(e.result)[0]);
  assert.ok(kinds.every((k) => k === 'statusUpdate' || k === 'artifactUpdate'), kinds.join(','));
  assert.ok(events.some((e) => e.result.statusUpdate?.status.state === 'TASK_STATE_WORKING'));
  assert.ok(events.some((e) => e.result.artifactUpdate?.artifact.name === 'out.txt'));
  assert.equal(events.at(-1).result.statusUpdate?.status.state ?? events.at(-2).result.statusUpdate?.status.state, 'TASK_STATE_COMPLETED');
  // SubscribeToTask on a terminal task is UnsupportedOperationError.
  assert.equal((await rpc(tokens['dana-bot'], 'SubscribeToTask', { id })).body.error.code, -32004);
});

test('SubscribeToTask streams an existing task to a party, never to anyone else', async () => {
  const r = await rpc(tokens['dana-bot'], 'SendMessage', { tenant: 'dana-two', message: msg('subscribe me'), configuration: { returnImmediately: true } });
  const id = r.body.result.task.id;
  assert.equal((await rpc(tokens['lior-bot'], 'SubscribeToTask', { id })).body.error.code, -32001);
  const res = await fetch(`${BASE}/a2a`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokens['dana-two']}`, 'A2A-Version': '1.0' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'SubscribeToTask', params: { id } }),
  });
  const eventsP = readSse(res);
  await new Promise((resolve) => setTimeout(resolve, 30));
  await rpc(tokens['dana-bot'], 'CancelTask', { id });
  const events = await eventsP;
  assert.equal(events[0].result.task.id, id);
  assert.equal(events.at(-1).result.statusUpdate.status.state, 'TASK_STATE_CANCELED');
});

test('GetExtendedAgentCard and per-agent cards are for authenticated callers', async () => {
  const ext = (await rpc(tokens['priya-bot'], 'GetExtendedAgentCard')).body.result;
  assert.ok(ext.skills.some((s) => s.id === 'agent:lior-bot' && s.tags.includes('relay')));
  assert.ok(!JSON.stringify(ext).includes('blocked'), 'no block information in the card');
  const res = await fetch(`${BASE}/a2a/agents/lior-bot/card`, { headers: { Authorization: `Bearer ${tokens['dana-bot']}` } });
  assert.equal(res.status, 200);
  const card = await res.json();
  assert.deepEqual(card.supportedInterfaces, [{ url: 'https://crane.example.com/a2a', protocolBinding: 'JSONRPC', tenant: 'lior-bot', protocolVersion: '1.0' }]);
  assert.equal((await fetch(`${BASE}/a2a/agents/lior-bot/card`)).status, 401);
  assert.equal((await fetch(`${BASE}/a2a/agents/nobody-here/card`, { headers: { Authorization: `Bearer ${tokens['dana-bot']}` } })).status, 404);
});

test('push config methods: create (SSRF-checked), get/list without secrets, delete idempotently', async () => {
  const r = await rpc(tokens['dana-bot'], 'SendMessage', { tenant: 'dana-two', message: msg('push me'), configuration: { returnImmediately: true } });
  const taskId = r.body.result.task.id;
  for (const url of ['https://127.0.0.1/hook', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/hook', 'https://10.0.0.8/hook', 'http://push.example.com/hook', 'https://localhost/hook']) {
    const bad = await rpc(tokens['dana-bot'], 'CreateTaskPushNotificationConfig', { taskId, url });
    assert.equal(bad.body.error?.code, -32602, `${url} was accepted`);
  }
  const before = db.prepare('SELECT COUNT(*) AS n FROM crew_tasks').get().n;
  const viaSend = await rpc(tokens['dana-bot'], 'SendMessage', { tenant: 'dana-two', message: msg('x'), configuration: { taskPushNotificationConfig: { url: 'https://169.254.169.254/' } } });
  assert.equal(viaSend.body.error.code, -32602);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM crew_tasks').get().n, before, 'a refused push config leaves no task behind');

  const created = await rpc(tokens['dana-bot'], 'CreateTaskPushNotificationConfig', {
    taskId, url: 'https://push.example.com/hook', token: 'client-token', authentication: { scheme: 'Bearer', credentials: 'webhook-secret-value' },
  });
  const cfg = created.body.result;
  assert.equal(cfg.taskId, taskId);
  assert.equal(cfg.url, 'https://push.example.com/hook');
  assert.deepEqual(cfg.authentication, { scheme: 'Bearer' });
  assert.ok(!JSON.stringify(cfg).includes('webhook-secret-value') && !JSON.stringify(cfg).includes('client-token'));
  const row = db.prepare('SELECT * FROM crew_push_configs WHERE id = ?').get(cfg.id);
  assert.ok(!row.auth_credentials_enc.includes('webhook-secret-value'), 'credentials are stored encrypted');
  assert.equal((await rpc(tokens['dana-bot'], 'GetTaskPushNotificationConfig', { taskId, id: cfg.id })).body.result.id, cfg.id);
  assert.equal((await rpc(tokens['dana-bot'], 'ListTaskPushNotificationConfigs', { taskId })).body.result.configs.length, 1);
  // The other party has its own configs, not this one.
  assert.equal((await rpc(tokens['dana-two'], 'GetTaskPushNotificationConfig', { taskId, id: cfg.id })).body.error.code, -32001);
  assert.equal((await rpc(tokens['lior-bot'], 'ListTaskPushNotificationConfigs', { taskId })).body.error.code, -32001);
  assert.deepEqual((await rpc(tokens['dana-bot'], 'DeleteTaskPushNotificationConfig', { taskId, id: cfg.id })).body.result, {});
  assert.deepEqual((await rpc(tokens['dana-bot'], 'DeleteTaskPushNotificationConfig', { taskId, id: cfg.id })).body.result, {}, 'idempotent (spec §3.1.10)');
});

test('the map: counts only, never titles or bodies; a block is shown only to the person who blocked', async () => {
  // Rita blocks lior-bot (which has two held tasks waiting on her) and lior-bot
  // tries again.
  assert.equal((await rest(rita, 'POST', '/api/crew/blocks', { agent: 'lior-bot' })).status, 201);
  await rpc(tokens['lior-bot'], 'SendMessage', { tenant: 'rita-bot', message: msg('third', { metadata: { title: TITLE_MARK } }) });

  const forRita = (await rest(rita, 'GET', '/api/crew/map')).body;
  const forLior = (await rest(lior, 'GET', '/api/crew/map')).body;
  const forPriya = (await rest(priya, 'GET', '/api/crew/map')).body;
  for (const m of [forRita, forLior, forPriya]) {
    const s = JSON.stringify(m);
    assert.ok(!s.includes(TITLE_MARK), 'a title reached the map');
    assert.ok(!s.includes(BODY_MARK), 'a body reached the map');
    assert.ok(!s.includes('tidy logs'), 'a title reached the map');
    assert.ok(m.nodes.some((n) => n.name === 'lior-bot' && n.owner === 'Lior'));
    for (const e of m.edges) assert.deepEqual(Object.keys(e).filter((k) => !['from', 'to', 'total', 'pending_first_contact', 'last_activity', 'states', 'blocked', 'refused'].includes(k)), []);
  }
  const ritaEdge = forRita.edges.find((e) => e.from === 'lior-bot' && e.to === 'rita-bot');
  assert.equal(ritaEdge.blocked, true);
  assert.equal(ritaEdge.states.rejected, 3);
  const liorEdge = forLior.edges.find((e) => e.from === 'lior-bot' && e.to === 'rita-bot');
  assert.equal(liorEdge.states.rejected, 3, 'the sender sees its rejections, as in its log');
  assert.equal(liorEdge.blocked, undefined, 'but never that it was blocked');
  assert.ok(!forPriya.edges.some((e) => e.from === 'lior-bot' && e.to === 'rita-bot'), 'third parties see no rejected-only edge');
  // Priya's own block of lior-bot is hers alone.
  assert.equal(forPriya.edges.find((e) => e.from === 'lior-bot' && e.to === 'priya-bot').blocked, true);
  assert.equal(forRita.edges.find((e) => e.from === 'lior-bot' && e.to === 'priya-bot'), undefined);
  // Accepted traffic between other people's agents is visible to everyone.
  const accepted = forPriya.edges.find((e) => e.from === 'dana-two' && e.to === 'lior-bot');
  assert.equal(accepted.total, 1);
  assert.equal(accepted.states.submitted, 1);
  // Owners are colour keys, not user ids.
  assert.ok(forPriya.nodes.every((n) => Number.isInteger(n.owner_key) && !('owner_user_id' in n)));
});
