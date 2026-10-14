import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// A2A SendMessage without returnImmediately waits (bounded) for the task to
// settle. That wait is for a SENDER waiting on another agent. Measured behind
// Caddy: the receiver's own progress reports (WORKING, replies) also waited the
// full bound, 30 s each by default, because only the caller itself could settle
// the task it was holding open. The suite's other A2A tests run with the wait
// set to 0, which is why nothing caught it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-a2a-block-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.com';
process.env.LOG_LEVEL = 'error';
const WAIT_MS = 3000;
process.env.CREW_A2A_BLOCKING_WAIT_MS = String(WAIT_MS);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name) {
  const key = generateApiKey('dhk_user');
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,'user',?,1,'human')")
    .run(name, `${name.toLowerCase()}@example.com`, hashApiKey(key));
  return { key };
}
const dana = mkUser('Dana');

const a2aRoutes = (await import('../server/routes/a2a.js')).default;
const crewRoutes = (await import('../server/routes/crew.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const app = express();
app.use('/a2a', a2aRoutes);
app.use(express.json());
app.use('/api/crew', crewRoutes);
app.use(errorHandler);
const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

async function register(name) {
  const r = await fetch(`${BASE}/api/crew/agents`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': dana.key }, body: JSON.stringify({ name }),
  });
  return (await r.json()).a2a_token;
}
let n = 0;
async function rpc(token, method, params) {
  const t0 = Date.now();
  const res = await fetch(`${BASE}/a2a`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'A2A-Version': '1.0', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++n, method, params }),
  });
  return { body: await res.json(), ms: Date.now() - t0 };
}

test('the receiver reporting progress on its own task is answered at once', async () => {
  const sender = await register('send-bot');
  const receiver = await register('recv-bot');
  const sent = await rpc(sender, 'SendMessage', {
    tenant: 'recv-bot', message: { messageId: 'a', role: 'ROLE_USER', parts: [{ text: 'do it' }] }, configuration: { returnImmediately: true },
  });
  const id = sent.body.result.task.id;
  const working = await rpc(receiver, 'SendMessage', {
    message: { messageId: 'b', role: 'ROLE_AGENT', taskId: id, parts: [{ text: 'on it' }], metadata: { taskState: 'TASK_STATE_WORKING' } },
  });
  assert.equal(working.body.result.task.status.state, 'TASK_STATE_WORKING');
  assert.ok(working.ms < WAIT_MS / 2, `receiver's WORKING update took ${working.ms} ms; it must not wait on itself`);
});

test('a sender without returnImmediately still waits until the receiver settles the task', async () => {
  const sender = await register('send-two');
  const receiver = await register('recv-two');
  const pending = rpc(sender, 'SendMessage', {
    tenant: 'recv-two', message: { messageId: 'c', role: 'ROLE_USER', parts: [{ text: 'and this' }] },
  });
  await new Promise((r) => setTimeout(r, 300));
  const list = await rpc(receiver, 'ListTasks', {});
  const id = list.body.result.tasks[0].id;
  await rpc(receiver, 'SendMessage', {
    message: { messageId: 'd', role: 'ROLE_AGENT', taskId: id, parts: [{ text: 'done' }], metadata: { taskState: 'TASK_STATE_COMPLETED' } },
  });
  const done = await pending;
  assert.equal(done.body.result.task.status.state, 'TASK_STATE_COMPLETED');
  assert.ok(done.ms >= 300 && done.ms < WAIT_MS, `sender returned after ${done.ms} ms`);
});
