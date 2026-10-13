import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import https from 'https';

// Crew, phase 2 (v2.106.0): A2A push notifications and their SSRF guard.
//
// The guard is tested against REAL sockets where it matters: a loopback TCP
// listener counts connections, and a refused target must produce ZERO of them.
// "The request failed" is not enough — a request that was attempted and then
// failed (ECONNREFUSED, TLS error) is exactly the SSRF primitive.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-push-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { postSafely, validatePushConfig, createPushConfig, startCrewPush, drainPushQueue, PUSH_LIMITS } = await import('../server/services/crewPush.js');
const { makeGuardedLookup } = await import('../server/services/remoteFetch.js');
const { registerAgent, sendTask, reply, taskFor } = await import('../server/services/crew.js');
const { generateCa, issueCert } = await import('../server/services/dbPki.js');
const { rotateAgentToken, revokeAgentToken } = await import('../server/services/crewTokens.js');

// A loopback listener that only counts who connects.
let connections = 0;
const counter = net.createServer((s) => { connections += 1; s.destroy(); });
await new Promise((r) => counter.listen(0, '127.0.0.1', r));
const COUNTER_PORT = counter.address().port;
const counter6 = net.createServer((s) => { connections += 1; s.destroy(); });
const have6 = await new Promise((r) => { counter6.once('error', () => r(false)); counter6.listen(COUNTER_PORT, '::1', () => r(true)); });

// A local TLS server, for the paths that must actually connect (redirects,
// success). Trusted through a throwaway CA from dbPki; the address guard is
// lifted for these calls ONLY, explicitly, via postSafely's test parameter.
const ca = generateCa({ commonName: 'Crew Push Test CA' });
const leaf = issueCert({ ca, commonName: 'localhost', usage: 'server', ips: ['127.0.0.1'] });
const seen = [];
let respond = (req, res) => { res.writeHead(200); res.end('ok'); };
const tls = https.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => { seen.push({ url: req.url, headers: req.headers, body }); respond(req, res); });
});
await new Promise((r) => tls.listen(0, '127.0.0.1', r));
const TLS_URL = `https://127.0.0.1:${tls.address().port}`;
const allowLocal = { isBlocked: () => false, ca: ca.certPem };

after(() => { counter.close(); counter6.close(); tls.closeAllConnections?.(); tls.close(); });

test('postSafely refuses loopback, private, link-local and metadata targets without connecting', async () => {
  const targets = [
    `https://127.0.0.1:${COUNTER_PORT}/hook`,
    `https://localhost:${COUNTER_PORT}/hook`,          // a NAME that resolves to loopback
    ...(have6 ? [`https://[::1]:${COUNTER_PORT}/hook`] : []),
    'https://10.1.2.3/hook',
    'https://172.16.0.9/hook',
    'https://192.168.1.1/hook',
    'https://169.254.169.254/latest/meta-data/',
    'https://[::ffff:127.0.0.1]/hook',
  ];
  for (const url of targets) {
    const r = await postSafely(url, { body: '{}', timeoutMs: 2000 });
    assert.equal(r.ok, false, url);
    assert.equal(r.reason, 'blocked_address', `${url} → ${r.reason}`);
    assert.equal(r.permanent, true);
  }
  assert.equal(connections, 0, 'a refused target must never be dialled');
});

test('a public-looking name that resolves to a private address is refused at connect time', async () => {
  const resolve = async (host) => (host === 'internal.example.com' ? [{ address: '10.20.30.40', family: 4 }] : [{ address: '127.0.0.1', family: 4 }]);
  for (const host of ['internal.example.com', 'rebind.example.com']) {
    const r = await postSafely(`https://${host}:${COUNTER_PORT}/hook`, { body: '{}', lookup: makeGuardedLookup({ resolve }) });
    assert.equal(r.reason, 'blocked_address', host);
  }
  assert.equal(connections, 0);
});

test('redirects are never followed: a 3xx is a failed delivery, Location unread', async () => {
  respond = (req, res) => { res.writeHead(302, { Location: 'https://169.254.169.254/latest/meta-data/' }); res.end(); };
  seen.length = 0;
  const r = await postSafely(`${TLS_URL}/hook`, { body: '{"x":1}', ...allowLocal });
  assert.deepEqual({ ok: r.ok, status: r.status, reason: r.reason }, { ok: false, status: 302, reason: 'redirect_refused' });
  assert.equal(seen.length, 1, 'exactly one request: the redirect was not followed');
  respond = (req, res) => { res.writeHead(200); res.end('ok'); };
});

test('http:// is refused before any request', async () => {
  assert.deepEqual(await postSafely(`http://127.0.0.1:${COUNTER_PORT}/x`, { body: '{}' }), { ok: false, reason: 'not_https', permanent: true });
  assert.equal(connections, 0);
});

test('a slow webhook times out; the response body is never kept', async () => {
  respond = () => { /* never answer */ };
  const r = await postSafely(`${TLS_URL}/slow`, { body: '{}', timeoutMs: 200, ...allowLocal });
  assert.equal(r.reason, 'timeout');
  respond = (req, res) => { res.writeHead(200); res.end('x'.repeat(PUSH_LIMITS.RESPONSE_MAX_BYTES * 2)); };
  const big = await postSafely(`${TLS_URL}/big`, { body: '{}', ...allowLocal });
  assert.equal(big.ok, true);
  assert.deepEqual(Object.keys(big).sort(), ['ok', 'reason', 'status'], 'no body field: nothing from the response is returned or stored');
  respond = (req, res) => { res.writeHead(200); res.end('ok'); };
});

test('validatePushConfig refuses unsafe URLs and header injection at create time', () => {
  for (const url of ['http://push.example.com/h', 'https://user:pw@push.example.com/h', 'https://127.0.0.1/h', 'https://[::1]/h',
    'https://169.254.169.254/', 'https://localhost/h', 'https://a.localhost/h', 'notaurl', `https://push.example.com/${'a'.repeat(2100)}`]) {
    assert.throws(() => validatePushConfig({ url }), undefined, url);
  }
  assert.throws(() => validatePushConfig({ url: 'https://push.example.com/h', authentication: { scheme: 'Bearer', credentials: 'x\r\nX-Evil: 1' } }));
  assert.throws(() => validatePushConfig({ url: 'https://push.example.com/h', authentication: { scheme: 'Bear er' } }));
  assert.throws(() => validatePushConfig({ url: 'https://push.example.com/h', token: 'a\nb' }));
  assert.deepEqual(validatePushConfig({ url: 'https://push.example.com/h', token: 't', authentication: { scheme: 'Bearer', credentials: 'c' } }),
    { url: 'https://push.example.com/h', token: 't', scheme: 'Bearer', credentials: 'c' });
});

// ── The delivery pipeline, with the network stubbed ─────────────────────────

const owner = (() => {
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Sam','sam@example.com','user','x-not-a-key',1,'human')").run().lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
})();
registerAgent(owner, { name: 'push-sender' }, { kind: 'hosted', actorKind: 'human' });
registerAgent(owner, { name: 'push-worker' }, { kind: 'hosted', actorKind: 'human' });
const sender = db.prepare("SELECT * FROM crew_agents WHERE name = 'push-sender'").get();
rotateAgentToken(owner, 'push-sender');
const liveTokenId = () => db.prepare('SELECT id FROM crew_agent_tokens WHERE agent_id = ? AND revoked_at IS NULL').get(sender.id).id;

function newTaskWithConfig(cfg = { url: 'https://push.example.com/hook', token: 'tok-1', authentication: { scheme: 'Bearer', credentials: 'cred-1' } }) {
  const { task_id } = sendTask(owner, { as_agent: 'push-sender', to_agent: 'push-worker', title: 'work', message: 'please' }, { actorKind: 'agent' });
  const config = createPushConfig(owner, sender, taskFor(sender.id, task_id), validatePushConfig(cfg), liveTokenId());
  return { task_id, config };
}

test('each update is POSTed as a StreamResponse with the client\'s Authorization and token', async () => {
  const calls = [];
  const stop = startCrewPush({ post: async (url, o) => { calls.push({ url, ...o }); return { ok: true, status: 200 }; }, delays: [1, 1] });
  const { task_id } = newTaskWithConfig();
  reply(owner, { as_agent: 'push-worker', task_id, message: 'on it', state: 'working' }, { actorKind: 'agent' });
  reply(owner, { as_agent: 'push-worker', task_id, message: 'done', state: 'completed', artifact: { name: 'r.md', body: 'ok' } }, { actorKind: 'agent' });
  await new Promise((r) => setTimeout(r, 30));
  await drainPushQueue();
  stop();
  assert.ok(calls.length >= 3, `expected >= 3 deliveries, got ${calls.length}`);
  for (const c of calls) {
    assert.equal(c.url, 'https://push.example.com/hook');
    assert.equal(c.headers.Authorization, 'Bearer cred-1');
    assert.equal(c.headers['X-A2A-Notification-Token'], 'tok-1');
  }
  const payloads = calls.map((c) => JSON.parse(c.body));
  assert.equal(payloads[0].statusUpdate.status.state, 'TASK_STATE_WORKING');
  assert.ok(payloads.some((p) => p.artifactUpdate?.artifact.name === 'r.md'));
  assert.equal(payloads.at(-1).statusUpdate.status.state, 'TASK_STATE_COMPLETED');
  assert.ok(payloads.every((p) => Object.keys(p).length === 1), 'exactly one StreamResponse member per POST (spec §4.3.3)');
  assert.equal(calls.length, 3, 'working, artifact, completed — nothing after the terminal state');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM crew_push_configs WHERE task_id = ?').get(task_id).n, 0, 'the config and its secrets are removed once the task is done');
});

test('failures retry with backoff; a refused address is not retried; repeated failures disable the config', async () => {
  let attempts = 0;
  let stop = startCrewPush({ post: async () => { attempts += 1; return { ok: false, status: 500, reason: 'http_500' }; }, delays: [1, 1, 1] });
  const a = newTaskWithConfig();
  reply(owner, { as_agent: 'push-worker', task_id: a.task_id, message: 'x', state: 'working' }, { actorKind: 'agent' });
  await new Promise((r) => setTimeout(r, 30));
  await drainPushQueue();
  stop();
  assert.equal(attempts, 4, 'one attempt plus three retries');
  assert.equal(db.prepare('SELECT consecutive_failures FROM crew_push_configs WHERE id = ?').get(a.config.id).consecutive_failures, 1);

  attempts = 0;
  stop = startCrewPush({ post: async () => { attempts += 1; return { ok: false, reason: 'blocked_address', permanent: true }; }, delays: [1, 1, 1] });
  const b = newTaskWithConfig();
  for (let i = 0; i < PUSH_LIMITS.MAX_CONSECUTIVE_FAILURES + 2; i++) {
    reply(owner, { as_agent: 'push-worker', task_id: b.task_id, message: `m${i}` }, { actorKind: 'agent' });
    await new Promise((r) => setTimeout(r, 5));
  }
  await new Promise((r) => setTimeout(r, 30));
  await drainPushQueue();
  stop();
  assert.equal(attempts, PUSH_LIMITS.MAX_CONSECUTIVE_FAILURES, 'no retries for a refused address, and nothing after the config is disabled');
  assert.ok(db.prepare('SELECT disabled_at FROM crew_push_configs WHERE id = ?').get(b.config.id).disabled_at);
});

test('the real delivery path goes through the guard: a config whose host turns private delivers nothing', async () => {
  const stop = startCrewPush({ delays: [1] });
  const { task_id, config } = newTaskWithConfig({ url: `https://localhost.example.invalid:${COUNTER_PORT}/hook` });
  // Point the stored URL at loopback, as a DNS change after creation would.
  db.prepare('UPDATE crew_push_configs SET url = ? WHERE id = ?').run(`https://127.0.0.1:${COUNTER_PORT}/hook`, config.id);
  reply(owner, { as_agent: 'push-worker', task_id, message: 'x', state: 'working' }, { actorKind: 'agent' });
  await new Promise((r) => setTimeout(r, 30));
  await drainPushQueue();
  stop();
  assert.equal(connections, 0);
  assert.equal(db.prepare('SELECT last_status FROM crew_push_configs WHERE id = ?').get(config.id).last_status, 'blocked_address');
});

test('revoking the token, or deactivating the owner, ends delivery and removes the config', async () => {
  const calls = [];
  const stop = startCrewPush({ post: async (url, o) => { calls.push(o); return { ok: true, status: 200 }; }, delays: [1] });
  const configs = (taskId) => db.prepare('SELECT COUNT(*) AS n FROM crew_push_configs WHERE task_id = ?').get(taskId).n;

  // 1. Revoke: the config goes in the same transaction, and nothing more is sent.
  const a = newTaskWithConfig();
  revokeAgentToken(owner, 'push-sender');
  assert.equal(configs(a.task_id), 0, 'revocation removes the agent\'s push configs at once');
  reply(owner, { as_agent: 'push-worker', task_id: a.task_id, message: 'after revoke', state: 'working' }, { actorKind: 'agent' });
  await new Promise((r) => setTimeout(r, 30));
  await drainPushQueue();
  assert.equal(calls.length, 0, 'a revoked token still received task content');

  // 2. Deactivated owner: the delivery-time check refuses and deletes.
  rotateAgentToken(owner, 'push-sender');
  const b = newTaskWithConfig();
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(owner.id);
  reply(owner, { as_agent: 'push-worker', task_id: b.task_id, message: 'after deactivation', state: 'working' }, { actorKind: 'agent' });
  await new Promise((r) => setTimeout(r, 30));
  await drainPushQueue();
  db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(owner.id);
  assert.equal(calls.length, 0, 'a deactivated owner\'s agent still received task content');
  assert.equal(configs(b.task_id), 0, 'the config is removed');

  // 3. A token revoked straight in the database (no hook ran): still refused.
  const c = newTaskWithConfig();
  db.prepare("UPDATE crew_agent_tokens SET revoked_at = datetime('now') WHERE agent_id = ?").run(sender.id);
  reply(owner, { as_agent: 'push-worker', task_id: c.task_id, message: 'x', state: 'working' }, { actorKind: 'agent' });
  await new Promise((r) => setTimeout(r, 30));
  await drainPushQueue();
  stop();
  assert.equal(calls.length, 0, 'the delivery-time check did not catch a revoked token');
  assert.equal(configs(c.task_id), 0);
  rotateAgentToken(owner, 'push-sender');
});
