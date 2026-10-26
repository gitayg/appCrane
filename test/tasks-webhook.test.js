import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import net from 'net';
import https from 'https';
import express from 'express';

// Tasks webhook: an app learns of assignee replies and status changes by an
// https POST to a URL it registered, signed with its own service token, behind
// the same SSRF guard as Crew push. A refused target must see ZERO connections.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tasks-hook-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name) {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,'user',?,1,'human')")
    .run(name, `${name.toLowerCase()}@example.com`, hashApiKey(key)).lastInsertRowid);
  return { id, key };
}
const dana = mkUser('Dana');
const lior = mkUser('Lior');
const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('CRM','crm',1,'managed','main')").run().lastInsertRowid);
for (const u of [dana, lior]) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, u.id);

const { issueServiceToken } = await import('../server/services/appServiceToken.js');
const token = issueServiceToken(appId);
const { configureTaskWebhooks, drainTaskWebhooks, postJsonSafely, setWebhook, getWebhook } = await import('../server/services/tasksWebhook.js');
const { generateCa, issueCert } = await import('../server/services/dbPki.js');

let connections = 0;
const counter = net.createServer((s) => { connections += 1; s.destroy(); });
await new Promise((r) => counter.listen(0, '127.0.0.1', r));
const COUNTER_PORT = counter.address().port;

const ca = generateCa({ commonName: 'Tasks Webhook Test CA' });
const leaf = issueCert({ ca, commonName: 'localhost', usage: 'server', ips: ['127.0.0.1'] });
const seen = [];
const tls = https.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => { seen.push({ headers: req.headers, body }); res.writeHead(200); res.end('ok'); });
});
await new Promise((r) => tls.listen(0, '127.0.0.1', r));
const TLS_URL = `https://127.0.0.1:${tls.address().port}/hook`;

const tasksServiceRoutes = (await import('../server/routes/tasksService.js')).default;
const tasksRoutes = (await import('../server/routes/tasks.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/service/tasks', tasksServiceRoutes);
api.use('/api/tasks', tasksRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => {
  counter.close(); tls.closeAllConnections?.(); tls.close();
  server.closeAllConnections?.(); server.close();
});

async function call(method, path, headers, body) {
  const res = await fetch(`${BASE}${path}`, {
    method, headers: { 'Content-Type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
const asApp = (method, path, body) => call(method, `/api/service/tasks${path}`, { 'X-AppCrane-Service-Token': token }, body);
const asUser = (u, method, path, body) => call(method, `/api/tasks${path}`, { 'X-API-Key': u.key }, body);

// Names resolve through this table, so no test depends on real DNS.
const DNS = { 'hooks.example.com': '93.184.216.34', 'internal.example.com': '10.20.30.40', 'meta.example.com': '169.254.169.254' };
configureTaskWebhooks({ delays: [0], resolve: async (h) => [{ address: net.isIP(h) ? h : (DNS[h] || '127.0.0.1'), family: net.isIP(h) === 6 ? 6 : 4 }] });

test('setting a webhook refuses loopback, private, link-local, http and credentialed URLs', async () => {
  const refused = [
    [`https://127.0.0.1:${COUNTER_PORT}/hook`, 'WEBHOOK_URL_BLOCKED'],
    ['https://[::1]/hook', 'WEBHOOK_URL_BLOCKED'],
    ['https://10.0.0.5/hook', 'WEBHOOK_URL_BLOCKED'],
    ['https://169.254.169.254/latest/meta-data/', 'WEBHOOK_URL_BLOCKED'],
    ['https://localhost/hook', 'WEBHOOK_URL_BLOCKED'],
    ['https://internal.example.com/hook', 'WEBHOOK_URL_BLOCKED'],
    ['https://meta.example.com/hook', 'WEBHOOK_URL_BLOCKED'],
    ['http://hooks.example.com/hook', 'WEBHOOK_URL_INVALID'],
    ['https://user:pw@hooks.example.com/hook', 'WEBHOOK_URL_INVALID'],
  ];
  for (const [url, code] of refused) {
    const r = await asApp('PUT', '/webhook', { url });
    assert.equal(r.status, 400, url);
    assert.equal(r.body.error.code, code, url);
  }
  assert.equal(getWebhook(appId).url, null);
  const ok = await asApp('PUT', '/webhook', { url: 'https://hooks.example.com/tasks' });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.webhook.url, 'https://hooks.example.com/tasks');
  assert.equal(connections, 0);
});

test('an assignee reply and status change are POSTed, signed with the service token; app-side changes are not echoed', async () => {
  setWebhook(appId, TLS_URL);
  configureTaskWebhooks({ post: (url, opts) => postJsonSafely(url, { ...opts, isBlocked: () => false, ca: ca.certPem }) });
  const t = (await asApp('POST', '/', { subject: 'Review', requester_user_id: dana.id, assignee_user_id: lior.id })).body.task;
  await asApp('POST', `/${t.id}/comments`, { body: 'from the app' });
  await drainTaskWebhooks();
  assert.equal(seen.length, 0, "the app's own create and comment are not pushed back to it");

  await asUser(lior, 'POST', `/${t.id}/comments`, { body: 'reply from Lior' });
  await asUser(lior, 'PATCH', `/${t.id}`, { status: 'in_progress' });
  await drainTaskWebhooks();
  assert.equal(seen.length, 2);
  const [c, s] = seen.map((x) => ({ ...x, json: JSON.parse(x.body) }));
  assert.equal(c.json.type, 'task.comment');
  assert.equal(c.json.event.task_id, t.id);
  assert.equal(c.json.event.comment.body, 'reply from Lior');
  assert.equal(c.json.event.actor.id, lior.id);
  assert.equal(s.json.type, 'task.status');
  assert.equal(s.json.event.to_status, 'in_progress');
  for (const x of [c, s]) {
    assert.equal(x.headers['content-type'], 'application/json');
    const expected = 'sha256=' + crypto.createHmac('sha256', token).update(`${x.headers['x-appcrane-timestamp']}.${x.body}`).digest('hex');
    assert.equal(x.headers['x-appcrane-signature'], expected);
  }
  assert.equal(getWebhook(appId).last_status, '200');
  // The poll feed carries the same reply.
  const feed = await asApp('GET', '/events');
  assert.ok(feed.body.events.some((e) => e.type === 'task.comment' && e.comment?.body === 'reply from Lior'));
});

test('a stored URL that points at loopback at delivery time is refused without a connection', async () => {
  configureTaskWebhooks({ post: null });
  setWebhook(appId, `https://127.0.0.1:${COUNTER_PORT}/hook`);
  const t = (await asApp('POST', '/', { subject: 'Rebind', requester_user_id: dana.id, assignee_user_id: lior.id })).body.task;
  await asUser(lior, 'POST', `/${t.id}/comments`, { body: 'x' });
  await drainTaskWebhooks();
  assert.equal(connections, 0, 'a refused target must never be dialled');
  assert.equal(getWebhook(appId).last_status, 'blocked_address');

  const r = await postJsonSafely(`https://localhost:${COUNTER_PORT}/hook`, { body: '{}', timeoutMs: 2000 });
  assert.equal(r.reason, 'blocked_address');
  assert.equal(connections, 0);
});

test('the app can remove its webhook', async () => {
  const r = await asApp('PUT', '/webhook', { url: null });
  assert.equal(r.status, 200);
  assert.equal(r.body.webhook.url, null);
});
