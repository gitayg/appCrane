import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import https from 'https';
import express from 'express';

// /api/settings/siem: platform admin only, credentials masked on every read and
// kept on an update that omits them, the private allowlist validated, the TLS
// skip-verify toggle audited, and "Send test event" reaching a real receiver.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-siem-api-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { generateCa, issueCert } = await import('../server/services/dbPki.js');
const siemRoutes = (await import('../server/routes/siem.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const delivery = await import('../server/services/siem/delivery.js');

function makeUser(name, role = 'user') {
  const key = generateApiKey('dhk_admin');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
}
const admin = makeUser('admin', 'platform_admin');
const user = makeUser('plain');

const ca = generateCa({ commonName: 'SIEM API Test CA' });
const leaf = issueCert({ ca, commonName: 'localhost', usage: 'server', dnsNames: ['localhost'], ips: ['127.0.0.1'] });
const received = [];
const receiver = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => { received.push({ url: req.url, headers: req.headers, body }); res.writeHead(200); res.end('{"text":"Success"}'); });
});
await new Promise(r => receiver.listen(0, '127.0.0.1', r));
const RECV = `https://127.0.0.1:${receiver.address().port}`;

const api = express();
api.use(express.json());
api.use('/api/settings', siemRoutes);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}/api/settings`;
after(() => {
  delivery._resetSiemForTests();
  for (const s of [server, receiver]) { s.closeAllConnections?.(); s.close(); }
});

const call = (method, path, key, body) => fetch(`${BASE}${path}`, {
  method, headers: { ...(key ? { 'X-API-Key': key } : {}), 'Content-Type': 'application/json' },
  body: body && method !== 'GET' && method !== 'DELETE' ? JSON.stringify(body) : undefined,
});

const TOKEN = 'hec-token-PLAINTEXT-0123456789';
const splunkBody = { name: 'Splunk', type: 'https', preset: 'splunk', ca_pem: ca.certPem, config: { url: RECV }, secrets: { token: TOKEN } };

test('every SIEM route is platform admin only', async () => {
  for (const [m, p] of [['GET', '/siem'], ['POST', '/siem'], ['PUT', '/siem/1'], ['DELETE', '/siem/1'], ['POST', '/siem/1/test'], ['PUT', '/siem/network'], ['POST', '/siem/1/cursor'], ['POST', '/siem/1/flush']]) {
    assert.equal((await call(m, p, null, {})).status, 401, `${m} ${p} anonymous`);
    assert.equal((await call(m, p, user.key, {})).status, 403, `${m} ${p} non-admin`);
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM siem_sinks').get().n, 0);
});

test('credentials are encrypted at rest, masked on read, kept on update, and used for delivery', async () => {
  let r = await call('POST', '/siem', admin.key, splunkBody);
  assert.equal(r.status, 201);
  let text = await r.text();
  assert.ok(!text.includes(TOKEN), 'create response has no token');
  const { sink } = JSON.parse(text);
  assert.deepEqual(sink.secrets.token, { set: true, preview: sink.secrets.token.preview });
  assert.ok(sink.secrets.token.preview.endsWith('789'));
  const raw = db.prepare('SELECT * FROM siem_sinks WHERE id = ?').get(sink.id);
  assert.ok(!JSON.stringify(raw).includes(TOKEN), 'not stored in plain text');

  r = await call('GET', '/siem', admin.key);
  text = await r.text();
  assert.ok(!text.includes(TOKEN), 'list has no token');
  assert.equal(JSON.parse(text).sinks[0].health.lag_events, 1, 'its own creation audit event is pending');

  r = await call('PUT', `/siem/${sink.id}`, admin.key, { name: 'Splunk renamed', config: { url: RECV, index: 'sec' } });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).sink.secrets.token.set, true, 'omitted secret is kept');

  r = await call('POST', '/siem/network', admin.key, {});
  assert.equal(r.status, 404);
  r = await call('POST', `/siem/${sink.id}/test`, admin.key);
  let j = await r.json();
  assert.equal(j.ok, false, 'loopback refused before it is allowlisted');
  assert.match(j.error, /private, loopback or link-local/);

  r = await call('PUT', '/siem/network', admin.key, { private_allowlist: ['10.0.0.0/2'] });
  assert.equal(r.status, 400);
  r = await call('PUT', '/siem/network', admin.key, { private_allowlist: ['127.0.0.1/32'] });
  assert.deepEqual((await r.json()).private_allowlist, ['127.0.0.1/32']);

  r = await call('POST', `/siem/${sink.id}/test`, admin.key);
  j = await r.json();
  assert.equal(j.ok, true, JSON.stringify(j));
  const hit = received.at(-1);
  assert.equal(hit.url, '/services/collector/event');
  assert.equal(hit.headers.authorization, `Splunk ${TOKEN}`, 'the kept token is what is sent');
  assert.equal(JSON.parse(hit.body).index, 'sec');
  assert.equal(JSON.parse(hit.body).event.event.action, 'siem.test');

  r = await call('PUT', `/siem/${sink.id}`, admin.key, { secrets: { token: null } });
  assert.equal(r.status, 400, 'Splunk without a token is refused');
});

test('validation, skip-verify auditing, cursor and delete', async () => {
  let r = await call('POST', '/siem', admin.key, { ...splunkBody, config: { url: 'http://plain.example.test' } });
  assert.equal(r.status, 400);
  r = await call('POST', '/siem', admin.key, { ...splunkBody, config: { url: 'https://u:p@siem.example.test' } });
  assert.equal(r.status, 400);
  r = await call('POST', '/siem', admin.key, { ...splunkBody, secrets: { token: TOKEN, password: 'x' } });
  assert.equal(r.status, 400, 'unknown credential field');
  r = await call('POST', '/siem', admin.key, { ...splunkBody, ca_pem: 'not a cert' });
  assert.equal(r.status, 400);

  r = await call('POST', '/siem', admin.key, { ...splunkBody, name: 'skip', ca_pem: null, tls_skip_verify: true });
  assert.equal(r.status, 201);
  const { sink } = await r.json();
  const audit = db.prepare("SELECT action, user_id FROM audit_log WHERE action LIKE 'siem.%' ORDER BY id").all();
  assert.ok(audit.some(a => a.action === 'siem.tls-verify-disabled' && a.user_id === admin.id));
  assert.ok(!JSON.stringify(db.prepare("SELECT detail FROM audit_log WHERE action LIKE 'siem.%'").all()).includes(TOKEN), 'audit carries no token');

  db.prepare("INSERT INTO events (kind, summary) VALUES ('audit', 'x')").run();
  r = await call('POST', `/siem/${sink.id}/cursor`, admin.key, { to: 'all' });
  assert.equal((await r.json()).sink.cursor_event_id, 0);
  r = await call('POST', `/siem/${sink.id}/cursor`, admin.key, { to: 'bogus' });
  assert.equal(r.status, 400);

  r = await call('DELETE', `/siem/${sink.id}`, admin.key);
  assert.equal(r.status, 200);
  assert.equal((await call('DELETE', `/siem/${sink.id}`, admin.key)).status, 404);
});
