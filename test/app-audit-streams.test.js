import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import https from 'https';
import express from 'express';

// Owner-managed audit streams (services/appAudit/streams.js + delivery.js):
// an app owner points their own app's audit events at a SIEM. A real HTTPS
// receiver with a certificate from a throwaway CA checks that a stream gets
// only its own app's events; the routes check owner-only management, masked
// credentials, the private-address guard and the platform switch.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-app-audit-streams-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { generateCa, issueCert } = await import('../server/services/dbPki.js');
const { issueServiceToken } = await import('../server/services/appServiceToken.js');
const net = await import('../server/services/siem/netGuard.js');
const delivery = await import('../server/services/appAudit/delivery.js');
const streams = await import('../server/services/appAudit/streams.js');

const ca = generateCa({ commonName: 'App Audit Test CA' });
const leaf = issueCert({ ca, commonName: 'localhost', usage: 'server', dnsNames: ['localhost'], ips: ['127.0.0.1'] });

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid);
  return { id, key };
}
let slot = 7300;
const mkApp = (slug) => Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')").run(slug, slug, ++slot).lastInsertRowid);
const assign = (appId, u, role) => db.prepare('INSERT OR REPLACE INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, u.id, role);

const admin = mkUser('asadmin', 'platform_admin');
const owner = mkUser('asowner');
const appAdmin = mkUser('asappadmin');
const member = mkUser('asmember');
const ALPHA = mkApp('as-alpha');
const BETA = mkApp('as-beta');
assign(ALPHA, owner, 'owner');
assign(ALPHA, appAdmin, 'admin');
assign(ALPHA, member, 'user');
assign(BETA, owner, 'owner');
const tokens = { [ALPHA]: issueServiceToken(ALPHA), [BETA]: issueServiceToken(BETA) };
for (const a of [ALPHA, BETA]) for (const act of ['invoice.paid', 'user.signed_in']) {
  db.prepare('INSERT INTO app_audit_event_types (app_id, action) VALUES (?, ?)').run(a, act);
}

const received = [];
const receiver = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    received.push({ url: req.url, headers: req.headers, docs: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
    res.writeHead(200); res.end('ok');
  });
});
await new Promise(r => receiver.listen(0, '127.0.0.1', r));
const RECEIVER = `https://127.0.0.1:${receiver.address().port}`;

const api = express();
api.use('/api/service/audit', (await import('../server/routes/appAuditService.js')).default);
api.use(express.json());
api.use('/api', (await import('../server/routes/appAudit.js')).default);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => {
  delivery._resetAppAuditDeliveryForTests();
  server.closeAllConnections?.(); server.close();
  receiver.closeAllConnections?.(); receiver.close();
  rmSync(process.env.DATA_DIR, { recursive: true, force: true });
});

async function call(method, path, user, body) {
  const r = await fetch(`${BASE}${path}`, {
    method, headers: { 'content-type': 'application/json', ...(user ? { 'x-api-key': user.key } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}
const emit = (appId, action = 'invoice.paid', extra = {}) => fetch(`${BASE}/api/service/audit/events`, {
  method: 'POST', headers: { 'content-type': 'application/json', 'x-appcrane-service-token': tokens[appId] },
  body: JSON.stringify({ action, ...extra }),
}).then(r => r.status);

const hook = (url = `${RECEIVER}/ingest`, extra = {}) => ({
  name: 'my siem', type: 'https', preset: 'generic', ca_pem: ca.certPem,
  config: { url, auth_header: 'Authorization' }, secrets: { auth_value: 'Bearer owner-stream-secret' }, ...extra,
});
const setPolicy = (p) => streams.setPlatformPolicy(p, admin.id);

beforeEach(() => {
  delivery._resetAppAuditDeliveryForTests();
  db.prepare('DELETE FROM app_audit_streams').run();
  received.length = 0;
  net.setAllowlist(['127.0.0.1/32'], admin.id);
  setPolicy({ owner_streams_enabled: true, owner_streams_private: false });
});

test('a private, loopback or metadata destination is refused for an owner stream', async () => {
  for (const url of [`${RECEIVER}/ingest`, 'https://10.1.2.3/x', 'https://192.168.0.10/x', 'https://[::1]/x', 'https://169.254.169.254/latest']) {
    const r = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook(url));
    assert.equal(r.status, 400, url);
    assert.equal(r.body.error.code, 'DESTINATION_NOT_ALLOWED', url);
  }
  const syslog = await call('POST', '/api/apps/as-alpha/audit-streams', owner,
    { name: 's', type: 'syslog', config: { host: '127.0.0.1', port: 6514, transport: 'tcp-tls' } });
  assert.equal(syslog.body?.error?.code, 'DESTINATION_NOT_ALLOWED');
  setPolicy({ owner_streams_private: true });
  const meta = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook('https://169.254.169.254/latest'));
  assert.equal(meta.status, 400, 'link-local stays refused even when the platform allows private destinations');
  const notListed = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook('https://10.1.2.3/x'));
  assert.equal(notListed.status, 400, 'only the platform allowlist is opened, not every private address');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM app_audit_streams').get().n, 0);
});

test('owner streams verify TLS and use TLS syslog only', async () => {
  setPolicy({ owner_streams_private: true });
  assert.equal((await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook(undefined, { tls_skip_verify: true }))).status, 400);
  const udp = await call('POST', '/api/apps/as-alpha/audit-streams', owner, { name: 'u', type: 'syslog', config: { host: '127.0.0.1', transport: 'udp' } });
  assert.equal(udp.status, 400);
});

test('only the owner (or a platform admin) manages streams; credentials come back masked', async () => {
  setPolicy({ owner_streams_private: true });
  assert.equal((await call('POST', '/api/apps/as-alpha/audit-streams', member, hook())).status, 403);
  assert.equal((await call('POST', '/api/apps/as-alpha/audit-streams', appAdmin, hook())).status, 403);
  assert.equal((await call('GET', '/api/apps/as-alpha/audit-streams', member)).status, 403);
  const r = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook());
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.stream.secrets.auth_value.set, true);
  assert.ok(!JSON.stringify(r.body).includes('owner-stream-secret'));
  const enc = db.prepare('SELECT secrets_enc FROM app_audit_streams WHERE id = ?').get(r.body.stream.id).secrets_enc;
  assert.ok(enc && !enc.includes('owner-stream-secret'), 'stored encrypted');
  const cross = await call('DELETE', `/api/apps/as-beta/audit-streams/${r.body.stream.id}`, owner);
  assert.equal(cross.status, 404, "a stream is reached only through its own app's path");
  assert.equal((await call('GET', '/api/apps/as-alpha/audit-streams', admin)).status, 200);
});

test("a stream receives only its own app's events, over the real HTTPS sender", async () => {
  setPolicy({ owner_streams_private: true });
  const r = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook(undefined, { filters: { actions: ['invoice'] } }));
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(await emit(ALPHA), 201);
  assert.equal(await emit(BETA), 201);
  assert.equal(await emit(ALPHA, 'user.signed_in'), 201);
  assert.equal(await emit(BETA), 201);
  assert.equal(await emit(ALPHA, 'invoice.paid', { targets: [{ type: 'invoice', id: 'i-2' }] }), 201);
  const f = await call('POST', `/api/apps/as-alpha/audit-streams/${r.body.stream.id}/flush`, owner);
  assert.equal(f.body.ok, true, JSON.stringify(f.body));
  const docs = received.flatMap(x => x.docs);
  assert.equal(docs.length, 2, 'two alpha invoice events; beta and the filtered action are not sent');
  assert.ok(docs.every(d => d.appcrane.app.slug === 'as-alpha' && d.appcrane.source === 'app' && d.event.dataset === 'appcrane.app_audit'));
  assert.ok(docs.every(d => d.event.action === 'invoice.paid'));
  assert.equal(received[0].headers.authorization, 'Bearer owner-stream-secret');
  const row = db.prepare('SELECT cursor_event_id FROM app_audit_streams WHERE id = ?').get(r.body.stream.id);
  assert.equal(row.cursor_event_id, db.prepare('SELECT MAX(id) AS m FROM app_audit_events WHERE app_id = ?').get(ALPHA).m);
  const again = await call('POST', `/api/apps/as-alpha/audit-streams/${r.body.stream.id}/flush`, owner);
  assert.equal(again.body.delivered, 0, 'the cursor holds: nothing is sent twice');
});

test('a platform admin can turn owner streams off: creating is refused and nothing is delivered', async () => {
  setPolicy({ owner_streams_private: true });
  const r = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook());
  assert.equal(r.status, 201);
  assert.equal((await call('PUT', '/api/app-audit/settings', owner, { owner_streams_enabled: false })).status, 403);
  const off = await call('PUT', '/api/app-audit/settings', admin, { owner_streams_enabled: false });
  assert.equal(off.body.owner_streams_enabled, false);
  assert.equal((await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook())).body.error.code, 'OWNER_STREAMS_DISABLED');
  await emit(ALPHA);
  await delivery.deliverStream(r.body.stream.id, { force: true });
  await delivery.tickAllStreams();
  assert.equal(received.length, 0);
});

test('owner streams take syslog over TLS and the S3 export to a public address; the list offers every preset', async () => {
  const sys = await call('POST', '/api/apps/as-alpha/audit-streams', owner,
    { name: 'syslog', type: 'syslog', ca_pem: ca.certPem, config: { host: '203.0.113.10', port: 6514, transport: 'tcp-tls' } });
  assert.equal(sys.status, 201, JSON.stringify(sys.body));
  assert.equal(sys.body.stream.config.transport, 'tcp-tls');
  const s3 = await call('POST', '/api/apps/as-alpha/audit-streams', owner, {
    name: 'r2', type: 's3', config: { bucket: 'audit-bucket', access_key_id: 'AKIDEXAMPLE', endpoint: 'https://203.0.113.11', prefix: 'alpha/' },
    secrets: { secret_access_key: 's3-secret-value' },
  });
  assert.equal(s3.status, 201, JSON.stringify(s3.body));
  assert.equal(s3.body.stream.secrets.secret_access_key.set, true);
  const privS3 = await call('POST', '/api/apps/as-alpha/audit-streams', owner, {
    name: 'r2', type: 's3', config: { bucket: 'audit-bucket', access_key_id: 'AKIDEXAMPLE', endpoint: 'https://10.0.0.9' },
    secrets: { secret_access_key: 'x' },
  });
  assert.equal(privS3.body?.error?.code, 'DESTINATION_NOT_ALLOWED');
  const list = await call('GET', '/api/apps/as-alpha/audit-streams', owner);
  assert.deepEqual(Object.keys(list.body.options.presets).sort(), ['datadog', 'elastic', 'generic', 'sentinel', 'splunk', 'sumo']);
  assert.deepEqual(list.body.options.s3_secrets, ['secret_access_key']);
  assert.equal(list.body.streams.length, 2);
});

test('changing the destination without resending the credential drops the stored one', async () => {
  setPolicy({ owner_streams_private: true });
  const r = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook());
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const id = r.body.stream.id;
  const moved = await call('PUT', `/api/apps/as-alpha/audit-streams/${id}`, owner, { config: { url: `${RECEIVER}/elsewhere`, auth_header: 'Authorization' } });
  assert.equal(moved.status, 200, JSON.stringify(moved.body));
  assert.equal(moved.body.stream.secrets.auth_value?.set ?? false, false, 'the stored credential survived a destination change');
  assert.equal(await emit(ALPHA), 201);
  await call('POST', `/api/apps/as-alpha/audit-streams/${id}/flush`, owner);
  assert.ok(received.length > 0);
  assert.ok(received.every((x) => x.headers.authorization !== 'Bearer owner-stream-secret'), 'the old credential was sent to the new destination');

  // Same destination, other fields changed: the credential stays.
  const r2 = await call('POST', '/api/apps/as-alpha/audit-streams', owner, hook());
  const renamed = await call('PUT', `/api/apps/as-alpha/audit-streams/${r2.body.stream.id}`, owner, { name: 'renamed' });
  assert.equal(renamed.body.stream.secrets.auth_value.set, true);
  // A new destination with the credential sent again keeps it.
  const resent = await call('PUT', `/api/apps/as-alpha/audit-streams/${r2.body.stream.id}`, owner,
    { config: { url: `${RECEIVER}/other`, auth_header: 'Authorization' }, secrets: { auth_value: 'Bearer new-secret' } });
  assert.equal(resent.body.stream.secrets.auth_value.set, true);
});
