import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import tls from 'tls';
import https from 'https';
import dgram from 'dgram';
import zlib from 'zlib';

// SIEM streaming (services/siem/*): real local receivers — a TLS syslog server
// and an HTTPS server with a certificate from a throwaway CA, and a UDP
// listener — check framing, formats, auth headers, the durable cursor, filters,
// output scrubbing, TLS verification, the private-address guard and Job Health.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-siem-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateCa, issueCert } = await import('../server/services/dbPki.js');
const store = await import('../server/services/siem/store.js');
const delivery = await import('../server/services/siem/delivery.js');
const net = await import('../server/services/siem/netGuard.js');
const { recordEvent, _resetEventStoreForTests } = await import('../server/services/eventStore.js');
const jobHealth = await import('../server/services/jobHealth.js');
const { _clearSentinelTokens } = await import('../server/services/siem/https.js');

const ca = generateCa({ commonName: 'SIEM Test CA' });
const leaf = issueCert({ ca, commonName: 'localhost', usage: 'server', dnsNames: ['localhost'], ips: ['127.0.0.1'] });
const otherCa = generateCa({ commonName: 'Other Test CA' });

const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Ada Admin','ada@t.test','platform_admin','x-hash',1,'human')").run().lastInsertRowid;
db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('A','app-a',1,'managed')").run();

// ── receivers ─────────────────────────────────────────────────────────────
const syslogFrames = [];
let syslogConns = 0;
const tlsServer = tls.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (sock) => {
  syslogConns++;
  let buf = Buffer.alloc(0);
  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      const sp = buf.indexOf(0x20);
      if (sp < 0) break;
      const len = Number(buf.subarray(0, sp).toString('ascii'));
      if (!Number.isInteger(len) || buf.length < sp + 1 + len) break;
      syslogFrames.push({ declared: len, msg: buf.subarray(sp + 1, sp + 1 + len).toString('utf8') });
      buf = buf.subarray(sp + 1 + len);
    }
  });
  sock.on('error', () => {});
});
await new Promise(r => tlsServer.listen(0, '127.0.0.1', r));
const SYSLOG_PORT = tlsServer.address().port;

const udpMessages = [];
const udp = dgram.createSocket('udp4');
udp.on('message', m => udpMessages.push(m.toString('utf8')));
await new Promise(r => udp.bind(0, '127.0.0.1', r));
const UDP_PORT = udp.address().port;

const httpReqs = [];
let httpFail = 0;
const httpsServer = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    let body = Buffer.concat(chunks);
    if (req.headers['content-encoding'] === 'gzip') body = zlib.gunzipSync(body);
    const text = body.toString('utf8');
    if (req.url.includes('/oauth2/v2.0/token')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ access_token: 'aad-access-token', expires_in: 3600 }));
    }
    httpReqs.push({ method: req.method, url: req.url, headers: req.headers, text });
    if (httpFail) { res.writeHead(httpFail); return res.end('unavailable'); }
    if (req.url.startsWith('/services/collector')) { res.writeHead(200); return res.end('{"text":"Success","code":0}'); }
    if (req.url.startsWith('/api/v2/logs')) { res.writeHead(202); return res.end('{}'); }
    if (req.url.endsWith('/_bulk')) { res.writeHead(200); return res.end(JSON.stringify({ errors: false, items: [] })); }
    if (req.url.startsWith('/dataCollectionRules')) { res.writeHead(204); return res.end(); }
    res.writeHead(200); res.end('ok');
  });
});
await new Promise(r => httpsServer.listen(0, '127.0.0.1', r));
const HTTPS = `https://127.0.0.1:${httpsServer.address().port}`;

after(() => {
  delivery._resetSiemForTests();
  tlsServer.close(); udp.close();
  httpsServer.closeAllConnections?.(); httpsServer.close();
});

async function waitFor(fn, what, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fn()) return;
    await new Promise(r => setTimeout(r, 20));
  }
  assert.fail(`timed out waiting for ${what}`);
}

function makeSink(body, startFrom = 'now') {
  return store.insertSink(store.validateSink(body), { userId: adminId, startFrom });
}

function sinkRow(id) { return store.getSinkRow(id); }

function syslogSink(extra = {}) {
  return makeSink({ name: 'syslog', type: 'syslog', format: 'json', ca_pem: ca.certPem,
    config: { host: '127.0.0.1', port: SYSLOG_PORT, transport: 'tcp-tls' }, ...extra });
}

function genericSink(extra = {}) {
  const { config = {}, ...rest } = extra;
  return makeSink({ name: 'hook', type: 'https', preset: 'generic', ca_pem: ca.certPem,
    config: { url: `${HTTPS}/ingest`, auth_header: 'Authorization', ...config },
    secrets: { auth_value: 'Bearer hook-secret-value' }, ...rest });
}

function emit(n, base = {}) {
  const ids = [];
  for (let i = 0; i < n; i++) ids.push(recordEvent({ kind: 'deploy.succeeded', summary: `Deployed v${i}`, appSlug: 'app-a', userId: adminId, ...base }));
  return ids;
}

beforeEach(() => {
  delivery._resetSiemForTests();
  _resetEventStoreForTests();
  _clearSentinelTokens();
  db.prepare('DELETE FROM siem_sinks').run();
  syslogFrames.length = 0; udpMessages.length = 0; httpReqs.length = 0; httpFail = 0; syslogConns = 0;
  net.setAllowlist(['127.0.0.1/32'], adminId);
});

test('syslog over TLS: RFC 6587 octet counting, RFC 5424 header, JSON and CEF bodies', async () => {
  const id = syslogSink();
  const cefId = syslogSink({ name: 'cef', format: 'cef' });
  const ids = emit(2);
  recordEvent({ kind: 'login.failed', severity: 'warning', summary: 'Sign-in failed', subjectUserId: adminId });
  await delivery.deliverSink(id);
  await delivery.deliverSink(cefId);
  await waitFor(() => syslogFrames.length === 6, '6 syslog frames');
  for (const f of syslogFrames) assert.equal(Buffer.byteLength(f.msg), f.declared, 'octet count matches the message bytes');
  const json = syslogFrames.filter(f => !f.msg.includes('CEF:0|'));
  const cef = syslogFrames.filter(f => f.msg.includes('CEF:0|'));
  assert.equal(json.length, 3);
  assert.equal(cef.length, 3);
  const m = json[0].msg.match(/^<(\d+)>1 (\S+) (\S+) appcrane - (\S+) \[appcrane@32473 eventId="([^"]+)" kind="([^"]+)"\] (.*)$/);
  assert.ok(m, `RFC 5424 shape: ${json[0].msg.slice(0, 160)}`);
  assert.equal(m[1], String(13 * 8 + 6), 'facility 13 (log audit), severity 6 (info)');
  assert.equal(m[4], 'deploy.succeeded');
  const doc = JSON.parse(m[7]);
  assert.equal(doc.event.action, 'deploy.succeeded');
  assert.equal(doc.event.outcome, 'success');
  assert.equal(doc.appcrane.event_id, ids[0]);
  assert.equal(doc.appcrane.app.slug, 'app-a');
  assert.equal(doc.user.name, 'Ada Admin');
  assert.match(doc.event.id, new RegExp(`^appcrane-.+-${ids[0]}$`));
  assert.match(json[2].msg, /^<108>1 /, 'warning maps to syslog severity 4');
  assert.match(cef[2].msg, /CEF:0\|AppCrane\|AppCrane\|[^|]+\|login\.failed\|Sign-in failed\|6\|.*outcome=failure/);
  assert.equal(sinkRow(id).cursor_event_id, ids[1] + 1);
});

test('syslog over UDP: one RFC 5424 message per datagram', async () => {
  const id = makeSink({ name: 'udp', type: 'syslog', config: { host: '127.0.0.1', port: UDP_PORT, transport: 'udp' } });
  emit(3);
  await delivery.deliverSink(id);
  await waitFor(() => udpMessages.length === 3, '3 datagrams');
  for (const m of udpMessages) assert.match(m, /^<110>1 \S+ \S+ appcrane - deploy\.succeeded \[appcrane@32473 eventId="appcrane-/);
});

test('HTTPS presets: Splunk HEC, Datadog, Elastic _bulk (gzip), Sumo, Sentinel send the right path, auth and body', async () => {
  const splunk = makeSink({ name: 's', type: 'https', preset: 'splunk', ca_pem: ca.certPem, config: { url: HTTPS, index: 'sec' }, secrets: { token: 'hec-token-1' } });
  const dd = makeSink({ name: 'd', type: 'https', preset: 'datadog', ca_pem: ca.certPem, config: { url: `${HTTPS}/api/v2/logs`, tags: 'env:test' }, secrets: { api_key: 'dd-key-1' } });
  const es = makeSink({ name: 'e', type: 'https', preset: 'elastic', ca_pem: ca.certPem, config: { url: HTTPS, index: 'appcrane', gzip: true }, secrets: { api_key: 'es-key-1' } });
  const sumo = makeSink({ name: 'u', type: 'https', preset: 'sumo', ca_pem: ca.certPem, config: {}, secrets: { url: `${HTTPS}/receiver/v1/http/abc` } });
  const sen = makeSink({ name: 'm', type: 'https', preset: 'sentinel', ca_pem: ca.certPem,
    config: { tenant_id: 'tenant-1', client_id: 'client-1', dce_url: HTTPS, dcr_id: 'dcr-1', stream: 'Custom-AppCrane_CL', authority: HTTPS },
    secrets: { client_secret: 'aad-secret' } });
  const ids = emit(2);
  for (const id of [splunk, dd, es, sumo, sen]) await delivery.deliverSink(id);

  const s = httpReqs.find(r => r.url === '/services/collector/event');
  assert.ok(s, 'Splunk path');
  assert.equal(s.headers.authorization, 'Splunk hec-token-1');
  const hec = s.text.split('\n').map(l => JSON.parse(l));
  assert.equal(hec.length, 2);
  assert.equal(hec[0].index, 'sec');
  assert.equal(hec[0].event.appcrane.event_id, ids[0]);

  const d = httpReqs.find(r => r.url === '/api/v2/logs');
  assert.equal(d.headers['dd-api-key'], 'dd-key-1');
  const arr = JSON.parse(d.text);
  assert.equal(arr.length, 2);
  assert.equal(arr[0].ddsource, 'appcrane');
  assert.equal(arr[0].ddtags, 'env:test');

  const e = httpReqs.find(r => r.url === '/_bulk');
  assert.equal(e.headers['content-encoding'], 'gzip');
  assert.equal(e.headers.authorization, 'ApiKey es-key-1');
  assert.equal(e.headers['content-type'], 'application/x-ndjson');
  const lines = e.text.trim().split('\n').map(l => JSON.parse(l));
  assert.deepEqual(lines[0], { create: { _index: 'appcrane', _id: lines[1].event.id } }, 'create with the stable event id as _id');

  const u = httpReqs.find(r => r.url === '/receiver/v1/http/abc');
  assert.equal(u.text.trim().split('\n').length, 2);

  const m = httpReqs.find(r => r.url.startsWith('/dataCollectionRules'));
  assert.equal(m.url, '/dataCollectionRules/dcr-1/streams/Custom-AppCrane_CL?api-version=2023-01-01');
  assert.equal(m.headers.authorization, 'Bearer aad-access-token');
  const rows = JSON.parse(m.text);
  assert.equal(rows[0].Kind, 'deploy.succeeded');
  assert.ok(rows[0].TimeGenerated);
});

test('cursor: an outage loses nothing; after a restart every event arrives once, in order', async () => {
  const id = genericSink();
  const first = emit(5);
  httpFail = 503;
  await assert.rejects(delivery.deliverSink(id), /HTTP 503/);
  assert.equal(sinkRow(id).cursor_event_id, first[0] - 1, 'cursor did not move on failure');
  assert.equal(sinkRow(id).consecutive_failures, 1);
  const r = await delivery.deliverSink(id);
  assert.equal(r.waiting, true, 'in backoff, no attempt');
  const second = emit(3);
  delivery._resetSiemForTests();
  httpFail = 0;
  httpReqs.length = 0;
  await delivery.deliverSink(id);
  const got = httpReqs.flatMap(q => JSON.parse(q.text)).map(d => d.appcrane.event_id);
  assert.deepEqual(got, [...first, ...second]);
  assert.equal(new Set(got).size, got.length);
  const row = sinkRow(id);
  assert.equal(row.cursor_event_id, second.at(-1));
  assert.equal(row.consecutive_failures, 0);
  assert.equal(row.last_error, null);
  assert.equal(row.delivered_count, 8);
  httpReqs.length = 0;
  await delivery.deliverSink(id, { force: true });
  assert.equal(httpReqs.length, 0, 'nothing re-sent once delivered');
});

test('bounded batches: a backlog larger than batch_size goes out in several requests, in order', async () => {
  const id = genericSink({ config: { batch_size: 4, auth_header: 'Authorization' } });
  const ids = emit(10);
  await delivery.deliverSink(id);
  assert.deepEqual(httpReqs.map(q => JSON.parse(q.text).length), [4, 4, 2]);
  assert.deepEqual(httpReqs.flatMap(q => JSON.parse(q.text)).map(d => d.appcrane.event_id), ids);
});

test('filters: kinds, minimum severity and apps; the cursor still moves past what was skipped', async () => {
  const id = genericSink({ filters: { kinds: ['deploy'], min_severity: 'warning', apps: ['app-a'] } });
  recordEvent({ kind: 'deploy.failed', severity: 'warning', summary: 'Deploy failed', appSlug: 'app-a' });
  recordEvent({ kind: 'deploy.succeeded', severity: 'info', summary: 'too low', appSlug: 'app-a' });
  recordEvent({ kind: 'deploy.failed', severity: 'warning', summary: 'other app', appSlug: 'app-b' });
  recordEvent({ kind: 'login.failed', severity: 'warning', summary: 'wrong kind' });
  recordEvent({ kind: 'deployment', severity: 'critical', summary: 'prefix only, not a dotted child', appSlug: 'app-a' });
  const last = recordEvent({ kind: 'deploy.rollback', severity: 'critical', summary: 'Rolled back', appSlug: 'app-a' });
  await delivery.deliverSink(id);
  const got = httpReqs.flatMap(q => JSON.parse(q.text)).map(d => d.message);
  assert.deepEqual(got, ['Deploy failed', 'Rolled back']);
  assert.equal(sinkRow(id).cursor_event_id, last);
});

test('secrets are scrubbed on output even when an event row carries one', async () => {
  const id = genericSink();
  const planted = ['dhk_admin_PLANTEDsecretKEY1234567890', 'ghp_PLANTEDtoken0123456789abcdefABCDEF', 'hunter2-planted-pw'];
  db.prepare("INSERT INTO events (kind, severity, summary, data) VALUES ('audit','info',?,?)")
    .run(`Leaked ${planted[0]} and ${planted[1]}`, JSON.stringify({ detail: { note: `password=${planted[2]}`, header: 'Bearer abc.def.ghi' } }));
  await delivery.deliverSink(id);
  const wire = httpReqs.map(q => q.text).join('\n');
  assert.ok(wire.includes('Leaked'), 'the event was sent');
  for (const p of planted) assert.ok(!wire.includes(p), `${p.slice(0, 12)}... must not reach the SIEM`);
  assert.ok(!wire.includes('abc.def.ghi'));
});

test('TLS: an untrusted or wrong CA is refused; the right custom CA or the explicit skip-verify toggle connects', async () => {
  const noCa = syslogSink({ name: 'no-ca', ca_pem: null });
  const wrong = syslogSink({ name: 'wrong', ca_pem: otherCa.certPem });
  const httpsWrong = genericSink({ name: 'hw', ca_pem: otherCa.certPem });
  emit(1);
  await assert.rejects(delivery.deliverSink(noCa), /self[- ]signed|unable to verify|certificate/i);
  await assert.rejects(delivery.deliverSink(wrong), /self[- ]signed|unable to verify|certificate/i);
  await assert.rejects(delivery.deliverSink(httpsWrong), /self[- ]signed|unable to verify|certificate/i);
  assert.equal(syslogFrames.length, 0);
  assert.equal(httpReqs.length, 0);
  assert.match(sinkRow(wrong).last_error, /certificate|verify|signed/i);

  const right = syslogSink({ name: 'right' });
  const skip = syslogSink({ name: 'skip', ca_pem: null, tls_skip_verify: true });
  db.prepare('UPDATE siem_sinks SET cursor_event_id = 0 WHERE id IN (?, ?)').run(right, skip);
  await delivery.deliverSink(right);
  await delivery.deliverSink(skip);
  await waitFor(() => syslogFrames.length >= 2, 'frames from both trusted sinks');
});

test('private destinations are refused unless allowlisted; metadata addresses never', async () => {
  const id = genericSink();
  const byName = makeSink({ name: 'name', type: 'https', preset: 'generic', ca_pem: ca.certPem,
    config: { url: `https://localhost:${httpsServer.address().port}/x` } });
  emit(2);
  net.setAllowlist([], adminId);
  await assert.rejects(delivery.deliverSink(id), /private, loopback or link-local/);
  await assert.rejects(delivery.deliverSink(byName), /private, loopback or link-local/);
  const conns = syslogConns;
  const sys = syslogSink({ name: 'sys' });
  db.prepare('UPDATE siem_sinks SET cursor_event_id = 0 WHERE id = ?').run(sys);
  await assert.rejects(delivery.deliverSink(sys), /private, loopback or link-local/);
  assert.equal(httpReqs.length, 0, 'no request reached the receiver');
  assert.equal(syslogConns, conns, 'no syslog connection was opened');

  net.setAllowlist(['localhost'], adminId);
  delivery._resetSiemForTests();
  await delivery.deliverSink(byName);
  assert.equal(httpReqs.length, 1, 'an allowlisted host name may resolve to a private address');

  const isBlocked = net.policyFor('169.254.169.254', ['169.254.0.0/16', '169.254.169.254']);
  assert.equal(isBlocked('169.254.169.254'), true, 'link-local stays refused even when listed');
  assert.equal(net.policyFor('x', ['10.1.0.0/16'])('10.1.2.3'), false);
  assert.equal(net.policyFor('x', ['10.1.0.0/16'])('10.2.0.1'), true);
  assert.equal(net.policyFor('x', [])('8.8.8.8'), false, 'public addresses are allowed');
  assert.throws(() => net.normalizeAllowlist(['10.0.0.0/4']), /too wide/);
  assert.throws(() => net.normalizeAllowlist(['not a host!']), /not an IP/);
});

test('Job Health: one job per sink; sustained failure and lag turn it failing, recovery turns it ok', async () => {
  const id = genericSink({ config: { alert_after_sec: 0, auth_header: 'Authorization' } });
  emit(3);
  httpFail = 500;
  jobHealth.enableJobHealthAlerts();
  await delivery.tickSink(sinkRow(id)).catch(() => {});
  await waitFor(() => db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE source = 'job-health' AND subject LIKE '%SIEM stream%'").get().n === 1, 'admin alert e-mail');
  let job = jobHealth.getJobHealth().find(j => j.id === `siem:${id}`);
  assert.ok(job, 'registered as a Job Health job');
  assert.equal(job.status, 'failing');
  assert.match(job.last_error, /delivery failing.*HTTP 500/);
  assert.equal(job.detail.lag_events, 3);

  httpFail = 0;
  delivery._resetSiemForTests();
  await delivery.tickSink(sinkRow(id));
  job = jobHealth.getJobHealth().find(j => j.id === `siem:${id}`);
  assert.equal(job.status, 'ok');
  assert.equal(job.detail.lag_events, 0);
  assert.ok(job.detail.last_success_at);

  const lagging = genericSink({ name: 'lag', config: { alert_after_sec: 86400, max_lag_sec: 60, auth_header: 'Authorization' } });
  db.prepare("INSERT INTO events (ts, kind, severity, summary) VALUES (datetime('now','-2 hours'),'audit','info','old')").run();
  db.prepare('UPDATE siem_sinks SET cursor_event_id = (SELECT MAX(id) - 1 FROM events) WHERE id = ?').run(lagging);
  httpFail = 503;
  await delivery.tickSink(sinkRow(lagging)).catch(() => {});
  job = jobHealth.getJobHealth().find(j => j.id === `siem:${lagging}`);
  assert.equal(job.status, 'failing');
  assert.match(job.last_error, /oldest undelivered event is \d+s old \(max 60s\)/);

  jobHealth._resetJobHealthForTests();
  db.prepare('DELETE FROM siem_sinks').run();
  await delivery.tickAll();
  assert.equal(jobHealth.getJobHealth().some(j => j.id.startsWith('siem:')), false, 'deleted sinks leave Job Health');
});

test('S3 export: daily-partitioned JSONL objects keyed by event ids (retries overwrite)', async () => {
  const puts = [];
  delivery._setSendersForTests({ s3: (docs, sink, secrets, allow) => import('../server/services/siem/s3Export.js').then(m => m.sendS3(docs, sink, secrets, allow, { put: async o => puts.push(o) })) });
  const id = makeSink({ name: 'obj', type: 's3', config: { bucket: 'siem-bucket', access_key_id: 'AKIDTEST', prefix: 'appcrane/', flush_sec: 3600 },
    secrets: { secret_access_key: 'shh' } });
  const ids = emit(3);
  const r = await delivery.deliverSink(id);
  assert.equal(puts.length, 0, 'held until flush_sec or a full batch');
  assert.equal(r.delivered, 0);
  await delivery.deliverSink(id, { force: true });
  assert.equal(puts.length, 1);
  const day = new Date().toISOString().slice(0, 10);
  assert.equal(puts[0].key, `appcrane/dt=${day}/appcrane-events-${ids[0]}-${ids[2]}.jsonl`);
  assert.equal(puts[0].secretAccessKey, 'shh');
  assert.deepEqual(puts[0].body.trim().split('\n').map(l => JSON.parse(l).appcrane.event_id), ids);
});

test('recordEvent wakes delivery: a new event reaches the SIEM without waiting for the next tick', async () => {
  genericSink();
  delivery.startSiemDelivery({ intervalMs: 60_000 });
  recordEvent({ kind: 'secret.reveal', severity: 'warning', summary: 'Revealed 1 secret value(s)', appSlug: 'app-a' });
  await waitFor(() => httpReqs.length === 1, 'woken delivery', 4000);
  assert.equal(JSON.parse(httpReqs[0].text)[0].event.action, 'secret.reveal');
});
