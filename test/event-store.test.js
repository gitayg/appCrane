import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The shared event store (migration 134, services/eventStore.js): every hooked
// producer writes its event, a broken store never breaks a producer, retention
// prunes by severity tier, and the read APIs are scoped per caller. Docker is a
// PATH shim (memory admission reads `docker info` / `docker ps`).

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-events-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const a = process.argv.slice(2);\n' +
  'if (a[0] === "info") { process.stdout.write(String(1024 * 1024 * 1024) + "\\n"); process.exit(0); }\n' +
  'process.exit(0);\n',
  { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const { logAudit, auditLogin } = await import('../server/middleware/audit.js');
const store = await import('../server/services/eventStore.js');
const retention = await import('../server/services/eventRetention.js');
const clientErrors = await import('../server/services/clientErrors.js');
const jobHealth = await import('../server/services/jobHealth.js');
const hr = await import('../server/services/hostResources.js');
const adm = await import('../server/services/memoryAdmission.js');
const { syncVulnRequests } = await import('../server/services/vulnRequests.js');
const eventsRoutes = (await import('../server/routes/events.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

function makeUser(name, role = 'user') {
  const key = generateApiKey('dhk_admin');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
}
const admin = makeUser('admin', 'platform_admin');
const owner = makeUser('owner');
const appAdmin = makeUser('appadmin');
const member = makeUser('member');
const outsider = makeUser('outsider');
const ownerB = makeUser('ownerb');

const appA = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('A','ev-a',1,'managed')").run().lastInsertRowid;
const appB = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('B','ev-b',2,'managed')").run().lastInsertRowid;
const role = db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)');
role.run(appA, owner.id, 'owner');
role.run(appA, appAdmin.id, 'admin');
role.run(appA, member.id, 'user');
role.run(appB, ownerB.id, 'owner');

const api = express();
api.use(express.json());
api.use('/api', eventsRoutes);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const get = (path, key) => fetch(`${BASE}${path}`, { headers: key ? { 'X-API-Key': key } : {} });
const put = (path, key, body) => fetch(`${BASE}${path}`, { method: 'PUT', headers: { 'X-API-Key': key, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const events = () => db.prepare('SELECT * FROM events ORDER BY id').all();
const byKind = (kind) => db.prepare('SELECT * FROM events WHERE kind = ? ORDER BY id').all(kind);
const insertAt = db.prepare('INSERT INTO events (ts, kind, severity, app_id, app_slug, user_id, subject_user_id, summary) VALUES (?,?,?,?,?,?,?,?)');
const ago = (ms) => retention.sqliteTime(Date.now() - ms);
const DAY = 86_400_000;
const HOUR = 3_600_000;

beforeEach(() => {
  db.prepare('DELETE FROM events').run();
  db.prepare("DELETE FROM settings WHERE key LIKE 'event_retention_%'").run();
  store._resetEventStoreForTests();
});

// ── producers ────────────────────────────────────────────────────────────

test('the audit helper writes one event per audit row, mapping logins and reveals to their own kinds', () => {
  logAudit(owner.id, appA, 'app-update', { name: 'renamed' });
  auditLogin(owner.id, 'ok', { method: 'password', ip: '127.0.0.1' });
  auditLogin(owner.id, 'failed', { method: 'password', reason: 'bad_password', ip: '127.0.0.1' });
  logAudit(owner.id, appA, 'env-reveal', { env: 'production', keys: ['A', 'B'] });

  const audit = db.prepare('SELECT id, action FROM audit_log ORDER BY id DESC LIMIT 4').all().reverse();
  const ev = events();
  assert.equal(ev.length, 4);
  assert.deepEqual(ev.map(e => e.kind), ['audit', 'login', 'login.failed', 'secret.reveal']);
  assert.deepEqual(ev.map(e => e.ref_id), audit.map(a => a.id));
  assert.ok(ev.every(e => e.ref_table === 'audit_log'));
  assert.equal(ev[0].app_id, appA);
  assert.equal(ev[0].app_slug, 'ev-a');
  assert.equal(ev[0].user_id, owner.id);
  assert.equal(ev[1].user_id, owner.id);
  assert.equal(ev[2].user_id, null, 'a failed sign-in has no proven actor');
  assert.equal(ev[2].subject_user_id, owner.id, 'the account it was tried against is the subject');
  assert.equal(ev[2].severity, 'warning');
  assert.equal(ev[3].severity, 'warning');
  assert.equal(ev[3].summary, 'Revealed 2 secret value(s) (production)');
});

test('client errors: a new fingerprint and a count reaching 10 each write an event, other hits do not', () => {
  db.prepare('DELETE FROM client_errors').run();
  const report = clientErrors.normalizeReport({ message: 'boom', stack: 'Error: boom\n    at x (/a.js:1:1)', page: '/dashboard', appSlug: 'ev-a' });
  for (let i = 0; i < 11; i++) clientErrors.recordClientError(report, member.id);
  const ev = byKind('client_error');
  assert.equal(ev.length, 2, JSON.stringify(ev.map(e => e.summary)));
  assert.match(ev[0].summary, /^New browser error: boom/);
  assert.match(ev[1].summary, /seen 10 times/);
  assert.equal(ev[0].ref_table, 'client_errors');
  assert.equal(ev[0].app_id, appA);
});

test('Job Health: failing, still failing, recovered writes failed then recovered only', () => {
  jobHealth._resetJobHealthForTests();
  const boom = () => { throw new Error('token=supersecretvalue123 broke'); };
  assert.throws(() => jobHealth.trackJobSync('vuln-scan', boom));
  assert.throws(() => jobHealth.trackJobSync('vuln-scan', boom));
  assert.equal(jobHealth.trackJobSync('vuln-scan', () => 7), 7);
  const ev = events().filter(e => e.kind.startsWith('job.'));
  assert.deepEqual(ev.map(e => e.kind), ['job.failed', 'job.recovered']);
  assert.ok(!ev[0].data.includes('supersecretvalue123'));
  jobHealth._resetJobHealthForTests();
});

test('host resources: a level change writes host.alert, the same level again does not, recovery writes host.recovered', async () => {
  hr._resetHostResourcesForTests();
  const MiB = 1024 * 1024;
  const deps = (availMb) => ({
    platform: 'linux',
    readFile: () => `MemTotal: ${8192 * 1024} kB\nMemAvailable: ${availMb * 1024} kB\n`,
    statfs: () => ({ bavail: 50 * 256, bsize: 4 * MiB, blocks: 100 * 256 }),
    deviceOf: () => 42,
    dockerRootDir: async () => '/var/lib/docker',
    measure: async () => ({ committedBytes: 1000 * MiB, capacityBytes: 7000 * MiB, totalBytes: 8192 * MiB, reserveBytes: 0, totalSource: 'docker' }),
    dataDir: () => '/data',
  });
  await hr.runHostCheck({ deps: deps(4000) });
  await hr.runHostCheck({ deps: deps(300) });
  await hr.runHostCheck({ deps: deps(300) });
  await hr.runHostCheck({ deps: deps(4000) });
  const ev = events().filter(e => e.kind.startsWith('host.'));
  assert.deepEqual(ev.map(e => [e.kind, e.severity]), [['host.alert', 'critical'], ['host.recovered', 'info']]);
  hr._resetHostResourcesForTests();
});

test('memory admission: a warning and a refusal each write a memory.admission event', async () => {
  const set = (k, v) => db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
  set(adm.RESERVE_KEY, '0');
  const notify = async () => {};
  set(adm.MODE_KEY, 'warn');
  adm._resetMemoryAdmissionForTests();
  await adm.admitContainer({ name: 'appcrane-ev-a-production', memoryMb: 4096, slug: 'ev-a', appId: appA, env: 'production', notify });
  set(adm.MODE_KEY, 'refuse');
  adm._resetMemoryAdmissionForTests();
  await assert.rejects(adm.admitContainer({ name: 'appcrane-ev-a-production', memoryMb: 4096, slug: 'ev-a', appId: appA, env: 'production', notify }));
  const ev = byKind('memory.admission');
  assert.deepEqual(ev.map(e => [e.severity, JSON.parse(e.data).outcome]), [['warning', 'warned'], ['critical', 'refused']]);
  assert.ok(ev.every(e => e.app_id === appA));
});

test('dependency scans: a new advisory writes scan.finding, its disappearance writes scan.resolved', () => {
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appA);
  const finding = { ecosystem: 'npm', name: 'lodash', version: '4.0.0', ids: ['GHSA-test-0001'], fixed: '4.17.21' };
  const scan = (status, findings) => {
    const id = db.prepare("INSERT INTO app_vuln_scans (app_id, env, source, status, findings_json) VALUES (?, 'production', 'manual', ?, ?)")
      .run(appA, status, findings ? JSON.stringify(findings) : null).lastInsertRowid;
    return db.prepare('SELECT * FROM app_vuln_scans WHERE id = ?').get(id);
  };
  const s1 = scan('findings', [finding]);
  syncVulnRequests(db, app, s1);
  syncVulnRequests(db, app, s1);
  const s2 = scan('ok', null);
  syncVulnRequests(db, app, s2);
  const ev = events().filter(e => e.kind.startsWith('scan.'));
  assert.deepEqual(ev.map(e => [e.kind, e.ref_id]), [['scan.finding', s1.id], ['scan.resolved', s2.id]]);
});

test('every producer still works when the event store cannot be written', async () => {
  db.exec('ALTER TABLE events RENAME TO events_off');
  try {
    const before = db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n;
    logAudit(owner.id, appA, 'app-update', { name: 'x' });
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n, before + 1, 'the audit row is still written');
    const r = clientErrors.recordClientError(clientErrors.normalizeReport({ message: 'still works' }), null);
    assert.equal(r.created, true);
    jobHealth._resetJobHealthForTests();
    assert.throws(() => jobHealth.trackJobSync('vuln-scan', () => { throw new Error('x'); }), /x/);
    assert.equal(jobHealth.trackJobSync('vuln-scan', () => 'ok'), 'ok');
    hr._resetHostResourcesForTests();
    assert.equal(store.recordEvent({ kind: 'audit', summary: 'x' }), null);
    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appA);
    const sid = db.prepare("INSERT INTO app_vuln_scans (app_id, env, source, status, findings_json) VALUES (?, 'sandbox', 'manual', 'findings', ?)")
      .run(appA, JSON.stringify([{ ecosystem: 'npm', name: 'left-pad', version: '1.0.0', ids: ['GHSA-test-0002'], fixed: null }])).lastInsertRowid;
    const res = syncVulnRequests(db, app, db.prepare('SELECT * FROM app_vuln_scans WHERE id = ?').get(sid));
    assert.equal(res.opened, 1);
    assert.equal(res.error, undefined);
  } finally {
    db.exec('ALTER TABLE events_off RENAME TO events');
    jobHealth._resetJobHealthForTests();
  }
});

// ── scrubbing ────────────────────────────────────────────────────────────

test('a planted dhk_ key and Bearer token are never stored, in the summary or the data', () => {
  const KEY = 'dhk_admin_' + 'Q7'.repeat(20);
  const BEARER = 'Bearer abc.def-ghi_jkl1234567';
  store.recordEvent({ kind: 'audit', summary: `used ${KEY} with ${BEARER}`, data: { note: `header ${BEARER}`, nested: { list: [KEY] }, github_token: 'ghp_plain' } });
  logAudit(owner.id, appA, 'app-update', { message: `pasted ${KEY}`, header: BEARER });
  const all = JSON.stringify(events());
  assert.ok(!all.includes(KEY.slice(10)), all);
  assert.ok(!all.includes('abc.def-ghi_jkl1234567'), all);
  assert.ok(!all.includes('ghp_plain'), all);
  assert.equal(events().length, 2);
});

// ── retention ────────────────────────────────────────────────────────────

test('retention prunes each severity only past its own window (30 / 90 / 365 by default)', async () => {
  const rows = [
    ['info', 29, true], ['info', 31, false],
    ['warning', 89, true], ['warning', 91, false],
    ['critical', 364, true], ['critical', 366, false],
  ];
  for (const [sev, days] of rows) insertAt.run(ago(days * DAY), 'audit', sev, null, null, null, null, `${sev}-${days}`);
  const removed = await retention.pruneEvents();
  assert.deepEqual(removed, { info: 1, warning: 1, critical: 1 });
  assert.deepEqual(events().map(e => e.summary).sort(), ['critical-364', 'info-29', 'warning-89']);
});

test('retention follows the platform setting and deletes a backlog in batches', async () => {
  for (let i = 0; i < 7; i++) insertAt.run(ago(10 * DAY), 'audit', 'info', null, null, null, null, `old-${i}`);
  insertAt.run(ago(2 * DAY), 'audit', 'info', null, null, null, null, 'recent');
  assert.deepEqual(await retention.pruneEvents({ batch: 3 }), { info: 0, warning: 0, critical: 0 }, '10 days is inside the default 30');
  const r = await put('/api/events/retention', admin.key, { info: 7 });
  assert.equal(r.status, 200);
  assert.deepEqual((await r.json()).retention, { info: 7, warning: 90, critical: 365 });
  assert.deepEqual(await retention.pruneEvents({ batch: 3 }), { info: 7, warning: 0, critical: 0 });
  assert.deepEqual(events().filter(e => e.ref_table == null).map(e => e.summary), ['recent']);
  assert.equal((await put('/api/events/retention', admin.key, { info: 0 })).status, 400);
  assert.equal((await put('/api/events/retention', owner.key, { info: 10 })).status, 403);
});

test('the retention job is registered in Job Health', () => {
  assert.ok(jobHealth.JOBS['event-retention']);
});

// ── read APIs ────────────────────────────────────────────────────────────

function seedTimeline() {
  insertAt.run(ago(3 * HOUR), 'deploy.succeeded', 'info', appA, 'ev-a', owner.id, null, 'A deploy');
  insertAt.run(ago(2 * HOUR), 'audit', 'info', appB, 'ev-b', ownerB.id, null, 'B change');
  insertAt.run(ago(1 * HOUR), 'login', 'info', null, null, member.id, null, 'member signed in');
  insertAt.run(ago(0), 'login.failed', 'warning', null, null, null, owner.id, 'owner sign-in failed');
}

test('per-app events: owner and app admin and platform admin allowed; member, outsider and another app refused', async () => {
  seedTimeline();
  for (const who of [owner, appAdmin, admin]) {
    const r = await get('/api/apps/ev-a/events', who.key);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.deepEqual(body.events.map(e => e.summary), ['A deploy']);
  }
  assert.equal((await get('/api/apps/ev-a/events', member.key)).status, 403);
  assert.equal((await get('/api/apps/ev-a/events', outsider.key)).status, 403);
  assert.equal((await get('/api/apps/ev-b/events', owner.key)).status, 403);
  assert.equal((await get('/api/apps/ev-a/events?app=ev-b', owner.key)).status, 200);
  const widened = await (await get('/api/apps/ev-a/events?app=ev-b', owner.key)).json();
  assert.deepEqual(widened.events.map(e => e.summary), ['A deploy'], 'a query parameter cannot widen the app scope');
  assert.equal((await get('/api/apps/ev-a/events')).status, 401);
});

test('GET /api/events: a platform admin sees every event, anyone else is refused', async () => {
  seedTimeline();
  const r = await get('/api/events', admin.key);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).events.length, 4);
  assert.equal((await get('/api/events', owner.key)).status, 403);
});

test('GET /api/me/events returns only events I did or that were done to my account', async () => {
  seedTimeline();
  const mine = await (await get('/api/me/events', owner.key)).json();
  assert.deepEqual(mine.events.map(e => e.summary), ['owner sign-in failed', 'A deploy']);
  const other = await (await get(`/api/me/events?user=${member.id}`, owner.key)).json();
  assert.deepEqual(other.events.map(e => e.summary), ['owner sign-in failed', 'A deploy'], 'user= cannot point it at someone else');
});

test('filters and cursor pagination', async () => {
  seedTimeline();
  const q = async (qs) => (await (await get(`/api/events?${qs}`, admin.key)).json());
  assert.deepEqual((await q('kind=login')).events.map(e => e.kind), ['login.failed', 'login'], 'a kind matches its sub-kinds');
  assert.deepEqual((await q('severity=warning')).events.map(e => e.kind), ['login.failed']);
  assert.deepEqual((await q('app=ev-b')).events.map(e => e.summary), ['B change']);
  assert.deepEqual((await q(`user=${owner.id}`)).events.map(e => e.summary), ['owner sign-in failed', 'A deploy']);
  assert.deepEqual((await q('q=signed')).events.map(e => e.summary), ['member signed in']);
  assert.deepEqual((await q('q=%25')).events, [], 'LIKE wildcards are literal');
  const p1 = await q('limit=3');
  assert.equal(p1.events.length, 3);
  const p2 = await q(`limit=3&before=${p1.next_cursor}`);
  assert.equal(p2.events.length, 1);
  assert.equal(p2.next_cursor, null);
  const from = new Date(Date.now() - 90 * 60_000).toISOString();
  assert.equal((await q(`from=${encodeURIComponent(from)}`)).events.length, 2);
});

test('related events: same app or same person within ±2h, nothing outside the window or unrelated', async () => {
  const base = Date.now() - 10 * HOUR;
  const at = (ms) => retention.sqliteTime(base + ms);
  const focus = insertAt.run(at(0), 'deploy.failed', 'warning', appA, 'ev-a', owner.id, null, 'focus').lastInsertRowid;
  insertAt.run(at(HOUR), 'audit', 'info', appA, 'ev-a', appAdmin.id, null, 'same app +1h');
  insertAt.run(at(-110 * 60_000), 'login', 'info', null, null, owner.id, null, 'same person -1h50');
  insertAt.run(at(90 * 60_000), 'login.failed', 'warning', null, null, null, owner.id, 'owner as subject +1h30');
  insertAt.run(at(3 * HOUR), 'audit', 'info', appA, 'ev-a', owner.id, null, 'same app +3h');
  insertAt.run(at(30 * 60_000), 'audit', 'info', appB, 'ev-b', ownerB.id, null, 'other app +30m');

  const r = await get(`/api/events/${focus}/related`, admin.key);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.event.summary, 'focus');
  assert.deepEqual(body.related.map(e => e.summary), ['same person -1h50', 'same app +1h', 'owner as subject +1h30']);

  const asOwner = await (await get(`/api/events/${focus}/related`, owner.key)).json();
  assert.deepEqual(asOwner.related.map(e => e.summary), ['same person -1h50', 'same app +1h', 'owner as subject +1h30']);
  assert.equal((await get(`/api/events/${focus}/related`, outsider.key)).status, 404);
  assert.equal((await get(`/api/events/${focus}/related`, member.key)).status, 404, 'a plain member cannot read the app trail');
});
