import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// One app request per dependency-scan finding (migration 121, vulnRequests.js).
//
// Pinned here: opened once per (app, ecosystem, package, advisory) whatever the
// env, scan, or ordering; closed by a later scan only when no environment still
// has it; never reopened; an ordinary request in the owner's queue; linked from
// the daily digest; and none of it able to fail a scan.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-vuln-requests-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.BASE_URL = 'http://crane.test';
delete process.env.CRANE_DOMAIN;
const DATA_DIR = process.env.DATA_DIR;

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { scanApp, clearAdvisoryCache } = await import('../server/services/appScan.js');
const { buildDigest, sendVulnDigest } = await import('../server/services/vulnDigest.js');

let slot = 300;
function makeApp(slug, ownerId = null) {
  const id = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type,created_by) VALUES (?,?,?,'managed',?)"
  ).run(slug, slug, slot++, ownerId).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

function writeLock(slug, deps, env = 'production') {
  const dir = join(DATA_DIR, 'apps', slug, env, 'current');
  mkdirSync(dir, { recursive: true });
  const packages = { '': { name: slug, version: '1.0.0' } };
  for (const [name, version] of Object.entries(deps)) packages[`node_modules/${name}`] = { version };
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
}

// OSV stub: `vulns` maps "name@version" to advisory ids, `fixes` maps an
// advisory id to its fixed version (absent = OSV published none). `down`
// makes querybatch fail, which records the scan as 'error'.
const realFetch = globalThis.fetch;
let osv = { vulns: {}, fixes: {}, down: false };
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (!u.includes('osv.dev')) return realFetch(url, opts);
  if (osv.down) return { ok: false, status: 503, json: async () => ({}) };
  if (u.includes('/v1/vulns/')) {
    const id = decodeURIComponent(u.slice(u.indexOf('/v1/vulns/') + '/v1/vulns/'.length));
    const fixed = osv.fixes[id];
    return {
      ok: true, status: 200,
      json: async () => ({
        id,
        affected: fixed ? [{ package: { ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed }] }] }] : [],
      }),
    };
  }
  const body = JSON.parse(opts.body);
  return {
    ok: true, status: 200,
    json: async () => ({
      results: body.queries.map((q) => {
        const ids = osv.vulns[`${q.package.name}@${q.version}`];
        return ids ? { vulns: ids.map((id) => ({ id, modified: '2026-09-08T00:00:00Z' })) } : {};
      }),
    }),
  };
};
function setOsv(vulns, fixes = {}, down = false) {
  osv = { vulns, fixes, down };
  clearAdvisoryCache();
}

const vulnRows = (slug) => db.prepare(
  'SELECT * FROM enhancement_requests WHERE app_slug = ? AND vuln_key IS NOT NULL ORDER BY id'
).all(slug);

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

test('a scan with a finding opens one ordinary request, worded for a coder', async () => {
  const app = makeApp('vr-one');
  writeLock('vr-one', { 'proxy-addr': '2.0.7', safe: '1.0.0' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-jqcg-44mw-7w3h'] }, { 'GHSA-jqcg-44mw-7w3h': '2.0.8' });
  const scan = await scanApp(db, app, 'production', 'deploy');
  assert.equal(scan.status, 'findings');
  const rows = vulnRows('vr-one');
  assert.equal(rows.length, 1);
  const r = rows[0];
  assert.equal(r.message.split('\n')[0], 'Upgrade proxy-addr 2.0.7 → 2.0.8 (GHSA-jqcg-44mw-7w3h)');
  assert.match(r.message, /Package: proxy-addr 2\.0\.7 \(npm\)/);
  assert.match(r.message, /First found in: production \(deploy scan\)/);
  assert.match(r.message, /osv\.dev\/vulnerability\/GHSA-jqcg-44mw-7w3h/);
  assert.equal(r.status, 'new');
  assert.equal(r.user_id, null);
  assert.equal(r.user_name, 'AppCrane dependency scan');
});

test('a second scan with the same findings opens nothing new', async () => {
  const app = makeApp('vr-repeat');
  writeLock('vr-repeat', { 'proxy-addr': '2.0.7' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-aaaa'] }, { 'GHSA-aaaa': '2.0.8' });
  await scanApp(db, app, 'production', 'deploy');
  await scanApp(db, app, 'production', 'scheduled');
  await scanApp(db, app, 'production', 'manual');
  assert.equal(vulnRows('vr-repeat').length, 1);
});

test('two scans racing each other still open one request', async () => {
  const app = makeApp('vr-race');
  writeLock('vr-race', { 'proxy-addr': '2.0.7' });
  writeLock('vr-race', { 'proxy-addr': '2.0.7' }, 'sandbox');
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-race'] }, { 'GHSA-race': '2.0.8' });
  await Promise.all([
    scanApp(db, app, 'production', 'scheduled'),
    scanApp(db, app, 'sandbox', 'scheduled'),
    scanApp(db, app, 'production', 'manual'),
  ]);
  assert.equal(vulnRows('vr-race').length, 1);
});

test('the same advisory in sandbox and production is one request, even at another version', async () => {
  const app = makeApp('vr-envs');
  writeLock('vr-envs', { 'proxy-addr': '2.0.6' }, 'sandbox');
  writeLock('vr-envs', { 'proxy-addr': '2.0.7' }, 'production');
  setOsv({ 'proxy-addr@2.0.6': ['GHSA-envs'], 'proxy-addr@2.0.7': ['GHSA-envs'] }, { 'GHSA-envs': '2.0.8' });
  await scanApp(db, app, 'sandbox', 'deploy');
  await scanApp(db, app, 'production', 'deploy');
  const rows = vulnRows('vr-envs');
  assert.equal(rows.length, 1);
  assert.match(rows[0].message, /First found in: sandbox/);
});

test('two advisories on the same package are two requests', async () => {
  const app = makeApp('vr-two');
  writeLock('vr-two', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-one', 'GHSA-two'] }, { 'GHSA-one': '4.17.16', 'GHSA-two': '4.17.21' });
  await scanApp(db, app, 'production', 'deploy');
  const rows = vulnRows('vr-two');
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((r) => r.message.split('\n')[0]).sort(), [
    'Upgrade lodash 4.17.15 → 4.17.21 (GHSA-one)',
    'Upgrade lodash 4.17.15 → 4.17.21 (GHSA-two)',
  ]);
});

test('different apps get separate requests for the same advisory', async () => {
  const a = makeApp('vr-app-a');
  const b = makeApp('vr-app-b');
  writeLock('vr-app-a', { 'proxy-addr': '2.0.7' });
  writeLock('vr-app-b', { 'proxy-addr': '2.0.7' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-apps'] }, { 'GHSA-apps': '2.0.8' });
  await scanApp(db, a, 'production', 'deploy');
  await scanApp(db, b, 'production', 'deploy');
  assert.equal(vulnRows('vr-app-a').length, 1);
  assert.equal(vulnRows('vr-app-b').length, 1);
});

test('a scan with no findings opens nothing', async () => {
  const app = makeApp('vr-clean');
  writeLock('vr-clean', { 'proxy-addr': '2.0.8' });
  setOsv({});
  const scan = await scanApp(db, app, 'production', 'deploy');
  assert.equal(scan.status, 'ok');
  assert.equal(vulnRows('vr-clean').length, 0);
});

test('no fixed version is said plainly', async () => {
  const app = makeApp('vr-nofix');
  writeLock('vr-nofix', { 'left-pad': '1.0.0' });
  setOsv({ 'left-pad@1.0.0': ['GHSA-nofix'] });
  await scanApp(db, app, 'production', 'deploy');
  const [r] = vulnRows('vr-nofix');
  assert.equal(r.message.split('\n')[0], 'Upgrade left-pad 1.0.0: no fixed version yet (GHSA-nofix)');
  assert.match(r.message, /no fixed version has been published yet/);
});

test('a failure opening requests does not fail the scan', async () => {
  const app = makeApp('vr-broken');
  writeLock('vr-broken', { 'proxy-addr': '2.0.7' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-broken'] }, { 'GHSA-broken': '2.0.8' });
  db.exec(`CREATE TRIGGER vr_break BEFORE INSERT ON enhancement_requests
           WHEN NEW.app_slug = 'vr-broken' BEGIN SELECT RAISE(ABORT, 'request insert refused'); END`);
  try {
    const scan = await scanApp(db, app, 'production', 'deploy');
    assert.equal(scan.status, 'findings');
    assert.ok(db.prepare('SELECT id FROM app_vuln_scans WHERE id = ?').get(scan.id));
    assert.equal(vulnRows('vr-broken').length, 0);
  } finally {
    db.exec('DROP TRIGGER vr_break');
  }
});

// ---------------------------------------------------------------------------
// Closing
// ---------------------------------------------------------------------------

test('closes only once the finding is gone from every environment', async () => {
  const app = makeApp('vr-close');
  writeLock('vr-close', { 'proxy-addr': '2.0.7' }, 'sandbox');
  writeLock('vr-close', { 'proxy-addr': '2.0.7' }, 'production');
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-close'] }, { 'GHSA-close': '2.0.8' });
  await scanApp(db, app, 'sandbox', 'deploy');
  await scanApp(db, app, 'production', 'deploy');

  writeLock('vr-close', { 'proxy-addr': '2.0.8' }, 'sandbox');
  await scanApp(db, app, 'sandbox', 'deploy');
  let [r] = vulnRows('vr-close');
  assert.equal(r.status, 'new', 'production still has it, so the sandbox fix must not close it');
  assert.equal(r.done_note, null);

  writeLock('vr-close', { 'proxy-addr': '2.0.8' }, 'production');
  await scanApp(db, app, 'production', 'deploy');
  [r] = vulnRows('vr-close');
  assert.equal(r.status, 'done');
  assert.match(r.done_note, /no longer finds this advisory/);
});

test('an errored scan closes nothing, and does not count as the env being clean', async () => {
  const app = makeApp('vr-error');
  writeLock('vr-error', { 'proxy-addr': '2.0.7' }, 'sandbox');
  writeLock('vr-error', { 'proxy-addr': '2.0.7' }, 'production');
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-error'] }, { 'GHSA-error': '2.0.8' });
  await scanApp(db, app, 'sandbox', 'deploy');
  await scanApp(db, app, 'production', 'deploy');

  setOsv({}, {}, true);
  const scan = await scanApp(db, app, 'production', 'scheduled');
  assert.equal(scan.status, 'error');
  assert.equal(vulnRows('vr-error')[0].status, 'new');

  // Sandbox is now clean. Production's latest scan is the error, which proves
  // nothing; its latest SUCCESSFUL scan still has the finding, so it stays open.
  writeLock('vr-error', { 'proxy-addr': '2.0.8' }, 'sandbox');
  setOsv({});
  await scanApp(db, app, 'sandbox', 'scheduled');
  assert.equal(vulnRows('vr-error')[0].status, 'new');
});

test('a request a person closed is not re-closed, re-noted or reopened', async () => {
  const app = makeApp('vr-human');
  writeLock('vr-human', { 'proxy-addr': '2.0.7' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-human'] }, { 'GHSA-human': '2.0.8' });
  await scanApp(db, app, 'production', 'deploy');
  const [opened] = vulnRows('vr-human');
  db.prepare("UPDATE enhancement_requests SET status = 'no_changes_needed', done_note = 'Not reachable in our code.' WHERE id = ?").run(opened.id);

  writeLock('vr-human', { 'proxy-addr': '2.0.8' });
  setOsv({});
  await scanApp(db, app, 'production', 'scheduled');
  let rows = vulnRows('vr-human');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].status, 'no_changes_needed');
  assert.equal(rows[0].done_note, 'Not reachable in our code.');

  writeLock('vr-human', { 'proxy-addr': '2.0.7' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-human'] }, { 'GHSA-human': '2.0.8' });
  await scanApp(db, app, 'production', 'scheduled');
  rows = vulnRows('vr-human');
  assert.equal(rows.length, 1, 'opened once: the advisory coming back does not open a second request');
  assert.equal(rows[0].status, 'no_changes_needed');
});

// ---------------------------------------------------------------------------
// The owner's queue
// ---------------------------------------------------------------------------

test("a scan-opened request is in the owner's request queue like any other", async () => {
  const ownerId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Owner','owner@example.com','user','vr-owner-key',1,'human')")
    .run().lastInsertRowid;
  const app = makeApp('vr-queue', ownerId);
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(app.id, ownerId);
  const SESSION = 'sess_' + 'v'.repeat(40);
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))")
    .run(ownerId, hashApiKey(SESSION));
  writeLock('vr-queue', { 'proxy-addr': '2.0.7' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-queue'] }, { 'GHSA-queue': '2.0.8' });
  await scanApp(db, app, 'production', 'deploy');
  const [opened] = vulnRows('vr-queue');

  const enhancementsRoutes = (await import('../server/routes/enhancements.js')).default;
  const { errorHandler } = await import('../server/utils/errors.js');
  const api = express();
  api.use(express.json());
  api.use('/api/enhancements', enhancementsRoutes);
  api.use(errorHandler);
  const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/api/enhancements/owned`, {
      headers: { authorization: `Bearer ${SESSION}` },
    });
    assert.equal(res.status, 200);
    const { requests } = await res.json();
    const row = requests.find((r) => r.id === opened.id);
    assert.ok(row, 'the request is listed in /api/enhancements/owned');
    assert.equal(row.status, 'new');
    assert.equal(row.bucket, 'triage');
    assert.equal(row.message.split('\n')[0], 'Upgrade proxy-addr 2.0.7 → 2.0.8 (GHSA-queue)');
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

// ---------------------------------------------------------------------------
// The digest
// ---------------------------------------------------------------------------

test('the digest links each finding to its request, and omits the link when there is none', async () => {
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Root','root@example.com','platform_admin','vr-root-key',1,'human')").run();
  const linked = makeApp('vr-digest');
  writeLock('vr-digest', { 'proxy-addr': '2.0.7' });
  setOsv({ 'proxy-addr@2.0.7': ['GHSA-digest'] }, { 'GHSA-digest': '2.0.8' });
  await scanApp(db, linked, 'production', 'scheduled');
  const [req] = vulnRows('vr-digest');

  const unlinked = makeApp('vr-digest-none');
  db.prepare(`INSERT INTO app_vuln_scans (app_id, env, source, ecosystem, status, package_count, findings_json)
              VALUES (?, 'production', 'scheduled', 'npm', 'findings', 1, ?)`)
    .run(unlinked.id, JSON.stringify([{ name: 'minimist', version: '0.0.8', ecosystem: 'npm', ids: ['GHSA-nolink'], fixed: '1.2.6' }]));

  const { recipients } = buildDigest(db);
  assert.ok(recipients.length > 0);
  sendVulnDigest(db);
  const mail = db.prepare("SELECT * FROM email_queue WHERE source = 'vuln-digest' AND to_email = 'root@example.com'").get();
  assert.ok(mail, 'a digest was queued');
  const url = `http://crane.test/requests?request=${req.id}`;
  assert.ok(mail.body_html.includes(`<a href="${url}" style="color:#2563eb;">GHSA-digest</a>`), 'the HTML links the advisory to its request');
  assert.ok(mail.body_text.includes(`GHSA-digest (request #${req.id}: ${url})`), 'the text part names the request and its link');
  assert.ok(mail.body_html.includes('GHSA-nolink') && mail.body_text.includes('GHSA-nolink'), 'the finding without a request is still listed');
  assert.ok(!mail.body_text.includes('GHSA-nolink (request') && !mail.body_html.includes('GHSA-nolink</a>'), 'and is not linked');
});

after(() => { globalThis.fetch = realFetch; });
