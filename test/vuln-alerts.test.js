import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Immediate vulnerability e-mail (vulnAlerts.js, migration 152): one mail per
// recipient per scan for findings nobody was told about yet, never twice.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-vuln-alerts-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.BASE_URL = 'http://crane.test';
delete process.env.CRANE_DOMAIN;
const DATA_DIR = process.env.DATA_DIR;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { scanApp, clearAdvisoryCache } = await import('../server/services/appScan.js');
const { alertNewFindings, _setVulnAlertDepsForTests } = await import('../server/services/vulnAlerts.js');

const realFetch = globalThis.fetch;
let osv = { vulns: {}, fixes: {}, cwes: {}, down: false };
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
        summary: 'test advisory',
        database_specific: { cwe_ids: osv.cwes[id] || [], severity: 'HIGH' },
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
function setOsv(vulns, fixes = {}, cwes = {}, down = false) {
  osv = { vulns, fixes, cwes, down };
  clearAdvisoryCache();
}

let n = 0;
function user(name, role = 'user', active = 1) {
  n++;
  return Number(db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES (?,?,?,?,?,'human')")
    .run(name, `${name.toLowerCase()}${n}@example.com`, role, active, `h${n}`).lastInsertRowid);
}
const admin = user('Ada', 'platform_admin');
const bothId = user('Bea', 'platform_admin');

let slot = 400;
function makeApp(slug, owners = []) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')").run(slug, slug, slot++).lastInsertRowid);
  for (const o of owners) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, o);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function writeLock(slug, deps, env = 'production') {
  const dir = join(DATA_DIR, 'apps', slug, env, 'current');
  mkdirSync(dir, { recursive: true });
  const packages = { '': { name: slug, version: '1.0.0' } };
  for (const [name, version] of Object.entries(deps)) packages[`node_modules/${name}`] = { version };
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
}
const mails = (app) => db.prepare("SELECT * FROM email_queue WHERE source = 'vuln-alert' AND app_id = ? ORDER BY id").all(app.id);
const setSetting = (v) => db.prepare(`INSERT INTO settings (key, value) VALUES ('vuln_alerts_immediate', ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(v);

beforeEach(() => {
  _setVulnAlertDepsForTests(null);
  db.prepare("DELETE FROM settings WHERE key = 'vuln_alerts_immediate'").run();
});

test('a new finding after a deploy scan mails each owner and admin once; a person who is both gets one mail', async () => {
  const owner = user('Olga');
  const app = makeApp('va-one', [owner, bothId]);
  writeLock('va-one', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-aaaa-bbbb-cccc'] }, { 'GHSA-aaaa-bbbb-cccc': '4.17.21' });
  await scanApp(db, app, 'production', 'deploy');

  const m = mails(app);
  const to = m.map((r) => r.to_email).sort();
  assert.equal(m.length, 3, `owner + admin + (owner and admin) = 3 people, got ${JSON.stringify(to)}`);
  assert.equal(new Set(to).size, 3);
  const bea = m.find((r) => r.to_email.startsWith('bea'));
  assert.match(bea.body_text, /an owner of this app and a platform admin/);
  assert.match(m[0].body_text, /lodash@4\.17\.15 \(npm\): Fixed in 4\.17\.21/);
  assert.match(m[0].body_text, /https:\/\/github\.com\/advisories\/GHSA-aaaa-bbbb-cccc/);
  assert.match(m[0].body_text, /A request is open in the app's queue \(#\d+\)/);
  assert.match(m[0].body_text, /release check will block production releases until lodash is upgraded/);
  assert.match(m[0].body_html, />App<\/span><span[^>]*>Crane</, 'branded layout');
  assert.equal(m[0].env, 'production');

  const ev = db.prepare("SELECT * FROM events WHERE kind = 'vuln.alert' AND app_id = ?").all(app.id);
  assert.equal(ev.length, 1);
  assert.equal(JSON.parse(ev[0].data).recipients, 3);
  assert.doesNotMatch(ev[0].data, /@example\.com/);

  await scanApp(db, app, 'production', 'scheduled');
  await scanApp(db, app, 'sandbox', 'deploy');
  assert.equal(mails(app).length, 3, 'the same finding on later scans, any env, mails nobody');
});

test('two new findings in one scan arrive in one e-mail that lists both', async () => {
  const owner = user('Omar');
  const app = makeApp('va-two', [owner]);
  writeLock('va-two', { lodash: '4.17.15', minimist: '1.2.0' });
  setOsv({ 'lodash@4.17.15': ['GHSA-1111-2222-3333'], 'minimist@1.2.0': ['GHSA-4444-5555-6666'] });
  await scanApp(db, app, 'production', 'deploy');
  const m = mails(app).filter((r) => r.to_email.startsWith('omar'));
  assert.equal(m.length, 1);
  assert.match(m[0].subject, /2 newly found vulnerable packages/);
  assert.match(m[0].body_text, /lodash@4\.17\.15/);
  assert.match(m[0].body_text, /minimist@1\.2\.0/);
  assert.match(m[0].body_text, /No fixed version published yet/);
  assert.match(m[0].body_text, /warning; it does not block production while no fix exists/);
});

test('the migration backfill marks existing findings as alerted, so the first scan after the upgrade mails nobody', async () => {
  const owner = user('Otto');
  const app = makeApp('va-backfill', [owner]);
  const findings = [{ name: 'lodash', version: '4.17.15', ecosystem: 'npm', ids: ['GHSA-bbbb-0000-1111'], fixed: '4.17.21' }];
  db.prepare(`INSERT INTO app_vuln_scans (app_id, env, source, ecosystem, status, package_count, findings_json)
    VALUES (?, 'production', 'scheduled', 'npm', 'findings', 1, ?)`).run(app.id, JSON.stringify(findings));
  db.prepare(`INSERT INTO app_vuln_scans (app_id, env, source, ecosystem, status, package_count, findings_json)
    VALUES (?, 'sandbox', 'scheduled', 'npm', 'findings', 1, 'not json')`).run(app.id);
  db.exec(readFileSync(new URL('../server/migrations/152-vuln-alerts.sql', import.meta.url), 'utf8'));
  assert.equal(db.prepare('SELECT COUNT(*) n FROM vuln_alerts WHERE app_id = ? AND scan_id IS NULL').get(app.id).n, 1);
  db.prepare("DELETE FROM app_vuln_scans WHERE app_id = ? AND findings_json = 'not json'").run(app.id);

  writeLock('va-backfill', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-bbbb-0000-1111'] }, { 'GHSA-bbbb-0000-1111': '4.17.21' });
  await scanApp(db, app, 'production', 'deploy');
  assert.equal(mails(app).length, 0);
});

test('error and skipped scans mail nobody', async () => {
  const owner = user('Oona');
  const app = makeApp('va-error', [owner]);
  writeLock('va-error', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-eeee-0000-1111'] }, {}, {}, true);
  assert.equal((await scanApp(db, app, 'production', 'deploy')).status, 'error');
  const skipped = makeApp('va-skipped', [owner]);
  assert.equal((await scanApp(db, skipped, 'production', 'deploy')).status, 'skipped');
  const fake = { id: 999999, env: 'production', source: 'deploy', status: 'error',
    findings_json: JSON.stringify([{ name: 'x', version: '1', ecosystem: 'npm', ids: ['GHSA-x'], fixed: null }]) };
  assert.equal((await alertNewFindings(db, app, fake)).skipped, 'status');
  assert.equal(mails(app).length + mails(skipped).length, 0);
});

test('deactivated owners and admins are skipped', async () => {
  const gone = user('Gus', 'user', 0);
  const goneAdmin = user('Gia', 'platform_admin', 0);
  const app = makeApp('va-inactive', [gone]);
  writeLock('va-inactive', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-iiii-0000-1111'] });
  await scanApp(db, app, 'production', 'deploy');
  const to = mails(app).map((r) => r.to_email);
  assert.ok(to.length >= 2, 'the active admins are still mailed');
  assert.ok(!to.some((t) => t.startsWith('gus') || t.startsWith('gia')), JSON.stringify(to));
  void goneAdmin;
});

test('the platform setting off sends nothing, and turning it back on does not mail the backlog', async () => {
  const owner = user('Opal');
  const app = makeApp('va-off', [owner]);
  writeLock('va-off', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-oooo-0000-1111'] });
  setSetting('false');
  await scanApp(db, app, 'production', 'deploy');
  assert.equal(mails(app).length, 0);
  setSetting('true');
  await scanApp(db, app, 'production', 'scheduled');
  assert.equal(mails(app).length, 0);
});

test('RCE wording when auto-patch applies, "a person needs to act" when it does not', async () => {
  const owner = user('Rex');
  _setVulnAlertDepsForTests({ usesLocalRepo: async () => true });
  const app = makeApp('va-rce', [owner]);
  writeLock('va-rce', { ejs: '3.1.6' });
  setOsv({ 'ejs@3.1.6': ['GHSA-rrrr-0000-1111'] }, { 'GHSA-rrrr-0000-1111': '3.1.7' }, { 'GHSA-rrrr-0000-1111': ['CWE-94'] });
  await scanApp(db, app, 'production', 'deploy');
  const m = mails(app).find((r) => r.to_email.startsWith('rex'));
  assert.match(m.body_text, /remote code execution/);
  assert.match(m.body_text, /RCE auto-patch will try this fix by itself/);
  assert.doesNotMatch(m.body_text, /A person needs to act/);

  _setVulnAlertDepsForTests({ usesLocalRepo: async () => false });
  const app2 = makeApp('va-rce-github', [owner]);
  writeLock('va-rce-github', { ejs: '3.1.6' });
  await scanApp(db, app2, 'production', 'deploy');
  const m2 = mails(app2).find((r) => r.to_email.startsWith('rex'));
  assert.match(m2.body_text, /auto-patch will not handle it \(auto-patch only works on apps whose repository AppCrane hosts\)\. A person needs to act\./);

  const app3 = makeApp('va-plain', [owner]);
  writeLock('va-plain', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-pppp-0000-1111'] }, { 'GHSA-pppp-0000-1111': '4.17.21' });
  await scanApp(db, app3, 'production', 'deploy');
  const m3 = mails(app3).find((r) => r.to_email.startsWith('rex'));
  assert.match(m3.body_text, /A person needs to act: upgrade the package/);
  assert.doesNotMatch(m3.body_text, /auto-patch will try/);
});

test('retrying the same scan does not send twice', async () => {
  const owner = user('Ivy');
  const app = makeApp('va-retry', [owner]);
  writeLock('va-retry', { lodash: '4.17.15' });
  setOsv({ 'lodash@4.17.15': ['GHSA-tttt-0000-1111'] });
  const row = await scanApp(db, app, 'production', 'deploy');
  const before = mails(app).length;
  assert.ok(before >= 1);
  const r = await alertNewFindings(db, app, row);
  assert.equal(r.sent, 0);
  assert.equal(r.findings, 1, 'the retry still recognises this scan as the one that found it');
  assert.equal(mails(app).length, before);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM events WHERE kind = 'vuln.alert' AND app_id = ?").get(app.id).n, 1);
});

test('a fixed finding that comes back is mailed again', async () => {
  const owner = user('Uma');
  const app = makeApp('va-back', [owner]);
  setOsv({ 'lodash@4.17.15': ['GHSA-kkkk-0000-1111'] });
  writeLock('va-back', { lodash: '4.17.15' });
  await scanApp(db, app, 'production', 'deploy');
  const first = mails(app).length;
  writeLock('va-back', { lodash: '4.17.21' });
  await scanApp(db, app, 'production', 'deploy');
  assert.equal(mails(app).length, first);
  writeLock('va-back', { lodash: '4.17.15' });
  await scanApp(db, app, 'production', 'deploy');
  const m = mails(app);
  assert.equal(m.length, first * 2);
  assert.match(m[m.length - 1].body_text, /was already closed; it is not reopened/);
});
