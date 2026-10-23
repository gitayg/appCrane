import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The release check's auto-patch delta mode: an auto-patch run passes the
// dependency check when the target advisory is gone and every fixable finding
// left is one production's own scan already has. Everything else, and every
// run a person starts, is judged exactly as before.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-ap-delta-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug', 'error']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
const { submitIntake, reviewIntake } = await import('../server/services/appIntake.js');
const rc = await import('../server/services/releaseCheck.js');
const { promoteApp } = await import('../server/services/deployer.js');
const { autoPatchMail } = await import('../server/services/autoPatch/mail.js');
const { runtimePatchMail } = await import('../server/services/autoPatch/runtimeMail.js');

const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Ada','ada@t.test','platform_admin','a',1,'human')").run().lastInsertRowid;
const ownerId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Owen','owen@t.test','user','x',1,'human')").run().lastInsertRowid;
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);

const RCE = { name: 'minimist', version: '1.2.5', ecosystem: 'npm', ids: ['GHSA-RCE1'], fixed: '1.2.6' };
const OLD = { name: 'lodash', version: '4.17.15', ecosystem: 'npm', ids: ['GHSA-OLD1'], fixed: '4.17.21' };
const NEW = { name: 'axios', version: '0.21.0', ecosystem: 'npm', ids: ['GHSA-NEW1'], fixed: '0.21.1' };
const rowOf = (findings) => ({ id: 1, status: findings.length ? 'findings' : 'ok', findings_json: findings.length ? JSON.stringify(findings) : null });

let candidate = rowOf([]);
let prodScan = rowOf([]);
const scans = [];
rc._setReleaseCheckDepsForTests({
  scanApp: async (_db, _app, env) => { scans.push(env); return env === 'production' ? prodScan : candidate; },
  scanTree: async () => candidate,
});
after(() => { rc._setReleaseCheckDepsForTests(null); try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

let nextSlot = 13100;
function makeApp(slug, { level = 'internal', files = { 'server.js': '1;\n' }, approve = true, source = 'upload' } = {}) {
  const id = db.prepare('INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, ?)').run(slug, slug, nextSlot++, source).lastInsertRowid;
  for (const env of ['production', 'sandbox']) db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(id, ownerId);
  let rel = null;
  if (source !== 'image') {
    rel = join(ROOT, 'apps', slug, 'sandbox', 'releases', 'r1');
    mkdirSync(rel, { recursive: true });
    for (const [f, c] of Object.entries(files)) writeFileSync(join(rel, f), c);
    symlinkSync(rel, join(ROOT, 'apps', slug, 'sandbox', 'current'));
  }
  db.prepare("INSERT INTO deployments (app_id, env, status, version, commit_hash, release_path, finished_at) VALUES (?, 'sandbox', 'live', '1.0.1', 'bbb222', ?, datetime('now'))").run(id, rel);
  db.prepare("INSERT INTO deployments (app_id, env, status, version, commit_hash, finished_at) VALUES (?, 'production', 'live', '1.0.0', 'aaa111', datetime('now', '-1 day'))").run(id);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  submitIntake(app, { data_classification: level, owner: ownerId, db });
  if (approve && (level === 'confidential' || level === 'restricted')) reviewIntake(db, app, { decision: 'approve' }, admin);
  return app;
}
const dep = (rec) => rec.checks.find((c) => c.id === 'dependencies');
const NPM_TARGET = { kind: 'npm', ecosystem: 'npm', name: 'minimist', advisory: 'GHSA-RCE1' };
const baselineOf = (findings) => ({ ok: true, scan_id: 9, findings });
const deltaRun = (app, delta, extra = {}) => rc.runReleaseCheck({ db, app, userId: null, trigger: 'auto-patch', mode: rc.AUTO_PATCH_DELTA, delta, ...extra });

test('delta pass: only findings production already has remain, and the target advisory is gone', async () => {
  const app = makeApp('d-pass');
  candidate = rowOf([OLD]);
  const rec = await deltaRun(app, { baseline: baselineOf([RCE, OLD]), target: NPM_TARGET });
  assert.equal(rec.blocked, false, JSON.stringify(rec.checks, null, 1));
  assert.equal(dep(rec).status, 'warn');
  assert.deepEqual(dep(rec).delta.pre_existing, ['lodash@4.17.15 (GHSA-OLD1)']);
  assert.ok(dep(rec).reasons.includes('1 pre-existing finding(s) unchanged: lodash@4.17.15 (GHSA-OLD1)'), JSON.stringify(dep(rec).reasons));
  assert.match(dep(rec).reasons[0], /GHSA-RCE1 on minimist is gone/);
  const stored = JSON.parse(db.prepare('SELECT checks_json FROM release_checks WHERE id = ?').get(rec.id).checks_json);
  assert.deepEqual(stored.find((c) => c.id === 'dependencies').delta.pre_existing, ['lodash@4.17.15 (GHSA-OLD1)'], 'the stored record names them');
  assert.deepEqual(rc.preExistingFindings(db, rec.id), ['lodash@4.17.15 (GHSA-OLD1)']);
});

test('a run a person starts is unchanged: the pre-existing finding still blocks it, delta asked for or not', async () => {
  const app = makeApp('d-human');
  candidate = rowOf([OLD]);
  const delta = { baseline: baselineOf([RCE, OLD]), target: NPM_TARGET };
  const plain = await rc.runReleaseCheck({ db, app, userId: ownerId, trigger: 'promote' });
  assert.equal(plain.blocked, true);
  assert.equal(dep(plain).status, 'fail');
  const asked = await rc.runReleaseCheck({ db, app, userId: ownerId, trigger: 'promote', mode: rc.AUTO_PATCH_DELTA, delta });
  assert.equal(asked.blocked, true, 'a user id turns the delta comparison off');
  assert.equal(dep(asked).delta, undefined);
  const noMode = await rc.runReleaseCheck({ db, app, userId: null, trigger: 'promote', delta });
  assert.equal(noMode.blocked, true, 'no mode, no delta');
});

test('delta fail: the candidate adds a fixable finding production does not have', async () => {
  const app = makeApp('d-new');
  candidate = rowOf([OLD, NEW]);
  const rec = await deltaRun(app, { baseline: baselineOf([RCE, OLD]), target: NPM_TARGET });
  assert.equal(rec.blocked, true);
  assert.equal(dep(rec).status, 'fail');
  assert.match(dep(rec).reasons[0], /did not pass: 1 fixable finding\(s\) production does not have: axios@0.21.0 \(GHSA-NEW1\)/);
});

test('delta fail: the target advisory is still in the candidate', async () => {
  const app = makeApp('d-target');
  candidate = rowOf([RCE, OLD]);
  const rec = await deltaRun(app, { baseline: baselineOf([RCE, OLD]), target: NPM_TARGET });
  assert.equal(rec.blocked, true);
  assert.match(dep(rec).reasons[0], /GHSA-RCE1 on minimist is still in the release/);
  const none = await deltaRun(app, { baseline: baselineOf([RCE, OLD]) });
  assert.equal(none.blocked, true, 'no target named: fails closed');
  assert.match(dep(none).reasons[0], /no target advisory was named/);
});

test('delta fails closed: no baseline, a baseline that errored, a production scan error, no live production', async () => {
  const app = makeApp('d-closed');
  candidate = rowOf([OLD]);
  for (const delta of [undefined, {}, { baseline: { ok: false, error: 'OSV query failed: fetch failed' }, target: NPM_TARGET }, { baseline: null, target: NPM_TARGET }]) {
    const rec = await deltaRun(app, delta);
    assert.equal(rec.blocked, true, JSON.stringify(delta));
    assert.match(dep(rec).reasons[0], /no production baseline/);
  }
  prodScan = { id: 2, status: 'error', error: 'OSV query failed: fetch failed' };
  const b = await rc.productionBaseline(db, app);
  assert.equal(b.ok, false);
  assert.match(b.error, /OSV query failed/);
  assert.equal(scans.at(-1), 'production', 'no fresh production scan on record: one is run');
  assert.equal((await deltaRun(app, { baseline: b, target: NPM_TARGET })).blocked, true);
  db.prepare("UPDATE deployments SET status = 'rolled_back' WHERE app_id = ? AND env = 'production'").run(app.id);
  assert.deepEqual(await rc.productionBaseline(db, app), { ok: false, error: 'production has no live release' });
  prodScan = rowOf([]);
});

test('productionBaseline reads a fresh production scan, and rescans when the one on record predates the live release', async () => {
  const app = makeApp('d-base');
  db.prepare(`INSERT INTO app_vuln_scans (app_id, env, source, status, findings_json, scanned_at) VALUES (?, 'production', 'deploy', 'findings', ?, datetime('now'))`).run(app.id, JSON.stringify([OLD]));
  const n = scans.length;
  const b = await rc.productionBaseline(db, app);
  assert.equal(b.ok, true);
  assert.deepEqual(b.findings, [OLD]);
  assert.equal(scans.length, n, 'fresh: not rescanned');
  db.prepare("UPDATE app_vuln_scans SET scanned_at = datetime('now', '-2 days') WHERE app_id = ?").run(app.id);
  prodScan = rowOf([RCE]);
  assert.deepEqual((await rc.productionBaseline(db, app)).findings, [RCE]);
  assert.equal(scans.at(-1), 'production');
  prodScan = rowOf([]);
});

test('every other check is still enforced in delta mode: a secret, and intake', async () => {
  candidate = rowOf([OLD]);
  const delta = { baseline: baselineOf([RCE, OLD]), target: NPM_TARGET };
  const key = `ghp_${'a1B2'.repeat(9)}`;
  const secret = makeApp('d-secret', { level: 'confidential', files: { 'config.js': `module.exports = { token: "${key}" };\n` } });
  const r1 = await deltaRun(secret, delta);
  assert.equal(r1.mode, 'enforce');
  assert.equal(dep(r1).status, 'warn');
  assert.equal(r1.checks.find((c) => c.id === 'secrets').status, 'fail');
  assert.equal(r1.blocked, true);
  const intake = makeApp('d-intake', { level: 'confidential', approve: false });
  const r2 = await deltaRun(intake, delta);
  assert.equal(r2.checks[0].status, 'fail');
  assert.equal(r2.blocked, true);
});

test('runtime rebuild: delta passes when the sandbox runtime is at or past the fix, and fails when it is not', async () => {
  const app = makeApp('d-runtime');
  candidate = rowOf([OLD]);
  const target = (version) => ({ kind: 'runtime', runtime: 'PHP', advisories: ['CVE-2026-109618'], fixed_version: '8.3.30', version });
  const ok = await deltaRun(app, { baseline: baselineOf([OLD]), target: target('8.3.30') });
  assert.equal(ok.blocked, false, JSON.stringify(dep(ok).reasons));
  assert.match(dep(ok).reasons[0], /PHP 8.3.30 \(fixed in 8.3.30, CVE-2026-109618\) is fixed/);
  const bad = await deltaRun(app, { baseline: baselineOf([OLD]), target: target('8.3.29') });
  assert.equal(bad.blocked, true);
  assert.match(dep(bad).reasons[0], /is not fixed/);
});

test('the delta reaches the promote check and the in-deploy check; a person\'s promote is still refused', async () => {
  candidate = rowOf([OLD]);
  const delta = { baseline: baselineOf([RCE, OLD]), target: NPM_TARGET };
  const img = makeApp('d-promote', { source: 'image' });
  await assert.rejects(promoteApp(img, null, { releaseCheckDelta: delta }), (e) => e.code === 'NO_IMAGE_REF', 'got past the release check');
  await assert.rejects(promoteApp(img, null), (e) => e.code === 'RELEASE_CHECK_FAILED');
  await assert.rejects(promoteApp(img, ownerId, { releaseCheckDelta: delta }), (e) => e.code === 'RELEASE_CHECK_FAILED');

  const app = makeApp('d-deploy');
  const deployId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'production', 'building', NULL)").run(app.id).lastInsertRowid;
  const rec = await rc.enforceReleaseCheckInDeploy({ app, deployId, releaseDir: null, commit: null, opts: { releaseCheckDelta: delta } });
  assert.equal(rec.blocked, false);
  await assert.rejects(rc.enforceReleaseCheckInDeploy({ app, deployId, releaseDir: null, commit: null, opts: {} }), /Release check refused/);
  const human = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'production', 'building', ?)").run(app.id, ownerId).lastInsertRowid;
  await assert.rejects(rc.enforceReleaseCheckInDeploy({ app, deployId: human, releaseDir: null, commit: null, opts: { releaseCheckDelta: delta } }), /Release check refused/);
});

test('the owner e-mails name the pre-existing findings', () => {
  const app = { slug: 'svc' };
  const pre = ['lodash@4.17.15 (GHSA-OLD1)'];
  const m = autoPatchMail(app, { status: 'applied', package: 'minimist', from_version: '1.2.5', to_version: '1.2.6', advisory_id: 'GHSA-RCE1', ecosystem: 'npm' }, { preExisting: pre });
  assert.match(m.text, /Already in production before this fix, unchanged by it \(1\): lodash@4\.17\.15 \(GHSA-OLD1\)/);
  assert.match(m.html, /lodash@4\.17\.15 \(GHSA-OLD1\)/);
  const r = runtimePatchMail(app, { status: 'applied', runtime: 'php', from_version: '8.3.29', to_version: '8.3.30', advisory_key: 'CVE-2026-109618' }, { preExisting: pre });
  assert.match(r.text, /unchanged by it \(1\): lodash@4\.17\.15/);
  assert.doesNotMatch(autoPatchMail(app, { status: 'applied', package: 'minimist', advisory_id: 'X', ecosystem: 'npm' }).text, /Already in production/);
});
