import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';
import express from 'express';

// The release check before production: each check's fail and pass, exceptions
// with reason and expiry, warn/off modes, and every production path refusing:
// the deploy route, the promote route, MCP deploy and promote, and the
// in-deploy check that webhook / push / AppStudio / artifact deploys reach
// through deployApp. Real deployApp of an image app against a `docker` shim
// and real health endpoints (the event-store-deploy.test.js harness).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-relcheck-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(ROOT, 'bin');
const RULES = join(ROOT, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) {\n' +
  '  if (r.match.every(tok => argv.includes(tok))) {\n' +
  '    process.stdout.write(r.stdout || ""); process.stderr.write(r.stderr || ""); process.exit(r.code || 0);\n' +
  '  }\n' +
  '}\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 });
writeFileSync(join(SHIM_DIR, 'caddy'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;
const DIGEST = `sha256:${'d4'.repeat(32)}`;
writeFileSync(RULES, JSON.stringify([
  { match: ['image', 'inspect'], stdout: `nginx@${DIGEST}\n` },
  { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
  { match: ['images', '--filter'], stdout: '' },
  { match: ['run', 'aquasec/trivy'], code: 1 },
]));

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug', 'error']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { submitIntake, reviewIntake } = await import('../server/services/appIntake.js');
const { setClassificationPolicy } = await import('../server/services/dataClassification.js');
const rc = await import('../server/services/releaseCheck.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp, rollbackApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { triggerAutoDeploys } = await import('../server/services/deployTrigger.js');
const { setRules } = await import('../server/services/accessRules.js');

const ADMIN_KEY = generateApiKey('dhk_admin');
const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Ada','ada@t.test','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY)).lastInsertRowid;
const ownerId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Owen','owen@t.test','user','x',1,'human')").run().lastInsertRowid;
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);
const owner = db.prepare('SELECT * FROM users WHERE id = ?').get(ownerId);

// The dependency/image scanner is replaced: the claim is about the gate's
// judgement of a scan result, not OSV or Trivy.
let scanRow = { status: 'ok', findings_json: null };
rc._setReleaseCheckDepsForTests({ scanApp: async () => scanRow, scanTree: async () => scanRow });
const CRITICAL = { status: 'findings', findings_json: JSON.stringify([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm', ids: ['GHSA-35jh-r3h4-6jhm'], fixed: '4.17.21' }]) };

const servers = [];
function listen(port) {
  return new Promise((res) => {
    const s = http.createServer((q, out) => { out.writeHead(200, { 'content-type': 'application/json' }); out.end('{"status":"ok"}'); });
    s.on('error', () => res(null));
    s.listen(port, '127.0.0.1', () => res(s));
  });
}
let IMG_SLOT = null;
for (let slot = 12745; slot < 12845 && IMG_SLOT === null; slot++) {
  const p = getPortsForSlot(slot);
  const a = await listen(p.sand_be);
  if (!a) continue;
  const b = await listen(p.prod_be);
  if (!b) { a.close(); continue; }
  IMG_SLOT = slot; servers.push(a, b);
}
assert.ok(IMG_SLOT !== null, 'no free port pair');

let nextSlot = 12900;
function treeApp(slug, level, files) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'upload')").run(slug, slug, nextSlot++).lastInsertRowid;
  for (const env of ['production', 'sandbox']) db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(id, ownerId);
  const rel = join(ROOT, 'apps', slug, 'sandbox', 'releases', 'r1');
  mkdirSync(join(rel, 'node_modules', 'dep'), { recursive: true });
  writeFileSync(join(rel, 'package.json'), '{"name":"x","version":"1.0.0"}');
  writeFileSync(join(rel, 'node_modules', 'dep', 'index.js'), `const k = "AKIA${'Q'.repeat(16)}";\n`);
  for (const [f, c] of Object.entries(files)) writeFileSync(join(rel, f), c);
  symlinkSync(rel, join(ROOT, 'apps', slug, 'sandbox', 'current'));
  db.prepare("INSERT INTO deployments (app_id, env, status, version, commit_hash, release_path, finished_at) VALUES (?, 'sandbox', 'live', '1.0.0', 'abc123', ?, datetime('now'))").run(id, rel);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  submitIntake(app, { data_classification: level, owner: ownerId, db });
  if (level === 'confidential' || level === 'restricted') reviewIntake(db, app, { decision: 'approve' }, admin);
  return app;
}
const byId = (rec, id) => rec.checks.find((c) => c.id === id);

let server;
let BASE;
before(async () => {
  const api = express();
  api.use(express.json());
  api.use('/api', (await import('../server/routes/releaseCheck.js')).default);
  api.use('/api/apps', (await import('../server/routes/deploy.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  BASE = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  rc._setReleaseCheckDepsForTests(null);
  for (const s of [...servers, server]) { s?.closeAllConnections?.(); s?.unref(); s?.close(); }
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker?.();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});
async function post(path, body = {}) {
  const r = await fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': ADMIN_KEY }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}

test('passes when the release is clean (node_modules is not scanned)', async () => {
  scanRow = { status: 'ok', findings_json: null };
  const app = treeApp('clean-a', 'confidential', { 'server.js': 'module.exports = 1;\n' });
  const rec = await rc.runReleaseCheck({ db, app, userId: adminId, trigger: 'promote' });
  assert.equal(rec.result, 'pass', JSON.stringify(rec.checks, null, 1));
  assert.equal(rec.blocked, false);
  assert.equal(rec.mode, 'enforce');
  assert.deepEqual(rec.checks.map((c) => c.id), ['intake', 'dependencies', 'secrets', 'access_rules', 'sso_gate', 'sandbox_health']);
  assert.ok(db.prepare('SELECT 1 FROM release_checks WHERE id = ?').get(rec.id), 'stored per release');
});

test('fails on a planted secret, naming file and line but never the value', async () => {
  scanRow = { status: 'ok', findings_json: null };
  const key = `ghp_${'a1B2'.repeat(9)}`;
  const app = treeApp('secret-a', 'confidential', { 'config.js': `module.exports = {\n  token: "${key}",\n};\n` });
  const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  const s = byId(rec, 'secrets');
  assert.equal(s.status, 'fail');
  assert.ok(s.reasons.some((r) => r === 'config.js:2 (github-token)'), JSON.stringify(s.reasons));
  assert.ok(!JSON.stringify(rec).includes(key));
  assert.equal(rec.blocked, true);
});

test('fails on a vulnerable dependency with a published fix; an unfixed one only warns', async () => {
  const app = treeApp('vuln-a', 'confidential', { 'server.js': '1;\n' });
  scanRow = CRITICAL;
  assert.equal(byId(await rc.runReleaseCheck({ db, app, trigger: 'promote' }), 'dependencies').status, 'fail');
  scanRow = { status: 'findings', findings_json: JSON.stringify([{ name: 'x', version: '1.0.0', ecosystem: 'npm', ids: ['GHSA-1'], fixed: null }]) };
  const warn = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  assert.equal(byId(warn, 'dependencies').status, 'warn');
  assert.equal(warn.blocked, false);
  scanRow = { status: 'error', error: 'OSV unreachable' };
  assert.equal(byId(await rc.runReleaseCheck({ db, app, trigger: 'promote' }), 'dependencies').status, 'fail');
  scanRow = { status: 'ok', findings_json: null };
});

test('a vulnerable dependency with a published fix blocks every app by default; the toggle turns that off', async () => {
  const app = treeApp('vuln-b', 'internal', { 'server.js': '1;\n' });
  assert.equal(setClassificationPolicy(db, {}, admin).block_vulnerable_dependencies, true, 'on by default');
  scanRow = CRITICAL;
  const on = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  assert.equal(on.mode, 'warn');
  assert.equal(on.blocked, true, 'an internal (warn-mode) app is still blocked on a fixable vulnerability');
  setClassificationPolicy(db, { block_vulnerable_dependencies: false }, admin);
  const off = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  assert.equal(byId(off, 'dependencies').status, 'fail');
  assert.equal(off.blocked, false);
  const conf = treeApp('vuln-c', 'confidential', { 'server.js': '1;\n' });
  assert.equal((await rc.runReleaseCheck({ db, app: conf, trigger: 'promote' })).blocked, false, 'off means a vulnerability never blocks, even on enforce levels');
  scanRow = { status: 'error', error: 'OSV unreachable' };
  assert.equal((await rc.runReleaseCheck({ db, app: conf, trigger: 'promote' })).blocked, true, 'a scan that could not run still follows the level mode');
  assert.throws(() => setClassificationPolicy(db, { block_vulnerable_dependencies: 'yes' }, admin), /true or false/);
  setClassificationPolicy(db, { block_vulnerable_dependencies: true }, admin);
  scanRow = { status: 'ok', findings_json: null };
});

test('restricted apps need access rules', async () => {
  const app = treeApp('rules-a', 'restricted', { 'server.js': '1;\n' });
  const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  assert.equal(byId(rec, 'access_rules').status, 'fail');
  setRules(db, app.id, 'production', 'dashboard', [{ path: '/admin/*', roles: ['admin'] }], adminId);
  assert.equal(byId(await rc.runReleaseCheck({ db, app, trigger: 'promote' }), 'access_rules').status, 'pass');
});

test('fails when the SSO gate is bypassed on a confidential app; allowed on internal', async () => {
  const app = treeApp('sso-a', 'confidential', { 'server.js': '1;\n' });
  db.prepare("UPDATE apps SET auth_mode = 'headless' WHERE id = ?").run(app.id);
  assert.equal(byId(await rc.runReleaseCheck({ db, app, trigger: 'promote' }), 'sso_gate').status, 'fail');
  db.prepare("UPDATE apps SET auth_mode = 'authenticated', domain = 'tool.acme.test' WHERE id = ?").run(app.id);
  assert.equal(byId(await rc.runReleaseCheck({ db, app, trigger: 'promote' }), 'sso_gate').status, 'fail');
  const internal = treeApp('sso-b', 'internal', { 'server.js': '1;\n' });
  db.prepare("UPDATE apps SET auth_mode = 'headless' WHERE id = ?").run(internal.id);
  assert.equal(byId(await rc.runReleaseCheck({ db, app: internal, trigger: 'promote' }), 'sso_gate').status, 'pass');
});

test('an exception unblocks one check with a reason and an expiry, and stops when it expires', async () => {
  const app = treeApp('exc-a', 'confidential', { 'k.pem': '-----BEGIN RSA PRIVATE KEY-----\nMIIx\n' });
  assert.equal((await rc.runReleaseCheck({ db, app, trigger: 'promote' })).blocked, true);
  assert.throws(() => rc.addException(db, app, { check_id: 'secrets', reason: 'short', days: 3 }, owner), /at least 10/);
  assert.throws(() => rc.addException(db, app, { check_id: 'secrets', reason: 'Test fixture key, not used', days: 120 }, owner), /at most 90 days/);
  assert.throws(() => rc.addException(db, app, { check_id: 'intake', reason: 'Not allowed at all', days: 3 }, owner), /check_id must be one of/);
  const ex = rc.addException(db, app, { check_id: 'secrets', reason: 'Test fixture key, not used', days: 3 }, owner);
  const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  assert.equal(byId(rec, 'secrets').status, 'excepted');
  assert.equal(byId(rec, 'secrets').exception.reason, 'Test fixture key, not used');
  assert.equal(rec.blocked, false);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'release-check-exception-add' AND app_id = ?").get(app.id));
  assert.ok(db.prepare("SELECT 1 FROM events WHERE kind = 'release_check.exception' AND app_id = ?").get(app.id));
  db.prepare("UPDATE release_check_exceptions SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(ex.id);
  assert.equal((await rc.runReleaseCheck({ db, app, trigger: 'promote' })).blocked, true, 'an expired exception covers nothing');
});

test('on restricted apps only platform admins record exceptions', async () => {
  const app = treeApp('exc-b', 'restricted', { 'server.js': '1;\n' });
  assert.throws(() => rc.addException(db, app, { check_id: 'access_rules', reason: 'Rules land next week', days: 7 }, owner), /Only platform admins/);
  assert.ok(rc.addException(db, app, { check_id: 'access_rules', reason: 'Rules land next week', days: 7 }, admin).id);
});

test('warn mode records failures without blocking; off skips the checks but not intake', async () => {
  const app = treeApp('mode-a', 'confidential', { 'k.pem': '-----BEGIN PRIVATE KEY-----\n' });
  setClassificationPolicy(db, { release_check_mode: 'warn' }, admin);
  const w = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  assert.equal(w.mode, 'warn');
  assert.equal(w.result, 'fail');
  assert.equal(w.blocked, false);
  setClassificationPolicy(db, { release_check_mode: 'off' }, admin);
  const o = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
  assert.equal(o.result, 'skipped');
  assert.equal(o.checks.length, 1);
  db.prepare("UPDATE app_intake SET status = 'pending' WHERE app_id = ?").run(app.id);
  assert.equal((await rc.runReleaseCheck({ db, app, trigger: 'promote' })).blocked, true, 'intake still refuses with the checks off');
  db.prepare("UPDATE app_intake SET status = 'approved' WHERE app_id = ?").run(app.id);
  setClassificationPolicy(db, { release_check_mode: 'by_classification', levels: { internal: { release_check: 'enforce' } } }, admin);
  const internal = treeApp('mode-b', 'internal', { 'k.pem': '-----BEGIN PRIVATE KEY-----\n' });
  assert.equal((await rc.runReleaseCheck({ db, app: internal, trigger: 'promote' })).blocked, true, 'the per-level mode is editable');
  setClassificationPolicy(db, { levels: { internal: { release_check: 'warn' } } }, admin);
  assert.throws(() => setClassificationPolicy(db, { release_check_mode: 'warn' }, owner), /Only platform admins/);
});

test('deploy route: production refused with the checklist, nothing recorded as a deployment', async () => {
  const app = treeApp('path-route', 'confidential', { 'k.pem': '-----BEGIN PRIVATE KEY-----\n' });
  const r = await post('/api/apps/path-route/deploy/production');
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'RELEASE_CHECK_FAILED');
  assert.equal(r.body.release_check.checks.find((c) => c.id === 'secrets').status, 'fail');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND env = 'production'").get(app.id).n, 0);
});

test('promote route: refused with the checklist', async () => {
  const app = treeApp('path-promote', 'confidential', { 'k.pem': '-----BEGIN PRIVATE KEY-----\n' });
  const r = await post('/api/apps/path-promote/promote');
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.release_check.trigger, 'promote');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND env = 'production'").get(app.id).n, 0);
});

test('MCP appcrane_deploy and appcrane_promote: refused', async () => {
  const app = treeApp('path-mcp', 'confidential', { 'k.pem': '-----BEGIN PRIVATE KEY-----\n' });
  const d = await callTool(admin, 'appcrane_deploy', { slug: 'path-mcp', env: 'production' }).then(() => null, (e) => e);
  assert.equal(d?.code, 'RELEASE_CHECK_FAILED');
  assert.match(d.message, /No secrets in code/);
  const p = await callTool(admin, 'appcrane_promote', { slug: 'path-mcp' }).then(() => null, (e) => e);
  assert.equal(p?.code, 'RELEASE_CHECK_FAILED');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND env = 'production'").get(app.id).n, 0);
});

test('preview route and history', async () => {
  const r = await post('/api/apps/path-mcp/release-check/run');
  assert.equal(r.status, 200);
  assert.equal(r.body.release_check.blocked, true);
  const g = await fetch(`${BASE}/api/apps/path-mcp/release-check`, { headers: { 'X-API-Key': ADMIN_KEY } }).then((x) => x.json());
  assert.equal(g.mode, 'enforce', JSON.stringify(g).slice(0, 300));
  assert.ok(g.history.length >= 3);
});

test('webhook (and every deployApp production path): the in-deploy check fails the deploy before any container change; rollback is allowed', async () => {
  scanRow = { status: 'ok', findings_json: null };
  const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,health_path) VALUES ('Img','img-a',?,'image','nginx:1',80,'/health')").run(IMG_SLOT).lastInsertRowid;
  for (const env of ['production', 'sandbox']) db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  let app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  submitIntake(app, { data_classification: 'confidential', owner: ownerId, db });
  reviewIntake(db, app, { decision: 'approve' }, admin);
  const ports = getPortsForSlot(IMG_SLOT);
  const sb = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)").run(id, adminId).lastInsertRowid;
  await deployApp(sb, app, 'sandbox', ports);
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(sb).status, 'live');

  for (const n of [1, 2]) {
    const ok = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'production', 'pending', ?)").run(id, adminId).lastInsertRowid;
    await deployApp(ok, app, 'production', ports);
    assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(ok).status, 'live', `clean production deploy ${n}`);
  }

  db.prepare("UPDATE apps SET auth_mode = 'headless' WHERE id = ?").run(id);
  app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  let pending = null;
  const triggered = await triggerAutoDeploys({
    config: { app_id: id, slug: 'img-a', auto_deploy_sandbox: 0, auto_deploy_prod: 1 },
    branch: 'main', commitSha: 'f'.repeat(40), commitMessage: 'push', logDelivery: () => {},
    deps: { deployApp: (...a) => { pending = deployApp(...a); return pending; }, getPortsForSlot },
  });
  await assert.rejects(pending, /Release check refused production/);
  const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(triggered[0].deployment_id);
  assert.equal(row.status, 'failed');
  assert.match(row.log, /fail: SSO gate not bypassed/);

  const rb = await rollbackApp(app, 'production', null, adminId);
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(rb.deployment_id).status, 'live', 'rollback to a release that already shipped is not re-gated');
});
