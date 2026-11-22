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
const { emptySupabase } = await import('../server/services/servedOutputScan.js');
const cleanCrawl = async () => ({ ok: true, error: null, findings: [], scanned: [{ path: '/' }], truncated: false, html: true, supabase: emptySupabase() });
const cleanProbe = async () => ({ ok: true, error: null, openapi: null, requests: 1, truncated: false, discovered: {}, skipped: {}, reads: [], writes: [], write_candidates: [] });
const baseDeps = { scanApp: async () => scanRow, scanTree: async () => scanRow, crawlServed: cleanCrawl, probeUnauth: cleanProbe };
rc._setReleaseCheckDepsForTests(baseDeps);
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

// The SBOM the sandbox deploy recorded (services/imageTrust/store.js), as the
// deploy's attestation step writes it: a signed row whose dir holds sbom.cdx.json.
const { dirFor: attestationDir, writeDoc: writeAttestationDoc, FILES: ATTESTATION_FILES } = await import('../server/services/imageTrust/store.js');
function attachSbom(app, components) {
  const dep = db.prepare("SELECT id FROM deployments WHERE app_id = ? AND env = 'sandbox' AND status = 'live' ORDER BY id DESC LIMIT 1").get(app.id);
  const id = Number(db.prepare("INSERT INTO deploy_attestations (deployment_id, app_id, env, origin, image_ref, status) VALUES (?, ?, 'sandbox', 'deploy', 'img', 'pending')").run(dep.id, app.id).lastInsertRowid);
  const dir = attestationDir(app.slug, 'sandbox', id);
  writeAttestationDoc(dir, ATTESTATION_FILES.sbom, JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components }));
  db.prepare("UPDATE deploy_attestations SET status = 'signed', dir = ? WHERE id = ?").run(dir, id);
}
const MIT = (name) => ({ type: 'library', name, version: '1.0.0', licenses: [{ license: { id: 'MIT' } }] });

test('passes when the release is clean (node_modules is not scanned)', async () => {
  scanRow = { status: 'ok', findings_json: null };
  const app = treeApp('clean-a', 'confidential', { 'server.js': 'module.exports = 1;\n' });
  attachSbom(app, [MIT('express')]);
  const rec = await rc.runReleaseCheck({ db, app, userId: adminId, trigger: 'promote' });
  assert.equal(rec.result, 'pass', JSON.stringify(rec.checks, null, 1));
  assert.equal(rec.blocked, false);
  assert.equal(rec.mode, 'enforce');
  assert.deepEqual(rec.checks.map((c) => c.id), ['intake', 'dependencies', 'secrets', 'served_secrets', 'supabase_rls', 'unauth_endpoints', 'access_rules', 'sso_gate', 'sandbox_health', 'licenses']);
  assert.ok(db.prepare('SELECT 1 FROM release_checks WHERE id = ?').get(rec.id), 'stored per release');
});

test('license policy: the sandbox release SBOM is checked; no SBOM warns, a flagged license warns, a denied one fails and blocks production', async () => {
  scanRow = { status: 'ok', findings_json: null };
  const { setTrustPolicy } = await import('../server/services/imageTrust/policy.js');
  const app = treeApp('lic-a', 'confidential', { 'server.js': 'module.exports = 1;\n' });

  let rec = await rc.runReleaseCheck({ db, app, userId: adminId, trigger: 'promote' });
  assert.equal(byId(rec, 'licenses').status, 'warn');
  assert.match(byId(rec, 'licenses').reasons[0], /No SBOM for this release/);
  assert.equal(byId(rec, 'licenses').label, 'License policy');
  assert.equal(rec.blocked, false, 'a missing SBOM never blocks');

  attachSbom(app, [MIT('express'), { type: 'library', name: 'ghostdb', version: '2.0.0', licenses: [{ license: { id: 'AGPL-3.0-only' } }] }]);
  rec = await rc.runReleaseCheck({ db, app, userId: adminId, trigger: 'promote' });
  assert.equal(byId(rec, 'licenses').status, 'warn', JSON.stringify(byId(rec, 'licenses')));
  assert.ok(byId(rec, 'licenses').reasons.some((r) => r.includes('ghostdb@2.0.0: AGPL-3.0-only')));
  assert.equal(rec.blocked, false);

  setTrustPolicy(db, { denied: ['AGPL-3.0-only'] }, adminId);
  try {
    rec = await rc.runReleaseCheck({ db, app, userId: adminId, trigger: 'promote' });
    assert.equal(byId(rec, 'licenses').status, 'fail');
    assert.equal(rec.result, 'fail');
    assert.equal(rec.blocked, true, 'a denied license blocks production under enforce');
    assert.ok(rc.EXCEPTABLE.includes('licenses'), 'a license failure can be excepted like the other checks');
  } finally {
    setTrustPolicy(db, { denied: [] }, adminId);
  }
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

test('a linked deployhub.json does not count towards the required access rules; a regular one does', async () => {
  const body = JSON.stringify({ access: { rules: [{ path: '/admin/*', roles: ['admin'] }] } });
  const hostFile = join(ROOT, 'host-deployhub.json');
  writeFileSync(hostFile, body);
  const linked = treeApp('rules-link', 'restricted', { 'server.js': '1;\n' });
  symlinkSync(hostFile, join(ROOT, 'apps', 'rules-link', 'sandbox', 'releases', 'r1', 'deployhub.json'));
  assert.equal(byId(await rc.runReleaseCheck({ db, app: linked, trigger: 'promote' }), 'access_rules').status, 'fail');
  const regular = treeApp('rules-file', 'restricted', { 'server.js': '1;\n', 'deployhub.json': body });
  assert.equal(byId(await rc.runReleaseCheck({ db, app: regular, trigger: 'promote' }), 'access_rules').status, 'pass');
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

// Served output and Supabase RLS: a real dist on disk served on the app's own
// sandbox loopback port, crawled for real; a PostgREST imitation stands in for
// the Supabase project.
const fx = await import('./served-output-fixtures.js');
const { encrypt } = await import('../server/services/encryption.js');

async function servedApp(slug, level) {
  const app = treeApp(slug, level, { 'server.js': '1;\n' });
  for (let slot = 13101; slot < 13300; slot++) {
    if (db.prepare('SELECT 1 FROM apps WHERE slot = ?').get(slot)) continue;
    const dist = fx.buildDist(join(ROOT, 'served', slug), { basePath: `/${slug}-sandbox/` });
    const s = await fx.serveDir(dist, getPortsForSlot(slot).sand_be).catch(() => null);
    if (!s) continue;
    servers.push(s);
    db.prepare('UPDATE apps SET slot = ? WHERE id = ?').run(slot, app.id);
    return db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  }
  throw new Error('no free sandbox port');
}
function assertNoSecret(where, text) {
  for (const [name, v] of Object.entries(fx.SECRETS)) assert.ok(!String(text).includes(v.slice(0, 20)), `${name} in ${where}`);
}
function assertNothingStoredLeaks(app) {
  assertNoSecret('release_checks', JSON.stringify(db.prepare('SELECT * FROM release_checks WHERE app_id = ?').all(app.id)));
  assertNoSecret('events', JSON.stringify(db.prepare('SELECT * FROM events WHERE app_id = ?').all(app.id)));
  assertNoSecret('audit_log', JSON.stringify(db.prepare('SELECT * FROM audit_log').all()));
}

test('served output: service_role JWT, sk_live, a key in a source map and a served .env fail the check; the anon key is not flagged; values never stored', async () => {
  scanRow = { status: 'ok', findings_json: null };
  rc._setReleaseCheckDepsForTests({ scanApp: baseDeps.scanApp, scanTree: baseDeps.scanTree });
  try {
    const app = await servedApp('leak-a', 'confidential');
    const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
    const s = byId(rec, 'served_secrets');
    assert.equal(s.status, 'fail', JSON.stringify(s));
    const rulesSeen = s.reasons.slice(1).map((r) => /\(([a-z-]+),/.exec(r)?.[1]).filter(Boolean).sort();
    assert.deepEqual(rulesSeen, ['anthropic-key', 'github-token', 'openai-key', 'served-env-file', 'stripe-live-secret', 'supabase-service-role-key']);
    assert.ok(s.reasons.some((r) => r.startsWith('/assets/index-a1b2c3.js:1 (supabase-service-role-key, eyJhbG... (')), JSON.stringify(s.reasons));
    assert.ok(s.reasons.some((r) => /1 Supabase anon\/publishable key\(s\) in the output: public by design, not a finding/.test(r)));
    assert.equal(byId(rec, 'secrets').status, 'pass', 'the source tree itself is clean');
    assert.equal(rec.blocked, true, 'enforce mode blocks on a served secret');
    const rls = byId(rec, 'supabase_rls');
    assert.equal(rls.status, 'warn');
    assert.match(rls.reasons[0], new RegExp(`${fx.REF} reached with an anon key, but the RLS probe is off`));
    assertNoSecret('record', JSON.stringify(rec));
    assertNothingStoredLeaks(app);

    const internal = await servedApp('leak-b', 'internal');
    const w = await rc.runReleaseCheck({ db, app: internal, trigger: 'promote' });
    assert.equal(byId(w, 'served_secrets').status, 'fail');
    assert.equal(w.mode, 'warn');
    assert.equal(w.blocked, false, 'warn mode records the leak without blocking');
  } finally {
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});

test('served output: the in-deploy check refuses production and its deploy log carries no secret', async () => {
  rc._setReleaseCheckDepsForTests({ scanApp: baseDeps.scanApp, scanTree: baseDeps.scanTree });
  try {
    const app = await servedApp('leak-c', 'confidential');
    const deployId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by, log) VALUES (?, 'production', 'deploying', ?, '')").run(app.id, adminId).lastInsertRowid;
    const log = [];
    await assert.rejects(rc.enforceReleaseCheckInDeploy({ app, deployId, releaseDir: null, commit: null, appendLog: (l) => log.push(l) }), /No secrets in served output/);
    assert.ok(log.some((l) => /fail: No secrets in served output/.test(l)), log.join('\n'));
    assertNoSecret('deploy log', log.join('\n'));
  } finally {
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});

test('RLS probe (opt-in): a table that returns rows to anon fails the check; only GETs with the anon key reach the project', async () => {
  const mock = await fx.postgrestMock();
  servers.push(mock.server);
  setClassificationPolicy(db, { probe_supabase_rls: true }, admin);
  rc._setReleaseCheckDepsForTests({ scanApp: baseDeps.scanApp, scanTree: baseDeps.scanTree, supabaseBaseUrl: (ref) => (ref === fx.REF ? mock.url : null) });
  try {
    const app = await servedApp('rls-a', 'confidential');
    const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
    const rls = byId(rec, 'supabase_rls');
    assert.equal(rls.status, 'fail', JSON.stringify(rls));
    assert.match(rls.reasons[0], new RegExp(`^${fx.REF}: 1 table\\(s\\) return rows to the anon key .*: profiles$`));
    assert.ok(!JSON.stringify(rec).includes('row-content-must-not-leak'));
    assert.ok(!JSON.stringify(rec).includes(fx.ANON), 'the anon key is redacted too');
    assert.ok(mock.requests.length >= 3);
    for (const q of mock.requests) { assert.equal(q.method, 'GET'); assert.equal(q.apikey, fx.ANON); }
    assertNothingStoredLeaks(app);
  } finally {
    setClassificationPolicy(db, { probe_supabase_rls: false }, admin);
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});

test('RLS probe reads the URL and anon key from app env, never the service-role key stored beside them', async () => {
  const mock = await fx.postgrestMock();
  servers.push(mock.server);
  setClassificationPolicy(db, { probe_supabase_rls: true }, admin);
  rc._setReleaseCheckDepsForTests({ ...baseDeps, supabaseBaseUrl: () => mock.url });
  try {
    const app = treeApp('rls-env', 'confidential', { 'server.js': '1;\n' });
    const put = (env, k, v) => db.prepare('INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, ?, ?, ?)').run(app.id, env, k, encrypt(v));
    put('production', 'SUPABASE_SERVICE_ROLE_KEY', fx.SECRETS.serviceRole);
    put('production', 'SUPABASE_URL', `https://${fx.REF}.supabase.co`);
    put('production', 'VITE_SUPABASE_ANON_KEY', fx.SECRETS.serviceRole);
    put('sandbox', 'SUPABASE_ANON_KEY', fx.ANON);
    const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
    assert.equal(byId(rec, 'supabase_rls').status, 'fail', JSON.stringify(byId(rec, 'supabase_rls')));
    assert.ok(mock.requests.length >= 3);
    for (const q of mock.requests) {
      assert.equal(q.apikey, fx.ANON);
      assert.ok(!String(q.authorization).includes(fx.SECRETS.serviceRole));
    }
    assertNoSecret('record', JSON.stringify(rec));
  } finally {
    setClassificationPolicy(db, { probe_supabase_rls: false }, admin);
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});

test('no Supabase reference: the RLS check does not apply; an unreachable sandbox is a warning, not a pass', async () => {
  rc._setReleaseCheckDepsForTests({ scanApp: baseDeps.scanApp, scanTree: baseDeps.scanTree });
  try {
    const app = treeApp('unreach-a', 'internal', { 'server.js': '1;\n' });
    const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
    assert.equal(byId(rec, 'served_secrets').status, 'warn');
    assert.match(byId(rec, 'served_secrets').reasons[0], /could not fetch \/.*the served output was not scanned/);
    assert.equal(byId(rec, 'supabase_rls').status, 'pass');
    assert.equal(byId(rec, 'supabase_rls').applicable, false);
  } finally {
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});

// Unauthenticated endpoints: a real app on the sandbox's own loopback port,
// probed by the real crawl + probe; a recorder on the production port.
const ux = await import('./unauth-endpoint-fixtures.js');
const { generateCaddyfile } = await import('../server/services/caddy.js');

async function unauthApp(slug, level) {
  const app = treeApp(slug, level, { 'server.js': '1;\n' });
  for (let slot = 13301; slot < 13500; slot++) {
    if (db.prepare('SELECT 1 FROM apps WHERE slot = ?').get(slot)) continue;
    const ports = getPortsForSlot(slot);
    const sand = await ux.appServer({ port: ports.sand_be }).catch(() => null);
    if (!sand) continue;
    const prod = await ux.appServer({ port: ports.prod_be }).catch(() => null);
    if (!prod) { sand.server.close(); continue; }
    servers.push(sand.server, prod.server);
    db.prepare('UPDATE apps SET slot = ? WHERE id = ?').run(slot, app.id);
    return { app: db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id), sand, prod, ports };
  }
  throw new Error('no free port pair');
}
function assertNoValue(where, text) {
  for (const v of Object.values(ux.VALUES)) assert.ok(!String(text).includes(v), `${v} in ${where}`);
}
/** What the SSO gate adds to a request on its way to this app's sandbox, read from the generated Caddyfile. */
function gateHeadersFor(slug) {
  const saved = process.env.CRANE_DOMAIN;
  process.env.CRANE_DOMAIN = 'crane.example.test';
  try {
    const cf = generateCaddyfile();
    const start = cf.indexOf(`    handle /${slug}-sandbox* {\n`);
    assert.ok(start >= 0, 'sandbox block emitted');
    const block = cf.slice(start, cf.indexOf('\n    }\n', start));
    const names = new Set();
    for (const m of block.matchAll(/copy_headers ([^\n]+)/g)) for (const h of m[1].trim().split(/\s+/)) names.add(h.toLowerCase());
    for (const m of block.matchAll(/request_header (X-[A-Za-z-]+) "/g)) names.add(m[1].toLowerCase());
    for (const m of block.matchAll(/header_up (\S+)/g)) names.add(m[1].toLowerCase());
    const upstream = /reverse_proxy 127\.0\.0\.1:(\d+)$/m.exec(block)?.[1];
    return { names, upstream: Number(upstream), forwardAuth: block.includes('forward_auth') };
  } finally {
    if (saved === undefined) delete process.env.CRANE_DOMAIN; else process.env.CRANE_DOMAIN = saved;
  }
}

test('unauth endpoints: records served with no identity fail the check, found in the bundle and the OpenAPI doc; no gate header is sent; production is never probed', async () => {
  rc._setReleaseCheckDepsForTests({ scanApp: baseDeps.scanApp, scanTree: baseDeps.scanTree });
  try {
    const { app, sand, prod, ports } = await unauthApp('open-a', 'confidential');
    const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
    const u = byId(rec, 'unauth_endpoints');
    assert.equal(u.status, 'fail', JSON.stringify(u, null, 1));
    assert.equal(rec.blocked, true);
    assert.ok(u.reasons.includes('GET /api/users 200: array[1] of {id, email, name}'), JSON.stringify(u.reasons));
    assert.ok(u.reasons.includes('GET /api/reports 200: {reports: array[1] of {id, title}}'), 'discovered from the OpenAPI doc only');
    assert.ok(u.reasons.includes('GET /api/invoices 200: array[1] of {id, total, customer_email}'), 'discovered from the served bundle only');
    assert.ok(!u.reasons.some((r) => /\/api\/me|\/api\/health/.test(r)));
    assert.ok(u.reasons.some((r) => /1 write route\(s\) found but not sent a write \(platform policy probe_unauth_writes is off/.test(r)));
    assert.deepEqual(u.findings.map((f) => `${f.method} ${f.path} ${f.status}`), ['GET /api/invoices 200', 'GET /api/reports 200', 'GET /api/users 200']);
    assert.equal(sand.requests.filter((q) => q.method === 'POST').length, 0, 'no write by default');
    assert.equal(sand.requests.filter((q) => q.path === '/api/health').length, 0, 'health excluded');
    assert.equal(prod.requests.length, 0, 'production port never contacted');

    const gate = gateHeadersFor(app.slug);
    assert.equal(gate.forwardAuth, true);
    assert.equal(gate.upstream, ports.sand_be, 'the probe dials the very upstream the gate proxies to, so the gate is not in its path');
    assert.ok(gate.names.has('x-appcrane-user-email') && gate.names.has('x-appcrane-identity-sig') && gate.names.has('x-appcrane-auth-mode'), [...gate.names].join(','));
    for (const q of sand.requests) {
      const sent = Object.keys(q.headers).map((h) => h.toLowerCase());
      assert.deepEqual(sent.filter((h) => gate.names.has(h)), [], `${q.method} ${q.path} carried a gate header`);
      assert.deepEqual(ux.identityHeaderNames(q.headers), []);
    }

    const stored = db.prepare('SELECT checks_json FROM release_checks WHERE id = ?').get(rec.id).checks_json;
    assert.equal(JSON.parse(stored).find((c) => c.id === 'unauth_endpoints').findings.length, 3, 'findings stored in the release check record');
    assertNoValue('record', JSON.stringify(rec));
    assertNoValue('release_checks', JSON.stringify(db.prepare('SELECT * FROM release_checks WHERE app_id = ?').all(app.id)));
    assertNoValue('events', JSON.stringify(db.prepare('SELECT * FROM events WHERE app_id = ?').all(app.id)));
  } finally {
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});

test('unauth endpoints: write probing is opt-in; with it on, a POST that returns 201 with no identity fails the check', async () => {
  setClassificationPolicy(db, { probe_unauth_writes: true }, admin);
  rc._setReleaseCheckDepsForTests({ scanApp: baseDeps.scanApp, scanTree: baseDeps.scanTree });
  try {
    const { app, sand, prod } = await unauthApp('open-w', 'internal');
    const rec = await rc.runReleaseCheck({ db, app, trigger: 'promote' });
    const u = byId(rec, 'unauth_endpoints');
    assert.equal(u.status, 'fail');
    assert.ok(u.reasons.includes('POST /api/items 201'), JSON.stringify(u.reasons));
    assert.equal(u.writes_probed, true);
    const posts = sand.requests.filter((q) => q.method === 'POST');
    assert.deepEqual(posts.map((q) => [q.path, q.body]), [['/api/items', '{}']]);
    assert.equal(prod.requests.length, 0);
    assertNoValue('record', JSON.stringify(rec));
  } finally {
    setClassificationPolicy(db, { probe_unauth_writes: false }, admin);
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});

test('unauth endpoints: a release whose commit the sandbox is not running is not probed, and neither is production', async () => {
  rc._setReleaseCheckDepsForTests({ scanApp: baseDeps.scanApp, scanTree: baseDeps.scanTree });
  try {
    const { app, sand, prod } = await unauthApp('open-c', 'internal');
    const releaseDir = join(ROOT, 'apps', app.slug, 'sandbox', 'releases', 'r1');
    const rec = await rc.runReleaseCheck({ db, app, trigger: 'deploy', releaseDir, commit: 'fffffff' });
    const u = byId(rec, 'unauth_endpoints');
    assert.equal(u.status, 'warn');
    assert.match(u.reasons[0], /different commit .*production is never probed/);
    assert.equal(sand.requests.length, 0);
    assert.equal(prod.requests.length, 0);
  } finally {
    rc._setReleaseCheckDepsForTests(baseDeps);
  }
});
