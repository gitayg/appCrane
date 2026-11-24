import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import crypto from 'crypto';
import http from 'http';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Deployment records against what is actually running (services/reconcileState.js).
//
// Each test builds the real state a production box was found in, through the
// real routers, and reads the result back from the database, the disk, Docker
// and a listening port:
//   - an env whose health config is enabled but which has no container is
//     probed every second (interval 1) at a counting HTTP listener; after the
//     sweep the listener stops being hit, and it is hit again once a container
//     with that name exists (real `docker create`);
//   - a deleted app's directory and Crane-hosted repository land in the trash
//     and its probe stops;
//   - a rename moves the repository and re-points `current`;
//   - orphans are listed and fixed one click at a time, audited.

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'crane-reconcile-')));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const hc = await import('../server/services/healthChecker.js');
const rs = await import('../server/services/reconcileState.js');
const { createGrant } = await import('../server/services/stepUp.js');
const { errorHandler } = await import('../server/utils/errors.js');

const RUN = crypto.randomBytes(3).toString('hex');
const containers = [];
function dockerOk() {
  try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 10000 }); return true; } catch (_) { return false; }
}
const DOCKER = dockerOk();
function dockerCreate(name) {
  execFileSync('docker', ['create', '--name', name, '--label', 'appcrane=true', 'busybox:latest', 'true'], { stdio: 'pipe', timeout: 120000 });
  containers.push(name);
}
const containerExists = (name) => {
  try { execFileSync('docker', ['inspect', name], { stdio: 'pipe' }); return true; } catch (_) { return false; }
};

const api = express();
api.use(express.json());
api.use('/api/state-reconcile', (await import('../server/routes/stateReconcile.js')).default);
api.use('/api/apps', (await import('../server/routes/apps.js')).default);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const listeners = [];
after(async () => {
  rs.stopStateReconcile();
  hc.stopHealthChecker();
  server.closeAllConnections?.(); server.close();
  for (const l of listeners) l.close();
  for (const c of containers) { try { execFileSync('docker', ['rm', '-f', c], { stdio: 'pipe' }); } catch (_) {} }
  rmSync(ROOT, { recursive: true, force: true });
});

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key), ).lastInsertRowid);
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
const admin = mkUser('rc-admin', 'platform_admin');
const member = mkUser('rc-member');

// Slots far above anything else so the probe ports (4000 + 2*slot - 1 / - 0) are free here.
let slot = 2900 + Math.floor(Math.random() * 400);
function mkApp(slug, extra = {}) {
  const id = Number(db.prepare(`INSERT INTO apps (name, slug, slot, source_type, branch, github_url, repo_backend)
    VALUES (?, ?, ?, ?, 'main', ?, ?)`).run(slug, slug, ++slot, extra.source_type || 'github', extra.github_url || null, extra.repo_backend || null).lastInsertRowid);
  db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(id, admin.id, 'owner');
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function probeSetup(app, env, { isDown = 0, fails = 0 } = {}) {
  db.prepare('INSERT OR REPLACE INTO health_configs (app_id, env, endpoint, interval_sec, enabled) VALUES (?, ?, ?, 1, 1)').run(app.id, env, '/health');
  db.prepare('INSERT OR REPLACE INTO health_state (app_id, env, consecutive_fails, is_down) VALUES (?, ?, ?, ?)').run(app.id, env, fails, isDown);
}
// A listener on the env's loopback port: every probe the checker sends is counted.
async function countProbes(app, env) {
  const port = env === 'production' ? 4000 + app.slot * 2 - 1 : 4000 + app.slot * 2;
  const hits = { n: 0 };
  const s = http.createServer((req, res) => { hits.n++; res.end('{"status":"ok"}'); });
  await new Promise((r) => s.listen(port, '127.0.0.1', r));
  listeners.push(s);
  return hits;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(as ? { 'X-API-Key': as.key } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, body: json };
}
const finding = (kind, where) => db.prepare(`SELECT * FROM reconcile_findings WHERE kind = ? AND ${where} ORDER BY id DESC LIMIT 1`).get(kind);
const auditRows = (action) => db.prepare('SELECT * FROM audit_log WHERE action = ? ORDER BY id').all(action);

test('only a platform admin reads, runs and fixes', async () => {
  assert.equal((await call(null, 'GET', '/api/state-reconcile')).status, 401);
  assert.equal((await call(member, 'GET', '/api/state-reconcile')).status, 403);
  assert.equal((await call(member, 'POST', '/api/state-reconcile/run')).status, 403);
  assert.equal((await call(member, 'POST', '/api/state-reconcile/findings/1/fix')).status, 403);
  const r = await call(admin, 'GET', '/api/state-reconcile');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(Array.isArray(r.body.findings));
});

test('a never-deployed env with no container: probe paused (stops hitting the port), resumed when a container appears', { skip: !DOCKER && 'docker not available' }, async () => {
  const app = mkApp(`rc-haive-${RUN}`);
  probeSetup(app, 'production', { isDown: 1, fails: 394164 });
  const hits = await countProbes(app, 'production');
  hc.startHealthChecker();
  await sleep(2500);
  assert.ok(hits.n > 0, 'control: the checker probes the env before the sweep');

  const r = await call(admin, 'POST', '/api/state-reconcile/run');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.paused >= 1, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT enabled FROM health_configs WHERE app_id = ? AND env = ?').get(app.id, 'production').enabled, 0);
  assert.match(db.prepare('SELECT reason FROM health_probe_pauses WHERE app_id = ?').get(app.id).reason, /never deployed/);
  const f = finding('probe_without_container', `app_id = ${app.id}`);
  assert.equal(f.status, 'auto_fixed');
  assert.ok(auditRows('reconcile-auto-fix').some((a) => a.app_id === app.id && /paused/.test(a.detail)));

  await sleep(300);
  const before = hits.n;
  await sleep(2500);
  assert.equal(hits.n, before, 'the paused probe still fires');

  const g = await call(admin, 'GET', '/api/state-reconcile');
  assert.ok(g.body.paused_probes.some((p) => p.app_id === app.id && p.env === 'production'));
  assert.ok(g.body.findings.some((x) => x.kind === 'probe_paused' && x.app_id === app.id));

  dockerCreate(`appcrane-${app.slug}-production`);
  const r2 = await call(admin, 'POST', '/api/state-reconcile/run');
  assert.ok(r2.body.resumed >= 1, JSON.stringify(r2.body));
  assert.equal(db.prepare('SELECT enabled FROM health_configs WHERE app_id = ? AND env = ?').get(app.id, 'production').enabled, 1);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM health_probe_pauses WHERE app_id = ?').get(app.id).n, 0);
  assert.equal(finding('probe_paused', `app_id = ${app.id}`).status, 'resolved');
  const resumedAt = hits.n;
  await sleep(2500);
  assert.ok(hits.n > resumedAt, 'the resumed probe does not fire');
});

test('a probe a person disabled is never turned back on', { skip: !DOCKER && 'docker not available' }, async () => {
  const app = mkApp(`rc-manual-${RUN}`);
  probeSetup(app, 'sandbox');
  db.prepare('UPDATE health_configs SET enabled = 0 WHERE app_id = ?').run(app.id);
  dockerCreate(`appcrane-${app.slug}-sandbox`);
  await rs.reconcileOnce({ trigger: 'test', deps: { rescheduleHealth: async () => {}, resumeHealth: async () => {} } });
  assert.equal(db.prepare('SELECT enabled FROM health_configs WHERE app_id = ?').get(app.id).enabled, 0);
});

test('moorai-like sandbox: live without container, stale live rows marked replaced, live release missing, failed streak', { skip: !DOCKER && 'docker not available' }, async () => {
  const app = mkApp(`rc-moor-${RUN}`);
  probeSetup(app, 'sandbox');
  const rel = join(ROOT, 'apps', app.slug, 'sandbox', 'releases', '1-git');
  mkdirSync(rel, { recursive: true });
  const dep = (status, releasePath, reason = null) => Number(db.prepare(
    "INSERT INTO deployments (app_id, env, status, release_path, failure_reason, finished_at) VALUES (?, 'sandbox', ?, ?, ?, datetime('now', '-1 day'))",
  ).run(app.id, status, releasePath, reason).lastInsertRowid);
  const older = dep('live', rel);
  const newest = dep('live', null);
  for (let i = 0; i < 3; i++) dep('failed', null, `Health check failed (${i})`);

  const out = await rs.reconcileOnce({ trigger: 'test', deps: { rescheduleHealth: async () => {}, resumeHealth: async () => {} } });
  assert.equal(out.docker_ok, true);
  const lwc = finding('live_without_container', `app_id = ${app.id}`);
  assert.equal(lwc.status, 'open'); assert.equal(lwc.severity, 'error'); assert.equal(lwc.fix, 'recover');
  assert.equal(JSON.parse(lwc.detail_json).deployment_id, newest);
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(older).status, 'rolled_back');
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(newest).status, 'live');
  assert.equal(finding('stale_live_rows', `app_id = ${app.id}`).status, 'auto_fixed');
  assert.match(JSON.parse(finding('live_release_missing', `app_id = ${app.id}`).detail_json).problem, /no release_path/);
  const streak = JSON.parse(finding('failed_streak', `app_id = ${app.id}`).detail_json);
  assert.equal(streak.failures.length, 3);
  assert.match(streak.failures[0].failure_reason, /Health check failed/);
  assert.equal(db.prepare('SELECT enabled FROM health_configs WHERE app_id = ?').get(app.id).enabled, 1, 'a live env whose probe is not down is not paused');

  db.prepare("INSERT INTO upload_conversions (app_id, slug, status, error_code, error) VALUES (?, ?, 'skipped', 'releases_missing', 'live deployment with no uploaded release on disk: sandbox')").run(app.id, app.slug);
  await rs.reconcileOnce({ trigger: 'test', deps: { rescheduleHealth: async () => {}, resumeHealth: async () => {} } });
  assert.equal(finding('upload_conversion_skipped', `app_id = ${app.id}`).subject, 'releases_missing');
  assert.equal(finding('stale_live_rows', `app_id = ${app.id}`).status, 'resolved', 'one live row left: nothing stale');
});

test('Docker not answering: no container conclusions, and earlier ones are not resolved', async () => {
  const app = mkApp(`rc-dock-${RUN}`);
  db.prepare("INSERT INTO deployments (app_id, env, status, image_ref) VALUES (?, 'production', 'live', 'x@sha256:1')").run(app.id);
  db.prepare("UPDATE apps SET source_type = 'image' WHERE id = ?").run(app.id);
  const quiet = { rescheduleHealth: async () => {}, resumeHealth: async () => {} };
  await rs.reconcileOnce({ trigger: 'test', deps: { ...quiet, listContainers: async () => new Map() } });
  assert.equal(finding('live_without_container', `app_id = ${app.id}`).status, 'open');
  const out = await rs.reconcileOnce({ trigger: 'test', deps: { ...quiet, listContainers: async () => { throw new Error('daemon down'); } } });
  assert.equal(out.docker_ok, false);
  assert.equal(finding('live_without_container', `app_id = ${app.id}`).status, 'open');
});

test('orphans (bookstack-like leftovers): listed, fixed one click at a time, audited, never deleted', { skip: !DOCKER && 'docker not available' }, async () => {
  const ghost = `rc-ghost-${RUN}`;
  mkdirSync(join(ROOT, 'apps', ghost, 'production', 'data'), { recursive: true });
  writeFileSync(join(ROOT, 'apps', ghost, 'production', 'data', 'keep.txt'), 'user data');
  mkdirSync(join(ROOT, 'repos', `${ghost}.git`), { recursive: true });
  writeFileSync(join(ROOT, 'repos', `${ghost}.git`, 'HEAD'), 'ref: refs/heads/main\n');
  dockerCreate(`appcrane-${ghost}-sandbox`);
  db.pragma('foreign_keys = OFF');
  db.prepare("INSERT INTO health_configs (app_id, env) VALUES (999999, 'production')").run();
  db.pragma('foreign_keys = ON');

  const run = await call(admin, 'POST', '/api/state-reconcile/run');
  assert.equal(run.status, 200);
  const g = (await call(admin, 'GET', '/api/state-reconcile')).body.findings;
  const dirF = g.find((f) => f.kind === 'orphan_app_dir' && f.slug === ghost);
  const repoF = g.find((f) => f.kind === 'orphan_repo' && f.slug === ghost);
  const ctrF = g.find((f) => f.kind === 'container_without_app' && f.slug === ghost);
  const rowF = g.find((f) => f.kind === 'orphan_rows' && f.app_id === 999999);
  for (const f of [dirF, repoF, ctrF, rowF]) assert.ok(f && f.status === 'open' && f.fix, JSON.stringify(g.map((x) => [x.kind, x.slug])));
  assert.ok(existsSync(join(ROOT, 'apps', ghost)), 'detection alone moved nothing');

  assert.equal((await call(member, 'POST', `/api/state-reconcile/findings/${dirF.id}/fix`)).status, 403);
  const fx = await call(admin, 'POST', `/api/state-reconcile/findings/${dirF.id}/fix`);
  assert.equal(fx.status, 200, JSON.stringify(fx.body));
  assert.equal(existsSync(join(ROOT, 'apps', ghost)), false);
  const t = db.prepare("SELECT * FROM app_trash WHERE slug = ? AND kind = 'app_dir'").get(ghost);
  assert.ok(t.trash_path.startsWith(join(ROOT, 'trash') + '/'));
  assert.equal(existsSync(join(t.trash_path, 'production', 'data', 'keep.txt')), true, 'the data is in the trash');
  assert.equal((await call(admin, 'POST', `/api/state-reconcile/findings/${dirF.id}/fix`)).status, 409, 'a fixed finding is not fixed twice');

  assert.equal((await call(admin, 'POST', `/api/state-reconcile/findings/${repoF.id}/fix`)).status, 200);
  assert.equal(existsSync(join(ROOT, 'repos', `${ghost}.git`)), false);
  assert.equal((await call(admin, 'POST', `/api/state-reconcile/findings/${ctrF.id}/fix`)).status, 200);
  assert.equal(containerExists(`appcrane-${ghost}-sandbox`), false);
  assert.equal((await call(admin, 'POST', `/api/state-reconcile/findings/${rowF.id}/fix`)).status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM health_configs WHERE app_id = 999999').get().n, 0);

  const fixes = auditRows('reconcile-fix').filter((a) => [dirF.id, repoF.id, ctrF.id, rowF.id].includes(JSON.parse(a.detail).finding_id));
  assert.equal(fixes.filter((a) => JSON.parse(a.detail).ok).length, 4);
  assert.ok(fixes.every((a) => a.user_id === admin.id));

  await call(admin, 'POST', '/api/state-reconcile/run');
  const after = (await call(admin, 'GET', '/api/state-reconcile')).body.findings;
  assert.equal(after.some((f) => f.slug === ghost), false, 'fixed orphans are found again');
});

test('a fix re-checks: a directory whose slug has an app again is not moved', async () => {
  const slug = `rc-back-${RUN}`;
  mkdirSync(join(ROOT, 'apps', slug), { recursive: true });
  await rs.reconcileOnce({ trigger: 'test', deps: { listContainers: async () => new Map(), rescheduleHealth: async () => {}, resumeHealth: async () => {} } });
  const f = finding('orphan_app_dir', `slug = '${slug}'`);
  mkApp(slug);
  const r = await call(admin, 'POST', `/api/state-reconcile/findings/${f.id}/fix`);
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.code || r.body.error?.code, 'NO_LONGER_ORPHAN', JSON.stringify(r.body));
  assert.equal(existsSync(join(ROOT, 'apps', slug)), true);
});

test('delete takes its leftovers: data dir and repo to the trash, probe stops', async () => {
  const app = mkApp(`rc-del-${RUN}`, { source_type: 'managed', repo_backend: 'local' });
  const rel = join(ROOT, 'apps', app.slug, 'production', 'releases', '1-git');
  mkdirSync(rel, { recursive: true });
  writeFileSync(join(rel, 'server.js'), '');
  mkdirSync(join(ROOT, 'repos', `${app.slug}.git`), { recursive: true });
  writeFileSync(join(ROOT, 'repos', `${app.slug}.git`, 'HEAD'), 'ref: refs/heads/main\n');
  probeSetup(app, 'production');
  const hits = await countProbes(app, 'production');
  rs.startStateReconcile();
  hc.stopHealthChecker(); hc.startHealthChecker();
  await sleep(2500);
  assert.ok(hits.n > 0, 'control: the app is probed before the delete');

  createGrant(db, admin.id, 'delete_app', app.id);
  const r = await call(admin, 'DELETE', `/api/apps/${app.slug}?confirm=true`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.moved_to_trash.map((t) => t.kind).sort(), ['app_dir', 'repo']);
  assert.equal(existsSync(join(ROOT, 'apps', app.slug)), false);
  assert.equal(existsSync(join(ROOT, 'repos', `${app.slug}.git`)), false);
  for (const t of r.body.moved_to_trash) {
    const row = db.prepare('SELECT * FROM app_trash WHERE id = ?').get(t.trash_id);
    assert.ok(existsSync(row.trash_path), row.trash_path);
  }
  assert.equal(existsSync(join(db.prepare("SELECT trash_path FROM app_trash WHERE slug = ? AND kind = 'app_dir'").get(app.slug).trash_path, 'production', 'releases', '1-git', 'server.js')), true);
  assert.ok(auditRows('app-trash').some((a) => JSON.parse(a.detail).slug === app.slug));

  await sleep(300);
  const before = hits.n;
  await sleep(2500);
  assert.equal(hits.n, before, 'the deleted app is still probed');
  rs.stopStateReconcile();
});

test('rename takes its leftovers: repository moved, current re-pointed; an old-slug directory is a rename leftover', async () => {
  const app = mkApp(`rc-ren-${RUN}`, { source_type: 'managed', repo_backend: 'local' });
  const newSlug = `rc-ren2-${RUN}`;
  const rel = join(ROOT, 'apps', app.slug, 'sandbox', 'releases', '1-git');
  mkdirSync(rel, { recursive: true });
  writeFileSync(join(rel, 'package.json'), '{}');
  symlinkSync(rel, join(ROOT, 'apps', app.slug, 'sandbox', 'current'));
  mkdirSync(join(ROOT, 'repos', `${app.slug}.git`), { recursive: true });
  writeFileSync(join(ROOT, 'repos', `${app.slug}.git`, 'HEAD'), 'ref: refs/heads/main\n');

  const r = await call(admin, 'POST', `/api/apps/${app.slug}/rename`, { new_slug: newSlug });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(existsSync(join(ROOT, 'repos', `${newSlug}.git`, 'HEAD')), true, 'the repository did not follow the app');
  assert.equal(existsSync(join(ROOT, 'repos', `${app.slug}.git`)), false);
  const link = join(ROOT, 'apps', newSlug, 'sandbox', 'current');
  assert.ok(lstatSync(link).isSymbolicLink());
  assert.equal(readlinkSync(link), join(ROOT, 'apps', newSlug, 'sandbox', 'releases', '1-git'));
  assert.equal(existsSync(join(link, 'package.json')), true, 'current dangles after the rename');

  mkdirSync(join(ROOT, 'apps', app.slug), { recursive: true });
  await rs.reconcileOnce({ trigger: 'test', deps: { listContainers: async () => new Map(), rescheduleHealth: async () => {}, resumeHealth: async () => {} } });
  const f = finding('rename_leftover_dir', `slug = '${app.slug}'`);
  assert.equal(JSON.parse(f.detail_json).renamed_to, newSlug);
  assert.equal(f.fix, 'trash_dir');
});

test('rename refuses when the target repository is already on disk, before anything moves', async () => {
  const app = mkApp(`rc-rr-${RUN}`, { source_type: 'managed', repo_backend: 'local' });
  mkdirSync(join(ROOT, 'repos', `${app.slug}.git`), { recursive: true });
  mkdirSync(join(ROOT, 'repos', `rc-rr2-${RUN}.git`), { recursive: true });
  const r = await call(admin, 'POST', `/api/apps/${app.slug}/rename`, { new_slug: `rc-rr2-${RUN}` });
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT slug FROM apps WHERE id = ?').get(app.id).slug, app.slug);
});

test('github_url that no longer names the attached repository: one click sets it, refused once the attachment changes', async () => {
  const app = mkApp(`rc-gh-${RUN}`, { github_url: 'https://github.com/acme/curaiq-server' });
  db.prepare('INSERT INTO app_github_installations (app_id, slug, installation_id, repo_full_name) VALUES (?, ?, 1, ?)').run(app.id, app.slug, 'acme/moorai-server');
  const quiet = { listContainers: async () => new Map(), rescheduleHealth: async () => {}, resumeHealth: async () => {} };
  await rs.reconcileOnce({ trigger: 'test', deps: quiet });
  const f = finding('github_url_mismatch', `app_id = ${app.id}`);
  assert.equal(f.status, 'open');
  const r = await call(admin, 'POST', `/api/state-reconcile/findings/${f.id}/fix`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT github_url FROM apps WHERE id = ?').get(app.id).github_url, 'https://github.com/acme/moorai-server');

  db.prepare("UPDATE apps SET github_url = 'https://github.com/acme/a' WHERE id = ?").run(app.id);
  await rs.reconcileOnce({ trigger: 'test', deps: quiet });
  const f2 = finding('github_url_mismatch', `app_id = ${app.id}`);
  db.prepare("UPDATE app_github_installations SET repo_full_name = 'acme/b' WHERE app_id = ?").run(app.id);
  assert.equal((await call(admin, 'POST', `/api/state-reconcile/findings/${f2.id}/fix`)).status, 409);
  assert.equal(db.prepare('SELECT github_url FROM apps WHERE id = ?').get(app.id).github_url, 'https://github.com/acme/a');
});

test('trash: kept for the retention, purge refused before it, then listed and purged by a platform admin', async () => {
  const t = db.prepare("SELECT * FROM app_trash WHERE kind = 'app_dir' AND purged_at IS NULL ORDER BY id LIMIT 1").get();
  assert.ok(t);
  assert.equal((await call(admin, 'POST', `/api/state-reconcile/trash/${t.id}/purge`)).status, 409);
  assert.equal(existsSync(t.trash_path), true);
  db.prepare("UPDATE app_trash SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(t.id);
  await rs.reconcileOnce({ trigger: 'test', deps: { listContainers: async () => new Map(), rescheduleHealth: async () => {}, resumeHealth: async () => {} } });
  const f = finding('trash_expired', `subject = '${t.id}'`);
  assert.equal(f.status, 'open');
  assert.equal((await call(member, 'POST', `/api/state-reconcile/trash/${t.id}/purge`)).status, 403);
  const r = await call(admin, 'POST', `/api/state-reconcile/findings/${f.id}/fix`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(existsSync(t.trash_path), false);
  assert.ok(db.prepare('SELECT purged_at FROM app_trash WHERE id = ?').get(t.id).purged_at);
});

test('dismiss keeps a finding dismissed across sweeps', async () => {
  const slug = `rc-dis-${RUN}`;
  mkdirSync(join(ROOT, 'apps', slug), { recursive: true });
  const quiet = { listContainers: async () => new Map(), rescheduleHealth: async () => {}, resumeHealth: async () => {} };
  await rs.reconcileOnce({ trigger: 'test', deps: quiet });
  const f = finding('orphan_app_dir', `slug = '${slug}'`);
  assert.equal((await call(admin, 'POST', `/api/state-reconcile/findings/${f.id}/dismiss`)).status, 200);
  await rs.reconcileOnce({ trigger: 'test', deps: quiet });
  assert.equal(db.prepare('SELECT status FROM reconcile_findings WHERE id = ?').get(f.id).status, 'dismissed');
  assert.ok(auditRows('reconcile-dismiss').some((a) => JSON.parse(a.detail).finding_id === f.id));
});
