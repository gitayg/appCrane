import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Deploy on push, and check-for-updates, for a managed app whose repository is
// on this host (apps.repo_backend = 'local').
//
// Real git and the real push tools throughout; the repo is read back with an
// isolated git, never through the module under test. Deploys are real
// deployApp runs that stop at the docker shim (which fails), so no container
// can start. The only other boundary stubbed is fetch, which counts: a local
// app must never reach GitHub.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-dop-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { deployAfterLocalPush } = await import('../server/services/deployTrigger.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const lg = await import('../server/services/localGit.js');
const { default: webhooksRouter } = await import('../server/routes/webhooks.js');

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (args) => execFileSync('git', args, { env: CLEAN_ENV }).toString('utf8').trim();
const tipOf = (slug, branch = 'main') => git([`--git-dir=${lg.repoPath(slug)}`, 'rev-parse', `refs/heads/${branch}`]);

const GH_SHA = 'a1b2c3d4'.repeat(5);
const realFetch = global.fetch;
const githubCalls = [];
global.fetch = async (url, init) => {
  const u = String(url);
  if (u.startsWith('http://127.0.0.1')) return realFetch(url, init);
  githubCalls.push(u);
  if (u === 'https://api.github.com/repos/o/r/commits/main') {
    return { ok: true, status: 200, json: async () => ({ sha: GH_SHA, commit: { message: 'gh head\nbody', committer: { date: '2026-09-01T00:00:00Z' } } }) };
  }
  return { ok: false, status: 404, headers: new Headers(), json: async () => ({ message: 'stub' }), text: async () => '{}' };
};

const API_KEY = 'dop-test-key-0001';
const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('dop','dop@x.test','platform_admin',?,1,'human')",
).run(hashApiKey(API_KEY)).lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'dop' };

const web = express();
web.use(express.json());
web.use('/api/apps', webhooksRouter);
web.use((err, _req, res, _next) => res.status(err.statusCode || err.status || 500).json({ error: err.message }));
const server = await new Promise((r) => { const s = web.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
const updates = async (slug) => (await fetch(`${BASE}/api/apps/${slug}/updates`, { headers: { 'x-api-key': API_KEY } })).json();

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}
const appRow = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
const deploysOf = (appId) => db.prepare('SELECT * FROM deployments WHERE app_id = ? ORDER BY id').all(appId);
const deliveriesOf = (appId) => db.prepare('SELECT * FROM webhook_deliveries WHERE app_id = ? ORDER BY id').all(appId);
const setConfig = (appId, cols) => {
  for (const [k, v] of Object.entries(cols)) db.prepare(`UPDATE webhook_configs SET ${k} = ? WHERE app_id = ?`).run(v, appId);
};

/** Wait until no deployment of the app is still in flight. */
async function settle(appId) {
  const deadline = Date.now() + 60000;
  while (db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND status IN ('pending','building','deploying')").get(appId).n) {
    if (Date.now() > deadline) throw new Error(`deploys of app ${appId} did not settle: ${JSON.stringify(deploysOf(appId).map((d) => [d.id, d.status]))}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

let seq = 0;
async function localApp() {
  const slug = `dop-${++seq}`;
  await tool('appcrane_create_managed_app', { name: slug, slug });
  const app = appRow(slug);
  assert.equal(app.repo_backend, 'local');
  return app;
}

// ---------------------------------------------------------------------------
// Deploy on push
// ---------------------------------------------------------------------------

test('a local push with auto_deploy_sandbox=1 starts exactly one sandbox deployment at the branch tip, audited to the pusher', async () => {
  const app = await localApp();
  const cfg = db.prepare('SELECT auto_deploy_sandbox, auto_deploy_prod, branch_filter FROM webhook_configs WHERE app_id = ?').get(app.id);
  assert.deepEqual({ ...cfg }, { auto_deploy_sandbox: 1, auto_deploy_prod: 0, branch_filter: 'main' }, 'creation defaults changed');
  assert.equal(deploysOf(app.id).length, 0, 'creating the app deployed it');

  const res = await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'a.txt', content: 'one\n' }] });
  const tip = tipOf(app.slug);
  assert.equal(res.commit.sha, tip);

  const rows = deploysOf(app.id);
  assert.equal(rows.length, 1, `expected one deployment, got ${JSON.stringify(rows)}`);
  assert.equal(rows[0].env, 'sandbox');
  assert.equal(rows[0].commit_hash, tip.slice(0, 8));
  // rows[0].log is not asserted here: the real deployApp rewrites it as soon as
  // it starts. The note written at insert time is pinned in the injected-deps
  // test below.

  assert.deepEqual(res.auto_deploy, {
    action: 'deploy_triggered', branch: 'main', commit: tip.slice(0, 8),
    triggered: [{ env: 'sandbox', deployment_id: rows[0].id }],
  });
  assert.match(res.next, /do not call appcrane_deploy/);

  const audits = db.prepare("SELECT user_id, action, detail FROM audit_log WHERE app_id = ? AND action = 'push-deploy'").all(app.id);
  assert.deepEqual(audits.map((a) => ({ ...a })), [{ user_id: adminId, action: 'push-deploy', detail: JSON.stringify({ env: 'sandbox', commit: tip.slice(0, 8) }) }]);

  const del = deliveriesOf(app.id);
  assert.equal(del.length, 1);
  assert.equal(del[0].event, 'managed-push');
  assert.equal(del[0].action_taken, 'deploy_triggered');
  assert.equal(del[0].deploy_id, rows[0].id);
  assert.equal(del[0].branch, 'main');
  assert.equal(del[0].commit_hash, tip.slice(0, 8));

  await settle(app.id);
  const log = deploysOf(app.id)[0].log;
  assert.match(log, new RegExp(`Cloned successfully\\. Commit: ${tip.slice(0, 7)}`), `the deploy did not clone the pushed tip:\n${log}`);
  assert.equal(/does not match the last pushed commit/.test(log), false, `the push-triggered deploy was verified against a stale push record:\n${log}`);
  assert.equal(githubCalls.length, 0, 'a local push reached GitHub');
});

test('a chunk upload triggers no deploy; the assemble that commits it triggers exactly one', async () => {
  const app = await localApp();
  const chunk = (part, content) => tool('appcrane_managed_push_chunk', { slug: app.slug, path: 'big.txt', session: `dop-s-${app.slug}`, part, of: 2, content });
  await chunk(1, 'hello ');
  assert.equal(deploysOf(app.id).length, 0, 'staging part 1 deployed');
  await chunk(2, 'world');
  assert.equal(deploysOf(app.id).length, 0, 'staging part 2 deployed');
  assert.equal(deliveriesOf(app.id).length, 0, 'a staged chunk was recorded as a push');

  const res = await tool('appcrane_managed_assemble', { slug: app.slug, session: `dop-s-${app.slug}`, path: 'big.txt' });
  const rows = deploysOf(app.id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].commit_hash, tipOf(app.slug).slice(0, 8));
  assert.equal(res.auto_deploy.triggered[0].deployment_id, rows[0].id);
  await settle(app.id);
});

test('a patch commits and triggers exactly one deploy', async () => {
  const app = await localApp();
  setConfig(app.id, { auto_deploy_sandbox: 0 });
  await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'p.txt', content: 'one\n' }] });
  setConfig(app.id, { auto_deploy_sandbox: 1 });
  const res = await tool('appcrane_managed_patch', { slug: app.slug, path: 'p.txt', unified_diff: '@@ -1 +1 @@\n-one\n+two' });
  const rows = deploysOf(app.id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].commit_hash, tipOf(app.slug).slice(0, 8));
  assert.equal(res.auto_deploy.action, 'deploy_triggered');
  await settle(app.id);
});

test('a push to a branch other than the filter deploys nothing; the filter is matched against the branch pushed', async () => {
  const app = await localApp();
  git([`--git-dir=${lg.repoPath(app.slug)}`, 'branch', 'feature', 'main']);

  const res = await tool('appcrane_push_to_managed_app', { slug: app.slug, branch: 'feature', files: [{ path: 'f.txt', content: 'f' }] });
  assert.equal(deploysOf(app.id).length, 0, 'a push to a non-filter branch deployed');
  assert.equal(res.auto_deploy.action, 'skipped_branch');
  assert.equal(res.auto_deploy.branch_filter, 'main');
  assert.match(res.next, /No automatic deploy: branch 'feature' is not the deploy-on-push branch 'main'/);
  assert.deepEqual(deliveriesOf(app.id).map((d) => [d.action_taken, d.branch]), [['skipped_branch', 'feature']]);

  setConfig(app.id, { branch_filter: 'feature' });
  await tool('appcrane_push_to_managed_app', { slug: app.slug, branch: 'feature', files: [{ path: 'f.txt', content: 'g' }] });
  const rows = deploysOf(app.id);
  assert.equal(rows.length, 1, 'with the filter on the pushed branch, the push must deploy');
  assert.equal(rows[0].commit_hash, tipOf(app.slug, 'feature').slice(0, 8));
  await settle(app.id);
});

test('auto_deploy_prod=0 never deploys production; auto_deploy_prod=1 does; both off deploys nothing', async () => {
  const app = await localApp();
  for (let i = 0; i < 3; i++) {
    await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'x.txt', content: String(i) }] });
  }
  assert.equal(deploysOf(app.id).filter((d) => d.env === 'production').length, 0, 'production deployed with auto_deploy_prod=0');
  assert.equal(deploysOf(app.id).length, 3);
  await settle(app.id);

  setConfig(app.id, { auto_deploy_sandbox: 0, auto_deploy_prod: 1 });
  const res = await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'x.txt', content: 'prod' }] });
  const newRows = deploysOf(app.id).slice(3);
  assert.deepEqual(newRows.map((d) => d.env), ['production']);
  assert.deepEqual(res.auto_deploy.triggered.map((t) => t.env), ['production']);
  await settle(app.id);

  setConfig(app.id, { auto_deploy_sandbox: 0, auto_deploy_prod: 0 });
  const off = await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'x.txt', content: 'off' }] });
  assert.equal(deploysOf(app.id).length, 4);
  assert.equal(off.auto_deploy.action, 'skipped_no_auto');
});

test('a push whose commit is no longer the branch tip does not deploy; the push that owns the tip deploys it', async () => {
  const app = await localApp();
  const calls = [];
  const deps = { deployApp: async (...a) => { calls.push(a); }, getPortsForSlot: () => ({}) };

  const first = await lg.pushFilesToManagedRepo(app.slug, [{ path: 'r.txt', content: 'first' }]);
  const second = await lg.pushFilesToManagedRepo(app.slug, [{ path: 'r.txt', content: 'second' }]);
  assert.notEqual(first.commit.sha, tipOf(app.slug));

  const outFirst = await deployAfterLocalPush(appRow(app.slug), first, { actorId: adminId, deps });
  assert.equal(outFirst.action, 'skipped_superseded');
  assert.equal(outFirst.commit, second.commit.sha.slice(0, 8));
  assert.equal(deploysOf(app.id).length, 0, 'a displaced push deployed');
  assert.equal(calls.length, 0);

  const outSecond = await deployAfterLocalPush(appRow(app.slug), second, { actorId: adminId, deps });
  assert.equal(outSecond.action, 'deploy_triggered');
  const rows = deploysOf(app.id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].commit_hash, second.commit.sha.slice(0, 8));
  assert.equal(rows[0].commit_message, second.message);
  assert.equal(rows[0].log, 'Triggered by push to the managed repository');
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], rows[0].id);
  assert.equal(calls[0][1].slug, app.slug);
  assert.equal(calls[0][2], 'sandbox');
});

test('the deploy a push starts is verified against THAT push, whoever called the facade', async () => {
  // appcrane_push_to_managed_app records last_managed_push_sha only after the
  // facade returns; a direct caller of the facade never records it. The deploy
  // started inside the facade must still be checked against its own commit.
  const app = await localApp();
  setConfig(app.id, { auto_deploy_sandbox: 0 });
  await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'v.txt', content: 'recorded by the tool' }] });
  setConfig(app.id, { auto_deploy_sandbox: 1 });

  const { pushFilesToManagedRepo } = await import('../server/services/managedRepo.js');
  const result = await pushFilesToManagedRepo(appRow(app.slug), [{ path: 'v.txt', content: 'direct' }], { actorId: adminId });
  assert.equal(result.auto_deploy.action, 'deploy_triggered');
  await settle(app.id);
  const log = deploysOf(app.id)[0].log;
  assert.match(log, new RegExp(`Cloned successfully\\. Commit: ${result.commit.sha.slice(0, 7)}`), log);
  assert.equal(/does not match the last pushed commit/.test(log), false, `verified against the previous push:\n${log}`);
  assert.equal(appRow(app.slug).last_managed_push_sha, result.commit.sha);
});

test('a push whose deploy cannot be started still reports the commit, and says why', async () => {
  const app = await localApp();
  db.prepare('DELETE FROM webhook_configs WHERE app_id = ?').run(app.id);
  const res = await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'n.txt', content: 'n' }] });
  assert.equal(res.commit.sha, tipOf(app.slug));
  assert.equal(res.auto_deploy.action, 'skipped_no_config');
  assert.equal(deploysOf(app.id).length, 0);
});

// ---------------------------------------------------------------------------
// Check for updates
// ---------------------------------------------------------------------------

test('/updates for a local app: the shape the dashboard reads, answered from the local branch tip', async () => {
  const app = await localApp();
  setConfig(app.id, { auto_deploy_sandbox: 0 });
  await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'u.txt', content: '1' }] });
  const c1 = tipOf(app.slug);

  assert.deepEqual(await updates(app.slug), {
    available: false, latest_sha: c1.slice(0, 8), latest_message: null, latest_date: null,
    production: { deployed_sha: null, update_available: null },
    sandbox: { deployed_sha: null, update_available: null },
  });

  db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'sandbox', 'live', ?)").run(app.id, c1.slice(0, 7));
  const upToDate = await updates(app.slug);
  assert.equal(upToDate.available, false);
  assert.deepEqual(upToDate.sandbox, { deployed_sha: c1.slice(0, 7), update_available: false });

  await tool('appcrane_push_to_managed_app', { slug: app.slug, files: [{ path: 'u.txt', content: '2' }] });
  const c2 = tipOf(app.slug);
  const behind = await updates(app.slug);
  assert.equal(behind.available, true);
  assert.equal(behind.latest_sha, c2.slice(0, 8));
  assert.deepEqual(behind.sandbox, { deployed_sha: c1.slice(0, 7), update_available: true });
  assert.equal(behind.production.update_available, null);
  assert.equal(githubCalls.length, 0, 'a local /updates reached GitHub');

  // The same keys, in the same order, as a GitHub app's answer.
  const ghApp = db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES ('g','dop-gh',?,'github','https://github.com/o/r','main')").run(getNextSlot(db)).lastInsertRowid;
  db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'sandbox', 'live', ?)").run(ghApp, GH_SHA.slice(0, 7));
  const gh = await updates('dop-gh');
  assert.deepEqual(gh, {
    available: false, latest_sha: GH_SHA.slice(0, 8), latest_message: 'gh head', latest_date: '2026-09-01T00:00:00Z',
    production: { deployed_sha: null, update_available: null },
    sandbox: { deployed_sha: GH_SHA.slice(0, 7), update_available: false },
  });
  assert.deepEqual(Object.keys(behind), Object.keys(gh));
  githubCalls.length = 0;
});

test('/updates: an app with no GitHub URL and no local marker is still not_applicable; an unknown marker is reported', async () => {
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('u','dop-upload',?,'upload')").run(getNextSlot(db));
  assert.deepEqual(await updates('dop-upload'), { available: false, not_applicable: true, reason: 'No GitHub URL configured' });

  db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url) VALUES ('m','dop-bogus',?,'managed','https://github.com/o/r')").run(getNextSlot(db));
  db.pragma('ignore_check_constraints = ON');
  try { db.prepare("UPDATE apps SET repo_backend = 'lcoal' WHERE slug = 'dop-bogus'").run(); } finally { db.pragma('ignore_check_constraints = OFF'); }
  const res = await updates('dop-bogus');
  assert.equal(res.available, false);
  assert.match(res.reason, /does not recognise/);
  assert.equal(githubCalls.length, 0, 'an unknown marker was routed to GitHub');
});
