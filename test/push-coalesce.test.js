import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Deploy-on-push coalescing: a push that lands while a deploy of the same
// app+env is in flight is queued (newest wins) and deployed once when that
// deploy ends. deployApp is a stub that records its calls and leaves the row
// pending, so the test decides when a deploy finishes by updating the row and
// polling the coalescer by hand.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-coalesce-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const {
  triggerAutoDeploys, deployAfterLocalPush, pushDeployView, pushConfigForApp, LOCAL_PUSH_SOURCE,
} = await import('../server/services/deployTrigger.js');
const { tickPushCoalescer, resetPushCoalescer, queuedFollowUps } = await import('../server/services/pushCoalescer.js');
const lg = await import('../server/services/localGit.js');

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const tipOf = (slug) => execFileSync('git', [`--git-dir=${lg.repoPath(slug)}`, 'rev-parse', 'refs/heads/main'], { env: CLEAN_ENV }).toString().trim();

const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('pc','pc@x.test','platform_admin',?,1,'human')",
).run(hashApiKey('pc-test-key-0001')).lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'pc' };

after(async () => {
  resetPushCoalescer();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});
beforeEach(() => resetPushCoalescer());

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}

const appRow = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
const deploysOf = (appId) => db.prepare('SELECT * FROM deployments WHERE app_id = ? ORDER BY id').all(appId);
const deliveriesOf = (appId) => db.prepare('SELECT action_taken, deploy_id, commit_hash FROM webhook_deliveries WHERE app_id = ? ORDER BY id').all(appId);
const finish = (id, status = 'live') => db.prepare("UPDATE deployments SET status = ?, finished_at = datetime('now') WHERE id = ?").run(status, id);

function stubDeps() {
  const calls = [];
  return { calls, deps: { deployApp: async (...a) => { calls.push(a); }, getPortsForSlot: () => ({}) } };
}

let seq = 0;
async function localApp() {
  const slug = `pc-${++seq}`;
  await tool('appcrane_create_managed_app', { name: slug, slug });
  const app = appRow(slug);
  assert.equal(app.repo_backend, 'local');
  return app;
}

function trigger(app, deps, commitSha, logged = []) {
  return triggerAutoDeploys({
    config: pushConfigForApp(app.id), branch: 'main', commitSha, commitMessage: `msg ${commitSha}`,
    logDelivery: (d) => logged.push(d), source: LOCAL_PUSH_SOURCE, actorId: adminId, deps,
  });
}

test('a second trigger while the first deploy is in flight inserts no row and returns queued', async () => {
  const app = await localApp();
  const { calls, deps } = stubDeps();
  const logged = [];

  const first = await trigger(app, deps, 'aaaaaaa1', logged);
  assert.equal(first.length, 1);
  const firstId = first[0].deployment_id;

  const second = await trigger(app, deps, 'aaaaaaa2', logged);
  assert.deepEqual(second, [{ env: 'sandbox', status: 'queued', queued_behind: firstId }]);
  assert.equal(deploysOf(app.id).length, 1, 'a push during an in-flight deploy inserted a second deployment');
  assert.equal(calls.length, 1, 'deployApp ran twice');
  assert.deepEqual(logged.map((d) => d.actionTaken), ['deploy_triggered', 'deploy_queued']);
  assert.equal(logged[1].deployId, firstId);
  assert.deepEqual(queuedFollowUps().map((q) => [q.env, q.behind]), [['sandbox', firstId]]);
});

test('ten triggers during one deploy produce exactly one follow-up deploy, of the newest push, after it finishes', async () => {
  const app = await localApp();
  const { calls, deps } = stubDeps();
  const logged = [];
  const first = await trigger(app, deps, 'bbbbbbb0', logged);
  const firstId = first[0].deployment_id;
  for (let i = 1; i <= 10; i++) {
    const r = await trigger(app, deps, `bbbbbb${String(i).padStart(2, '0')}`, logged);
    assert.equal(r[0].status, 'queued');
  }
  assert.equal(queuedFollowUps().length, 1);

  await tickPushCoalescer();
  assert.equal(deploysOf(app.id).length, 1, 'the follow-up ran while the first deploy was still in flight');
  assert.equal(logged.filter((d) => d.actionTaken === 'deploy_queued').length, 10, 'the follow-up ran (and re-queued) while the first deploy was still in flight');

  finish(firstId);
  await tickPushCoalescer();
  await tickPushCoalescer();
  const rows = deploysOf(app.id);
  assert.equal(rows.length, 2, `expected exactly one follow-up deploy, got ${JSON.stringify(rows.map((r) => [r.id, r.status, r.commit_hash]))}`);
  assert.equal(rows[1].commit_hash, 'bbbbbb10', 'the follow-up did not deploy the newest push');
  assert.equal(rows[1].log, LOCAL_PUSH_SOURCE.deploymentLog);
  assert.equal(calls.length, 2);
  assert.equal(calls[1][0], rows[1].id);
  assert.equal(queuedFollowUps().length, 0);

  const audits = db.prepare("SELECT user_id, action FROM audit_log WHERE app_id = ? AND action = 'push-deploy'").all(app.id);
  assert.equal(audits.length, 2);
  assert.ok(audits.every((a) => a.user_id === adminId && a.action === 'push-deploy'));
});

test('a follow-up behind a deploy that failed or was reclaimed still runs', async () => {
  const app = await localApp();
  const { deps } = stubDeps();
  const first = await trigger(app, deps, 'ccccccc0');
  await trigger(app, deps, 'ccccccc1');
  finish(first[0].deployment_id, 'failed');
  await tickPushCoalescer();
  assert.equal(deploysOf(app.id).length, 2);
});

test('a local push queued behind a deploy deploys the branch tip read at follow-up time, once', async () => {
  const app = await localApp();
  const { calls, deps } = stubDeps();

  const p1 = await lg.pushFilesToManagedRepo(app.slug, [{ path: 'a.txt', content: '1' }]);
  const out1 = await deployAfterLocalPush(appRow(app.slug), p1, { actorId: adminId, deps });
  assert.equal(out1.action, 'deploy_triggered');
  const firstId = out1.triggered[0].deployment_id;

  const p2 = await lg.pushFilesToManagedRepo(app.slug, [{ path: 'b.txt', content: '2' }]);
  const out2 = await deployAfterLocalPush(appRow(app.slug), p2, { actorId: adminId, deps });
  assert.equal(out2.action, 'deploy_queued');
  assert.deepEqual(out2.triggered, [{ env: 'sandbox', status: 'queued', queued_behind: firstId }]);

  // Pushed meanwhile without going through deploy-on-push: only a tip re-read sees it.
  await lg.pushFilesToManagedRepo(app.slug, [{ path: 'c.txt', content: '3' }]);
  const tip = tipOf(app.slug);
  assert.notEqual(tip.slice(0, 8), out2.commit);

  finish(firstId);
  await tickPushCoalescer();
  const rows = deploysOf(app.id);
  assert.equal(rows.length, 2);
  assert.equal(rows[1].commit_hash, tip.slice(0, 8), 'the follow-up deployed the queued commit, not the tip');
  assert.equal(calls.length, 2);
  assert.ok(deliveriesOf(app.id).some((d) => d.action_taken === 'deploy_queued' && d.deploy_id === firstId));
});

test('a stale in-flight deploy does not queue the push', async () => {
  const app = await localApp();
  const { calls, deps } = stubDeps();
  const staleId = db.prepare(
    "INSERT INTO deployments (app_id, env, status, commit_hash, started_at) VALUES (?, 'sandbox', 'building', 'old', datetime('now', '-31 minutes'))",
  ).run(app.id).lastInsertRowid;

  const r = await trigger(app, deps, 'ddddddd1');
  assert.equal(r.length, 1);
  assert.equal(r[0].status, undefined, 'a push queued behind a stale deploy');
  assert.ok(r[0].deployment_id > staleId);
  assert.equal(calls.length, 1);
  assert.equal(queuedFollowUps().length, 0);
});

test('a queued follow-up is dropped when its branch stopped being the deploy-on-push branch meanwhile', async () => {
  const app = await localApp();
  const { deps } = stubDeps();
  const logged = [];
  const first = await trigger(app, deps, 'eeeeeee0', logged);
  await trigger(app, deps, 'eeeeeee1', logged);
  db.prepare("UPDATE webhook_configs SET branch_filter = 'release' WHERE app_id = ?").run(app.id);
  finish(first[0].deployment_id);
  await tickPushCoalescer();
  assert.equal(deploysOf(app.id).length, 1, 'a queued push deployed after its branch was no longer watched');
  assert.equal(queuedFollowUps().length, 0);
  assert.equal(logged.at(-1).actionTaken, 'skipped_branch');
});

test('pushDeployView tells the agent the push is queued and not to deploy', () => {
  const view = pushDeployView('s', { auto_deploy: {
    action: 'deploy_queued', branch: 'main', commit: 'abcdef12',
    triggered: [{ env: 'sandbox', status: 'queued', queued_behind: 41 }],
  } }, 'default next');
  assert.equal(view.next,
    'Pushed. A deploy of this app (deployment 41) is still running; this commit is queued and AppCrane will deploy the ' +
    'branch tip once, when it finishes, including any files you push meanwhile. Do not call appcrane_deploy. ' +
    'Push the rest of the change now, ideally all files in ONE appcrane_push_to_managed_app call.');
  assert.equal(view.auto_deploy.action, 'deploy_queued');

  const mixed = pushDeployView('s', { auto_deploy: {
    action: 'deploy_triggered', branch: 'main', commit: 'abcdef12',
    triggered: [{ env: 'sandbox', deployment_id: 7 }, { env: 'production', status: 'queued', queued_behind: 5 }],
  } }, 'default next');
  assert.match(mixed.next, /started sandbox deployment 7 for commit abcdef12/);
  assert.match(mixed.next, /appcrane_wait_deploy deployment_id=7\./);
  assert.match(mixed.next, /production is queued behind deployment 5/);
});
