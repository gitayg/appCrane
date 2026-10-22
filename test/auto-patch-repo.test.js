import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The commit path auto-patch uses: the managed-repo facade with expectParent
// (compare-and-swap: refuse rather than displace another push) and
// deployOnPush: false (the worker starts the sandbox deploy itself). Real git.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-auto-patch-repo-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const { pushFilesToManagedRepo, localBranchHeadSha } = await import('../server/services/managedRepo.js');

await lg.createAppRepo('cas');
const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('cas','cas',960,'managed','local','main')").run().lastInsertRowid);
db.prepare("INSERT INTO webhook_configs (app_id, token, secret, auto_deploy_sandbox, auto_deploy_prod) VALUES (?, 'tok-cas', 'sec-cas', 1, 0)").run(appId);
const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);

test('expectParent: a moved branch is refused and nothing is committed', async () => {
  const tip = await localBranchHeadSha(app, 'main');
  await assert.rejects(
    pushFilesToManagedRepo(app, [{ path: 'a.txt', content: 'a' }], { branch: 'main', expectParent: 'f'.repeat(40), deployOnPush: false }),
    (e) => e.code === 'BRANCH_MOVED',
  );
  assert.equal(await localBranchHeadSha(app, 'main'), tip);
});

test('expectParent at the tip commits; deployOnPush: false starts no deploy', async () => {
  const tip = await localBranchHeadSha(app, 'main');
  const r = await pushFilesToManagedRepo(app, [{ path: 'b.txt', content: 'b' }], { branch: 'main', expectParent: tip, deployOnPush: false });
  assert.equal(await localBranchHeadSha(app, 'main'), r.commit.sha);
  assert.equal(r.auto_deploy, undefined);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(appId).n, 0);
  assert.equal(db.prepare('SELECT last_managed_push_sha s FROM apps WHERE id = ?').get(appId).s, r.commit.sha);
});

test('promoteApp refuses when the live sandbox is not the one auto-patch tested', async () => {
  const { promoteApp } = await import('../server/services/deployer.js');
  const live = Number(db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'sandbox', 'live', 'abc')").run(appId).lastInsertRowid);
  await assert.rejects(promoteApp(app, null, { expectSandboxDeploymentId: live + 1 }), (e) => e.code === 'SANDBOX_CHANGED');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND env = 'production'").get(appId).n, 0);
});
