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

test('resolveCommitExact: full SHA only for exactly one matching commit; ambiguous, missing and non-commit prefixes are refused', async () => {
  const { execFileSync } = await import('child_process');
  const { resolveCommitExact, deploymentCommit } = await import('../server/services/autoPatch/commits.js');
  const CLEAN = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
  const objects = () => execFileSync('git', [`--git-dir=${lg.repoPath('cas')}`, 'cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)'], { env: CLEAN })
    .toString().trim().split('\n').map((l) => l.split(' '));
  // Write commits (git commit-tree, unreferenced but in the object store,
  // which is what prefix resolution searches) until two objects share a
  // 4-hex prefix with a commit among them: a birthday collision, ~300 objects.
  const gd = `--git-dir=${lg.repoPath('cas')}`;
  const ID = { ...CLEAN, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.com', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.com' };
  const tree = execFileSync('git', [gd, 'rev-parse', 'refs/heads/main^{tree}'], { env: CLEAN }).toString().trim();
  const seen = new Map(objects().map(([sha]) => [sha.slice(0, 4), sha]));
  let ambiguous = null;
  for (let i = 0; i < 5000 && !ambiguous; i++) {
    const c = execFileSync('git', [gd, 'commit-tree', tree, '-m', `n${i}`], { env: ID }).toString().trim();
    if (seen.has(c.slice(0, 4))) ambiguous = c;
    else seen.set(c.slice(0, 4), c);
  }
  assert.ok(ambiguous, 'found a commit whose 4-hex prefix is shared');
  assert.equal(await resolveCommitExact('cas', ambiguous.slice(0, 4)), null, 'ambiguous prefix refused');
  assert.equal(await resolveCommitExact('cas', ambiguous), ambiguous, 'full SHA resolves to itself');
  const tip = await localBranchHeadSha(app, 'main');
  const short = tip.slice(0, 12);
  assert.equal(await resolveCommitExact('cas', short), tip, 'unique short hash resolves to the full SHA');
  assert.equal(await resolveCommitExact('cas', 'f'.repeat(40)), null, 'missing');
  const blob = objects().find(([, type]) => type === 'blob')[0];
  assert.equal(await resolveCommitExact('cas', blob), null, 'a blob is not a commit');
  assert.equal(await resolveCommitExact('cas', 'HEAD'), null, 'only hex is accepted');
  assert.equal(await deploymentCommit('cas', { commit_sha: tip, commit_hash: 'zzzz' }), tip);
  assert.equal(await deploymentCommit('cas', { commit_sha: null, commit_hash: ambiguous.slice(0, 4) }), null);
});
