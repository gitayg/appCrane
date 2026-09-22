import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * A managed clone whose HEAD differs from `last_managed_push_sha` can differ in
 * two directions, and the advice is opposite in each:
 *
 *   clone BEHIND the record  -> stale. Re-deploying fetches the pushed commit.
 *   clone AHEAD of the record -> a commit reached the repository without going
 *     through the managed-push path that records the SHA. Re-deploying fails
 *     identically, so "re-run the deploy" sends the operator in a circle.
 *
 * Measured on a real host: a push made with localGit directly instead of the
 * managedRepo facade produced
 *
 *   Supply-chain verify FAILED: managed clone HEAD e03612f15173… does not match
 *   the last pushed commit 9cb8df3a951f…. The clone is stale — re-run the
 *   deploy so it fetches the pushed commit.
 *
 * and the clone was NEWER, not stale. The direction is answerable because the
 * repository is on the same host.
 */
const ROOT = mkdtempSync(join(tmpdir(), 'crane-scdir-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const { verifyCommitSha } = await import('../server/services/supplyChain.js');

const SLUG = 'scdir';
await lg.createAppRepo(SLUG, { description: 'direction test' });
db.prepare(`INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch)
            VALUES ('SC Dir', ?, 901, 'managed', 'local', 'main')`).run(SLUG);

const first  = await lg.pushFilesToManagedRepo(SLUG, [{ path: 'a.txt', content: 'one' }]);
const second = await lg.pushFilesToManagedRepo(SLUG, [{ path: 'a.txt', content: 'two' }]);

/**
 * A deploy clone pinned at `sha`, the way the deployer makes one. The counter
 * matters: two tests pin the same commit, and a shared directory name made
 * `git clone` fail with "destination path already exists" -- a test-harness
 * failure that looks nothing like the assertion it hides.
 */
let cloneSeq = 0;
function cloneAt(sha) {
  const dir = join(ROOT, `rel-${sha.slice(0, 7)}-${++cloneSeq}`);
  mkdirSync(dir, { recursive: true });
  execFileSync('git', ['clone', '--quiet', '--no-local', lg.repoPath(SLUG), dir], { stdio: 'pipe' });
  execFileSync('git', ['-C', dir, 'checkout', '--quiet', sha], { stdio: 'pipe' });
  return dir;
}

const appWith = (recorded) => ({
  ...db.prepare('SELECT * FROM apps WHERE slug = ?').get(SLUG),
  last_managed_push_sha: recorded,
});

test('clone AHEAD of the record is not called stale, and the advice is actionable', async () => {
  // Recorded = the FIRST push; the clone is at the second. This is the real
  // case: a commit landed without the facade recording it.
  const err = await verifyCommitSha(appWith(first.commit.sha), cloneAt(second.commit.sha), 'main', () => {})
    .then(() => null, (e) => e);
  assert.ok(err, 'a mismatch did not fail the verify');
  assert.match(err.message, /AHEAD of the last recorded push/, err.message);
  assert.match(err.message, /without going through AppCrane's managed-push path/, err.message);
  assert.doesNotMatch(
    err.message, /clone is stale/,
    'a clone that is newer than the record is still being called stale — the operator re-deploys and fails identically',
  );
});

test('clone BEHIND the record still says stale, because re-deploying does fix that', async () => {
  const err = await verifyCommitSha(appWith(second.commit.sha), cloneAt(first.commit.sha), 'main', () => {})
    .then(() => null, (e) => e);
  assert.ok(err, 'a mismatch did not fail the verify');
  assert.match(err.message, /clone is stale/, err.message);
  assert.doesNotMatch(err.message, /AHEAD/, err.message);
});

test('an unreadable recorded commit says so rather than guessing a direction', async () => {
  const absent = 'd'.repeat(40);
  const err = await verifyCommitSha(appWith(absent), cloneAt(second.commit.sha), 'main', () => {})
    .then(() => null, (e) => e);
  assert.ok(err, 'a mismatch did not fail the verify');
  assert.match(err.message, /Could not determine which side moved/, err.message);
});

test('a matching clone passes the freshness gate', async () => {
  const out = await verifyCommitSha(appWith(second.commit.sha), cloneAt(second.commit.sha), 'main', () => {})
    .then((r) => r, (e) => e);
  assert.ok(!(out instanceof Error), `a matching clone failed: ${out?.message}`);
});
