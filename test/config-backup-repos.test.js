import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync, mkdirSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import AdmZip from 'adm-zip';

// Config backup must carry managed-app git repos (DATA_DIR/repos).
//
// While managed-app source lived on GitHub it never needed backing up. Once it
// lives on the host, a disk loss erases it unless the backup has it — the same
// silent failure v2.70.2 fixed for declared volumes. So the round trip is
// proven by what a repo IS (every ref's SHA, byte-identical, and a clean
// `git fsck --full`), never by a directory existing: an import that recreated
// empty repos would pass an existence check.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cfgrepos-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb } = await import('../server/db.js');
initDb();
const { exportConfig, importConfig } = await import('../server/services/configBackup.js');
const {
  createAppRepo, pushFilesToManagedRepo, readManagedRepoFile, repoPath, reposRoot,
} = await import('../server/services/localGit.js');

after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (dir, ...args) => execFileSync('git', [`--git-dir=${dir}`, ...args], { env: CLEAN_ENV }).toString('utf8');
const fsck = (dir) => spawnSync('git', [`--git-dir=${dir}`, 'fsck', '--full'], { env: CLEAN_ENV });
const refsOf = (slug) => git(repoPath(slug), 'for-each-ref', '--format=%(objectname) %(refname)');
const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

async function seed() {
  await createAppRepo('shop', { description: 'shop' });
  for (let i = 0; i < 5; i++) {
    await pushFilesToManagedRepo('shop', [
      { path: `src/m${i}.js`, content: `export const v = ${i};\n`.repeat(50) },
      { path: 'bin/blob.dat', content: Buffer.from(Array.from({ length: 4096 }, (_, j) => (i * 31 + j) & 255)).toString('base64'), encoding: 'base64' },
    ], { message: `commit ${i}` });
  }
  // A second branch and a tag: a restore that brought back only HEAD's branch would lose them.
  const dir = repoPath('shop');
  const tip = git(dir, 'rev-parse', 'refs/heads/main').trim();
  git(dir, 'update-ref', 'refs/heads/feature', `${tip}~2`);
  git(dir, 'update-ref', 'refs/tags/v1', `${tip}~1`);
  // A repo whose HEAD points at a non-default branch.
  await createAppRepo('blog');
  git(repoPath('blog'), 'update-ref', 'refs/heads/trunk', git(repoPath('blog'), 'rev-parse', 'refs/heads/main').trim());
  git(repoPath('blog'), 'symbolic-ref', 'HEAD', 'refs/heads/trunk');
  // A repo with no refs at all.
  await createAppRepo('empty', { autoInit: false });
}

test('managed repos survive export -> delete DATA_DIR/repos -> import, SHA-identical and fsck-clean', async () => {
  await seed();
  const before = { shop: refsOf('shop'), blog: refsOf('blog'), empty: refsOf('empty') };
  const headBefore = git(repoPath('shop'), 'rev-parse', 'refs/heads/main').trim();
  assert.match(before.shop, /refs\/heads\/feature/);
  assert.match(before.shop, /refs\/tags\/v1/);

  const { buffer, manifest } = exportConfig('2.72.1');
  assert.ok(manifest.includes.includes('repos'), 'manifest must declare the repos prefix');
  assert.equal(manifest.repos, 3);

  rmSync(reposRoot(), { recursive: true, force: true });
  assert.equal(existsSync(repoPath('shop')), false, 'precondition: repos are gone');

  const result = importConfig(buffer, { restoreEnv: false });
  assert.equal(result.repos, 3, 'the restored count must be reported so a silent zero is visible');

  const headAfter = git(repoPath('shop'), 'rev-parse', 'refs/heads/main').trim();
  console.log(`# SHA round trip: before=${headBefore} after=${headAfter}`);
  assert.equal(headAfter, headBefore, 'branch head SHA changed across the round trip');
  assert.equal(refsOf('shop'), before.shop, 'every ref of shop must come back byte-identical');
  assert.equal(refsOf('blog'), before.blog);
  assert.equal(refsOf('empty'), '', 'the empty repo must come back with no refs');
  assert.equal(result.repoHeads.find((r) => r.slug === 'shop').headSha, headBefore);

  for (const slug of ['shop', 'blog', 'empty']) {
    const r = fsck(repoPath(slug));
    assert.equal(r.status, 0, `git fsck --full failed for ${slug}: ${r.stderr}`);
  }
  assert.equal(git(repoPath('blog'), 'symbolic-ref', 'HEAD').trim(), 'refs/heads/trunk', 'HEAD target must be restored');
  assert.equal(git(repoPath('shop'), 'symbolic-ref', 'HEAD').trim(), 'refs/heads/main');

  // The restored repo is usable, not just present.
  assert.equal((await readManagedRepoFile('shop', 'src/m4.js')).content, 'export const v = 4;\n'.repeat(50));
  const pushed = await pushFilesToManagedRepo('shop', [{ path: 'after.txt', content: 'post-restore' }]);
  assert.equal(git(repoPath('shop'), 'rev-parse', `${pushed.commit.sha}^`).trim(), headBefore);
  await pushFilesToManagedRepo('blog', [{ path: 'x', content: 'y' }]);
  assert.deepEqual(readdirSync(reposRoot()).filter((n) => n.startsWith('.')), [], 'no staging dir left behind');
});

test("a repo's own config and hooks are not carried through a backup", async () => {
  const dir = repoPath('blog');
  mkdirSync(join(dir, 'hooks'), { recursive: true });
  writeFileSync(join(dir, 'hooks', 'reference-transaction'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  git(dir, 'config', 'core.hooksPath', '/tmp/somewhere-hostile');
  const { buffer } = exportConfig('2.72.1');
  assert.deepEqual(new AdmZip(buffer).getEntries().map((e) => e.entryName).filter((n) => n.startsWith('repos/')).sort(),
    ['repos/blog.HEAD', 'repos/blog.bundle', 'repos/empty.HEAD', 'repos/shop.HEAD', 'repos/shop.bundle']);
  rmSync(reposRoot(), { recursive: true, force: true });
  importConfig(buffer, { restoreEnv: false });
  assert.equal(existsSync(join(repoPath('blog'), 'hooks', 'reference-transaction')), false);
  assert.equal(spawnSync('git', [`--git-dir=${repoPath('blog')}`, 'config', 'core.hooksPath'], { env: CLEAN_ENV }).status, 1,
    'core.hooksPath came back from the backup');
});

test('an import over live repos keeps the replaced one in the pre-import dir', () => {
  const { buffer } = exportConfig('2.72.1');
  const backedUp = refsOf('shop');
  git(repoPath('shop'), 'update-ref', 'refs/heads/live-only', git(repoPath('shop'), 'rev-parse', 'refs/heads/main').trim());
  const result = importConfig(buffer, { restoreEnv: false });
  assert.equal(refsOf('shop'), backedUp, 'the live repo must be replaced by the backup');
  const aside = join(result.preImportDir, 'repos', 'shop.git');
  assert.match(git(aside, 'for-each-ref', '--format=%(refname)'), /refs\/heads\/live-only/, 'the replaced repo must be kept, not deleted');
});

test('a corrupt bundle refuses the whole import before the DB or any repo is replaced', () => {
  const { buffer } = exportConfig('2.72.1');
  const zip = new AdmZip(buffer);
  const good = zip.getEntry('repos/shop.bundle').getData();
  zip.updateFile('repos/shop.bundle', good.subarray(0, Math.floor(good.length * 0.6)));
  const broken = zip.toBuffer();

  const dbFile = join(ROOT, 'deployhub.db');
  const dbBefore = sha256(dbFile);
  const refsBefore = refsOf('shop');
  // Make the live state distinguishable from the backup so a partial restore is visible.
  git(repoPath('blog'), 'update-ref', 'refs/heads/marker', git(repoPath('blog'), 'rev-parse', 'refs/heads/trunk').trim());
  const blogBefore = refsOf('blog');

  assert.throws(() => importConfig(broken, { restoreEnv: false }), /failed verification, nothing was restored/);
  assert.equal(sha256(dbFile), dbBefore, 'the DB was replaced by an import that then failed');
  assert.equal(refsOf('shop'), refsBefore);
  assert.equal(refsOf('blog'), blogBefore, 'a good repo from the same broken bundle was installed anyway');
  assert.deepEqual(readdirSync(reposRoot()).filter((n) => n.startsWith('.')), [], 'no staging dir left behind');
});

test('a bundle with no HEAD entry is refused', () => {
  const zip = new AdmZip(exportConfig('2.72.1').buffer);
  zip.deleteFile('repos/shop.HEAD');
  assert.throws(() => importConfig(zip.toBuffer(), { restoreEnv: false }), /has no repos\/shop\.HEAD/);
});

test('a bundle that unbundles cleanly but is missing objects is refused (only fsck --full catches it)', () => {
  // Measured with real git: a bundle whose pack holds the commit and tree but
  // NOT the blob passes `bundle verify`, `bundle unbundle` and `update-ref`
  // (rc=0 each); `fsck --full` is the only step that fails. A truncated bundle
  // fails earlier, at unbundle, and so cannot prove this guard.
  const W = mkdtempSync(join(tmpdir(), 'crane-partial-'));
  try {
    const src = join(W, 'src.git');
    execFileSync('git', ['init', '-q', '--bare', '-b', 'main', src], { env: CLEAN_ENV });
    const idEnv = { ...CLEAN_ENV, GIT_AUTHOR_NAME: 'T', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 'T', GIT_COMMITTER_EMAIL: 't@t.invalid' };
    const g = (args, input) => execFileSync('git', [`--git-dir=${src}`, ...args], { env: idEnv, input });
    const blob = g(['hash-object', '-w', '--stdin'], 'payload').toString().trim();
    const tree = g(['mktree'], `100644 blob ${blob}\tf.txt\n`).toString().trim();
    const commit = g(['commit-tree', tree], 'm\n').toString().trim();
    const pack = g(['pack-objects', '--stdout', '-q'], `${commit}\n${tree}\n`);
    const bundle = Buffer.concat([Buffer.from(`# v2 git bundle\n${commit} refs/heads/main\n\n`), pack]);

    const zip = new AdmZip(exportConfig('2.72.1').buffer);
    zip.addFile('repos/partial.HEAD', Buffer.from('refs/heads/main\n'));
    zip.addFile('repos/partial.bundle', bundle);
    const dbBefore = sha256(join(ROOT, 'deployhub.db'));

    assert.throws(() => importConfig(zip.toBuffer(), { restoreEnv: false }), /failed verification, nothing was restored/);
    assert.equal(existsSync(repoPath('partial')), false, 'an incomplete repo was installed');
    assert.equal(sha256(join(ROOT, 'deployhub.db')), dbBefore, 'the DB was replaced by an import that then failed');
  } finally {
    rmSync(W, { recursive: true, force: true });
  }
});
