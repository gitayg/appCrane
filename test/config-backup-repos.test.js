import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'child_process';
import {
  mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync, mkdirSync, readdirSync, statSync, symlinkSync,
} from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';
import AdmZip from 'adm-zip';

// Managed-app git repos (DATA_DIR/repos) are backed up as ONE ARCHIVE PER REPO
// (v2.74.0), separate from the data archive, and old combined zips (v2.73.x)
// still restore.
//
// Every round trip is proven by what a repo IS — every ref's SHA, byte-identical,
// and a clean `git fsck --full` — never by a directory existing: an import that
// recreated empty repos would pass an existence check. Fixtures are real git
// repos made by localGit and real archives made by the exporter; the corrupt
// ones are real archives with real bytes damaged.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cfgrepos-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const { exportDataArchive, importDataArchive } = await import('../server/services/configBackup.js');
const {
  exportRepoArchive, exportRepoArchives, importRepoArchive, verifyRepoSet, readRepoState, repoFingerprint,
} = await import('../server/services/repoArchive.js');
const {
  createAppRepo, pushFilesToManagedRepo, readManagedRepoFile, repoPath, reposRoot, bundleRepoSync, listLocalRepoSlugs,
} = await import('../server/services/localGit.js');

after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

const BACKUPS = join(ROOT, 'backups');
const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (dir, ...args) => execFileSync('git', [`--git-dir=${dir}`, ...args], { env: CLEAN_ENV }).toString('utf8');
const fsck = (dir) => spawnSync('git', [`--git-dir=${dir}`, 'fsck', '--full'], { env: CLEAN_ENV });
const refsOf = (slug) => git(repoPath(slug), 'for-each-ref', '--format=%(objectname) %(refname)');
const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const sha256Buf = (b) => createHash('sha256').update(b).digest('hex');
const liveDb = () => join(ROOT, 'deployhub.db');
const dbSha = () => { getDb().pragma('wal_checkpoint(TRUNCATE)'); return sha256(liveDb()); };
const leftovers = () => [
  ...(existsSync(reposRoot()) ? readdirSync(reposRoot()).filter((n) => n.startsWith('.')) : []),
  ...(existsSync(BACKUPS) ? readdirSync(BACKUPS).filter((n) => n.startsWith('.')) : []),
];

let n = 0;
/** Unpack a real archive, let `mutate` damage it, and pack it back into the backups dir. */
function rewriteRepoArchive(src, mutate) {
  const dir = mkdtempSync(join(tmpdir(), 'crane-rewrite-'));
  try {
    execFileSync('tar', ['-xf', src, '-C', dir]);
    const manifest = JSON.parse(readFileSync(join(dir, 'appcrane-repo.json'), 'utf8'));
    const members = mutate(dir, manifest) || ['appcrane-repo.json', ...(existsSync(join(dir, 'repo.bundle')) ? ['repo.bundle'] : [])];
    writeFileSync(join(dir, 'appcrane-repo.json'), JSON.stringify(manifest));
    const dest = join(BACKUPS, `rewritten-${++n}.tar`);
    execFileSync('tar', ['-cf', dest, '-C', dir, ...members]);
    return dest;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

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

test('each repo survives export -> delete that repo -> import, SHA-identical and fsck-clean', async () => {
  await seed();
  const { exported, failed, total } = await exportRepoArchives();
  assert.equal(total, 3);
  assert.deepEqual(failed, []);
  assert.deepEqual(exported.map((e) => e.slug), ['blog', 'empty', 'shop'], 'one archive per repo');
  for (const e of exported) assert.match(e.file, new RegExp(`^appcrane-repo-${e.slug}-[0-9a-f]{12}-\\d{4}-\\d{2}-\\d{2}\\.tar$`));

  for (const e of exported) {
    const before = refsOf(e.slug);
    const headTarget = git(repoPath(e.slug), 'symbolic-ref', 'HEAD').trim();
    rmSync(repoPath(e.slug), { recursive: true, force: true });
    assert.equal(existsSync(repoPath(e.slug)), false, 'precondition: repo is gone');

    const r = await importRepoArchive(e.file, { slug: e.slug });
    console.log(`# ${e.slug} SHA round trip:\n#  before: ${before.trim().split('\n').join('\n#          ') || '(no refs)'}\n#  after:  ${refsOf(e.slug).trim().split('\n').join('\n#          ') || '(no refs)'}`);
    assert.equal(refsOf(e.slug), before, `every ref of ${e.slug} must come back byte-identical`);
    assert.equal(r.verified, true);
    assert.equal(r.fingerprint, e.fingerprint);
    assert.equal(git(repoPath(e.slug), 'symbolic-ref', 'HEAD').trim(), headTarget, 'HEAD target must be restored');
    const f = fsck(repoPath(e.slug));
    assert.equal(f.status, 0, `git fsck --full failed for ${e.slug}: ${f.stderr}`);
  }
  assert.equal(refsOf('empty'), '', 'the empty repo must come back with no refs');

  // Restored repos are usable, not just present.
  const headBefore = git(repoPath('shop'), 'rev-parse', 'refs/heads/main').trim();
  assert.equal((await readManagedRepoFile('shop', 'src/m4.js')).content, 'export const v = 4;\n'.repeat(50));
  const pushed = await pushFilesToManagedRepo('shop', [{ path: 'after.txt', content: 'post-restore' }]);
  assert.equal(git(repoPath('shop'), 'rev-parse', `${pushed.commit.sha}^`).trim(), headBefore);
  await pushFilesToManagedRepo('blog', [{ path: 'x', content: 'y' }]);
  assert.deepEqual(leftovers(), [], 'no staging or work dir left behind');
});

test('restoring ONE repo leaves every other repo untouched', async () => {
  const shop = await exportRepoArchive('shop');
  git(repoPath('blog'), 'update-ref', 'refs/heads/only-live', git(repoPath('blog'), 'rev-parse', 'refs/heads/trunk').trim());
  const blogRefs = refsOf('blog');
  const blogIno = statSync(repoPath('blog')).ino;
  const emptyIno = statSync(repoPath('empty')).ino;

  rmSync(repoPath('shop'), { recursive: true, force: true });
  await importRepoArchive(shop.path, { slug: 'shop' });

  assert.equal(readRepoState && refsOf('blog'), blogRefs, 'another repo\'s refs changed');
  assert.equal(statSync(repoPath('blog')).ino, blogIno, 'another repo was replaced on disk');
  assert.equal(statSync(repoPath('empty')).ino, emptyIno, 'another repo was replaced on disk');
  assert.equal(git(repoPath('shop'), 'for-each-ref', '--format=%(objectname) %(refname)'), refsOf('shop'));
  assert.equal(fsck(repoPath('shop')).status, 0);
});

test('a corrupt repo archive is refused while a good one alongside it restores', async () => {
  const shop = await exportRepoArchive('shop');
  const blog = await exportRepoArchive('blog');

  // Real bytes damaged in the middle of the bundle, inside the tar.
  const raw = readFileSync(shop.path);
  const at = raw.indexOf(Buffer.from('PACK'));
  assert.ok(at > 0, 'fixture: the archive holds a pack');
  raw[at + 400] ^= 0xff;
  const corrupt = join(BACKUPS, 'corrupt-shop.tar');
  writeFileSync(corrupt, raw);

  const shopBefore = refsOf('shop');
  const shopIno = statSync(repoPath('shop')).ino;
  const blogBefore = refsOf('blog');
  rmSync(repoPath('blog'), { recursive: true, force: true });

  const results = [];
  for (const [slug, path] of [['shop', corrupt], ['blog', blog.path]]) {
    try { results.push({ slug, ok: true, r: await importRepoArchive(path, { slug }) }); }
    catch (e) { results.push({ slug, ok: false, error: e.message }); }
  }
  console.log(`# corrupt/good isolation: ${JSON.stringify(results.map(({ slug, ok, error }) => ({ slug, ok, error })))}`);
  assert.equal(results[0].ok, false);
  assert.match(results[0].error, /failed verification, nothing was restored/);
  assert.equal(refsOf('shop'), shopBefore, 'the live repo changed after a refused import');
  assert.equal(statSync(repoPath('shop')).ino, shopIno, 'the live repo was replaced by a refused import');
  assert.equal(results[1].ok, true, `the good archive must still restore: ${results[1].error}`);
  assert.equal(refsOf('blog'), blogBefore);
  assert.equal(fsck(repoPath('blog')).status, 0);
  assert.deepEqual(leftovers(), []);
});

test('a bundle that unbundles cleanly but is missing objects is refused (only fsck --full catches it)', async () => {
  // Measured with real git: a bundle whose pack holds the commit and tree but
  // NOT the blob passes `bundle verify`, `bundle unbundle` and `update-ref`
  // (rc=0 each); `fsck --full` is the only step that fails. The manifest is
  // made to agree with the bundle (sha256 and fingerprint), so every check this
  // module does itself passes and only localGit's fsck is left to refuse it.
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

    const base = await exportRepoArchive('blog');
    const path = rewriteRepoArchive(base.path, (dir, m) => {
      writeFileSync(join(dir, 'repo.bundle'), bundle);
      m.slug = 'partial';
      m.head = 'refs/heads/main';
      m.refs = { 'refs/heads/main': commit };
      m.head_sha = commit;
      m.fingerprint = repoFingerprint(m.head, m.refs);
      m.bundle = { file: 'repo.bundle', bytes: bundle.length, sha256: sha256Buf(bundle) };
    });
    await assert.rejects(importRepoArchive(path, { slug: 'partial' }), /failed verification, nothing was restored: .*fsck/);
    assert.equal(existsSync(repoPath('partial')), false, 'an incomplete repo was installed');
    assert.deepEqual(leftovers(), []);
  } finally {
    rmSync(W, { recursive: true, force: true });
  }
});

test('archives whose manifest disagrees with their contents are refused before git runs', async () => {
  const base = await exportRepoArchive('shop');
  const live = refsOf('shop');
  const cases = {
    'no HEAD': rewriteRepoArchive(base.path, (_d, m) => { delete m.head; }),
    'refs edited': rewriteRepoArchive(base.path, (_d, m) => { m.refs['refs/heads/main'] = '0'.repeat(40); }),
    'fingerprint edited': rewriteRepoArchive(base.path, (_d, m) => { m.fingerprint = 'f'.repeat(64); }),
    'bundle swapped': rewriteRepoArchive(base.path, (d) => { writeFileSync(join(d, 'repo.bundle'), readFileSync(join(d, 'repo.bundle')).subarray(0, 200)); }),
    'bundle missing': rewriteRepoArchive(base.path, () => ['appcrane-repo.json']),
    'extra member': rewriteRepoArchive(base.path, (d) => { writeFileSync(join(d, 'hooks'), '#!/bin/sh'); return ['appcrane-repo.json', 'repo.bundle', 'hooks']; }),
    'symlink member': rewriteRepoArchive(base.path, (d) => { rmSync(join(d, 'repo.bundle')); symlinkSync('/etc/passwd', join(d, 'repo.bundle')); }),
  };
  const expected = {
    'no HEAD': /invalid HEAD/, 'refs edited': /manifest's refs do not match the bundle's refs/, 'fingerprint edited': /do not match the manifest fingerprint/,
    'bundle swapped': /sha256 does not match/, 'bundle missing': /manifest names a bundle the archive does not hold/,
    'extra member': /unexpected member "hooks"/, 'symlink member': /unexpected member "repo.bundle" \(symlink\)/,
  };
  for (const [name, path] of Object.entries(cases)) {
    await assert.rejects(importRepoArchive(path, { slug: 'shop' }), expected[name], name);
  }
  await assert.rejects(importRepoArchive(base.path, { slug: 'blog' }), /archive is for 'shop', not 'blog'/);
  assert.equal(refsOf('shop'), live, 'a refused archive changed the live repo');
  assert.deepEqual(leftovers(), []);
});

test('repo archive paths are confined to DATA_DIR/backups', async () => {
  const base = await exportRepoArchive('shop');
  const outside = join(ROOT, 'outside.tar');
  writeFileSync(outside, readFileSync(base.path));
  await assert.rejects(importRepoArchive(outside, { slug: 'shop' }), /must be inside/);
  await assert.rejects(importRepoArchive(`${BACKUPS}/../outside.tar`, { slug: 'shop' }), /must be inside/);
  symlinkSync(outside, join(BACKUPS, 'sneaky.tar'));
  await assert.rejects(importRepoArchive('sneaky.tar', { slug: 'shop' }), /resolves elsewhere/);
});

test("a repo's own config and hooks are not carried through a repo archive", async () => {
  const dir = repoPath('blog');
  mkdirSync(join(dir, 'hooks'), { recursive: true });
  writeFileSync(join(dir, 'hooks', 'reference-transaction'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  git(dir, 'config', 'core.hooksPath', '/tmp/somewhere-hostile');
  const a = await exportRepoArchive('blog');
  assert.deepEqual(execFileSync('tar', ['-tf', a.path]).toString().trim().split('\n').sort(), ['appcrane-repo.json', 'repo.bundle']);
  rmSync(dir, { recursive: true, force: true });
  await importRepoArchive(a.path, { slug: 'blog' });
  assert.equal(existsSync(join(repoPath('blog'), 'hooks', 'reference-transaction')), false);
  assert.equal(spawnSync('git', [`--git-dir=${repoPath('blog')}`, 'config', 'core.hooksPath'], { env: CLEAN_ENV }).status, 1,
    'core.hooksPath came back from the backup');
});

test('an import over a live repo keeps the replaced one in a pre-import dir', async () => {
  const a = await exportRepoArchive('shop');
  const backedUp = refsOf('shop');
  git(repoPath('shop'), 'update-ref', 'refs/heads/live-only', git(repoPath('shop'), 'rev-parse', 'refs/heads/main').trim());
  const r = await importRepoArchive(a.path, { slug: 'shop' });
  assert.equal(refsOf('shop'), backedUp, 'the live repo must be replaced by the backup');
  assert.ok(r.replaced_repo_kept_at, 'the result must say where the replaced repo went');
  assert.match(git(r.replaced_repo_kept_at, 'for-each-ref', '--format=%(refname)'), /refs\/heads\/live-only/, 'the replaced repo must be kept, not deleted');
});

test('the data archive holds no repos, records every repo, and detects a repo archive from a different export', async () => {
  const data = await exportDataArchive({ version: '2.74.0' });
  const members = execFileSync('tar', ['-tzf', data.path]).toString();
  assert.doesNotMatch(members, /repos\/|\.bundle/, 'repo bundles must not be inside the data archive');
  const set = data.manifest.repo_set;
  assert.deepEqual(set.repos.map((r) => r.slug), listLocalRepoSlugs());
  for (const r of set.repos) {
    const live = await readRepoState(r.slug);
    assert.equal(r.fingerprint, live.fingerprint);
    assert.deepEqual(r.refs, live.refs);
    assert.equal(r.head_sha, r.slug === 'empty' ? null : git(repoPath(r.slug), 'rev-parse', r.head).trim());
  }

  // A push AFTER the data export: the repo archive taken now is a different export.
  await pushFilesToManagedRepo('shop', [{ path: 'later.txt', content: 'after the data export' }]);
  const newerShop = await exportRepoArchive('shop');
  const sameBlog = await exportRepoArchive('blog');
  assert.notEqual(newerShop.fingerprint, set.repos.find((r) => r.slug === 'shop').fingerprint);

  rmSync(reposRoot(), { recursive: true, force: true });
  const imp = await importDataArchive(data.path, { restoreEnv: false });
  assert.deepEqual(imp.repoSet.verification.missing, ['blog', 'empty', 'shop'], 'a data restore must say which repo archives it expects');

  const shopImport = await importRepoArchive(newerShop.path, { slug: 'shop' });
  const blogImport = await importRepoArchive(sameBlog.path, { slug: 'blog' });
  const v = await verifyRepoSet();
  console.log(`# mismatched pair: shop import pairing=${JSON.stringify(shopImport.pairing)}`);
  console.log(`# mismatched pair: blog import pairing=${JSON.stringify(blogImport.pairing)}`);
  console.log(`# verifyRepoSet: matched=${v.matched} missing=${JSON.stringify(v.missing)} mismatched=${JSON.stringify(v.mismatched)} rows=${JSON.stringify(v.rows.map(({ slug, state, expected_fingerprint, present_fingerprint }) => ({ slug, state, expected: expected_fingerprint.slice(0, 12), present: present_fingerprint?.slice(0, 12) || null })))}`);
  assert.equal(shopImport.pairing.matched, false, 'a repo archive from a different export must be reported at import');
  assert.equal(blogImport.pairing.matched, true);
  assert.equal(v.matched, false);
  assert.deepEqual(v.mismatched, ['shop']);
  assert.deepEqual(v.missing, ['empty']);
});

// ---------------------------------------------------------------------------
// Old backups: v2.73.x combined zips (repos inside) must still restore.
// Built with adm-zip in exactly the v2.73.1 layout — adm-zip is what wrote them.
// ---------------------------------------------------------------------------

async function legacyZip({ version = '2.73.1', withRepos = true, mutate } = {}) {
  const zip = new AdmZip();
  const tmpDb = join(ROOT, `legacy-src-${++n}.db`);
  await getDb().backup(tmpDb);
  zip.addLocalFile(tmpDb, '', 'deployhub.db');
  rmSync(tmpDb);
  zip.addFile('appdata/shop/production/legacy.txt', Buffer.from('LEGACY-DATA'));
  const slugs = withRepos ? listLocalRepoSlugs() : [];
  for (const slug of slugs) {
    const { head, bundle } = bundleRepoSync(slug);
    zip.addFile(`repos/${slug}.HEAD`, Buffer.from(`${head}\n`));
    if (bundle) zip.addFile(`repos/${slug}.bundle`, bundle);
  }
  mutate?.(zip);
  zip.addFile('appcrane-backup.json', Buffer.from(JSON.stringify({
    kind: 'appcrane-config-backup', version, exported_at: new Date().toISOString(),
    includes: ['deployhub.db', 'icons', 'appdata', 'appvolumes', ...(withRepos ? ['repos'] : [])], counts: {},
    ...(withRepos ? { repos: slugs.length } : {}),
  })));
  mkdirSync(BACKUPS, { recursive: true });
  const dest = join(BACKUPS, `legacy-${n}.zip`);
  zip.writeZip(dest);
  return dest;
}

test('a v2.73.x combined zip restores its repos in place, SHA-identical and fsck-clean', async () => {
  // The pairing test above deliberately left 'empty' unrestored; a repo with no refs belongs in this fixture.
  if (!listLocalRepoSlugs().includes('empty')) await createAppRepo('empty', { autoInit: false });
  assert.deepEqual(listLocalRepoSlugs(), ['blog', 'empty', 'shop']);
  const zipPath = await legacyZip();
  const before = Object.fromEntries(listLocalRepoSlugs().map((s) => [s, refsOf(s)]));
  rmSync(reposRoot(), { recursive: true, force: true });
  const r = await importDataArchive(zipPath, { restoreEnv: false });
  assert.equal(r.format, 'legacy-zip');
  assert.equal(r.repos, 3, 'the restored count must be reported so a silent zero is visible');
  for (const [slug, refs] of Object.entries(before)) {
    assert.equal(refsOf(slug), refs, `legacy restore changed refs of ${slug}`);
    assert.equal(fsck(repoPath(slug)).status, 0);
  }
  assert.equal(readFileSync(join(ROOT, 'apps', 'shop', 'production', 'shared', 'data', 'legacy.txt'), 'utf8'), 'LEGACY-DATA');
  assert.match(r.repoSet.note, /Legacy combined backup: 3 repositories restored in place/);
  assert.deepEqual(leftovers(), []);
});

test('a v2.73.x zip with a corrupt bundle refuses the whole import before the DB or any repo is replaced', async () => {
  const good = bundleRepoSync('shop').bundle;
  const zipPath = await legacyZip({
    mutate: (z) => z.updateFile('repos/shop.bundle', good.subarray(0, Math.floor(good.length * 0.6))),
  });
  const dbBefore = dbSha();
  git(repoPath('blog'), 'update-ref', 'refs/heads/marker', git(repoPath('blog'), 'rev-parse', 'refs/heads/trunk').trim());
  const shopBefore = refsOf('shop');
  const blogBefore = refsOf('blog');
  await assert.rejects(importDataArchive(zipPath, { restoreEnv: false }), /failed verification, nothing was restored/);
  assert.equal(sha256(liveDb()), dbBefore, 'the DB was replaced by an import that then failed');
  assert.equal(refsOf('shop'), shopBefore);
  assert.equal(refsOf('blog'), blogBefore, 'a good repo from the same broken zip was installed anyway');
  assert.deepEqual(leftovers(), []);
});

test('a v2.73.x zip bundle with no HEAD entry is refused', async () => {
  const zipPath = await legacyZip({ mutate: (z) => z.deleteFile('repos/shop.HEAD') });
  const dbBefore = dbSha();
  await assert.rejects(importDataArchive(zipPath, { restoreEnv: false }), /has no repos\/shop\.HEAD/);
  assert.equal(sha256(liveDb()), dbBefore);
});

test('a v2.72 zip (no repos at all) still imports and leaves live repos alone', async () => {
  const zipPath = await legacyZip({ version: '2.72.1', withRepos: false });
  const shopBefore = refsOf('shop');
  const ino = statSync(repoPath('shop')).ino;
  const r = await importDataArchive(zipPath, { restoreEnv: false });
  assert.equal(r.repos, 0);
  assert.match(r.repoSet.note, /predates repository archives/);
  assert.equal(refsOf('shop'), shopBefore);
  assert.equal(statSync(repoPath('shop')).ino, ino);
});
