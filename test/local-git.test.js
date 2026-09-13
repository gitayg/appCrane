import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync, chmodSync, readdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

// Host-local managed-app repos (phase 1). Every assertion here is checked with
// the REAL git binary, reading the bare repo independently of the module under
// test: a mock of git could keep a wrong plumbing sequence green.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-localgit-'));
process.env.DATA_DIR = ROOT;
process.env.LOG_LEVEL = 'error';

const lg = await import('../server/services/localGit.js');
const {
  createAppRepo, pushFilesToManagedRepo, readManagedRepoFile, getBranchHeadSha,
  repoPath, LOCAL_GIT_IDENTITY,
} = lg;

after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

// Independent reader: an isolated git, never the module's own helper.
const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (dir, ...args) => execFileSync('git', [`--git-dir=${dir}`, ...args], { env: CLEAN_ENV }).toString('utf8').trim();
const blobShaOf = (buf) => execFileSync('git', ['hash-object', '--stdin'], { input: buf, env: CLEAN_ENV }).toString().trim();

test('create: README initial commit on main, neutral identity, REPO_EXISTS on a second call', async () => {
  const r = await createAppRepo('alpha', { description: 'first app' });
  const dir = repoPath('alpha');
  assert.equal(r.clone_url, dir);
  assert.equal(r.default_branch, 'main');
  assert.equal(git(dir, 'symbolic-ref', 'HEAD'), 'refs/heads/main');
  assert.equal(git(dir, 'rev-parse', '--is-bare-repository'), 'true');
  const head = git(dir, 'rev-parse', 'refs/heads/main');
  assert.match(head, /^[0-9a-f]{40}$/);
  assert.equal(git(dir, 'ls-tree', '--name-only', head), 'README.md');
  assert.match(git(dir, 'show', `${head}:README.md`), /first app/);
  assert.equal(git(dir, 'log', '-1', '--format=%an <%ae>|%cn <%ce>', head),
    `${LOCAL_GIT_IDENTITY.name} <${LOCAL_GIT_IDENTITY.email}>|${LOCAL_GIT_IDENTITY.name} <${LOCAL_GIT_IDENTITY.email}>`);

  await assert.rejects(createAppRepo('alpha'), (e) => e.status === 409 && e.body?.code === 'REPO_EXISTS' && /^REPO_EXISTS/.test(e.message));
  assert.equal(git(dir, 'rev-parse', 'refs/heads/main'), head, 'a second create must not touch the existing repo');
  assert.deepEqual(readdirSync(lg.reposRoot()).filter((n) => n.startsWith('.')), [], 'no staging dir left behind');
});

test('create with autoInit:false has no branch, and push refuses it like GitHub does', async () => {
  await createAppRepo('bare-empty', { autoInit: false });
  const dir = repoPath('bare-empty');
  assert.equal(git(dir, 'for-each-ref'), '');
  await assert.rejects(pushFilesToManagedRepo('bare-empty', [{ path: 'a', content: 'x' }]),
    (e) => e.status === 404 && e.code === 'BRANCH_NOT_FOUND');
});

test('push: one commit on top of the tip, parent tree kept, blob SHAs and bytes are real', async () => {
  const dir = repoPath('alpha');
  const before = git(dir, 'rev-parse', 'refs/heads/main');
  const bin = Buffer.from([0, 1, 2, 255, 254, 10, 13, 0]);
  const res = await pushFilesToManagedRepo('alpha', [
    { path: 'src/index.js', content: 'console.log("hi")\n' },
    { path: 'assets/logo.bin', content: bin.toString('base64'), encoding: 'base64' },
  ], { message: 'feat: first push' });

  const after = git(dir, 'rev-parse', 'refs/heads/main');
  assert.equal(res.commit.sha, after, 'returned SHA must be the branch tip');
  assert.equal(await getBranchHeadSha('alpha', 'main'), after);
  assert.equal(git(dir, 'rev-parse', `${after}^`), before, 'parent must be the previous tip');
  assert.equal(git(dir, 'rev-list', '--count', `${before}..${after}`), '1', 'N files = 1 commit');
  assert.equal(git(dir, 'log', '-1', '--format=%B', after), 'feat: first push');
  assert.equal(res.branch, 'main');
  assert.deepEqual(git(dir, 'ls-tree', '-r', '--name-only', after).split('\n').sort(),
    ['README.md', 'assets/logo.bin', 'src/index.js'], 'files outside the push must survive (base_tree semantics)');

  const binEntry = res.files.find((f) => f.path === 'assets/logo.bin');
  assert.equal(binEntry.sha, blobShaOf(bin));
  assert.equal(binEntry.bytes, bin.length);
  assert.equal(binEntry.encoding, 'base64');
  assert.match(binEntry.sha256, /^[0-9a-f]{64}$/);
  assert.equal(git(dir, 'rev-parse', `${after}:assets/logo.bin`), blobShaOf(bin), 'binary bytes must land unchanged');
  execFileSync('git', [`--git-dir=${dir}`, 'fsck', '--full'], { env: CLEAN_ENV, stdio: 'pipe' });
});

test('read: content + blob SHA; missing path, branch, repo are FILE_NOT_FOUND; a dir is not a file', async () => {
  const r = await readManagedRepoFile('alpha', 'src/index.js');
  assert.equal(r.content, 'console.log("hi")\n');
  assert.equal(r.sha, blobShaOf(Buffer.from('console.log("hi")\n')));
  assert.equal(r.bytes, 18);
  for (const call of [
    () => readManagedRepoFile('alpha', 'src/nope.js'),
    () => readManagedRepoFile('alpha', 'src/index.js', { branch: 'no-such-branch' }),
    () => readManagedRepoFile('never-created', 'README.md'),
  ]) await assert.rejects(call(), (e) => e.status === 404 && /^FILE_NOT_FOUND/.test(e.message));
  await assert.rejects(readManagedRepoFile('alpha', 'src'), /is not a file/);
  // A pathspec-looking name must be read literally, not as a glob or as magic.
  // Measured: without GIT_LITERAL_PATHSPECS, ls-tree dies on ':(glob)...' with
  // "pathspec magic not supported", which would surface as a raw git error
  // instead of the FILE_NOT_FOUND 404 callers branch on.
  await assert.rejects(readManagedRepoFile('alpha', 'src/*.js'), (e) => e.status === 404);
  await assert.rejects(readManagedRepoFile('alpha', ':(glob)src/*.js'), (e) => e.status === 404 && /^FILE_NOT_FOUND/.test(e.message));
});

test('untrusted paths are refused and nothing is committed', async () => {
  const dir = repoPath('alpha');
  const tip = git(dir, 'rev-parse', 'refs/heads/main');
  for (const bad of ['../escape.txt', '/etc/passwd', 'a/../b', '.git/config', 'sub/.GIT/hooks/post-update',
    'x/.git', 'a//b', './a', 'a/', 'nul\0byte', 'back\\slash']) {
    await assert.rejects(pushFilesToManagedRepo('alpha', [{ path: 'ok.txt', content: 'x' }, { path: bad, content: 'x' }]),
      /invalid file path/, `path ${JSON.stringify(bad)} must be refused`);
    await assert.rejects(readManagedRepoFile('alpha', bad), /invalid file path/);
  }
  assert.equal(git(dir, 'rev-parse', 'refs/heads/main'), tip, 'a refused push must not move the branch');
});

test('untrusted slugs never become a path', async () => {
  for (const bad of ['../evil', 'a/b', 'UPPER', '', '.hidden', '-flag', 'x'.repeat(101)]) {
    assert.throws(() => repoPath(bad), /refusing slug/);
    await assert.rejects(createAppRepo(bad));
  }
  assert.equal(existsSync(join(ROOT, 'evil.git')), false);
  assert.equal(existsSync(resolve(ROOT, '..', 'evil.git')), false);
});

test('concurrent pushes: a push that lost the race fails, none is silently discarded', async () => {
  await createAppRepo('racer');
  const dir = repoPath('racer');
  let raced = false;
  for (let round = 0; round < 10 && !raced; round++) {
    const results = await Promise.allSettled(Array.from({ length: 6 }, (_, i) =>
      pushFilesToManagedRepo('racer', [{ path: `r${round}/f${i}.txt`, content: `${round}-${i}` }], { message: `r${round} p${i}` })));
    const tip = git(dir, 'rev-parse', 'refs/heads/main');
    const reachable = new Set(git(dir, 'rev-list', tip).split('\n'));
    for (const r of results) {
      if (r.status === 'fulfilled') {
        assert.ok(reachable.has(r.value.commit.sha),
          `push ${r.value.commit.sha} reported success but is not reachable from the branch — it was overwritten`);
      } else {
        assert.equal(r.reason.code, 'BRANCH_MOVED', r.reason.message);
        assert.equal(r.reason.status, 409);
        raced = true;
      }
    }
  }
  assert.ok(raced, 'the race never happened in 10 rounds, so compare-and-swap was not exercised');
  execFileSync('git', [`--git-dir=${dir}`, 'fsck', '--full'], { env: CLEAN_ENV, stdio: 'pipe' });
});

test("the host's hostile git config and the repo's own hooks have no effect", async () => {
  const H = mkdtempSync(join(tmpdir(), 'crane-hostile-'));
  const marker = join(H, 'PWNED');
  const hookDir = join(H, 'hooks');
  mkdirSync(hookDir);
  // Hooks exit 0 so they are only detectable by the marker; the gpg program
  // exits 1 so a commit that tried to sign would also fail outright.
  const script = `#!/bin/sh\necho "$0" >> "${marker}"\nexit 0\n`;
  for (const h of ['reference-transaction', 'post-update', 'pre-commit']) {
    writeFileSync(join(hookDir, h), script); chmodSync(join(hookDir, h), 0o755);
  }
  writeFileSync(join(H, 'evil-gpg'), `#!/bin/sh\necho "$0" >> "${marker}"\nexit 1\n`); chmodSync(join(H, 'evil-gpg'), 0o755);
  const hostile = [
    '[core]', `\thooksPath = ${hookDir}`, `\tfsmonitor = ${join(H, 'evil-gpg')}`,
    '[init]', '\tdefaultBranch = hostile',
    '[i18n]', '\tcommitEncoding = ISO-8859-1',
    '[user]', '\tname = Hostile Person', '\temail = hostile@example.com',
    '[commit]', '\tgpgSign = true',
    '[gpg]', `\tprogram = ${join(H, 'evil-gpg')}`,
  ].join('\n') + '\n';
  writeFileSync(join(H, '.gitconfig'), hostile);
  mkdirSync(join(H, 'xdg', 'git'), { recursive: true });
  writeFileSync(join(H, 'xdg', 'git', 'config'), hostile);
  writeFileSync(join(H, 'system.gitconfig'), hostile);

  const hostileEnv = {
    HOME: H, XDG_CONFIG_HOME: join(H, 'xdg'), GIT_CONFIG_SYSTEM: join(H, 'system.gitconfig'),
    GIT_CONFIG_COUNT: '2', GIT_CONFIG_KEY_0: 'core.hooksPath', GIT_CONFIG_VALUE_0: hookDir,
    GIT_CONFIG_KEY_1: 'i18n.commitEncoding', GIT_CONFIG_VALUE_1: 'ISO-8859-1',
    GIT_DIR: join(H, 'nowhere.git'), GIT_INDEX_FILE: join(H, 'hostile-index'),
    GIT_AUTHOR_NAME: 'Hostile Person', GIT_COMMITTER_EMAIL: 'hostile@example.com',
  };

  // Control: prove the fixture is real — plain git under this environment DOES
  // pick up the hostile default branch and DOES run the hook.
  const ctl = join(H, 'control.git');
  const plainEnv = { ...process.env, ...hostileEnv };
  delete plainEnv.GIT_DIR; delete plainEnv.GIT_INDEX_FILE;
  execFileSync('git', ['init', '--bare', '-q', ctl], { env: plainEnv });
  assert.equal(execFileSync('git', [`--git-dir=${ctl}`, 'symbolic-ref', 'HEAD'], { env: plainEnv }).toString().trim(),
    'refs/heads/hostile', 'control: the hostile init.defaultBranch must be visible to plain git');
  // The control ref update needs a real commit object: git rejects a ref to a
  // missing object before any hook runs. (git 2.50 also fires the hook from
  // `init`; 2.39 does not, so the marker must come from this update-ref.)
  const ctlGit = (args, input) => execFileSync('git', [`--git-dir=${ctl}`, ...args], { env: plainEnv, input }).toString().trim();
  const ctlTree = ctlGit(['mktree'], '');
  const ctlCommit = ctlGit(['commit-tree', '--no-gpg-sign', ctlTree], 'control\n');
  const ctlRef = spawnSync('git', [`--git-dir=${ctl}`, 'update-ref', 'refs/heads/x', ctlCommit], { env: plainEnv });
  assert.equal(ctlRef.status, 0, `control: update-ref failed: ${ctlRef.stderr}`);
  assert.equal(existsSync(marker), true, 'control: the hostile hook must fire for plain git, or this test proves nothing');
  assert.match(readFileSync(marker, 'utf8'), /reference-transaction/, 'control: the marker must come from the hostile hook');
  rmSync(marker);

  const saved = {};
  for (const k of Object.keys(hostileEnv)) { saved[k] = process.env[k]; process.env[k] = hostileEnv[k]; }
  try {
    const created = await createAppRepo('isolated');
    const dir = created.clone_url;
    // The repo's OWN config and hooks dir, as a hostile restore would leave them.
    mkdirSync(join(dir, 'hooks'), { recursive: true });
    for (const h of ['reference-transaction', 'post-update']) {
      writeFileSync(join(dir, 'hooks', h), script); chmodSync(join(dir, 'hooks', h), 0o755);
    }
    execFileSync('git', [`--git-dir=${dir}`, 'config', 'core.hooksPath', hookDir], { env: CLEAN_ENV });
    execFileSync('git', [`--git-dir=${dir}`, 'config', 'commit.gpgSign', 'true'], { env: CLEAN_ENV });

    const res = await pushFilesToManagedRepo('isolated', [{ path: 'a.txt', content: 'safe' }]);
    const read = await readManagedRepoFile('isolated', 'a.txt');
    assert.equal(read.content, 'safe');

    assert.equal(existsSync(marker), false, 'a hook or gpg program ran');
    assert.equal(git(dir, 'symbolic-ref', 'HEAD'), 'refs/heads/main', 'host init.defaultBranch leaked');
    assert.equal(git(dir, 'log', '-1', '--format=%an <%ae>|%cn <%ce>', res.commit.sha),
      `${LOCAL_GIT_IDENTITY.name} <${LOCAL_GIT_IDENTITY.email}>|${LOCAL_GIT_IDENTITY.name} <${LOCAL_GIT_IDENTITY.email}>`,
      'host identity leaked into the commit');
    const rawCommit = git(dir, 'cat-file', 'commit', res.commit.sha);
    assert.doesNotMatch(rawCommit, /gpgsig/, 'commit was signed');
    // Only config can add this header, and nothing overrides it explicitly — so
    // it shows whether ANY inherited or host config reached git.
    assert.doesNotMatch(rawCommit, /^encoding /m, 'host i18n.commitEncoding reached commit-tree');
    assert.equal(existsSync(join(H, 'nowhere.git')), false, 'inherited GIT_DIR was honoured');
    assert.equal(existsSync(join(H, 'hostile-index')), false, 'inherited GIT_INDEX_FILE was honoured');
  } finally {
    for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    rmSync(H, { recursive: true, force: true });
  }
});

test('a git older than 2.32 is refused before anything is written', () => {
  const fake = mkdtempSync(join(tmpdir(), 'crane-oldgit-'));
  writeFileSync(join(fake, 'git'), '#!/bin/sh\necho "git version 2.31.8"\n');
  chmodSync(join(fake, 'git'), 0o755);
  const data = mkdtempSync(join(tmpdir(), 'crane-oldgit-data-'));
  const mod = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'services', 'localGit.js');
  const r = spawnSync(process.execPath, ['--input-type=module', '-e',
    `const m = await import(${JSON.stringify(mod)}); try { await m.createAppRepo('old'); console.log('CREATED'); } catch (e) { console.log(e.code); }`],
  { env: { ...process.env, PATH: `${fake}:${process.env.PATH}`, DATA_DIR: data } });
  const out = r.stdout.toString().trim();
  try {
    assert.equal(out, 'GIT_TOO_OLD', r.stderr.toString());
    assert.equal(existsSync(join(data, 'repos', 'old.git')), false);
  } finally {
    rmSync(fake, { recursive: true, force: true }); rmSync(data, { recursive: true, force: true });
  }
});
