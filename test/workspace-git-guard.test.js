import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync, symlinkSync, renameSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * A coder workspace is chmod 777'd and mounted into the agent's container, so
 * the agent can rewrite its .git/. The HOST runs git there (the change list,
 * the release bookkeeping commit, the eviction rescue commit), and with only
 * `safe.directory` set, git honours whatever the agent planted: core.fsmonitor
 * on status, filter drivers on add, hooks on commit, include.path, a .git that
 * points at another repo. Each case below plants one with real git and proves
 * the host refuses, and — for the ones that would execute — that the planted
 * command never ran.
 */

const ROOT = mkdtempSync(join(tmpdir(), 'crane-wsguard-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { assertSafeWorkspaceGit } = await import('../server/services/builder/workspaceGitGuard.js');
const { gitIn } = await import('../server/services/builder/appContainer.js');
const { listWorkspaceChanges, markReleasedInWorkspace } = await import('../server/services/builder/gitOps.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

let n = 0;
/** A fresh repo with one commit, configured only with keys AppCrane itself writes. */
function makeRepo() {
  const dir = join(ROOT, `ws${++n}`);
  mkdirSync(dir, { recursive: true });
  execFileSync('git', ['init', '-q', '-b', 'main', dir]);
  execFileSync('git', ['-C', dir, 'config', 'user.email', 'builder@appcrane.local']);
  execFileSync('git', ['-C', dir, 'config', 'user.name', 'AppCrane Builder']);
  writeFileSync(join(dir, 'a.txt'), 'one\n');
  execFileSync('git', ['-C', dir, 'add', 'a.txt']);
  execFileSync('git', ['-C', dir, '-c', 'core.hooksPath=/dev/null', 'commit', '-q', '-m', 'init']);
  return dir;
}

/** A script that, if anything runs it, leaves `marker` behind. */
function markerScript(name) {
  const marker = join(ROOT, `${name}.ran`);
  const script = join(ROOT, `${name}.sh`);
  writeFileSync(script, `#!/bin/sh\necho ran > '${marker}'\ncat\n`, { mode: 0o755 });
  return { marker, script };
}

/**
 * Runs fn, and checks the marker BEFORE checking that fn refused, so a missing
 * guard shows up as "the command ran on the host", not just "no exception".
 */
function refusedWithoutRunning(fn, marker, pattern, what) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  assert.equal(existsSync(marker), false, `${what} ran on the host`);
  assert.ok(err, `${what}: host git was not refused`);
  assert.match(err.message, pattern);
}

test('(a) a clean workspace passes and the host git wrappers work', () => {
  const dir = makeRepo();
  assert.doesNotThrow(() => assertSafeWorkspaceGit(dir));
  writeFileSync(join(dir, 'a.txt'), 'two\n');
  assert.match(gitIn(dir, ['status', '--porcelain=v1']), /a\.txt/);
  const changes = listWorkspaceChanges(dir);
  assert.deepEqual(changes.map((c) => [c.path, c.status]), [['a.txt', 'modified']]);
  assert.match(changes[0].diff, /\+two/);
  assert.equal(markReleasedInWorkspace(dir, ['a.txt'], 'release'), true);
  assert.deepEqual(listWorkspaceChanges(dir), []);
});

test('premise: unguarded host git DOES run a planted core.fsmonitor', () => {
  const dir = makeRepo();
  const { marker, script } = markerScript('premise');
  execFileSync('git', ['-C', dir, 'config', 'core.fsmonitor', script]);
  try { execFileSync('git', ['-c', `safe.directory=${dir}`, '-C', dir, 'status'], { stdio: 'pipe' }); } catch (_) {}
  assert.ok(existsSync(marker), 'the attack premise no longer holds on this git: fsmonitor did not run');
});

test('(b) core.fsmonitor is refused and never runs', () => {
  const dir = makeRepo();
  const { marker, script } = markerScript('fsmonitor');
  execFileSync('git', ['-C', dir, 'config', 'core.fsmonitor', script]);
  assert.throws(() => assertSafeWorkspaceGit(dir), /core\.fsmonitor.*could make the host run a command/);
  refusedWithoutRunning(() => gitIn(dir, ['status']), marker, /core\.fsmonitor/, 'the planted fsmonitor (gitIn)');
  refusedWithoutRunning(() => listWorkspaceChanges(dir), marker, /core\.fsmonitor/, 'the planted fsmonitor (workspaceGit)');
});

test('(c) a filter driver + .gitattributes is refused and never runs', () => {
  const dir = makeRepo();
  const { marker, script } = markerScript('filter');
  execFileSync('git', ['-C', dir, 'config', 'filter.evil.clean', script]);
  writeFileSync(join(dir, '.gitattributes'), '* filter=evil\n');
  writeFileSync(join(dir, 'b.txt'), 'x\n');
  assert.throws(() => assertSafeWorkspaceGit(dir), /filter\.evil\.clean/);
  refusedWithoutRunning(() => gitIn(dir, ['add', '-A']), marker, /filter\.evil\.clean/, 'the planted clean filter (gitIn)');
  assert.equal(markReleasedInWorkspace(dir, ['b.txt'], 'release'), false);
  assert.equal(existsSync(marker), false, 'the planted clean filter (workspaceGit) ran on the host');
});

test('(d) .git as a symlink to another repo is refused', () => {
  const other = makeRepo();
  const dir = join(ROOT, `ws${++n}`);
  mkdirSync(dir);
  symlinkSync(join(other, '.git'), join(dir, '.git'));
  assert.throws(() => assertSafeWorkspaceGit(dir), /\.git is a symlink/);
  assert.throws(() => gitIn(dir, ['status']), /\.git is a symlink/);
});

test('(d) .git as a gitdir: file is refused', () => {
  const other = makeRepo();
  const dir = join(ROOT, `ws${++n}`);
  mkdirSync(dir);
  writeFileSync(join(dir, '.git'), `gitdir: ${join(other, '.git')}\n`);
  assert.throws(() => assertSafeWorkspaceGit(dir), /\.git is not a directory/);
  assert.throws(() => listWorkspaceChanges(dir), /\.git is not a directory/);
});

test('(e) include.path is refused', () => {
  const dir = makeRepo();
  const { marker, script } = markerScript('include');
  const inc = join(ROOT, 'included.cfg');
  writeFileSync(inc, `[core]\n\tfsmonitor = ${script}\n`);
  execFileSync('git', ['-C', dir, 'config', 'include.path', inc]);
  assert.throws(() => assertSafeWorkspaceGit(dir), /include\.path/);
  refusedWithoutRunning(() => gitIn(dir, ['status']), marker, /include\.path/, 'the included fsmonitor');
});

test('.git/commondir pointing at a repo with a planted config is refused', () => {
  const dir = makeRepo();
  const { marker, script } = markerScript('commondir');
  const evil = join(ROOT, 'evil-common.git');
  execFileSync('git', ['init', '-q', '--bare', evil]);
  execFileSync('git', ['--git-dir', evil, 'config', 'core.fsmonitor', script]);
  writeFileSync(join(dir, '.git', 'commondir'), `${evil}\n`);
  refusedWithoutRunning(() => gitIn(dir, ['status']), marker, /\.git\/commondir exists/, 'the commondir fsmonitor');
});

test('(f) a hook in .git/hooks is not run by a host commit', () => {
  const dir = makeRepo();
  const { marker } = markerScript('hook');
  mkdirSync(join(dir, '.git', 'hooks'), { recursive: true });
  for (const h of ['pre-commit', 'commit-msg', 'post-commit']) {
    writeFileSync(join(dir, '.git', 'hooks', h), `#!/bin/sh\necho ran > '${marker}'\n`, { mode: 0o755 });
  }
  writeFileSync(join(dir, 'c.txt'), 'c\n');
  assert.equal(markReleasedInWorkspace(dir, ['c.txt'], 'release'), true);
  gitIn(dir, ['commit', '--allow-empty', '-q', '-m', 'empty']);
  assert.equal(existsSync(marker), false, 'a .git/hooks script ran on the host');
  // Sanity: the hook IS runnable, so its silence above is the override, not a broken script.
  execFileSync('git', ['-C', dir, 'commit', '--allow-empty', '-q', '-m', 'unguarded']);
  assert.ok(existsSync(marker), 'the hook would not have run anyway; this case proves nothing');
  renameSync(marker, `${marker}.seen`);
});
