import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// The platform What's New reads release notes from the install's own git
// checkout (v2.93.5). Before, it preferred CHANGELOG.md, which stopped at
// 2.78.1, so the upgrade preview for any newer release had no notes at all.

const { gitVersionNotes, parseVersionSubjects } = await import('../server/services/releaseNotes.js');

const git = (cwd, ...args) => execFileSync('git', args, {
  cwd, stdio: 'pipe',
  env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.test', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.test' },
}).toString();

function commit(dir, subject) {
  writeFileSync(join(dir, 'f.txt'), subject);
  git(dir, 'add', 'f.txt');
  git(dir, 'commit', '-q', '-m', subject);
}

/** An upstream with releases, and an install cloned before the newest ones. */
function setup() {
  const root = mkdtempSync(join(tmpdir(), 'crane-notes-'));
  const upstream = join(root, 'upstream');
  const origin = join(root, 'origin.git');
  const install = join(root, 'install');
  git(root, 'init', '-q', '-b', 'main', upstream);
  commit(upstream, 'v1.0.0: first release');
  commit(upstream, 'chore: not a release');
  git(root, 'clone', '-q', '--bare', upstream, origin);
  git(root, 'clone', '-q', origin, install);
  git(upstream, 'remote', 'add', 'origin', origin);
  // Released after this install last updated; it only learns of them by fetching.
  for (let i = 1; i <= 60; i++) commit(upstream, `v1.0.${i}: release ${i}`);
  git(upstream, 'push', '-q', 'origin', 'main');
  return { install };
}

test('notes include releases pushed after the install last fetched', async () => {
  const { install } = setup();
  const notes = await gitVersionNotes({ repoDir: install });
  const versions = notes.map(n => n.version);
  assert.ok(versions.includes('1.0.60'), 'the newest release is missing: origin was not fetched');
  assert.equal(notes[0].version, '1.0.60');
  assert.equal(notes[0].commit_message, 'release 60');
});

test('every release is listed, not only the latest 50 commits', async () => {
  const { install } = setup();
  const versions = (await gitVersionNotes({ repoDir: install })).map(n => n.version);
  assert.equal(versions.length, 61);
  assert.ok(versions.includes('1.0.0') && versions.includes('1.0.5'));
});

test('a directory that is not a git checkout gives no notes rather than throwing', async () => {
  assert.deepEqual(await gitVersionNotes({ repoDir: mkdtempSync(join(tmpdir(), 'crane-nogit-')) }), []);
});

test('only "vX.Y.Z: ..." subjects count, and the newest per version wins', () => {
  const notes = parseVersionSubjects([
    'a\x1f2026-09-29T00:00:00Z\x1fv2.0.1: second fix',
    'b\x1f2026-09-28T00:00:00Z\x1fdocs: not a release',
    'c\x1f2026-09-27T00:00:00Z\x1fv2.0.1: older duplicate',
    '',
  ]);
  assert.deepEqual(notes.map(n => [n.version, n.commit_message, n.commit_hash]), [['2.0.1', 'second fix', 'a']]);
});
