import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';

// The platform What's New (dialog and e-mail) shows the plain lines in
// release-notes.json, and a release cannot ship without them.

const here = dirname(fileURLToPath(import.meta.url));
const {
  parseCurated, mergeCuratedNotes, curatedEntryProblem, getVersionNotes, CURATED_FILE,
} = await import('../server/services/releaseNotes.js');

const pkgVersion = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')).version;
const shipped = parseCurated(readFileSync(join(here, '..', CURATED_FILE), 'utf8'));

test("package.json's version has friendly release notes", () => {
  const problem = curatedEntryProblem(pkgVersion, shipped);
  assert.equal(problem, null, problem);
});

test('every curated entry is 1-4 plain lines', () => {
  for (const version of Object.keys(shipped)) {
    const problem = curatedEntryProblem(version, shipped);
    assert.equal(problem, null, problem);
  }
});

test('a version with no curated entry fails, and the message says exactly what to add', () => {
  const problem = curatedEntryProblem('9.9.9', shipped);
  assert.ok(problem, 'an uncurated version must be refused');
  assert.match(problem, /package\.json is at 9\.9\.9/);
  assert.match(problem, /release-notes\.json/);
  assert.match(problem, /"9\.9\.9": \[/);
  assert.match(curatedEntryProblem('1.0.0', { '1.0.0': ['fixed a TOCTOU race'] }), /reads like a changelog/);
  assert.match(curatedEntryProblem('1.0.0', { '1.0.0': ['a', 'b', 'c', 'd', 'e'] }), /4 or fewer/);
});

test('curated lines win over the commit subject; a missing version falls back to its subject', () => {
  const subjects = [
    { version: '1.0.2', commit_message: 'security review pass 2 — helper container', commit_hash: 'b' },
    { version: '1.0.1', commit_message: 'plain subject', commit_hash: 'a' },
  ];
  const merged = mergeCuratedNotes(subjects, { '1.0.2': ['You can do X now.', 'Y is faster.'], '1.0.3': ['Not committed yet.'] });
  assert.deepEqual(merged.map((n) => n.version), ['1.0.3', '1.0.2', '1.0.1']);
  assert.deepEqual(merged[1].lines, ['You can do X now.', 'Y is faster.']);
  assert.equal(merged[1].commit_message, '• You can do X now.\n• Y is faster.');
  assert.equal(merged[1].commit_hash, 'b');
  assert.equal(merged[2].commit_message, 'plain subject');
  assert.equal(merged[2].lines, undefined);
  assert.equal(merged[0].commit_message, 'Not committed yet.');
});

test('malformed curated files and entries are ignored, not thrown', () => {
  assert.deepEqual(parseCurated('{not json'), {});
  assert.deepEqual(parseCurated('[]'), {});
  assert.deepEqual(parseCurated(JSON.stringify({ 'v1': ['x'], '1.0.0': 'x', '1.0.1': ['', '  '], '1.0.2': [' ok ', 3] })), { '1.0.2': ['ok'] });
});

const git = (cwd, ...args) => execFileSync('git', args, {
  cwd, stdio: 'pipe',
  env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.test', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.test' },
}).toString();

test('getVersionNotes: the checkout\'s curated file, origin/main\'s for releases not installed yet, else subjects', async () => {
  const root = mkdtempSync(join(tmpdir(), 'crane-curated-'));
  const upstream = join(root, 'upstream');
  const origin = join(root, 'origin.git');
  const install = join(root, 'install');
  git(root, 'init', '-q', '-b', 'main', upstream);
  const commit = (subject, curated) => {
    writeFileSync(join(upstream, 'f.txt'), subject);
    if (curated) writeFileSync(join(upstream, CURATED_FILE), JSON.stringify(curated));
    git(upstream, 'add', '-A');
    git(upstream, 'commit', '-q', '-m', subject);
  };
  commit('v1.0.0: first release — internal jargon');
  commit('v1.0.1: second release', { '1.0.1': ['Friendly one.'] });
  git(root, 'clone', '-q', '--bare', upstream, origin);
  git(root, 'clone', '-q', origin, install);
  git(upstream, 'remote', 'add', 'origin', origin);
  commit('v1.0.2: third release, not installed', { '1.0.1': ['Friendly one.'], '1.0.2': ['Friendly two.'] });
  git(upstream, 'push', '-q', 'origin', 'main');

  const notes = await getVersionNotes({ repoDir: install });
  const by = Object.fromEntries(notes.map((n) => [n.version, n.commit_message]));
  assert.deepEqual(Object.keys(by), ['1.0.2', '1.0.1', '1.0.0']);
  assert.equal(by['1.0.2'], 'Friendly two.', 'origin/main\'s curated notes cover a release the install has not pulled');
  assert.equal(by['1.0.1'], 'Friendly one.');
  assert.equal(by['1.0.0'], 'first release — internal jargon', 'no curated entry: the commit subject is the fallback');
});

test('getVersionNotes works without git: curated notes alone', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'crane-curated-nogit-'));
  writeFileSync(join(dir, CURATED_FILE), JSON.stringify({ '2.0.0': ['Only from the file.'] }));
  const notes = await getVersionNotes({ repoDir: dir, fetchImpl: async () => ({ ok: false }) });
  assert.deepEqual(notes.map((n) => [n.version, n.commit_message]), [['2.0.0', 'Only from the file.']]);
});
