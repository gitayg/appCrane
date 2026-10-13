import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { WORKSPACE_DOCKER_PRELUDE } from './fixtures/workspaceDockerShim.js';

/**
 * builder/workspaceReader.js: file bytes leave an agent-writable workspace
 * through a fixed program run INSIDE the container, never through a host
 * readFileSync. Here docker is the workspace shim, which runs that program on
 * the host in the workspace directory — so a reader that FOLLOWED a symlink
 * would really read the host file below, and the marker would show. That is
 * what makes the symlink cases meaningful without Docker;
 * test/workspace-runner-live.test.js repeats them against a real container,
 * with a loop racing the swap.
 */

const ROOT = mkdtempSync(join(tmpdir(), 'crane-wsreader-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const BIN = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker.log');
mkdirSync(BIN, { recursive: true });
writeFileSync(DOCKER_LOG, '');
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
echo "$1" >> "${DOCKER_LOG}"
${WORKSPACE_DOCKER_PRELUDE}
echo "docker shim: refusing '$1'" >&2
exit 1
`, { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const reader = await import('../server/services/builder/workspaceReader.js');
const { readWorkspaceFilesForRelease, MAX_RELEASE_FILE_BYTES } = await import('../server/services/builder/gitOps.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const dockerCalls = () => readFileSync(DOCKER_LOG, 'utf8').split('\n').filter(Boolean);
const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const git = (ws, ...a) => execFileSync('git', ['-C', ws, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=t', '-c', 'user.email=t@example.com', ...a], { env: CLEAN, stdio: 'pipe' });

// A host file the workspace must never be able to release: outside the
// workspace, in a directory no container mounts.
const HOST_ONLY = join(ROOT, 'host-only');
mkdirSync(HOST_ONLY, { recursive: true });
const MARKER = 'HOST-ONLY-MARKER-7f3a';
writeFileSync(join(HOST_ONLY, 'secret.env'), `ENCRYPTION_KEY=${MARKER}\n`);

function workspace(name) {
  const ws = join(ROOT, name);
  mkdirSync(ws, { recursive: true });
  execFileSync('git', ['init', '-q', '-b', 'main', ws], { env: CLEAN });
  return ws;
}

test('a release is read in ONE container round trip, whatever the file count, with bytes intact', () => {
  const ws = workspace('ws-batch');
  const paths = [];
  for (let i = 0; i < 25; i++) { writeFileSync(join(ws, `f${i}.txt`), `file ${i}\n`); paths.push(`f${i}.txt`); }
  mkdirSync(join(ws, 'img'));
  const bin = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe, 0x0a, 0x0a]);
  writeFileSync(join(ws, 'img', 'a.png'), bin);
  paths.push('img/a.png');
  writeFileSync(DOCKER_LOG, '');
  const files = readWorkspaceFilesForRelease(ws, paths);
  assert.deepEqual(dockerCalls(), ['run'], 'expected exactly one helper run for the whole release');
  assert.equal(files.length, 26);
  assert.deepEqual(files[3], { path: 'f3.txt', content: 'file 3\n', encoding: 'utf-8' });
  assert.equal(files[25].encoding, 'base64');
  assert.deepEqual(Buffer.from(files[25].content, 'base64'), bin);
});

test('a symlink is reported as a symlink — its target string — never followed', () => {
  const ws = workspace('ws-link');
  symlinkSync(join(HOST_ONLY, 'secret.env'), join(ws, 'secret-link'));
  writeFileSync(join(ws, 'ok.txt'), 'ok\n');
  const recs = reader.readWorkspaceFiles(ws, ['secret-link', 'ok.txt'], { maxFileBytes: 1024, maxBatchBytes: 4096 });
  assert.deepEqual(recs.get('secret-link'), { kind: 'L', size: Buffer.byteLength(join(HOST_ONLY, 'secret.env')), target: join(HOST_ONLY, 'secret.env') });
  assert.equal(recs.get('ok.txt').body.toString(), 'ok\n');
  // The release refuses it, by name, as a symlink — and the host bytes are nowhere.
  let err = null;
  try { readWorkspaceFilesForRelease(ws, ['ok.txt', 'secret-link']); } catch (e) { err = e; }
  assert.ok(err, 'a symlink was released');
  assert.match(err.message, /'secret-link' is a symlink/);
  assert.ok(!err.message.includes(MARKER));
});

test('a parent directory that is a symlink does not lead the reader out of the workspace', () => {
  const ws = workspace('ws-parent');
  symlinkSync(HOST_ONLY, join(ws, 'conf'));
  const recs = reader.readWorkspaceFiles(ws, ['conf/secret.env'], { maxFileBytes: 1024, maxBatchBytes: 4096 });
  assert.equal(recs.get('conf/secret.env').kind, 'O');
  assert.equal(recs.get('conf/secret.env').body, null);
  assert.throws(() => readWorkspaceFilesForRelease(ws, ['conf/secret.env']), (e) => /not a regular file/.test(e.message) && !e.message.includes(MARKER));
});

test('paths are validated before anything runs: no absolute, no .., no empty or . component, no NUL', () => {
  const ws = workspace('ws-paths');
  writeFileSync(DOCKER_LOG, '');
  for (const bad of ['/etc/passwd', '../host-only/secret.env', 'a/../../x', 'a/./b', 'a//b', 'a/', '', 'a\0b', '.']) {
    assert.throws(() => reader.readWorkspaceFiles(ws, [bad], { maxFileBytes: 10, maxBatchBytes: 10 }), /workspace path/, JSON.stringify(bad));
  }
  assert.throws(() => reader.readWorkspaceFiles(ws, ['a', 'a'], { maxFileBytes: 10, maxBatchBytes: 10 }), /duplicate/);
  assert.throws(() => reader.readWorkspaceFiles(ws, ['a'], { source: 'commit', commit: '--output=/tmp/x', maxFileBytes: 10, maxBatchBytes: 10 }), /refusing to read at commit/);
  assert.deepEqual(dockerCalls(), [], 'a bad path reached docker');
});

test('size caps: per file (not read into the release), per batch, and the host re-checks the container', () => {
  const ws = workspace('ws-caps');
  writeFileSync(join(ws, 'big.bin'), Buffer.alloc(MAX_RELEASE_FILE_BYTES + 1, 7));
  assert.throws(() => readWorkspaceFilesForRelease(ws, ['big.bin']), new RegExp(`is ${MAX_RELEASE_FILE_BYTES + 1} bytes, over the ${MAX_RELEASE_FILE_BYTES}-byte limit`));

  writeFileSync(join(ws, 'a'), 'x'.repeat(60));
  writeFileSync(join(ws, 'b'), 'y'.repeat(60));
  const recs = reader.readWorkspaceFiles(ws, ['a', 'b'], { maxFileBytes: 100, maxBatchBytes: 100 });
  assert.equal(recs.get('a').kind, 'F');
  assert.equal(recs.get('b').kind, 'T', 'the batch budget was not enforced in the container');
  assert.equal(reader.readWorkspaceFiles(ws, ['a'], { maxFileBytes: 50, maxBatchBytes: 1000 }).get('a').kind, 'B');
  const t = reader.readWorkspaceFiles(ws, ['a'], { maxFileBytes: 50, maxBatchBytes: 1000, truncate: true }).get('a');
  assert.equal(t.kind, 'P');
  assert.equal(t.body.length, 50);

  // The container's output is not trusted: an over-cap record, a short body
  // or trailing bytes are refused by the host parser.
  assert.throws(() => reader.parseReaderOutput(Buffer.from('F 11\nhello world'), ['a'], { maxFileBytes: 10 }), /over the 10-byte cap/);
  assert.throws(() => reader.parseReaderOutput(Buffer.from('F 5\nhel'), ['a'], { maxFileBytes: 10 }), /truncated/);
  assert.throws(() => reader.parseReaderOutput(Buffer.from('F 1\nhM 0\n'), ['a'], { maxFileBytes: 10 }), /trailing/);
  assert.throws(() => reader.parseReaderOutput(Buffer.from('X 1\nh'), ['a'], { maxFileBytes: 10 }), /malformed/);
});

test('commit mode reads git objects at the commit, not the working tree; a 120000 entry is a symlink', () => {
  const ws = workspace('ws-commit');
  writeFileSync(join(ws, 'README.md'), 'committed\n');
  symlinkSync(join(HOST_ONLY, 'secret.env'), join(ws, 'link.md'));
  git(ws, 'add', '-A');
  git(ws, 'commit', '-q', '-m', 'i');
  const head = git(ws, 'rev-parse', 'HEAD').toString().trim();
  writeFileSync(join(ws, 'README.md'), 'working tree edit\n');
  const recs = reader.readWorkspaceFiles(ws, ['README.md', 'link.md', 'nope.md'], {
    source: 'commit', commit: head, maxFileBytes: 1024, maxBatchBytes: 4096, truncate: true,
  });
  assert.equal(recs.get('README.md').body.toString(), 'committed\n');
  assert.equal(recs.get('link.md').kind, 'L');
  assert.equal(recs.get('link.md').target, join(HOST_ONLY, 'secret.env'));
  assert.equal(recs.get('nope.md').kind, 'M');
});
