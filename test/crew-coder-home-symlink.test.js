import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, readdirSync, symlinkSync, lstatSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// SECURITY FIX (review of v2.131.0): the per-task Claude home is mounted
// read-write into the Crew turn container, so whatever a turn leaves there
// (symlinks included) is in place when AppCrane, as root on the host, prepares
// the home for the next turn. Pinned here: a planted `projects` symlink, a
// dangling `<sid>.jsonl` symlink, or a symlinked legacy transcript never makes
// prepare write (or read) outside the home; the one-time legacy copy happens
// only into a home this call created; stale mount-point removal, ownership
// and home removal do not follow symlinks.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-coder-home-link-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const home = await import('../server/services/crewCoderHome.js');
const { transcriptDirFor } = await import('../server/services/builder/appContainer.js');

const legacyDir = join(transcriptDirFor('shop'), '-workspace');
mkdirSync(legacyDir, { recursive: true });
writeFileSync(join(legacyDir, 'sid1.jsonl'), 'legacy conversation');

function outsideDir() {
  return mkdtempSync(join(tmpdir(), 'crane-crew-outside-'));
}

test('a planted `projects` symlink in an existing home: nothing is written outside', () => {
  const dir = home.prepareCrewTaskHome('link1', { slug: 'shop' });
  const outside = outsideDir();
  symlinkSync(outside, join(dir, 'projects'));
  home.prepareCrewTaskHome('link1', { slug: 'shop', resumeId: 'sid1' });
  assert.deepEqual(readdirSync(outside), [], 'nothing created through the symlink');
});

test('a planted `-workspace` symlink in an existing home: nothing is written outside', () => {
  const dir = home.prepareCrewTaskHome('link2', { slug: 'shop' });
  const outside = outsideDir();
  mkdirSync(join(dir, 'projects'));
  symlinkSync(outside, join(dir, 'projects', '-workspace'));
  home.prepareCrewTaskHome('link2', { slug: 'shop', resumeId: 'sid1' });
  assert.deepEqual(readdirSync(outside), []);
});

test('a dangling `<sid>.jsonl` symlink in an existing home: its target is never created', () => {
  const dir = home.prepareCrewTaskHome('link3', { slug: 'shop' });
  const outside = outsideDir();
  const target = join(outside, 'written-as-root');
  mkdirSync(join(dir, 'projects', '-workspace'), { recursive: true });
  symlinkSync(target, join(dir, 'projects', '-workspace', 'sid1.jsonl'));
  home.prepareCrewTaskHome('link3', { slug: 'shop', resumeId: 'sid1' });
  assert.ok(!existsSync(target), 'the symlink target was not created');
  assert.deepEqual(readdirSync(outside), []);
});

test('a fresh home still gets the one-time legacy copy, as a regular file', () => {
  const dir = home.prepareCrewTaskHome('fresh1', { slug: 'shop', resumeId: 'sid1' });
  const copied = join(dir, 'projects', '-workspace', 'sid1.jsonl');
  assert.equal(readFileSync(copied, 'utf8'), 'legacy conversation');
  assert.ok(lstatSync(copied).isFile());
});

test('the legacy copy is never made into a home that already existed', () => {
  const dir = home.prepareCrewTaskHome('old1', { slug: 'shop' });
  home.prepareCrewTaskHome('old1', { slug: 'shop', resumeId: 'sid1' });
  assert.ok(!existsSync(join(dir, 'projects')));
});

test('a legacy transcript that is a symlink is not copied (no read of host files)', () => {
  const outside = outsideDir();
  writeFileSync(join(outside, 'host-secret'), 'host secret');
  symlinkSync(join(outside, 'host-secret'), join(legacyDir, 'sid2.jsonl'));
  const dir = home.prepareCrewTaskHome('fresh2', { slug: 'shop', resumeId: 'sid2' });
  assert.ok(!existsSync(join(dir, 'projects', '-workspace', 'sid2.jsonl')));
});

test('stale mount points that are symlinks are removed without touching their targets', () => {
  const dir = home.prepareCrewTaskHome('link4', { slug: 'shop' });
  const outside = outsideDir();
  writeFileSync(join(outside, 'keep'), 'keep');
  symlinkSync(outside, join(dir, 'skills'));
  symlinkSync(join(outside, 'keep'), join(dir, 'credentials.json'));
  home.prepareCrewTaskHome('link4', { slug: 'shop' });
  assert.ok(!existsSync(join(dir, 'skills')) && !existsSync(join(dir, 'credentials.json')));
  assert.equal(readFileSync(join(outside, 'keep'), 'utf8'), 'keep');
});

test('ownership is set without following symlinks (chown -h)', () => {
  const shim = mkdtempSync(join(tmpdir(), 'crane-chown-shim-'));
  const log = join(shim, 'argv');
  writeFileSync(join(shim, 'chown'), `#!/bin/sh\nprintf '%s\\n' "$@" > '${log}'\n`, { mode: 0o755 });
  const path = process.env.PATH;
  process.env.PATH = `${shim}:${path}`;
  try {
    home.prepareCrewTaskHome('own1', { slug: 'shop' });
  } finally {
    process.env.PATH = path;
  }
  const argv = readFileSync(log, 'utf8').trim().split('\n');
  assert.ok(argv.includes('-R') && argv.includes('-h'), `chown argv: ${argv.join(' ')}`);
});

test('removing a home does not follow a symlink inside it', () => {
  const dir = home.prepareCrewTaskHome('link5', { slug: 'shop' });
  const outside = outsideDir();
  writeFileSync(join(outside, 'keep'), 'keep');
  symlinkSync(outside, join(dir, 'projects'));
  assert.equal(home.removeCrewTaskHome('link5'), true);
  assert.equal(readFileSync(join(outside, 'keep'), 'utf8'), 'keep');
});

test('the legacy file actually opened must be the one under the transcript mount, not one reached through a swapped parent', async () => {
  const { openedInside } = await import('../server/services/crewCoderHome.js');
  const { openSync, closeSync, rmSync } = await import('fs');
  const root = mkdtempSync(join(tmpdir(), 'crane-crew-root-'));
  const outside = mkdtempSync(join(tmpdir(), 'crane-crew-outside-'));
  mkdirSync(join(root, '-workspace'));
  writeFileSync(join(root, '-workspace', 'sid1.jsonl'), 'real');
  writeFileSync(join(outside, 'sid1.jsonl'), 'secret');
  const expected = join('-workspace', 'sid1.jsonl');

  let fd = openSync(join(root, '-workspace', 'sid1.jsonl'), 'r');
  assert.equal(openedInside(fd, join(root, '-workspace', 'sid1.jsonl'), root, expected), true);
  closeSync(fd);

  // The parent is swapped for a symlink after the checks: the open lands outside.
  rmSync(join(root, '-workspace'), { recursive: true });
  symlinkSync(outside, join(root, '-workspace'));
  fd = openSync(join(root, '-workspace', 'sid1.jsonl'), 'r');
  assert.equal(openedInside(fd, join(root, '-workspace', 'sid1.jsonl'), root, expected), false);
  closeSync(fd);
});
