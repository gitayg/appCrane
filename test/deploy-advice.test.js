import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, symlinkSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Rule engine only (server/services/deployAdvice.js): no DB, no handlers.

const A = await import('../server/services/deployAdvice.js');
const MIN = 60 * 1000;
const NOW = Date.parse('2026-11-02T12:00:00Z');
const sqlite = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');

beforeEach(() => A._resetDeployAdvice());

// --- R1 single-file-pushes -------------------------------------------------

test('R1: three 1-file pushes inside 10 minutes fire, naming counts and window', () => {
  A.recordPush('app1', { files: 1, at: NOW - 9 * MIN, commit: 'a'.repeat(40) });
  A.recordPush('app1', { files: 2, at: NOW - 5 * MIN, commit: 'b'.repeat(40) });
  A.recordPush('app1', { files: 1, at: NOW - 1 * MIN, commit: 'c'.repeat(40) });
  const it = A.singleFilePushAdvice('app1', { now: NOW });
  assert.equal(it.rule, 'single-file-pushes');
  assert.equal(it.severity, 'warn');
  assert.match(it.message, /3 pushes/);
  assert.match(it.message, /10 minutes/);
  assert.match(it.fix, /ONE appcrane_push_to_managed_app call/);
  assert.match(it.fix, /200 files/);
  assert.match(it.fix, /No API key is needed/);
  assert.deepEqual(it.evidence.files_per_push, [1, 2, 1]);
  assert.deepEqual(Object.keys(it).sort(), ['evidence', 'fix', 'message', 'rule', 'severity']);
});

test('R1: two small pushes do not fire', () => {
  A.recordPush('app1', { files: 1, at: NOW - 2 * MIN });
  A.recordPush('app1', { files: 1, at: NOW - 1 * MIN });
  assert.equal(A.singleFilePushAdvice('app1', { now: NOW }), null);
});

test('R1: a 3-file push is not small and does not count', () => {
  A.recordPush('app1', { files: 1, at: NOW - 3 * MIN });
  A.recordPush('app1', { files: 3, at: NOW - 2 * MIN });
  A.recordPush('app1', { files: 1, at: NOW - 1 * MIN });
  assert.equal(A.singleFilePushAdvice('app1', { now: NOW }), null);
});

test('R1 window edge: exactly 10 minutes old counts, 10 minutes + 1 ms does not', () => {
  A.recordPush('app1', { files: 1, at: NOW - 10 * MIN });
  A.recordPush('app1', { files: 1, at: NOW - 2 * MIN });
  A.recordPush('app1', { files: 1, at: NOW - 1 * MIN });
  assert.ok(A.singleFilePushAdvice('app1', { now: NOW }));
  assert.equal(A.singleFilePushAdvice('app1', { now: NOW + 1 }), null);
});

test('R1: pushes to a different app do not count', () => {
  A.recordPush('app1', { files: 1, at: NOW - 3 * MIN });
  A.recordPush('app2', { files: 1, at: NOW - 2 * MIN });
  A.recordPush('app1', { files: 1, at: NOW - 1 * MIN });
  assert.equal(A.singleFilePushAdvice('app1', { now: NOW }), null);
});

test('R1: the ring is capped', () => {
  for (let i = 0; i < 200; i++) A.recordPush('app1', { files: 1, at: NOW - i });
  assert.equal(A.recentPushes('app1').length, 50);
});

// --- R2 half-pushed-build --------------------------------------------------

const failedDep = (over = {}) => ({
  id: 7, status: 'failed', started_at: sqlite(NOW), commit_hash: 'aaaaaaaa',
  log: 'step 4\nerror during build:\nRollupError: "helper" is not exported by "src/util.js"\n', ...over,
});

test('R2: failed build with an unresolved export and another push inside the window fires', () => {
  const it = A.halfPushedBuildAdvice('app1', failedDep(), [{ at: NOW + 3 * MIN, commit: 'b'.repeat(40) }]);
  assert.equal(it.rule, 'half-pushed-build');
  assert.equal(it.severity, 'warn');
  assert.match(it.fix, /partly pushed change/);
  assert.equal(it.evidence.deployment_id, 7);
  assert.match(it.evidence.log_line, /is not exported by/);
});

test('R2: each import pattern is recognised', () => {
  for (const line of [
    '[MISSING_EXPORT] x',
    'SyntaxError: The requested module ./a.js does not provide an export named b',
    'Could not resolve "./b" from "src/a.ts"',
    "Error: Cannot find module './c'",
    "Module not found: Error: Can't resolve './d'",
  ]) {
    assert.ok(A.halfPushedBuildAdvice('app1', failedDep({ log: line }), [{ at: NOW, commit: 'cccccccc' }]), line);
  }
});

test('R2 negatives: live deploy, unrelated failure, no other push, only its own commit', () => {
  const other = [{ at: NOW + MIN, commit: 'bbbbbbbb' }];
  assert.equal(A.halfPushedBuildAdvice('app1', failedDep({ status: 'live' }), other), null);
  assert.equal(A.halfPushedBuildAdvice('app1', failedDep({ log: 'npm ERR! ENOSPC no space left' }), other), null);
  assert.equal(A.halfPushedBuildAdvice('app1', failedDep(), []), null);
  assert.equal(A.halfPushedBuildAdvice('app1', failedDep(), [{ at: NOW, commit: 'a'.repeat(40) }]), null,
    'the push that started this deployment is not "another push"');
});

test('R2 window edge: a push 10 minutes from the start counts, 10 minutes + 1 ms does not', () => {
  assert.ok(A.halfPushedBuildAdvice('app1', failedDep(), [{ at: NOW - 10 * MIN, commit: 'bbbbbbbb' }]));
  assert.ok(A.halfPushedBuildAdvice('app1', failedDep(), [{ at: NOW + 10 * MIN, commit: 'bbbbbbbb' }]));
  assert.equal(A.halfPushedBuildAdvice('app1', failedDep(), [{ at: NOW + 10 * MIN + 1000, commit: 'bbbbbbbb' }]), null);
});

// --- R3 large-inline-file --------------------------------------------------

test('R3: an inline file over 64 KB is info advice naming chunk + assemble; 64 KB exactly is not', () => {
  assert.equal(A.largeInlineAdvice([{ path: 'a.js', bytes: 64 * 1024 }]), null);
  const it = A.largeInlineAdvice([{ path: 'a.js', bytes: 10 }, { path: 'big.js', bytes: 64 * 1024 + 1 }]);
  assert.equal(it.rule, 'large-inline-file');
  assert.equal(it.severity, 'info');
  assert.match(it.fix, /appcrane_managed_push_chunk/);
  assert.match(it.fix, /appcrane_managed_assemble/);
  assert.deepEqual(it.evidence.files, [{ path: 'big.js', bytes: 64 * 1024 + 1 }]);
});

// --- R4 upload-created-state-dir -------------------------------------------

test('R4: missingDataDirs lists only folders that are missing, never follows a link', () => {
  const root = mkdtempSync(join(tmpdir(), 'advice-r4-'));
  try {
    mkdirSync(join(root, 'have'));
    assert.deepEqual(A.missingDataDirs(root, 'file.json'), []);
    assert.deepEqual(A.missingDataDirs(root, 'have/file.json'), []);
    assert.deepEqual(A.missingDataDirs(root, 'have/new/deep/file.json'), ['have/new', 'have/new/deep']);
    assert.deepEqual(A.missingDataDirs(root, 'state/file.json'), ['state']);
    symlinkSync('/nonexistent-target', join(root, 'link'));
    assert.deepEqual(A.missingDataDirs(root, 'link/x/file.json'), []);
    const it = A.uploadCreatedDirAdvice('state/file.json', ['state']);
    assert.equal(it.rule, 'upload-created-state-dir');
    assert.equal(it.severity, 'info');
    assert.match(it.fix, /mkdir -p \/data\/state/);
    assert.equal(A.uploadCreatedDirAdvice('file.json', []), null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// --- dedup + context note --------------------------------------------------

test('dedup: one item per rule, nulls dropped, no field when empty', () => {
  const a = { rule: 'x', severity: 'info', message: 'm1', fix: 'f', evidence: {} };
  const b = { rule: 'x', severity: 'info', message: 'm2', fix: 'f', evidence: {} };
  assert.deepEqual(A.dedupeAdvice([a, null, b]), [a]);
  assert.deepEqual(A.adviceField([null, null]), {});
  assert.deepEqual(A.adviceField([a, b]), { advice: [a] });
});

test('context note: written once with its marker, not twice; info rules are never persisted', () => {
  A.recordPush('app1', { files: 1, at: NOW - 3 * MIN });
  A.recordPush('app1', { files: 1, at: NOW - 2 * MIN });
  A.recordPush('app1', { files: 1, at: NOW - 1 * MIN });
  const item = A.singleFilePushAdvice('app1', { now: NOW });
  const first = A.withAdviceNote('# Notes\nkeep me', item);
  assert.ok(first.startsWith('# Notes\nkeep me\n'));
  assert.ok(first.includes('<!-- appcrane-advice:single-file-pushes -->'));
  assert.match(first, /## AppCrane deploy advice — .* \(AppCrane\)/);
  assert.equal(A.withAdviceNote(first, item), null, 'second write must be refused by the marker');
  assert.equal(A.withAdviceNote('', A.largeInlineAdvice([{ path: 'a', bytes: 1e6 }])), null);
});
