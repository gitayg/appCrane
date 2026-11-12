import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync } from 'fs';
import { spawnSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';

// The preflight is the shell run in an agent container before claude starts:
// a mounted path the container user cannot use must stop the run with a
// [preflight] line instead of letting the CLI fail later with "Not logged in".
// `if ! a && b` negates only `a`, so before the fix no check ever failed.

process.env.LOG_LEVEL = 'error';
const { buildPreflightShell } = await import('../server/services/llm/runAgent.js');
const dir = mkdtempSync(join(tmpdir(), 'crane-preflight-'));
const run = (checks) => spawnSync('sh', ['-c', `${buildPreflightShell(checks)} echo REACHED`], { encoding: 'utf8' });

test('a missing file stops the run', () => {
  const r = run([{ path: join(dir, 'missing.json'), mode: 'rw', label: 'Claude credentials' }]);
  assert.equal(r.status, 75, r.stdout + r.stderr);
  assert.match(r.stderr, /\[preflight\] Claude credentials .* not read\+writable/);
  assert.doesNotMatch(r.stdout, /REACHED/);
});

test('a missing directory stops the run', () => {
  const r = run([{ path: join(dir, 'nope'), mode: 'dw', label: 'Workspace' }]);
  assert.equal(r.status, 75, r.stdout + r.stderr);
});

test('a read-only file fails an rw check', { skip: process.getuid?.() === 0 && 'root can write anything' }, () => {
  const f = join(dir, 'ro.json');
  writeFileSync(f, '{}');
  chmodSync(f, 0o444);
  const r = run([{ path: f, mode: 'rw', label: 'Claude credentials' }]);
  assert.equal(r.status, 75, r.stdout + r.stderr);
});

test('usable paths pass and the command runs', () => {
  const f = join(dir, 'ok.json');
  writeFileSync(f, '{}');
  const r = run([{ path: f, mode: 'rw' }, { path: dir, mode: 'dw' }, { path: dir, mode: 'd' }, { path: f, mode: 'r' }]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /REACHED/);
});
