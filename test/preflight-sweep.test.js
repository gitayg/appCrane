import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import net from 'net';
import { tmpdir } from 'os';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { PREFLIGHT_LABEL } from '../server/services/preflightCheck.js';
import { MIN_AGE_MS, preflightLeftoversFrom, startPreflightSweep, sweepPreflightLeftovers } from '../server/services/preflightSweep.js';

// AppCrane killed mid-check leaves a Created `appcrane-preflight-*` container and
// its anonymous volume. The real-docker reproduction of that crash is in
// fix-preflight-no-image-code.test.js.

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const TMP = mkdtempSync(join(tmpdir(), 'crane-preflight-sweep-'));
after(() => rmSync(TMP, { recursive: true, force: true }));

const NOW = Date.parse('2026-11-06T12:00:00Z');
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();
const line = (id, msAgo, status = 'created', label = 'true') => [id, iso(msAgo), status, label].join('\t');

function fakeRun(rows, { ids = rows.map((r) => r.split('\t')[0]) } = {}) {
  const calls = [];
  const run = async (args) => {
    calls.push(args);
    if (args[0] === 'ps') return { code: 0, stdout: `${ids.join('\n')}\n`, stderr: '' };
    if (args[0] === 'inspect') return { code: 0, stdout: `${rows.join('\n')}\n`, stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
  return { run, calls, removed: () => calls.filter((c) => c[0] === 'rm') };
}

test('the list is narrowed to the label and the Created state', async () => {
  const { run, calls } = fakeRun([]);
  assert.deepEqual(await sweepPreflightLeftovers({ run, now: NOW }), { removed: 0, failed: 0 });
  assert.deepEqual(calls, [['ps', '-a', '-q', '--no-trunc', '--filter', `label=${PREFLIGHT_LABEL}`, '--filter', 'status=created']]);
});

test('an old one goes with its volume, and without -f', async () => {
  const { run, removed } = fakeRun([line('old', MIN_AGE_MS)]);
  assert.deepEqual(await sweepPreflightLeftovers({ run, now: NOW }), { removed: 1, failed: 0 });
  assert.deepEqual(removed(), [['rm', '-v', 'old']]);
});

test('anything a check could still be using, or that is not a leftover, stays', async () => {
  const { run, removed } = fakeRun([
    line('young', MIN_AGE_MS - 1),
    line('started', MIN_AGE_MS * 2, 'running'),
    line('exited', MIN_AGE_MS * 2, 'exited'),
    line('unlabelled', MIN_AGE_MS * 2, 'created', ''),
    line('other-value', MIN_AGE_MS * 2, 'created', 'false'),
    line('bad-date', MIN_AGE_MS * 2).replace(iso(MIN_AGE_MS * 2), 'not a date'),
  ]);
  assert.deepEqual(await sweepPreflightLeftovers({ run, now: NOW }), { removed: 0, failed: 0 });
  assert.deepEqual(removed(), []);
  assert.deepEqual(preflightLeftoversFrom('', NOW), []);
});

test('a refused rm is counted and the rest still go; a failed list reports and removes nothing', async () => {
  const calls = [];
  const run = async (args) => {
    calls.push(args);
    if (args[0] === 'ps') return { code: 0, stdout: 'a\nb\n', stderr: '' };
    if (args[0] === 'inspect') return { code: 0, stdout: `${line('a', MIN_AGE_MS)}\n${line('b', MIN_AGE_MS)}\n`, stderr: '' };
    return { code: args[2] === 'a' ? 1 : 0, stdout: '', stderr: 'in use' };
  };
  assert.deepEqual(await sweepPreflightLeftovers({ run, now: NOW }), { removed: 1, failed: 1 });
  await assert.rejects(sweepPreflightLeftovers({ run: async () => ({ code: 1, stdout: '', stderr: 'daemon down' }) }), /daemon down/);
});

test('boot runs a pass now and another once a container from just before boot is old enough', async () => {
  let passes = 0;
  await startPreflightSweep({ sweep: async () => { passes += 1; return { removed: 0, failed: 0 }; }, followUpMs: 20 });
  assert.equal(passes, 1);
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(passes, 2);
  // A docker failure must never reach the boot.
  await startPreflightSweep({ sweep: async () => { throw new Error('no docker'); }, followUpMs: 1 });
  await new Promise((r) => setTimeout(r, 20));
});

test('the follow-up timer does not hold a process open', async () => {
  const script = `import { startPreflightSweep } from ${JSON.stringify(join(REPO, 'server/services/preflightSweep.js'))};
await startPreflightSweep({ sweep: async () => ({ removed: 0, failed: 0 }), followUpMs: 600000 });`;
  const file = join(TMP, 'unref.mjs');
  writeFileSync(file, script);
  const c = spawn(process.execPath, [file], { env: { ...process.env, LOG_LEVEL: 'error' }, stdio: 'ignore' });
  const killer = setTimeout(() => c.kill('SIGKILL'), 20000);
  const code = await new Promise((r) => c.on('close', (status) => r(status)));
  clearTimeout(killer);
  assert.equal(code, 0, 'the process had to be killed');
});

test('the event loop keeps running while docker is slow', async () => {
  const bin = mkdtempSync(join(TMP, 'slow-'));
  writeFileSync(join(bin, 'docker'), '#!/bin/sh\nsleep 1\n');
  chmodSync(join(bin, 'docker'), 0o755);
  const before = process.env.PATH;
  process.env.PATH = `${bin}:${before}`;
  let ticks = 0;
  const iv = setInterval(() => { ticks += 1; }, 50);
  try {
    assert.deepEqual(await sweepPreflightLeftovers(), { removed: 0, failed: 0 });
  } finally {
    clearInterval(iv);
    process.env.PATH = before;
  }
  assert.ok(ticks >= 10, `only ${ticks} timer ticks during a 1 s docker call`);
});

const freePort = () => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

test('the real server sweeps at boot', async () => {
  const data = mkdtempSync(join(TMP, 'boot-'));
  const events = join(data, 'events');
  writeFileSync(join(data, 'docker'), `#!/bin/bash
echo "$*" >> "${events}"
case "$1 $*" in
  ps*label=${PREFLIGHT_LABEL}*) echo leftover-id ;;
  inspect*Labels*) printf 'leftover-id\\t2020-01-01T00:00:00Z\\tcreated\\ttrue\\n' ;;
esac
exit 0
`);
  chmodSync(join(data, 'docker'), 0o755);
  const port = await freePort();
  let out = '';
  const child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO,
    env: { ...process.env, PATH: `${data}:${process.env.PATH}`, DATA_DIR: data, ENCRYPTION_KEY: 'e'.repeat(64), LOG_LEVEL: 'info', PORT: String(port), HOST: '127.0.0.1', APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { out += c; });
  try {
    const removed = () => existsSync(events) && readFileSync(events, 'utf8').split('\n').includes('rm -v leftover-id');
    for (let i = 0; i < 240 && !removed() && child.exitCode === null; i++) {
      await new Promise((r) => setTimeout(r, 250));
    }
    assert.ok(removed(), `no sweep at boot:\n${out.slice(-1500)}`);
    assert.doesNotMatch(readFileSync(events, 'utf8'), /^rm -f.*leftover-id/m);
  } finally {
    child.kill('SIGKILL');
  }
});
