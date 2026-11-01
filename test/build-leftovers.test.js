import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { runDocker } from '../server/services/buildCachePrune.js';
import { isBuildStepLeftover, leftoversFrom, pruneBuildLeftovers, MIN_AGE_MS } from '../server/services/buildLeftovers.js';

const NOP = ['/bin/sh', '-c', '#(nop) ', 'LABEL slug=shop'];

test('only the classic builder #(nop) step command counts as a leftover', () => {
  assert.equal(isBuildStepLeftover(NOP), true);
  assert.equal(isBuildStepLeftover(['/bin/sh', '-c', '#(nop) WORKDIR /app']), true);
  assert.equal(isBuildStepLeftover(['/bin/sh', '-c', 'npm start']), false);
  assert.equal(isBuildStepLeftover(['docker-entrypoint.sh', 'postgres']), false);
  assert.equal(isBuildStepLeftover(null), false);
});

test('a leftover younger than MIN_AGE_MS is kept: a build may be running it now', () => {
  const now = Date.parse('2026-10-31T12:00:00Z');
  const old = new Date(now - MIN_AGE_MS - 1000).toISOString();
  const fresh = new Date(now - 60_000).toISOString();
  const out = [
    `a1\t${old}\t${JSON.stringify(NOP)}`,
    `b2\t${fresh}\t${JSON.stringify(NOP)}`,
    `c3\t${old}\t${JSON.stringify(['/bin/sh', '-c', 'npm start'])}`,
    `d4\t${old}\tnot json`,
  ].join('\n');
  assert.deepEqual(leftoversFrom(out, now), ['a1']);
});

test('removes only the leftovers, then prunes untagged images', async () => {
  const now = Date.parse('2026-10-31T12:00:00Z');
  const old = new Date(now - MIN_AGE_MS - 1000).toISOString();
  const calls = [];
  const run = async (args) => {
    calls.push(args.join(' '));
    if (args[0] === 'ps') return { code: 0, stdout: 'a1\nc3\n', stderr: '' };
    if (args[0] === 'inspect') return { code: 0, stdout: `a1\t${old}\t${JSON.stringify(NOP)}\nc3\t${old}\t["true"]\n`, stderr: '' };
    if (args[0] === 'image') return { code: 0, stdout: 'Total reclaimed space: 1.6GB\n', stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
  const r = await pruneBuildLeftovers({ run, now });
  assert.deepEqual(r, { removed: 1, reclaimed: '1.6GB' });
  assert.ok(calls.includes('rm a1'));
  assert.ok(!calls.some((c) => c.startsWith('rm c3')), 'a never-started container that is not a build step stays');
  assert.equal(calls.at(-1), 'image prune -f');
});

function dockerOk() {
  try { execFileSync('docker', ['version'], { stdio: 'pipe', timeout: 10000 }); return true; } catch (_) { return false; }
}

test('LIVE: a never-started #(nop) step container is removed, a plain created container is not', { skip: !dockerOk() && 'docker unavailable' }, async () => {
  const d = (...a) => execFileSync('docker', a, { encoding: 'utf8', timeout: 60000 }).trim();
  try { d('image', 'inspect', 'alpine'); } catch (_) { d('pull', 'alpine'); }
  const step = d('create', '--label', 'appcrane-test=build-leftovers', 'alpine', '/bin/sh', '-c', '#(nop) ', 'LABEL slug=shop');
  const plain = d('create', '--label', 'appcrane-test=build-leftovers', 'alpine', 'true');
  try {
    // Real Docker, scoped to this test's containers: nothing else on the host is
    // listed, and the image prune is skipped.
    const run = (args) => args[0] === 'ps' ? runDocker([...args, '--filter', 'label=appcrane-test=build-leftovers'])
      : args[0] === 'image' ? Promise.resolve({ code: 0, stdout: '', stderr: '' }) : runDocker(args);
    const r = await pruneBuildLeftovers({ run, now: Date.now() + MIN_AGE_MS + 60_000 });
    assert.equal(r.removed, 1);
    const left = d('ps', '-a', '-q', '--no-trunc', '--filter', 'label=appcrane-test=build-leftovers').split('\n');
    assert.ok(!left.includes(step), 'the build step container was removed');
    assert.ok(left.includes(plain), 'the plain created container was kept');
  } finally {
    for (const id of [step, plain]) { try { d('rm', '-f', id); } catch (_) {} }
  }
});
