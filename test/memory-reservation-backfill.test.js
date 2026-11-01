import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { containersWithoutReservation, backfillMemoryReservations } from '../server/services/memoryReservationBackfill.js';

const MiB = 1024 * 1024;

test('only app containers with a cap and no reservation are picked, at half the cap', () => {
  const out = [
    `/appcrane-shop-production\t${1024 * MiB}\t0`,
    `/appcrane-shop-sandbox\t${512 * MiB}\t${256 * MiB}`,
    `/appcrane-db-postgres\t${1024 * MiB}\t0`,
    `/appcrane-free-production\t0\t0`,
    `/bold_clarke\t${1024 * MiB}\t0`,
  ].join('\n');
  assert.deepEqual(containersWithoutReservation(out), [{ name: 'appcrane-shop-production', guaranteedMb: 512, swapMb: null }]);
});

test('with host swap, a container whose swap allowance is not max + (max - guaranteed) is picked, even with a reservation', () => {
  const out = [
    `/appcrane-a-production\t${512 * MiB}\t${256 * MiB}\t${512 * MiB}`,
    `/appcrane-b-production\t${512 * MiB}\t${256 * MiB}\t${768 * MiB}`,
  ].join('\n');
  assert.deepEqual(containersWithoutReservation(out, 4096), [{ name: 'appcrane-a-production', guaranteedMb: 256, swapMb: 768 }]);
  assert.deepEqual(containersWithoutReservation(out, 0), [{ name: 'appcrane-b-production', guaranteedMb: 256, swapMb: 512 }],
    'without host swap the allowance goes back to equal to the max');
});

test('backfill runs docker update --memory-reservation on each, and reports failures', async () => {
  const calls = [];
  const docker = async (args) => {
    calls.push(args.join(' '));
    if (args[0] === 'ps') return 'id1\nid2';
    if (args[0] === 'inspect') return `/appcrane-a-production\t${1024 * MiB}\t0\t${1024 * MiB}\n/appcrane-b-sandbox\t${512 * MiB}\t0\t${512 * MiB}`;
    if (args[0] === 'update' && args.at(-1) === 'appcrane-b-sandbox') throw new Error('no such container');
    return '';
  };
  const r = await backfillMemoryReservations({ docker, swapMb: 0 });
  assert.deepEqual(r.updated, ['appcrane-a-production']);
  assert.deepEqual(r.failed, [{ name: 'appcrane-b-sandbox', error: 'no such container' }]);
  assert.ok(calls.includes('update --memory-reservation=512m --memory-swap=1024m appcrane-a-production'), calls.join('\n'));
  assert.ok(calls.includes('update --memory-reservation=256m --memory-swap=512m appcrane-b-sandbox'));
});

function dockerOk() {
  try { execFileSync('docker', ['version'], { stdio: 'pipe', timeout: 10000 }); return true; } catch (_) { return false; }
}

test('LIVE: a running app container without a reservation gets half its cap, without a restart', { skip: !dockerOk() && 'docker unavailable' }, async () => {
  const d = (...a) => execFileSync('docker', a, { encoding: 'utf8', timeout: 60000 }).trim();
  try { d('image', 'inspect', 'alpine'); } catch (_) { d('pull', 'alpine'); }
  const name = `appcrane-backfilltest${process.pid}-sandbox`;
  const id = d('run', '-d', '--name', name, '--memory', '64m', '--label', 'slug=backfilltest', '--label', 'env=sandbox',
    '--label', 'appcrane-test=reservation-backfill', 'alpine', 'sleep', '300');
  try {
    const started = d('inspect', '-f', '{{.State.StartedAt}}', id);
    // Real Docker, listing only this test's container.
    const docker = (args) => {
      const a = args[0] === 'ps' ? [...args, '--filter', 'label=appcrane-test=reservation-backfill'] : args;
      return Promise.resolve(execFileSync('docker', a, { encoding: 'utf8', timeout: 30000 }).trim());
    };
    const r = await backfillMemoryReservations({ docker, swapMb: 1024 });
    assert.deepEqual(r.updated, [name]);
    assert.equal(Number(d('inspect', '-f', '{{.HostConfig.MemorySwap}}', id)), 96 * MiB, 'swap allowance = max + (max - guaranteed)');
    assert.equal(Number(d('inspect', '-f', '{{.HostConfig.MemoryReservation}}', id)), 32 * MiB);
    assert.equal(d('inspect', '-f', '{{.State.StartedAt}}', id), started, 'not restarted');
    assert.deepEqual((await backfillMemoryReservations({ docker, swapMb: 1024 })).updated, [], 'a second run changes nothing');
  } finally {
    try { d('rm', '-f', id); } catch (_) {}
  }
});
