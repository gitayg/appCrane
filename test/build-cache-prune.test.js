import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// Docker build cache used to grow forever. Weekly, and when the host check
// sees a disk at warning or worse, AppCrane prunes entries unused for 168h and
// then trims to a size bound, using whichever size flag this Docker's `--help`
// offers. Runs are recorded in Job Health. Driven with a fake docker runner;
// the last test reads the real `--help` of the Docker on this machine.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-buildcache-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb } = await import('../server/db.js');
initDb();
const bc = await import('../server/services/buildCachePrune.js');
const { getJobHealth } = await import('../server/services/jobHealth.js');

const HELP_BUILDX = 'Usage:  docker buildx prune\n      --filter filter\n  -f, --force\n      --max-used-space bytes   Maximum amount of disk space allowed to keep for cache\n';
const HELP_LEGACY = 'Usage:  docker builder prune [OPTIONS]\n  -a, --all\n      --filter filter\n  -f, --force\n      --keep-storage bytes   Amount of disk space to keep for cache\n';
const HELP_NONE = 'Usage:  docker builder prune [OPTIONS]\n      --filter filter\n  -f, --force\n';

function fake(help, { failAge = false } = {}) {
  const calls = [];
  const run = async (args) => {
    calls.push(args.join(' '));
    if (args.includes('--help')) return { code: 0, stdout: help, stderr: '' };
    if (failAge && args.includes('--filter')) return { code: 1, stdout: '', stderr: 'Cannot connect to the Docker daemon' };
    return { code: 0, stdout: args.includes('--filter') ? 'Total:\t1.5GB\n' : 'Total reclaimed space: 300MB\n', stderr: '' };
  };
  return { calls, run };
}
const job = () => getJobHealth().find((j) => j.id === 'build-cache-prune');

beforeEach(() => bc._resetBuildCachePruneForTests());

test('buildx: age prune, then --max-used-space to the bound, as two calls', async () => {
  const f = fake(HELP_BUILDX);
  const d = await bc.pruneBuildCache({ run: f.run });
  assert.deepEqual(f.calls, [
    'builder prune --help',
    'builder prune -f --filter until=168h',
    `builder prune -f --max-used-space ${10 * 1024 ** 3}`,
  ]);
  assert.equal(d.reclaimed_by_age, '1.5GB');
  assert.equal(d.reclaimed_by_size, '300MB');
});

test('legacy builder: --keep-storage', async () => {
  const f = fake(HELP_LEGACY);
  await bc.pruneBuildCache({ run: f.run });
  assert.equal(f.calls[2], `builder prune -f --keep-storage ${10 * 1024 ** 3}`);
});

test('no size flag: only the age filter runs', async () => {
  const f = fake(HELP_NONE);
  const d = await bc.pruneBuildCache({ run: f.run });
  assert.deepEqual(f.calls, ['builder prune --help', 'builder prune -f --filter until=168h']);
  assert.equal(d.size_flag, null);
});

test('a failing prune throws with docker\'s message', async () => {
  const f = fake(HELP_BUILDX, { failAge: true });
  await assert.rejects(bc.pruneBuildCache({ run: f.run }), /until=168h failed: Cannot connect to the Docker daemon/);
});

test('the host check triggers a prune on a disk at warning, records it in Job Health, and not again within 6 hours', async () => {
  const f = fake(HELP_BUILDX);
  const sample = (level) => ({ resources: [{ id: 'memory', level: 'critical' }, { id: 'disk:42', label: 'Disk free (DATA_DIR)', level }] });
  assert.equal(bc.maybePruneForDisk(sample('ok'), { now: 1_000_000, run: f.run }), null, 'disk ok: no prune (memory does not count)');
  await bc.maybePruneForDisk(sample('warning'), { now: 1_000_000, run: f.run });
  assert.equal(f.calls.filter((c) => c.includes('--filter')).length, 1);
  assert.equal(job().last_run.ok, true);
  assert.match(job().detail.reason, /^disk warning: Disk free \(DATA_DIR\)/);
  assert.equal(bc.maybePruneForDisk(sample('critical'), { now: 1_000_000 + bc.DISK_TRIGGER_GAP_MS - 1, run: f.run }), null);
  await bc.maybePruneForDisk(sample('critical'), { now: 1_000_000 + bc.DISK_TRIGGER_GAP_MS, run: f.run });
  assert.equal(f.calls.filter((c) => c.includes('--filter')).length, 2);
});

test('a failed disk-triggered prune shows as failing in Job Health', async () => {
  const f = fake(HELP_BUILDX, { failAge: true });
  await bc.maybePruneForDisk({ resources: [{ id: 'disk:1', label: 'x', level: 'critical' }] }, { now: 5, run: f.run });
  assert.equal(job().last_run.ok, false);
});

test('this machine\'s Docker: the size flag is read from its real --help', { skip: (() => { try { execFileSync('docker', ['builder', 'prune', '--help'], { stdio: 'pipe' }); return false; } catch (_) { return 'docker not available'; } })() }, async () => {
  const flag = await bc.pruneSizeFlag();
  assert.ok(flag === '--max-used-space' || flag === '--keep-storage', String(flag));
});
