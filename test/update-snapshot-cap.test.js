import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, truncateSync, existsSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Pre-update snapshots are full copies of the database, and five of them reached
// 1.1 GB on a production box that then hit 100% disk. Retention is capped by
// total bytes as well as by count (the newest always kept), and a snapshot that
// would take DATA_DIR below the disk critical floor is skipped, not written.
// Large snapshots are planted as sparse files: statSync reports their size
// without the test writing gigabytes.

const DATA = mkdtempSync(join(tmpdir(), 'crane-snapcap-'));
process.env.DATA_DIR = DATA;
process.env.ENCRYPTION_KEY = 's'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb } = await import('../server/db.js');
initDb();
const { createPreUpdateSnapshot, listSnapshots, pruneSnapshots, snapshotRoot, MAX_TOTAL_BYTES } = await import('../server/services/updateSnapshot.js');

const cwd = mkdtempSync(join(tmpdir(), 'crane-snapcap-repo-'));
writeFileSync(join(cwd, '.env'), 'ENCRYPTION_KEY=feedface\n');
const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

function plant(id, bytes) {
  const dir = join(snapshotRoot(), id);
  mkdirSync(dir, { recursive: true });
  const f = join(dir, 'deployhub.db');
  writeFileSync(f, '');
  truncateSync(f, bytes);
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ reason: 'planted' }));
}
const ids = () => listSnapshots().map((s) => s.id);
const roomy = { statfs: () => ({ bavail: 200 * 256, bsize: 4 * MiB, blocks: 400 * 256 }) }; // 200 of 400 GB free

test('the cap is 1 GiB', () => {
  assert.equal(MAX_TOTAL_BYTES, GiB);
});

test('older snapshots beyond the byte cap are pruned even when under the count', () => {
  // initDb may have taken a pre-migration snapshot, depending on this host's free space.
  rmSync(snapshotRoot(), { recursive: true, force: true });
  for (let i = 1; i <= 3; i++) plant(`2020010${i}T000000Z`, 400 * MiB);
  const s = createPreUpdateSnapshot(cwd, { from: 'cap' }, null, roomy);
  assert.equal(s.ok, true, s.error);
  // newest (small) + 400 MiB + 400 MiB fits; the third 400 MiB would be ~1.2 GiB.
  assert.deepEqual(ids(), [s.id, '20200103T000000Z', '20200102T000000Z']);
  assert.ok(!existsSync(join(snapshotRoot(), '20200101T000000Z')));
  assert.ok(listSnapshots().reduce((n, x) => n + x.bytes, 0) <= GiB);
});

test('the newest snapshot is kept even when it alone exceeds the cap', () => {
  plant('29990101T000000Z', 2 * GiB);
  pruneSnapshots();
  assert.deepEqual(ids(), ['29990101T000000Z']);
});

test('a snapshot that would take DATA_DIR below the critical floor is skipped, without throwing', () => {
  const before = readdirSync(snapshotRoot()).length;
  // 4 GB free of 400 GB: already under the 5 GB floor once the copy is subtracted.
  const tight = { statfs: () => ({ bavail: 4 * 256, bsize: 4 * MiB, blocks: 400 * 256 }) };
  const s = createPreUpdateSnapshot(cwd, { from: 'tight' }, null, tight);
  assert.equal(s.ok, false);
  assert.equal(s.skipped, true);
  assert.match(s.error, /^snapshot skipped: DATA_DIR \(.+\) has 4\.0 GB free of 400\.0 GB, and a .+ database copy would take it below the floor of 5 GB/);
  assert.equal(readdirSync(snapshotRoot()).length, before, 'nothing was written');
});

test('the percent rule does not skip: 16 GB free on a 400 GB disk (4%) still snapshots', () => {
  const s = createPreUpdateSnapshot(cwd, { from: 'pct' }, null, { statfs: () => ({ bavail: 16 * 256, bsize: 4 * MiB, blocks: 400 * 256 }) });
  assert.equal(s.ok, true, s.error);
});

test('free space that cannot be read does not skip the snapshot', () => {
  const s = createPreUpdateSnapshot(cwd, { from: 'unknown' }, null, { statfs: () => { throw new Error('statfs broke'); } });
  assert.equal(s.ok, true, s.error);
});
