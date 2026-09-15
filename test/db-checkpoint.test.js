import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const ROOT = mkdtempSync(join(tmpdir(), 'crane-ckpt-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = '9'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { withMainCheckpointsDeferred } = await import('../server/services/dbCheckpoint.js');

after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

// The wal-index header: mxFrame (frames in the WAL) at byte 16, and the
// checkpoint info's nBackfill (frames already copied into the DB file) at byte
// 96, both native-endian u32. Read from the -shm file so that looking does not
// itself checkpoint.
function walState() {
  const shm = readFileSync(`${db.name}-shm`);
  const le = new Uint8Array(new Uint32Array([1]).buffer)[0] === 1;
  const u32 = (o) => (le ? shm.readUInt32LE(o) : shm.readUInt32BE(o));
  return { mxFrame: u32(16), nBackfill: u32(96) };
}

db.exec('CREATE TABLE IF NOT EXISTS ckpt_rows (id INTEGER PRIMARY KEY, b BLOB)');
const ins = db.prepare('INSERT INTO ckpt_rows (b) VALUES (?)');
// One commit per row, like request-driven writes: well past 1000 WAL pages.
const writeCommits = (n) => { for (let i = 0; i < n; i++) ins.run(Buffer.alloc(3000, i & 255)); };

test('while deferred, the main connection does not checkpoint; afterwards the WAL is backfilled by the worker and the setting restored', async () => {
  db.pragma('wal_checkpoint(TRUNCATE)');
  db.pragma('wal_autocheckpoint = 700');
  try {
    await withMainCheckpointsDeferred(async () => {
      assert.equal(db.pragma('wal_autocheckpoint', { simple: true }), 0);
      writeCommits(1500);
      const s = walState();
      assert.ok(s.mxFrame > 1400, `fixture: the WAL holds ${s.mxFrame} frames`);
      assert.equal(s.nBackfill, 0, 'the main connection checkpointed during the deferral');
      assert.ok(statSync(`${db.name}-wal`).size > 700 * 4096);
    });
    const s = walState();
    assert.ok(s.mxFrame > 1400);
    assert.equal(s.nBackfill, s.mxFrame, 'no checkpoint ran after the deferral');
    assert.equal(db.pragma('wal_autocheckpoint', { simple: true }), 700);
  } finally {
    db.pragma('wal_autocheckpoint = 1000');
  }
});

test('overlapping holders share one deferral, and a throwing holder still releases it', async () => {
  let releaseFirst;
  const first = withMainCheckpointsDeferred(() => new Promise((r) => { releaseFirst = r; }));
  await assert.rejects(withMainCheckpointsDeferred(async () => {
    assert.equal(db.pragma('wal_autocheckpoint', { simple: true }), 0);
    throw new Error('boom');
  }), /boom/);
  assert.equal(db.pragma('wal_autocheckpoint', { simple: true }), 0, 'the second holder restored the setting while the first still holds it');
  releaseFirst();
  await first;
  assert.equal(db.pragma('wal_autocheckpoint', { simple: true }), 1000);
});
