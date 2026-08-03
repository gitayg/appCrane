import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';

// Pre-migration snapshots (v2.30.0).
//
// The point of this test: a snapshot taken by /api/self-update runs in the code
// that is ALREADY running, so the first upgrade onto a build that has the
// feature can never be protected by it. Migrations run in the NEW code, so
// snapshotting there does cover that upgrade. These assertions pin that down.

const DATA = mkdtempSync(join(tmpdir(), 'crane-premig-'));
process.env.DATA_DIR = DATA;

const { initDb, getDb } = await import('../server/db.js');
const { listSnapshots } = await import('../server/services/updateSnapshot.js');

test('a fresh boot with pending migrations snapshots before applying them', () => {
  initDb();
  const snaps = listSnapshots();
  assert.equal(snaps.length, 1, `expected exactly one snapshot, got ${snaps.length}`);
  assert.equal(snaps[0].reason, 'pre-migration');
  assert.ok(Array.isArray(snaps[0].pending_migrations));
  assert.ok(snaps[0].pending_migrations.length > 0, 'records which migrations were pending');
  assert.ok(existsSync(join(snaps[0].dir, 'deployhub.db')), 'database captured');
});

test('the snapshot predates the migrations it guards', () => {
  const snap = listSnapshots()[0];
  // The live DB has migrations applied; the snapshot was taken before any ran,
  // so its _migrations table must be empty (or absent).
  const copy = new Database(join(snap.dir, 'deployhub.db'), { readonly: true });
  const row = copy.prepare(
    "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table' AND name='_migrations'"
  ).get();
  const appliedInSnapshot = row.n
    ? copy.prepare('SELECT COUNT(*) AS n FROM _migrations').get().n
    : 0;
  copy.close();

  const appliedNow = getDb().prepare('SELECT COUNT(*) AS n FROM _migrations').get().n;
  assert.ok(appliedNow > 0, 'migrations did run on the live DB');
  assert.equal(appliedInSnapshot, 0, 'snapshot was taken before any migration was applied');
});

test('a restart with nothing pending does not accumulate snapshots', () => {
  const before = listSnapshots().length;
  initDb();               // same DATA_DIR, all migrations already applied
  initDb();
  assert.equal(listSnapshots().length, before,
    'ordinary restarts must not fill the disk with snapshots');
});
