import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// v2.92.3: the WAL is checkpointed from a worker thread, not by whichever
// commit crosses wal_autocheckpoint on the main thread. Measured under a
// throttled, contended disk (services/dbCheckpoint.js): worst main-thread
// commit 3.5-5.9 s with the auto-checkpoint, 1.9-2.4 ms with this.
//
// What this proves: with the auto-checkpoint off on the main connection,
// committed pages still reach the database file, because the worker copies
// them. Without the worker they would sit in the WAL indefinitely.
const DIR = mkdtempSync(join(tmpdir(), 'crane-bgckpt-'));
process.env.DATA_DIR = DIR;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const { startBackgroundCheckpoints } = await import('../server/services/dbCheckpoint.js');

let stop = () => {};
after(() => { stop(); rmSync(DIR, { recursive: true, force: true }); });

const dbFile = join(DIR, 'deployhub.db');
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('the main connection stops checkpointing, and a worker moves committed pages into the database file', async () => {
  stop = startBackgroundCheckpoints({ intervalMs: 100 });
  const db = getDb();
  assert.equal(db.pragma('wal_autocheckpoint', { simple: true }), 0,
    'the main connection still checkpoints inside commits, on the event loop');

  db.exec('CREATE TABLE bg_ckpt (v BLOB)');
  const ins = db.prepare('INSERT INTO bg_ckpt (v) VALUES (?)');
  const before = statSync(dbFile).size;
  for (let i = 0; i < 1500; i++) ins.run(Buffer.alloc(2048, i % 256));   // ~3 MB, past the default 1000-page threshold

  let grown = 0;
  for (let i = 0; i < 50 && grown < 2_000_000; i++) {
    await wait(100);
    grown = statSync(dbFile).size - before;
  }
  assert.ok(grown >= 2_000_000,
    `committed pages never reached the database file (it grew ${grown} bytes): nothing is checkpointing the WAL`);
});

test('the server starts it at boot, right after the database is opened', () => {
  const idx = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
  const init = idx.indexOf('initDb();');
  const start = idx.indexOf('startBackgroundCheckpoints();');
  assert.ok(init > 0 && start > init && start - init < 400, 'the server does not start background checkpoints after initDb()');
});
