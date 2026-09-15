/**
 * Keep SQLite's WAL checkpoints off the main thread while a backup runs.
 *
 * The main connection checkpoints automatically: once the WAL passes
 * wal_autocheckpoint pages, the COMMIT that crossed the line copies frames into
 * the DB file and fsyncs it, inside the synchronous better-sqlite3 call. On an
 * idle disk that is milliseconds. During an export the disk is not idle: the
 * snapshot worker writes a full copy of the DB and tar writes the archive, and
 * ext4 makes that fsync wait for their writeback. Measured on node:22-bookworm
 * (--cpus=2, disk throttled to 120 MB/s, 512 MB DB + 128 MB /data): one main
 * thread write blocked 1573-1802 ms, strace showed it inside fsync() on the DB
 * file (2281 ms), and the event loop and an out-of-process HTTP probe stalled
 * for the same time. With the main connection's auto-checkpoint off the worst
 * write was under 20 ms. Doubling the CPUs did not remove it (--cpus=4: 1147-1610
 * ms, 5 of 5 runs): this is I/O, not starvation.
 *
 * So for the duration of an export the main connection does not checkpoint.
 * Nothing is lost by it: while the snapshot's read transaction is open no
 * checkpoint could pass its frames anyway. Afterwards a PASSIVE checkpoint runs
 * on a separate connection in a worker thread, so the fsync blocks that thread,
 * and only then is the main connection's own setting restored. PASSIVE never
 * takes the write lock, so the main connection keeps committing meanwhile.
 * Overlapping holders (a scheduled export during a manual one) share one
 * deferral, released when the last one finishes.
 */

import { Worker } from 'worker_threads';
import { createRequire } from 'module';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

const requireCjs = createRequire(import.meta.url);
const CHECKPOINT_WORKER = `
const { parentPort, workerData } = require('worker_threads');
try {
  const Database = require(workerData.driver);
  const d = new Database(workerData.src, { fileMustExist: true });
  try { parentPort.postMessage({ ok: true, result: d.pragma('wal_checkpoint(PASSIVE)')[0] }); } finally { d.close(); }
} catch (e) {
  parentPort.postMessage({ ok: false, message: e.message });
}
`;

/** PASSIVE checkpoint of the database file at `src`, run in a worker. Resolves { busy, log, checkpointed }. */
export function checkpointInWorker(src) {
  const driver = requireCjs.resolve('better-sqlite3');
  return new Promise((resolveP, reject) => {
    const w = new Worker(CHECKPOINT_WORKER, { eval: true, workerData: { driver, src } });
    let settled = false;
    w.once('message', (m) => { settled = true; m.ok ? resolveP(m.result) : reject(new Error(`checkpoint failed: ${m.message}`)); });
    w.once('error', (e) => { if (!settled) { settled = true; reject(e); } });
    w.once('exit', (code) => { if (!settled) reject(new Error(`checkpoint worker exited with ${code}`)); });
  });
}

let holders = 0;
let saved = null;

/** Run `fn` with the main connection's auto-checkpoint off; checkpoint in a worker afterwards. */
export async function withMainCheckpointsDeferred(fn) {
  const db = getDb();
  if (holders++ === 0) {
    saved = db.pragma('wal_autocheckpoint', { simple: true });
    db.pragma('wal_autocheckpoint = 0');
  }
  try {
    return await fn();
  } finally {
    if (holders === 1) {
      try {
        await checkpointInWorker(db.name);
      } catch (e) {
        log.warn(`[backup] deferred WAL checkpoint failed, the main connection will checkpoint on its own: ${e.message}`);
      }
    }
    if (--holders === 0) {
      db.pragma(`wal_autocheckpoint = ${Number(saved)}`);
      saved = null;
    }
  }
}
