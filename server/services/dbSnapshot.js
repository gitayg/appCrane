/**
 * Point-in-time copy of the live SQLite database, written no faster than the
 * disk takes it.
 *
 * WHY NOT VACUUM INTO (v2.74.0 to v2.77.1). VACUUM INTO in a worker kept the copy
 * off the event loop, but it writes the whole database into the page cache as
 * fast as it can read it. Linux then throttles EVERY task that writes to the
 * page cache while dirty plus writeback pages are over the limit: the kernel's
 * balance_dirty_pages() pauses the writer for up to 200 ms at a time, and the
 * main thread's next small WAL write is such a writer. Measured on
 * node:22-bookworm (4 CPUs, disk throttled to 150 MB/s, 2 GB memory limit, 512 MB
 * DB): main-thread writes of 203-217 ms with the thread in D state at
 * wchan=balance_dirty_pages while the cgroup had 397 MB under writeback, and
 * 1.6-2.1 s in the full suite. fdatasync-ing the copy from another thread did
 * not help (it turns dirty pages into writeback pages; the sum is what counts).
 *
 * So the copy is made with SQLite's backup API in a worker, a fixed number of
 * pages per step, and the worker fdatasyncs the destination after every step:
 * the producer waits for the disk, and the page cache never holds more than a
 * step of it. The worker's source connection opens a read transaction before
 * the first step and keeps it to the end, so every step reads the same WAL
 * snapshot: the backup is not restarted by the main connection's commits and
 * the copy is one point in time (measured: 0 restarts while the writer kept
 * committing, both ledger tables equal and gapless).
 *
 * The backup API run on the MAIN thread (better-sqlite3 steps it between
 * event-loop turns) stalled the loop: 127-129 ms on a clean page cache and
 * 246-406 ms after 1 GB of recent writes, measured before v2.74.0. Here every
 * page copy and every fsync happens in the worker.
 */

import { Worker } from 'worker_threads';
import { createRequire } from 'module';

export const SNAPSHOT_PAGES_PER_STEP = 1024;

const requireCjs = createRequire(import.meta.url);

const SNAPSHOT_WORKER = `
const { parentPort, workerData } = require('worker_threads');
const fs = require('fs');
(async () => {
  const t0 = performance.timeOrigin + performance.now();
  const Database = require(workerData.driver);
  const d = new Database(workerData.src, { readonly: true, fileMustExist: true });
  let fd = null;
  let steps = 0;
  let syncs = 0;
  try {
    d.exec('BEGIN');
    d.prepare('SELECT COUNT(*) FROM sqlite_schema').get();
    await d.backup(workerData.dest, {
      progress() {
        steps++;
        if (workerData.sync) {
          if (fd === null) fd = fs.openSync(workerData.dest, 'r');
          fs.fdatasyncSync(fd);
          syncs++;
        }
        return workerData.pages;
      },
    });
    d.exec('COMMIT');
  } finally {
    if (fd !== null) fs.closeSync(fd);
    d.close();
  }
  // The backup copies the source header, which says WAL. VACUUM INTO (the
  // previous snapshot) wrote a rollback-journal file; keep the archived file
  // the same so an extracted deployhub.db opens without -wal/-shm companions.
  const c = new Database(workerData.dest, { fileMustExist: true });
  try { c.pragma('journal_mode = DELETE'); } finally { c.close(); }
  parentPort.postMessage({ ok: true, t0, t1: performance.timeOrigin + performance.now(), steps, syncs });
})().catch((e) => parentPort.postMessage({ ok: false, message: e.message }));
`;

/**
 * Copy the database at `src` to `dest` (which must not exist) in a worker.
 * Resolves { t0, t1, steps, syncs } (absolute ms, backup steps, fdatasyncs).
 */
export function snapshotDatabasePaced(src, dest, { pages = SNAPSHOT_PAGES_PER_STEP, sync = true } = {}) {
  const driver = requireCjs.resolve('better-sqlite3');
  return new Promise((resolveP, reject) => {
    const w = new Worker(SNAPSHOT_WORKER, { eval: true, workerData: { driver, src, dest, pages, sync } });
    let settled = false;
    w.once('message', (m) => {
      settled = true;
      if (m.ok) resolveP({ t0: m.t0, t1: m.t1, steps: m.steps, syncs: m.syncs });
      else reject(new Error(`database snapshot failed: ${m.message}`));
    });
    w.once('error', (e) => { if (!settled) { settled = true; reject(e); } });
    w.once('exit', (code) => { if (!settled) reject(new Error(`database snapshot worker exited with ${code}`)); });
  });
}
