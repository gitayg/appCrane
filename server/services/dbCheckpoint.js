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
import { traceBackup } from './backupTrace.js';

const requireCjs = createRequire(import.meta.url);
const CHECKPOINT_WORKER = `
const { parentPort, workerData } = require('worker_threads');
try {
  const Database = require(workerData.driver);
  const t0 = performance.timeOrigin + performance.now();
  const d = new Database(workerData.src, { fileMustExist: true });
  try {
    const result = d.pragma('wal_checkpoint(PASSIVE)')[0];
    parentPort.postMessage({ ok: true, result, t0, t1: performance.timeOrigin + performance.now() });
  } finally { d.close(); }
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
    w.once('message', (m) => {
      settled = true;
      if (m.ok) traceBackup('checkpoint:passive-in-worker', { start: m.t0, end: m.t1, result: m.result });
      m.ok ? resolveP(m.result) : reject(new Error(`checkpoint failed: ${m.message}`));
    });
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
    traceBackup('defer:start');
  }
  try {
    return await fn();
  } finally {
    if (holders === 1) {
      traceBackup('checkpoint:start');
      try {
        await checkpointInWorker(db.name);
      } catch (e) {
        log.warn(`[backup] deferred WAL checkpoint failed, the main connection will checkpoint on its own: ${e.message}`);
      }
      traceBackup('checkpoint:end');
    }
    if (--holders === 0) {
      db.pragma(`wal_autocheckpoint = ${Number(saved)}`);
      saved = null;
      traceBackup('defer:end');
    }
  }
}

// ── Routine checkpoints, off the main thread (v2.92.3) ────────────────────
//
// The export path above defers checkpoints for one reason: the COMMIT that
// crosses wal_autocheckpoint runs the checkpoint, fsync included, inside the
// synchronous better-sqlite3 call, on the event loop. That is not special to
// exports. Any disk contention makes that fsync slow, and it lands on
// whichever request happened to commit. Measured on node:22-bookworm
// (--cpus=2, disk throttled to 120 MB/s and 400 IOPS, two background writers
// rewriting 256 MB files with fsync), 20 s of 4 KB commits every 5 ms:
//
//   autocheckpoint on the main thread (today)   worst commit 3512-5886 ms, 4-6 over 100 ms
//   synchronous = NORMAL, autocheckpoint on     worst 3554-5254 ms (no better)
//   autocheckpoint off, PASSIVE in a worker     worst 1.9-2.4 ms, none over 100 ms
//
// The per-commit WAL sync (synchronous = FULL) cost nothing measurable
// (p99 0.1 ms), so it stays: durability is unchanged, only WHERE the
// checkpoint's fsync runs moves. PASSIVE never takes the write lock, so the
// main connection keeps committing while the worker copies frames.
const BACKGROUND_WORKER = `
const { parentPort, workerData } = require('worker_threads');
const Database = require(workerData.driver);
const tick = () => {
  try {
    const d = new Database(workerData.src, { fileMustExist: true });
    try { d.pragma('wal_checkpoint(PASSIVE)'); } finally { d.close(); }
  } catch (e) {
    parentPort.postMessage({ ok: false, message: e.message });
  }
};
setInterval(tick, workerData.intervalMs);
`;

let background = null;

/**
 * Turn the main connection's auto-checkpoint off for good and checkpoint from a
 * worker thread every `intervalMs`. The server calls this once at boot; the CLI
 * does not, and keeps SQLite's default. Returns a stop function.
 */
export function startBackgroundCheckpoints({ intervalMs = 2000 } = {}) {
  if (background) return background.stop;
  const db = getDb();
  const driver = requireCjs.resolve('better-sqlite3');
  const w = new Worker(BACKGROUND_WORKER, { eval: true, workerData: { driver, src: db.name, intervalMs } });
  let warned = false;
  w.on('message', (m) => {
    if (!m.ok && !warned) { warned = true; log.warn(`[db] background WAL checkpoint failed: ${m.message}`); }
  });
  w.on('error', (e) => log.warn(`[db] background checkpoint worker stopped: ${e.message}`));
  w.unref();
  db.pragma('wal_autocheckpoint = 0');
  const stop = () => {
    if (!background) return;
    background = null;
    w.terminate();
    // Hand checkpointing back to SQLite rather than leave the WAL to grow.
    try { db.pragma('wal_autocheckpoint = 1000'); } catch (_) {}
  };
  background = { stop };
  return stop;
}
