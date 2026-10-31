// Docker build cache was never pruned: every image build adds layers to it and
// nothing took them away, so on a busy box it grows until the disk is full.
// Weekly, and whenever the host check sees a disk at warning or worse (at most
// every DISK_TRIGGER_GAP_MS), drop cache entries unused for a week, then trim
// what is left to KEEP_BYTES.
//
// The size flag depends on the installed Docker. With buildx (BuildKit;
// `docker builder prune` is an alias of `docker buildx prune` on Docker 23+)
// it is --max-used-space; --keep-storage is the older spelling, and the legacy
// builder without buildx has only --keep-storage. Read from `--help` at run
// time rather than guessed from a version number; with neither, only the age
// filter runs. The two prunes are separate calls so the age filter never
// depends on how a given version combines a filter with a size bound.

import { execFile } from 'child_process';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import { GiB } from './hostThresholds.js';
import log from '../utils/logger.js';

export const PRUNE_UNTIL = '168h';
export const KEEP_BYTES = 10 * GiB;
const HOUR = 3_600_000;
const WEEK = 7 * 24 * HOUR;
export const DISK_TRIGGER_GAP_MS = 6 * HOUR;
const PRUNE_TIMEOUT_MS = 30 * 60_000;
const FIRST_RUN_DELAY_MS = 20 * 60_000;

let lastDiskPrune = -Infinity;
let timers = [];

export function runDocker(args, timeout = PRUNE_TIMEOUT_MS) {
  return new Promise((res) => {
    execFile('docker', args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      res({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: String(stdout || ''), stderr: String(stderr || err?.message || '') });
    });
  });
}

export async function pruneSizeFlag(run = runDocker) {
  const help = await run(['builder', 'prune', '--help'], 30_000);
  const text = help.stdout + help.stderr;
  if (/--max-used-space\b/.test(text)) return '--max-used-space';
  if (/--keep-storage\b/.test(text)) return '--keep-storage';
  return null;
}

export function parseReclaimed(out) {
  return /Total(?: reclaimed space)?:\s*(\S+)/.exec(String(out || ''))?.[1] ?? null;
}

export async function pruneBuildCache({ reason = 'weekly', run = runDocker } = {}) {
  const sizeFlag = await pruneSizeFlag(run);
  const age = await run(['builder', 'prune', '-f', '--filter', `until=${PRUNE_UNTIL}`]);
  if (age.code !== 0) throw new Error(`docker builder prune --filter until=${PRUNE_UNTIL} failed: ${age.stderr.trim().slice(0, 300)}`);
  let size = null;
  if (sizeFlag) {
    size = await run(['builder', 'prune', '-f', sizeFlag, String(KEEP_BYTES)]);
    if (size.code !== 0) throw new Error(`docker builder prune ${sizeFlag} failed: ${size.stderr.trim().slice(0, 300)}`);
  }
  const detail = {
    at: new Date().toISOString(), reason, size_flag: sizeFlag, keep_bytes: sizeFlag ? KEEP_BYTES : null,
    reclaimed_by_age: parseReclaimed(age.stdout), reclaimed_by_size: size ? parseReclaimed(size.stdout) : null,
  };
  setJobDetail('build-cache-prune', detail);
  log.info(`[build-cache] ${reason} prune: ${detail.reclaimed_by_age ?? '?'} older than ${PRUNE_UNTIL}${sizeFlag ? `, ${detail.reclaimed_by_size ?? '?'} over the ${KEEP_BYTES / GiB} GB bound` : ' (this Docker has no size bound flag)'}`);
  return detail;
}

/** From the host check: prune when a disk is at warning or critical, at most every DISK_TRIGGER_GAP_MS. */
export function maybePruneForDisk(sample, { now = Date.now(), run = runDocker } = {}) {
  const low = (sample?.resources || []).find((r) => String(r.id).startsWith('disk:') && (r.level === 'warning' || r.level === 'critical'));
  if (!low || now - lastDiskPrune < DISK_TRIGGER_GAP_MS) return null;
  lastDiskPrune = now;
  return trackJob('build-cache-prune', () => pruneBuildCache({ reason: `disk ${low.level}: ${low.label}`, run }))
    .catch((e) => log.warn(`[build-cache] prune failed: ${e.message}`));
}

export function startBuildCachePrune() {
  if (timers.length) return;
  jobStarted('build-cache-prune');
  const run = () => trackJob('build-cache-prune', () => pruneBuildCache()).catch((e) => log.warn(`[build-cache] prune failed: ${e.message}`));
  const first = setTimeout(run, FIRST_RUN_DELAY_MS);
  const weekly = setInterval(run, WEEK);
  first.unref?.();
  weekly.unref?.();
  timers = [first, weekly];
}

export function _resetBuildCachePruneForTests() {
  lastDiskPrune = -Infinity;
  for (const t of timers) { clearTimeout(t); clearInterval(t); }
  timers = [];
}
