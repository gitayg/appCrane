// Host swap sized to the memory apps are allowed to burst into.
//
// Every app container is guaranteed half its max (--memory-reservation) and may
// burst to its max while the server has memory free. The max of every app, both
// environments, adds up to far more than the server's RAM (the fleet is
// over-committed on purpose), so a correlated burst used to end in the kernel's
// OOM killer: the hosts had no swap at all (measured 1 Nov 2026: Swap 0).
//
// AppCrane now keeps one swapfile of its own, sized to
//   sum of every deployed app's max, both environments  -  host RAM
// less any swap the host already has from elsewhere, rounded up to 256 MB. It
// never takes free disk below the disk floor in Settings > Job Health, nor below
// the disk warning percentage, so the swapfile cannot be what fills the disk.
// It grows when apps are added or limits raised; it only shrinks or goes away
// while nothing is swapped out to it, since swapoff of a used file needs RAM
// the host may not have.
//
// With host swap present, each app container may also swap out the part above
// its guarantee: --memory-swap = max + (max - guaranteed). Under pressure the
// kernel then moves an app's burst to disk instead of killing it, and an app
// that is slow under pressure beats one that is dead. Without host swap the two
// stay equal, so the configured number is still the whole ceiling and nothing
// reads as a fallback the host cannot deliver (see docker.js, --memory-swap).
//
// Linux only, and only when AppCrane runs as root. APPCRANE_MANAGE_SWAP=0 turns
// the swapfile management off; APPCRANE_SWAPFILE moves the file.

import { execFile } from 'child_process';
import { readFileSync, writeFileSync, existsSync, statfsSync, statSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { guaranteedMb } from './memoryAdmission.js';
import log from '../utils/logger.js';

const MiB = 1024 * 1024;
export const STEP_MB = 256;
export const DEFAULT_SWAPFILE = '/var/lib/appcrane/swapfile';

export function swapfilePath() {
  return process.env.APPCRANE_SWAPFILE || DEFAULT_SWAPFILE;
}

function procSwapsPath() {
  return process.env.APPCRANE_PROC_SWAPS || '/proc/swaps';
}

/** Parse /proc/swaps into [{ path, sizeMb, usedMb }]. */
export function parseProcSwaps(text) {
  const rows = [];
  for (const line of String(text || '').split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 4) continue;
    const size = Number(f[2]);
    const used = Number(f[3]);
    if (!Number.isFinite(size)) continue;
    rows.push({ path: f[0].replace(/\\040/g, ' '), sizeMb: Math.floor(size / 1024), usedMb: Math.floor((Number.isFinite(used) ? used : 0) / 1024) });
  }
  return rows;
}

export function readSwaps() {
  try { return parseProcSwaps(readFileSync(procSwapsPath(), 'utf8')); } catch (_) { return []; }
}

/** Total swap on the host in MB; 0 where /proc/swaps cannot be read (not Linux). */
export function hostSwapMb() {
  return readSwaps().reduce((t, s) => t + s.sizeMb, 0);
}

/** The --memory-swap value for an app container with this max. */
export function appMemorySwapMb(memoryMb, swapMb = hostSwapMb()) {
  const max = Number(memoryMb);
  if (!(swapMb > 0)) return max;
  return max + (max - guaranteedMb(max));
}

const roundUp = (mb) => Math.ceil(mb / STEP_MB) * STEP_MB;
const roundDown = (mb) => Math.floor(mb / STEP_MB) * STEP_MB;

/**
 * What to do with AppCrane's swapfile. Pure.
 * current: { sizeMb, usedMb, active } for our file, or null when it does not exist.
 * disk: { freeMb, totalMb } of the filesystem the file lives on.
 */
export function planSwap({ committedMb, hostMb, otherSwapMb = 0, current = null, disk, floorGb, warnPct }) {
  const wanted = roundUp(Math.max(0, committedMb - hostMb - otherSwapMb));
  const have = current ? current.sizeMb : 0;
  // Free disk if our file did not exist, minus what must stay free.
  const keepMb = Math.max(floorGb * 1024, Math.ceil(disk.totalMb * warnPct / 100));
  const room = roundDown(Math.max(0, disk.freeMb + have - keepMb));
  const target = Math.min(wanted, room);
  const capped = target < wanted;
  const base = { wantedMb: wanted, targetMb: target, capped };

  if (target < STEP_MB) {
    if (!current) return { ...base, action: 'none', reason: capped ? `wanted ${wanted} MB of swap, but the disk has no room above its floor` : 'apps fit in RAM; no swap needed' };
    if (current.usedMb > 0) return { ...base, action: 'none', reason: `${current.usedMb} MB is swapped out; the swapfile is removed once that is back in RAM` };
    return { ...base, action: 'remove', reason: capped ? 'the disk has no room above its floor' : 'apps fit in RAM; no swap needed' };
  }
  if (!current) return { ...base, action: 'create', sizeMb: target, reason: `apps may burst to ${committedMb} MB on ${hostMb} MB of RAM` };
  const drift = Math.abs(target - have);
  if (drift < Math.max(STEP_MB, Math.round(have * 0.1))) {
    return { ...base, action: current.active ? 'none' : 'activate', sizeMb: have, reason: 'swapfile is the right size' };
  }
  if (current.usedMb > 0) return { ...base, action: current.active ? 'none' : 'activate', sizeMb: have, reason: `${current.usedMb} MB is swapped out; resized once that is back in RAM` };
  return { ...base, action: 'resize', sizeMb: target, reason: `from ${have} MB to ${target} MB` };
}

function defaultRun(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 10 * 60_000 }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${cmd} ${args.join(' ')}: ${(stderr || err.message).trim().split('\n')[0]}`));
      else resolve(String(stdout));
    });
  });
}

export function fstabWithSwap(text, path) {
  const lines = String(text || '').split('\n');
  if (lines.some((l) => l.trim().split(/\s+/)[0] === path)) return null;
  const body = String(text || '');
  return `${body}${body && !body.endsWith('\n') ? '\n' : ''}${path} none swap sw 0 0\n`;
}

export function fstabWithoutSwap(text, path) {
  const lines = String(text || '').split('\n');
  const kept = lines.filter((l) => l.trim().split(/\s+/)[0] !== path);
  return kept.length === lines.length ? null : kept.join('\n');
}

async function createFile(path, sizeMb, run) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  try {
    await run('fallocate', ['-l', `${sizeMb}M`, path]);
  } catch (_) {
    // fallocate is refused on some filesystems (and makes holes mkswap rejects on others).
    await run('dd', ['if=/dev/zero', `of=${path}`, 'bs=1M', `count=${sizeMb}`, 'status=none']);
  }
  await run('chmod', ['600', path]);
  await run('mkswap', [path]);
  await run('swapon', [path]);
}

export async function applySwapPlan(plan, { path = swapfilePath(), run = defaultRun, fstab = '/etc/fstab' } = {}) {
  if (plan.action === 'create' || plan.action === 'resize') {
    if (plan.action === 'resize') {
      await run('swapoff', [path]).catch(() => {});
      await run('rm', ['-f', path]);
    }
    await createFile(path, plan.sizeMb, run);
    const next = fstabWithSwap(existsSync(fstab) ? readFileSync(fstab, 'utf8') : '', path);
    if (next != null) writeFileSync(fstab, next);
  } else if (plan.action === 'activate') {
    await run('swapon', [path]);
  } else if (plan.action === 'remove') {
    await run('swapoff', [path]).catch(() => {});
    await run('rm', ['-f', path]);
    if (existsSync(fstab)) {
      const next = fstabWithoutSwap(readFileSync(fstab, 'utf8'), path);
      if (next != null) writeFileSync(fstab, next);
    }
  }
}

function currentFile(path, swaps) {
  const active = swaps.find((s) => s.path === path);
  if (active) return { sizeMb: active.sizeMb, usedMb: active.usedMb, active: true };
  try {
    const sizeMb = Math.floor(statSync(path).size / MiB);
    return sizeMb > 0 ? { sizeMb, usedMb: 0, active: false } : null;
  } catch (_) { return null; }
}

let lastResult = null;
export function lastSwapResult() { return lastResult; }

let running = null;
/** Bring the swapfile to its planned size. Never throws; the result says what happened. */
export function ensureHostSwap(opts = {}) {
  if (!running) running = doEnsure(opts).finally(() => { running = null; });
  return running;
}

async function doEnsure({ db, run = defaultRun, path = swapfilePath(), fstab = '/etc/fstab' } = {}) {
  const at = new Date().toISOString();
  try {
    if (process.env.APPCRANE_MANAGE_SWAP === '0') return (lastResult = { at, action: 'skip', reason: 'APPCRANE_MANAGE_SWAP=0' });
    if (process.platform !== 'linux') return (lastResult = { at, action: 'skip', reason: 'not Linux' });
    if (typeof process.getuid === 'function' && process.getuid() !== 0) return (lastResult = { at, action: 'skip', reason: 'AppCrane is not running as root' });

    const { memoryBudget } = await import('./memoryBudget.js');
    const { readThresholds } = await import('./hostThresholds.js');
    const { getDb } = await import('../db.js');
    const handle = db || getDb();
    const budget = memoryBudget(handle);
    const t = readThresholds(handle);
    const swaps = readSwaps();
    const current = currentFile(path, swaps);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const fsInfo = statfsSync(dirname(path));
    const disk = { freeMb: Math.floor(fsInfo.bavail * fsInfo.bsize / MiB), totalMb: Math.floor(fsInfo.blocks * fsInfo.bsize / MiB) };
    const otherSwapMb = swaps.filter((s) => s.path !== path).reduce((n, s) => n + s.sizeMb, 0);
    const plan = planSwap({
      committedMb: budget.committed_mb, hostMb: budget.host_mb, otherSwapMb, current, disk,
      floorGb: t.disk_floor_gb, warnPct: t.disk_warn_pct,
    });
    await applySwapPlan(plan, { path, run, fstab });
    if (plan.action !== 'none') log.info(`[host-swap] ${plan.action} ${path}${plan.sizeMb ? ` (${plan.sizeMb} MB)` : ''}: ${plan.reason}`);
    if (plan.capped) log.warn(`[host-swap] wanted ${plan.wantedMb} MB of swap, the disk floor allows ${plan.targetMb} MB`);
    return (lastResult = { at, ...plan, path, swapMb: hostSwapMb() });
  } catch (e) {
    log.warn(`[host-swap] ${e.message}`);
    return (lastResult = { at, action: 'error', reason: e.message });
  }
}
