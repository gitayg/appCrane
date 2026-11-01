import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  parseProcSwaps, appMemorySwapMb, planSwap, fstabWithSwap, fstabWithoutSwap, applySwapPlan, hostSwapMb, STEP_MB,
} from '../server/services/hostSwap.js';

const PROC = `Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority
/swap.img                               file\t\t2097148\t\t1024\t\t-2
/var/lib/appcrane/swapfile              file\t\t7340028\t\t0\t\t-3
`;
const DISK = { freeMb: 100_000, totalMb: 400_000 };
const T = { floorGb: 5, warnPct: 10 };

test('/proc/swaps is read into sizes and use in MB', () => {
  assert.deepEqual(parseProcSwaps(PROC), [
    { path: '/swap.img', sizeMb: 2047, usedMb: 1 },
    { path: '/var/lib/appcrane/swapfile', sizeMb: 7167, usedMb: 0 },
  ]);
  assert.deepEqual(parseProcSwaps('Filename Type Size Used Priority\n'), []);
});

test('hostSwapMb reads the file APPCRANE_PROC_SWAPS names, and is 0 when it cannot be read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'swaps-'));
  try {
    writeFileSync(join(dir, 'swaps'), PROC);
    process.env.APPCRANE_PROC_SWAPS = join(dir, 'swaps');
    assert.equal(hostSwapMb(), 2047 + 7167);
    process.env.APPCRANE_PROC_SWAPS = join(dir, 'absent');
    assert.equal(hostSwapMb(), 0);
  } finally {
    delete process.env.APPCRANE_PROC_SWAPS;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an app may swap out the part above its guarantee only when the host has swap', () => {
  assert.equal(appMemorySwapMb(512, 4096), 768);
  assert.equal(appMemorySwapMb(1001, 4096), 1001 + (1001 - 500));
  assert.equal(appMemorySwapMb(512, 0), 512);
});

test('swapfile size = every app max (both environments) - host RAM - other swap, rounded up', () => {
  const p = planSwap({ committedMb: 40_000, hostMb: 32_092, otherSwapMb: 0, current: null, disk: DISK, ...T });
  assert.equal(p.action, 'create');
  assert.equal(p.sizeMb, Math.ceil(7908 / STEP_MB) * STEP_MB);
  const withOther = planSwap({ committedMb: 40_000, hostMb: 32_092, otherSwapMb: 2048, current: null, disk: DISK, ...T });
  assert.equal(withOther.sizeMb, Math.ceil(5860 / STEP_MB) * STEP_MB);
});

test('no swapfile when the apps fit in RAM', () => {
  assert.equal(planSwap({ committedMb: 8000, hostMb: 16_000, current: null, disk: DISK, ...T }).action, 'none');
});

test('the swapfile never takes free disk below the floor or the warning percentage', () => {
  // 20 GB free of 100 GB: keep max(5 GB, 10 GB) = 10 GB, so 10 GB of room.
  const p = planSwap({ committedMb: 60_000, hostMb: 16_000, current: null, disk: { freeMb: 20_480, totalMb: 102_400 }, ...T });
  assert.equal(p.action, 'create');
  assert.equal(p.sizeMb, 10_240);
  assert.equal(p.capped, true);
  // 4 GB free (app.opswat.com, 31 Oct 2026): no room at all.
  const none = planSwap({ committedMb: 32_000, hostMb: 15_701, current: null, disk: { freeMb: 4096, totalMb: 98_099 }, ...T });
  assert.equal(none.action, 'none');
  assert.match(none.reason, /no room/);
});

test('the swapfile grows; it shrinks or goes only while nothing is swapped out to it', () => {
  const base = { hostMb: 16_000, disk: DISK, ...T };
  assert.equal(planSwap({ ...base, committedMb: 26_000, current: { sizeMb: 4096, usedMb: 900, active: true } }).action, 'none',
    'growing would need a swapoff of a used file');
  assert.equal(planSwap({ ...base, committedMb: 26_000, current: { sizeMb: 4096, usedMb: 0, active: true } }).action, 'resize');
  assert.equal(planSwap({ ...base, committedMb: 20_100, current: { sizeMb: 4096, usedMb: 0, active: true } }).action, 'none', 'within 10%: left alone');
  assert.equal(planSwap({ ...base, committedMb: 12_000, current: { sizeMb: 4096, usedMb: 10, active: true } }).action, 'none');
  assert.equal(planSwap({ ...base, committedMb: 12_000, current: { sizeMb: 4096, usedMb: 0, active: true } }).action, 'remove');
  assert.equal(planSwap({ ...base, committedMb: 20_100, current: { sizeMb: 4096, usedMb: 0, active: false } }).action, 'activate',
    'a file left over from a reboot without fstab is switched back on');
});

test('fstab gains one line for the swapfile, once, and loses only that line', () => {
  const f = 'UUID=abc / ext4 defaults 0 1\n';
  const added = fstabWithSwap(f, '/var/lib/appcrane/swapfile');
  assert.equal(added, `${f}/var/lib/appcrane/swapfile none swap sw 0 0\n`);
  assert.equal(fstabWithSwap(added, '/var/lib/appcrane/swapfile'), null);
  assert.equal(fstabWithoutSwap(added, '/var/lib/appcrane/swapfile'), f);
  assert.equal(fstabWithoutSwap(f, '/var/lib/appcrane/swapfile'), null);
});

test('create runs fallocate, chmod 600, mkswap, swapon, then records it in fstab; remove undoes it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'swapplan-'));
  const fstab = join(dir, 'fstab');
  const path = join(dir, 'sub', 'swapfile');
  writeFileSync(fstab, 'UUID=abc / ext4 defaults 0 1\n');
  const calls = [];
  const run = async (cmd, args) => { calls.push([cmd, ...args].join(' ')); return ''; };
  try {
    await applySwapPlan({ action: 'create', sizeMb: 1024 }, { path, run, fstab });
    assert.deepEqual(calls, [`fallocate -l 1024M ${path}`, `chmod 600 ${path}`, `mkswap ${path}`, `swapon ${path}`]);
    assert.match(readFileSync(fstab, 'utf8'), new RegExp(`${path} none swap sw 0 0`));
    calls.length = 0;
    await applySwapPlan({ action: 'remove' }, { path, run, fstab });
    assert.deepEqual(calls, [`swapoff ${path}`, `rm -f ${path}`]);
    assert.equal(readFileSync(fstab, 'utf8'), 'UUID=abc / ext4 defaults 0 1\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('where fallocate is refused, the file is written with dd', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'swapdd-'));
  const calls = [];
  const run = async (cmd, args) => { calls.push(cmd); if (cmd === 'fallocate') throw new Error('Operation not supported'); return ''; };
  try {
    await applySwapPlan({ action: 'create', sizeMb: 256 }, { path: join(dir, 'swapfile'), run, fstab: join(dir, 'fstab') });
    assert.deepEqual(calls, ['fallocate', 'dd', 'chmod', 'mkswap', 'swapon']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
