// Give running app containers the guaranteed memory they would get today.
//
// Since v2.131.0 an app container starts with --memory-reservation at half its
// max, and memory admission counts that guaranteed half. A container started
// before then has no reservation, so admission counts its whole cap, and a host
// that upgraded reported 16384 of 14131 MB committed while its apps used a few
// hundred MB (31 Oct 2026). Those containers only gained a reservation when
// redeployed or when their limits were re-saved.
//
// At boot, every running app container (appcrane-<slug>-<env>, labelled with
// slug and env) that has a memory cap and no reservation gets one of half its
// cap, live, with `docker update`: no restart. Managed databases and helpers
// are not app containers and keep counting at their cap.
//
// The same pass sets each one's swap allowance to what a new start would get
// (services/hostSwap.js): max + the part above the guarantee where the host
// has swap, equal to the max where it has none. It runs after the swapfile is
// sized, so a container started before the host had swap gets its allowance.

import { execFile } from 'child_process';
import { invalidateMemoryMeasurement, guaranteedMb } from './memoryAdmission.js';
import { appMemorySwapMb, hostSwapMb } from './hostSwap.js';
import log from '../utils/logger.js';

const MiB = 1024 * 1024;
const APP_NAME = /^appcrane-[a-z0-9][a-z0-9-]*-(production|sandbox)$/;

function defaultDocker(args) {
  return new Promise((resolve, reject) => {
    execFile('docker', args, { timeout: 15_000 }, (err, stdout, stderr) => {
      if (err) reject(new Error((stderr || err.message).trim().split('\n')[0]));
      else resolve(String(stdout).trim());
    });
  });
}

/** Parse `docker inspect` lines of "<name>\t<memory>\t<reservation>\t<memory+swap>" (bytes) into the ones to update. */
export function containersWithoutReservation(inspectOut, swapMb = 0) {
  const out = [];
  for (const line of String(inspectOut || '').split('\n')) {
    const [rawName, mem, res, swap] = line.split('\t');
    const name = String(rawName || '').replace(/^\//, '').trim();
    const memBytes = Number(mem);
    if (!APP_NAME.test(name) || !Number.isFinite(memBytes) || memBytes <= 0) continue;
    const maxMb = Math.floor(memBytes / MiB);
    const wantSwapMb = appMemorySwapMb(maxMb, swapMb);
    const hasReservation = Number(res) > 0;
    const swapRight = swap === undefined || Number(swap) === wantSwapMb * MiB;
    if (hasReservation && swapRight) continue;
    out.push({ name, guaranteedMb: guaranteedMb(maxMb), swapMb: swap === undefined ? null : wantSwapMb });
  }
  return out;
}

export async function backfillMemoryReservations({ docker = defaultDocker, swapMb = hostSwapMb() } = {}) {
  const ids = (await docker(['ps', '-q', '--no-trunc', '--filter', 'label=slug', '--filter', 'label=env']))
    .split('\n').map((s) => s.trim()).filter(Boolean);
  if (!ids.length) return { updated: [], failed: [] };
  const todo = containersWithoutReservation(
    await docker(['inspect', '--format', '{{.Name}}\t{{.HostConfig.Memory}}\t{{.HostConfig.MemoryReservation}}\t{{.HostConfig.MemorySwap}}', ...ids]), swapMb);
  const updated = [];
  const failed = [];
  for (const c of todo) {
    if (c.guaranteedMb <= 0) continue;
    try {
      await docker(['update', `--memory-reservation=${c.guaranteedMb}m`, ...(c.swapMb ? [`--memory-swap=${c.swapMb}m`] : []), c.name]);
      updated.push(c.name);
    } catch (e) {
      failed.push({ name: c.name, error: e.message });
    }
  }
  if (updated.length) invalidateMemoryMeasurement();
  return { updated, failed };
}

export async function backfillMemoryReservationsAtBoot() {
  try {
    const { updated, failed } = await backfillMemoryReservations();
    if (updated.length) log.info(`[memory-reservation] gave ${updated.length} running app container(s) their guaranteed memory and swap allowance: ${updated.join(', ')}`);
    for (const f of failed) log.warn(`[memory-reservation] ${f.name}: ${f.error}; it gets one at its next deploy`);
  } catch (e) {
    log.warn(`[memory-reservation] backfill skipped: ${e.message}`);
  }
}
