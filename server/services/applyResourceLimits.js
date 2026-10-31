// Apply an app's new memory/CPU limits to its running containers, in place.
//
// `--memory`, `--memory-swap` and `--cpus` are `docker run` flags, so a limit
// changed on the Manage page used to sit in the database until the next deploy
// recreated the container, while the memory warning kept reporting the old cap
// (an admin lowered agentix and the mail still said "cap 1024 MB", 31 Oct
// 2026). `docker update` changes all three on a running container without a
// restart. Memory and swap are set together, equal, as at `docker run`
// (docker.js), so the container still gets no swap.
//
// A container already using about as much as the new limit is left alone: the
// kernel would reclaim and then OOM-kill it on the spot. Its new limit applies
// at the next deploy or restart, and the result says so.

import { execFile } from 'child_process';
import { readUsage, invalidateMemoryMeasurement } from './memoryAdmission.js';

const MiB = 1024 * 1024;
export const ENVS = ['production', 'sandbox'];
// Lowering is skipped when current use is above this share of the new limit.
export const LOWER_HEADROOM = 0.9;

function defaultDocker(args) {
  return new Promise((resolve, reject) => {
    execFile('docker', args, { timeout: 15_000 }, (err, stdout, stderr) => {
      if (err) reject(new Error((stderr || err.message).trim().split('\n')[0]));
      else resolve(String(stdout).trim());
    });
  });
}

export async function applyLimitsLive({ slug, memoryMb, cpus }, { docker = defaultDocker, usage = readUsage } = {}) {
  const results = [];
  for (const env of ENVS) {
    const name = `appcrane-${slug}-${env}`;
    let running;
    try { running = (await docker(['inspect', '--format', '{{.State.Running}}', name])) === 'true'; }
    catch (_) { running = false; }
    if (!running) { results.push({ env, applied: false, reason: 'not running' }); continue; }

    const used = (await usage([name])).get(name);
    if (used != null && used > memoryMb * MiB * LOWER_HEADROOM) {
      results.push({
        env, applied: false,
        reason: `uses ${Math.round(used / MiB)} MB, too close to the new ${memoryMb} MB limit to lower it now; it applies at the next deploy or restart`,
      });
      continue;
    }
    try {
      await docker(['update', `--memory=${memoryMb}m`, `--memory-swap=${memoryMb}m`, `--cpus=${cpus}`, name]);
      results.push({ env, applied: true });
    } catch (e) {
      results.push({ env, applied: false, reason: `${e.message}; it applies at the next deploy or restart` });
    }
  }
  invalidateMemoryMeasurement();
  return results;
}
