// v2.6.17: detect container boot crashes within the first few seconds
// and capture the FULL container log before Docker's restart policy
// rotates the buffer.
//
// Problem this fixes. v2.6.15 added `docker logs --tail 200` capture
// on health-check failure, but in a restart loop the last 200 lines
// are dominated by benign boot info from the most recent restart
// attempt — the original Node stack trace (the actual cause) is
// several restarts back and gone from the tail. Operators saw
// "fetch failed" + 200 lines of "step=0..2" info and had no way to
// reach the real `step=3 IMPORT FAILED: …` line on stderr.
//
// What this does. Polls `docker inspect` every 500ms for up to
// `windowMs`. Returns the moment a crash signal appears:
//   - state.Status === 'exited' with non-zero exit code, or
//   - state.RestartCount > 0 (Docker has already restarted once,
//     proving the previous instance crashed)
// On detection, captures the FULL container log (no --tail) so the
// first-attempt stderr is preserved before restart noise piles on top.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const POLL_INTERVAL_MS = 500;
const INSPECT_TIMEOUT_MS = 5000;
const LOG_FETCH_TIMEOUT_MS = 10000;
const LOG_TAIL_LINES = 500;

export async function watchBootForEarlyCrash({ containerName, windowMs = 5000 }) {
  const start = Date.now();
  while (Date.now() - start < windowMs) {
    await sleep(POLL_INTERVAL_MS);
    const state = await inspectContainerState(containerName);
    if (!state) continue;
    if (state.status === 'exited' && state.exitCode !== 0) {
      return {
        crashed: true,
        reason: `exited with code ${state.exitCode}`,
        exitCode: state.exitCode,
        restartCount: state.restartCount,
        elapsedMs: Date.now() - start,
        logTail: await captureFullLog(containerName),
      };
    }
    if (state.restartCount > 0) {
      return {
        crashed: true,
        reason: `restarted ${state.restartCount} time(s) within boot window`,
        exitCode: state.exitCode,
        restartCount: state.restartCount,
        elapsedMs: Date.now() - start,
        logTail: await captureFullLog(containerName),
      };
    }
  }
  return { crashed: false, elapsedMs: Date.now() - start };
}

async function inspectContainerState(containerName) {
  try {
    const { stdout } = await execFileAsync(
      'docker',
      [
        'inspect', containerName, '--format',
        '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}',
      ],
      { timeout: INSPECT_TIMEOUT_MS },
    );
    const parts = stdout.trim().split('|');
    if (parts.length !== 3) return null;
    return {
      status: parts[0],
      exitCode: parseInt(parts[1], 10),
      restartCount: parseInt(parts[2], 10),
    };
  } catch {
    return null;
  }
}

async function captureFullLog(containerName) {
  try {
    const { stdout, stderr } = await execFileAsync(
      'docker',
      ['logs', containerName],
      { timeout: LOG_FETCH_TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024 },
    );
    // Docker merges stdout+stderr into both streams' callbacks depending
    // on the runtime config; combine to be safe, dedupe trivial blanks.
    const combined = `${stdout}${stderr}`.trimEnd();
    if (!combined) return null;
    const lines = combined.split('\n');
    if (lines.length <= LOG_TAIL_LINES) return lines;
    return [
      `… (${lines.length - LOG_TAIL_LINES} earlier lines elided) …`,
      ...lines.slice(-LOG_TAIL_LINES),
    ];
  } catch {
    return null;
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
