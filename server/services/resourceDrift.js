// Are an app's CONFIGURED cpu/memory limits actually in force on its container?
//
// `--memory` and `--cpus` are `docker run` arguments. Changing max_ram_mb on a
// running app rewrites the database row and nothing else — the container keeps
// the command line it was created with until it is RECREATED. Every AppCrane
// surface reported the configured number, so a container running with NO memory
// limit looked exactly like one running with 512 MB.
//
// The August 2026 incident review is what this is for. It recorded clamd being
// OOM-killed at 992 MB anonymous RSS on an app configured `max_ram_mb: 512`.
// Those two figures cannot both be true: a 512 MB cgroup limit kills the process
// at 512 MB, so it can never reach 992 MB. The limit was not applied — and the
// review instead concluded that per-container limits are ineffective and that
// the fix was host swap. A wrong root cause, reached because no surface could
// distinguish "configured" from "applied".
//
// Same shape as ingressDrift: pure, comparing an app row against an already
// observed container state, knowing nothing about how that state was read.

const MB = 1024 * 1024;
const NANO = 1e9;

/** Docker rounds nothing here, but be tolerant of float dust in NanoCpus. */
const cpusClose = (a, b) => Math.abs(a - b) < 1e6;   // 0.001 of a CPU

/**
 * @param {object} app       app row with max_ram_mb / max_cpu_percent
 * @param {object|null} observed
 *   `null` when the container's state could not be read (Docker unreachable, or
 *   no container exists). Reported as `applied: null` — UNKNOWN — never as
 *   "not applied": saying a limit is missing because we failed to look is the
 *   same class of wrong answer this module exists to remove.
 *   Otherwise `{ memoryBytes, nanoCpus, running }` straight from docker inspect.
 * @returns {{ applied: boolean|null, findings: object[] }}
 */
export function resourceDrift(app, observed) {
  const wantMb = Number(app?.max_ram_mb) || 512;
  const wantPct = Number(app?.max_cpu_percent) || 50;
  const expected = { memory_mb: wantMb, cpu_percent: wantPct };

  if (observed === null || observed === undefined) {
    return { applied: null, expected, actual: null, findings: [] };
  }

  const findings = [];
  const actual = {
    memory_mb: observed.memoryBytes ? Math.round(observed.memoryBytes / MB) : 0,
    cpu_percent: observed.nanoCpus ? Math.round((observed.nanoCpus / NANO) * 100) : 0,
    running: !!observed.running,
  };

  // memoryBytes === 0 is Docker's own encoding for "no limit at all". It is a
  // different and far worse state than "limited to the wrong number": the
  // container can take the whole host, and on a box with no swap that ends as a
  // global OOM kill of whatever the kernel judges largest.
  if (observed.memoryBytes === 0) {
    findings.push({
      resource: 'memory', state: 'not_applied',
      expected_mb: wantMb, actual_mb: 0,
      message: `NO memory limit is in force on this container. AppCrane reports max_ram_mb=${wantMb}, ` +
        'but the container was created without --memory and can consume the entire host. ' +
        'A port publish and a resource limit are both `docker run` flags: they land only when the ' +
        'container is RECREATED (a deploy, or POST /api/apps/<slug>/restart/<env> — not `docker restart`, ' +
        'which reuses the existing container and its flags).',
    });
  } else if (Math.abs(observed.memoryBytes - wantMb * MB) >= MB) {
    findings.push({
      resource: 'memory', state: 'stale',
      expected_mb: wantMb, actual_mb: actual.memory_mb,
      message: `The container is limited to ${actual.memory_mb} MB, but AppCrane is configured for ` +
        `${wantMb} MB. The container predates the change — recreate it to apply.`,
    });
  }

  if (observed.nanoCpus === 0) {
    findings.push({
      resource: 'cpu', state: 'not_applied',
      expected_percent: wantPct, actual_percent: 0,
      message: `NO CPU limit is in force on this container. AppCrane reports max_cpu_percent=${wantPct}, ` +
        'but the container was created without --cpus and can saturate every core. Recreate it to apply. ' +
        'Note --cpus is a HARD ceiling (a CFS quota), not a share — so once applied it does cap the container.',
    });
  } else if (!cpusClose(observed.nanoCpus, (wantPct / 100) * NANO)) {
    findings.push({
      resource: 'cpu', state: 'stale',
      expected_percent: wantPct, actual_percent: actual.cpu_percent,
      message: `The container is capped at ${actual.cpu_percent}% of a CPU, but AppCrane is configured ` +
        `for ${wantPct}%. Recreate it to apply.`,
    });
  }

  return { applied: findings.length === 0, expected, actual, findings };
}
