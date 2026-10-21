// Who gets the CPU when the whole host is busy.
//
// The 2026-08-03 incident: a runaway container saturated both cores of a 2-core
// host, and Caddy and sshd got so little CPU that the site and SSH timed out.
// A --cpus cap bounds one container; it does nothing about many containers, an
// uncapped one, or a build. What keeps the host reachable is RELATIVE WEIGHT:
// under contention the kernel splits CPU between sibling cgroups in proportion
// to their weight, and only under contention ("This is only enforced when CPU
// cycles are constrained", Docker's resource-constraints page on --cpu-shares).
//
// Where the siblings are. With the systemd cgroup driver (the default on
// cgroup v2 hosts), dockerd's docs: the default cgroup parent "defaults to
// /docker for the cgroupfs driver, and system.slice for the systemd cgroup
// driver", so every container is a docker-<id>.scope next to caddy.service,
// ssh.service and appcrane.service in system.slice, and BuildKit's RUN steps
// land there too (moby newCgroupParent: "system.slice" + ":docker:"). systemd's
// resource-control manual: "The available CPU time is split up among all units
// within one slice relative to their CPU time weight", range 1 to 10000, "the
// kernel default is 100". With no flags a container weighs 100, exactly what
// Caddy and sshd weigh, so ten busy containers out-vote them ten to one.
//
// The numbers. Docker takes --cpu-shares (cgroup v1 units, default 1024) and
// runc converts them to cgroup v2 cpu.weight. runc <= 1.2 converts linearly,
// 1 + (shares - 2) * 9999 / 262142; opencontainers/cgroups (runc 1.3+) uses a
// curve that maps 1024 to 100. Both are covered:
//
//   container         shares   weight (linear / curve)
//   app, helper        128        5 / 21
//   managed database   256       10 / 35   (a stalled database stalls every app on it)
//   build                2        1 / 1
//   host services        -      1000       (systemd CPUWeight=, no conversion)
//
// So Caddy, sshd and AppCrane outweigh any single app container by 48x or
// more, and still hold the majority against 40 busy app containers. On a
// cgroupfs-driver host containers sit under /docker, a sibling of system.slice
// at the root: the host side then gets at least half the CPU under contention
// and the weights below order containers among themselves.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { availableParallelism, cpus as osCpus, totalmem } from 'os';
import { join } from 'path';

export const CPU_SHARES = Object.freeze({ app: 128, db: 256, build: 2 });
export const HOST_CPU_WEIGHT = 1000;

export const CPU_APP_FLAG = `--cpu-shares=${CPU_SHARES.app}`;
export const CPU_DB_FLAG = `--cpu-shares=${CPU_SHARES.db}`;

export const HOST_UNITS = Object.freeze(['appcrane.service', 'caddy.service', 'ssh.service', 'sshd.service']);
export const DROPIN_NAME = '50-appcrane-cpu-priority.conf';
export const SYSTEMD_DIR = '/etc/systemd/system';

const CFS_PERIOD_US = 100_000;
const MiB = 1024 * 1024;

export function hostCores() {
  try { return availableParallelism(); } catch (_) { return Math.max(1, osCpus().length); }
}

function positive(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * The CPU and memory a build may use. CPU: every core but one, at least one,
 * so the host keeps a whole core for Caddy, sshd and AppCrane while a build
 * runs (on a 2-core box: one core each). Memory: the host's RAM minus the same
 * reserve memory admission keeps (1 GiB or 10%, whichever is larger), at least
 * 1 GiB, so a build can no longer take the host into a whole-host OOM but is
 * not squeezed below what it could use before. APPCRANE_BUILD_CPUS and
 * APPCRANE_BUILD_MEMORY_MB override.
 */
export function buildLimits({ env = process.env, cores = hostCores(), totalBytes = totalmem() } = {}) {
  const cpus = positive(env.APPCRANE_BUILD_CPUS) ?? Math.max(1, cores - 1);
  const totalMb = Math.floor(totalBytes / MiB);
  const reserveMb = Math.max(1024, Math.floor(totalMb * 0.1));
  const memoryMb = Math.floor(positive(env.APPCRANE_BUILD_MEMORY_MB) ?? Math.max(1024, totalMb - reserveMb));
  return { cpus, memoryMb, cpusSource: positive(env.APPCRANE_BUILD_CPUS) ? 'env' : 'default' };
}

/**
 * `docker build` flags for those limits. The classic builder applies them to
 * every build container. Under BuildKit, `docker build` is buildx, whose
 * handling depends on its version (see buildCapStatus): buildx >= 0.35 turns
 * these same legacy flags into per-step --resource limits; older buildx parses
 * and ignores them. --resource itself is NOT used: buildx < 0.35 rejects it as
 * an unknown flag, which would fail every build.
 */
export function buildResourceArgs(limits = buildLimits()) {
  const quota = Math.max(1000, Math.round(limits.cpus * CFS_PERIOD_US));
  return [
    `--cpu-period=${CFS_PERIOD_US}`, `--cpu-quota=${quota}`, `--cpu-shares=${CPU_SHARES.build}`,
    `--memory=${limits.memoryMb}m`, `--memory-swap=${limits.memoryMb}m`,
  ];
}

/** nixpacks build flags; nixpacks passes them to `docker build` (it has no period or shares flag). */
export function nixpacksResourceArgs(limits = buildLimits()) {
  return ['--cpu-quota', String(Math.max(1000, Math.round(limits.cpus * CFS_PERIOD_US))), '--memory', `${limits.memoryMb}m`];
}

/** "github.com/docker/buildx v0.35.0-desktop.2 <sha>" -> [0, 35, 0]; null when unreadable. */
export function parseBuildxVersion(out) {
  const m = /\bv(\d+)\.(\d+)\.(\d+)/.exec(String(out || ''));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** Whether a build's caps are in force, from the builder in use and the buildx version. */
export function buildCapStatus({ buildkit, buildxVersion }) {
  if (!buildkit) return { enforced: true, detail: 'classic builder: the caps apply to every build container' };
  const v = parseBuildxVersion(buildxVersion);
  if (!v) return { enforced: null, detail: 'BuildKit with an unreadable buildx version: unknown whether the caps apply' };
  const atLeast035 = v[0] > 0 || v[1] >= 35;
  return atLeast035
    ? { enforced: true, detail: `buildx ${v.join('.')}: the caps apply to each build step (steps that run in parallel are capped one by one)` }
    : { enforced: false, detail: `buildx ${v.join('.')} accepts and ignores per-build CPU and memory flags (0.35 or later applies them); builds run uncapped` };
}

export function dropInContent(weight = HOST_CPU_WEIGHT) {
  return '# Written by AppCrane. Under CPU contention this service outweighs app containers\n'
    + '# (--cpu-shares 128 to 256) so the site and SSH stay reachable.\n'
    + `[Service]\nCPUWeight=${weight}\n`;
}

function unitKnown(unit, { unitDir, exists }) {
  return [join(unitDir, unit), `/lib/systemd/system/${unit}`, `/usr/lib/systemd/system/${unit}`].some((p) => exists(p));
}

/**
 * Give Caddy, sshd and AppCrane CPUWeight=1000 through a drop-in per unit,
 * idempotently: a file is written only when its content differs, and
 * `systemctl daemon-reload` runs only when something was written. Each written
 * unit then gets the same weight live (`systemctl set-property --runtime`, which
 * the manual describes as setting unit properties "at runtime where this is
 * supported"), so a running Caddy does not wait for its next restart.
 * Never throws: an install that is not root, or not systemd, gets a status
 * saying what to do instead.
 */
export function ensureHostCpuPriority({
  unitDir = SYSTEMD_DIR,
  units = HOST_UNITS,
  platform = process.platform,
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
  exists = existsSync,
  read = (p) => readFileSync(p, 'utf8'),
  write = (p, s) => writeFileSync(p, s, { mode: 0o644 }),
  mkdir = (p) => mkdirSync(p, { recursive: true }),
  run = (cmd, args) => execFileSync(cmd, args, { stdio: 'pipe', timeout: 15_000 }),
  isSystemd = () => existsSync('/run/systemd/system'),
} = {}) {
  const at = new Date().toISOString();
  try {
    if (platform !== 'linux') return { status: 'unsupported', at, reason: `not Linux (${platform})` };
    if (!isSystemd()) return { status: 'unsupported', at, reason: 'not a systemd host' };
    const content = dropInContent();
    const present = units.filter((u) => unitKnown(u, { unitDir, exists }));
    const pending = present.filter((u) => {
      const p = join(unitDir, `${u}.d`, DROPIN_NAME);
      try { return !exists(p) || read(p) !== content; } catch (_) { return true; }
    });
    if (!pending.length) return { status: 'already', at, units: present };
    if (uid !== 0) {
      return {
        status: 'not-permitted', at, units: present, missing: pending,
        reason: `not root; as root write ${join(unitDir, '<unit>.d', DROPIN_NAME)} with "[Service] CPUWeight=${HOST_CPU_WEIGHT}" for ${pending.join(', ')} and run systemctl daemon-reload (see the README host hardening note)`,
      };
    }
    for (const u of pending) {
      mkdir(join(unitDir, `${u}.d`));
      write(join(unitDir, `${u}.d`, DROPIN_NAME), content);
    }
    run('systemctl', ['daemon-reload']);
    const live = [];
    for (const u of pending) {
      try { run('systemctl', ['set-property', '--runtime', u, `CPUWeight=${HOST_CPU_WEIGHT}`]); live.push(u); } catch (_) { /* unit not loaded: the drop-in applies on its next start */ }
    }
    return { status: 'set', at, units: present, written: pending, live };
  } catch (e) {
    return { status: 'failed', at, reason: e.message };
  }
}

let lastHostStatus = null;

export function recordHostCpuPriority(status) {
  lastHostStatus = status;
  return status;
}

export function getHostCpuPriority() {
  return lastHostStatus;
}

let buildCapCache = null;

/** Whether builds on this host honour the caps: the builder AppCrane picks (docker.js dockerBuildEnv) and buildx's version. */
export async function readBuildCapStatus({ env = process.env, exec } = {}) {
  if (buildCapCache && !exec) return buildCapCache;
  const run = exec || ((cmd, args) => new Promise((res, rej) => {
    execFile(cmd, args, { timeout: 10_000 }, (err, stdout) => (err ? rej(err) : res(String(stdout))));
  }));
  let buildxVersion = null;
  try { buildxVersion = await run('docker', ['buildx', 'version']); } catch (_) { buildxVersion = null; }
  const override = env.APPCRANE_DOCKER_BUILDKIT;
  const buildkit = override !== undefined ? override !== '0' : buildxVersion !== null;
  const limits = buildLimits({ env });
  const status = { ...buildCapStatus({ buildkit, buildxVersion }), buildkit, cpus: limits.cpus, memory_mb: limits.memoryMb };
  if (!exec) buildCapCache = status;
  return status;
}
