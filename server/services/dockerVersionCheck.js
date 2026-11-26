// Job Health 'docker-version': is this host's Docker one whose reload breaks
// host.docker.internal, and where did its packages come from?
//
// A dockerd reload (SIGHUP) on 28.x and 29.0-29.2 empties host-gateway, and
// every container created afterwards gets "invalid IP" for host.docker.internal
// (measured in dind, 2026-11-25: 27.5.1 ok; 28.0.4, 28.5.2, 29.0.0, 29.1.3,
// 29.2.0 broken; 29.3.0, 29.4.0, 29.5.0, 29.10.1 ok; 28.0.0-28.0.3 and 29.2.1
// unmeasured, counted as broken). Ubuntu's docker.io is 29.1.3 on 24.04 and
// 25.10, so the fix is Docker CE from Docker's repository: scripts/docker-upgrade.sh.
// The same version set is in scripts/lib/docker-ce.sh and scripts/host-hardening.sh.
//
// A warning on the row, never a failure: the platform keeps serving.

import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';

const execFileAsync = promisify(execFile);

export const JOB_ID = 'docker-version';
export const MIN_FIXED = '29.3.0';
export const UPGRADE_SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'docker-upgrade.sh');
const CHECK_MS = 24 * 60 * 60_000;
const STARTUP_DELAY_MS = 20_000;
const EXEC_TIMEOUT_MS = 15_000;
const DOCKERD_PATHS = ['/usr/bin/dockerd', '/usr/sbin/dockerd'];
const DOCKER_PKG = /^(docker\.io|docker-ce|docker-ce-cli|docker-ce-rootless-extras|containerd|containerd\.io|runc|docker-buildx|docker-buildx-plugin|docker-compose-v2|docker-compose-plugin)$/;

/** "5:29.10.1-1~ubuntu.24.04~noble" or "29.1.3-0ubuntu3~24.04.2" -> "29.10.1"; null when not a version. */
export function upstreamVersion(s) {
  const m = /^(?:\d+:)?(\d+)\.(\d+)(?:\.(\d+))?/.exec(String(s ?? '').trim());
  return m ? `${m[1]}.${m[2]}.${m[3] ?? '0'}` : null;
}

function parts(v) {
  return upstreamVersion(v).split('.').map(Number);
}

export function versionAtLeast(v, min) {
  if (!upstreamVersion(v) || !upstreamVersion(min)) return false;
  const a = parts(v), b = parts(min);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return true;
}

/** True when a dockerd reload on this version breaks host-gateway. */
export function hasReloadBug(v) {
  if (!upstreamVersion(v)) return false;
  return versionAtLeast(v, '28.0.0') && !versionAtLeast(v, MIN_FIXED);
}

/** `dpkg -l` -> [{ state, name, version }] for the package rows (state ii, rc, ...). */
export function parseDpkgList(text) {
  const rows = [];
  for (const line of String(text ?? '').split('\n')) {
    const m = /^([a-zA-Z]{2})[A-Z]?\s+(\S+)\s+(\S+)/.exec(line);
    if (!m) continue;
    rows.push({ state: m[1].toLowerCase(), name: m[2].replace(/:[a-z0-9]+$/, ''), version: m[3] });
  }
  return rows;
}

/** `dpkg -S /usr/bin/dockerd` -> "docker.io"; null when no package owns it. */
export function parseDpkgSearch(text) {
  for (const line of String(text ?? '').split('\n')) {
    const m = /^([^\s:][^:]*):\s+\//.exec(line);
    if (m) return m[1].split(',')[0].trim().replace(/:[a-z0-9]+$/, '');
  }
  return null;
}

/** `apt-cache policy a b` -> { a: { installed, candidate }, ... }; "(none)" becomes null. */
export function parseAptPolicy(text) {
  const out = {};
  let cur = null;
  for (const line of String(text ?? '').split('\n')) {
    const head = /^(\S+):\s*$/.exec(line);
    if (head) { cur = out[head[1]] = { installed: null, candidate: null }; continue; }
    if (!cur) continue;
    const f = /^\s+(Installed|Candidate):\s+(\S+)/.exec(line);
    if (f) cur[f[1].toLowerCase()] = f[2] === '(none)' ? null : f[2];
  }
  return out;
}

/** The Job Health detail for what was read off the host. Pure. */
export function evaluateDockerHost({ serverVersion, owner, dpkgList, policy, script = UPGRADE_SCRIPT } = {}) {
  const fix = `Fix, in a maintenance window: sudo bash ${script} (installs Docker CE ${MIN_FIXED} or later from Docker's repository in place of docker.io; Docker restarts, so every container restarts).`;
  const rows = (dpkgList || []).filter((r) => DOCKER_PKG.test(r.name));
  const installed = rows.filter((r) => r.state === 'ii');
  const leftovers = rows.filter((r) => r.state === 'rc').map((r) => r.name);
  const has = (n) => installed.some((r) => r.name === n);
  const ceInstalled = installed.filter((r) => r.name.startsWith('docker-ce')).map((r) => r.name);
  const mixed = has('docker.io') && ceInstalled.length > 0;
  const source = owner === 'docker.io' ? 'docker.io (Ubuntu)'
    : owner && owner.startsWith('docker-ce') ? 'docker-ce (Docker repository)'
      : owner || 'unknown';
  const version = upstreamVersion(serverVersion);
  const distroCandidate = policy?.['docker.io']?.candidate || null;
  const ceCandidate = policy?.['docker-ce']?.candidate || null;
  const bad = !!version && hasReloadBug(version);

  const msgs = [];
  let severity = null;
  if (!version) {
    msgs.push('Docker is not answering (docker version gave no server version); the version check could not run.');
    severity = 'warning';
  } else if (bad) {
    msgs.push(`Docker ${version} (${source}) has the reload bug: after a dockerd reload, every new container gets "invalid IP" for host.docker.internal and cannot reach AppCrane or its databases. AppCrane does not reload it, but a reload by anything else breaks new app containers until Docker restarts.`);
    if (distroCandidate && owner === 'docker.io') {
      const dv = upstreamVersion(distroCandidate);
      msgs.push(hasReloadBug(dv) ? `Ubuntu's newest docker.io here is ${dv}, also affected.` : `Ubuntu offers docker.io ${dv}.`);
    }
    msgs.push(fix);
    severity = 'warning';
  } else {
    msgs.push(`Docker ${version} (${source}) reloads without breaking host.docker.internal.`);
  }
  if (mixed) {
    msgs.push(`docker.io and Docker CE packages are both installed (${ceInstalled.join(', ')}): a mixed-source Docker that can wedge the daemon socket.`);
    if (!bad) msgs.push(fix);
    severity = 'warning';
  }
  if (leftovers.length) {
    msgs.push(`Removed package(s) with their config still on disk (dpkg state rc): ${leftovers.join(', ')}. Harmless; the upgrade script reinstalls them from Docker's repository and keeps that config.`);
    severity = severity || 'info';
  }
  return {
    message: msgs.join(' '),
    ...(severity ? { severity } : {}),
    version, source, owner: owner || null, reload_bug: bad, mixed_source: mixed,
    installed: installed.map((r) => `${r.name}=${r.version}`), leftovers,
    distro_candidate: distroCandidate, docker_ce_candidate: ceCandidate,
  };
}

async function defaultExec(cmd, args) {
  const { stdout } = await execFileAsync(cmd, args, { timeout: EXEC_TIMEOUT_MS, env: { ...process.env, LC_ALL: 'C' } });
  return stdout;
}

let execImpl = defaultExec;
let pathExists = existsSync;

/** Test seam: replace the command runner ((cmd, args) -> stdout) and the dockerd path probe. */
export function _setDockerVersionExecForTests(fn, exists) {
  execImpl = fn || defaultExec;
  pathExists = exists || existsSync;
}

async function tryExec(cmd, args) {
  try { return await execImpl(cmd, args); } catch (_) { return ''; }
}

export async function runDockerVersionCheck() {
  const serverVersion = (await tryExec('docker', ['version', '--format', '{{.Server.Version}}'])).trim();
  let owner = null;
  for (const p of DOCKERD_PATHS) {
    if (!pathExists(p)) continue;
    owner = parseDpkgSearch(await tryExec('dpkg', ['-S', p]));
    if (owner) break;
  }
  const dpkgList = parseDpkgList(await tryExec('dpkg', ['-l']));
  const policy = parseAptPolicy(await tryExec('apt-cache', ['policy', 'docker.io', 'docker-ce']));
  const detail = evaluateDockerHost({ serverVersion, owner, dpkgList, policy });
  setJobDetail(JOB_ID, detail);
  return detail;
}

let timer = null;

export function startDockerVersionCheck() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: CHECK_MS });
  const tick = () => trackJob(JOB_ID, () => runDockerVersionCheck()).catch((e) => log.warn(`[docker-version] ${e.message}`));
  setTimeout(tick, STARTUP_DELAY_MS).unref?.();
  timer = setInterval(tick, CHECK_MS);
  timer.unref?.();
}
