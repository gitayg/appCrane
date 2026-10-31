// What the HOST AppCrane runs on is missing: pending Ubuntu/Debian security
// updates, a reboot the last upgrade asked for, and whether unattended-upgrades
// is installing them on its own. Detection only; hostVulnsNotify.js mails it.
//
// Works without root: pro, apt-get -s, apt-config and dpkg-query all read the
// package cache and dpkg database, which are world-readable. The price is that
// the answer is only as fresh as the cache, which the system's apt-daily timer
// refreshes (AppCrane never runs apt-get update), so the cache age is reported
// alongside and a stale cache is called out.
//
// Not Ubuntu/Debian (a macOS dev box, another distro): { supported: false } and
// no command is run.

import { execFile } from 'child_process';
import { readFileSync, statSync } from 'fs';
import {
  parseProSecurityStatus, parseAptSimulate, parseDpkgVersions,
  parseAptPeriodic, parseOsRelease, parseRebootPkgs,
} from './hostVulnsParse.js';

// apt-daily runs twice a day with a random delay of up to 12 hours, so a cache
// older than two days means the timer is not running (or cannot reach a mirror).
export const STALE_CACHE_MS = 48 * 60 * 60_000;
const EXEC_TIMEOUT_MS = 120_000;

function run(cmd, args) {
  return new Promise((res) => {
    execFile(cmd, args, { timeout: EXEC_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, LC_ALL: 'C' } },
      (err, stdout, stderr) => res({
        code: err ? (typeof err.code === 'number' ? err.code : -1) : 0,
        stdout: String(stdout || ''), stderr: String(stderr || ''),
        missing: err?.code === 'ENOENT',
      }));
  });
}

export const DEFAULT_DEPS = {
  platform: process.platform,
  exec: run,
  readFile: (p) => readFileSync(p, 'utf8'),
  mtimeMs: (p) => statSync(p).mtimeMs,
  now: () => Date.now(),
};

function tryRead(d, p) {
  try { return d.readFile(p); } catch (_) { return null; }
}

function tryMtime(d, p) {
  try { return d.mtimeMs(p); } catch (_) { return null; }
}

// The line worth showing from a failed command: pro prints a traceback and
// then a bug-report hint, so the last line is not the reason.
function reasonLine(s) {
  const l = String(s).trim().split('\n').map((x) => x.trim()).filter(Boolean);
  return l.find((x) => /^E:|error/i.test(x)) || l.pop() || '';
}

// pro first: it is Canonical's own classification (standard security vs ESM).
// It fails for a service user without a writable HOME (it logs to
// ~/.cache/ubuntu-pro; measured as nobody: "Permission denied: '/nonexistent'"),
// and does not exist on Debian, so apt's own view is the fallback.
async function securityUpdates(d) {
  const notes = [];
  const pro = await d.exec('pro', ['security-status', '--format', 'json']);
  const parsed = pro.code === 0 ? parseProSecurityStatus(pro.stdout) : null;
  if (parsed) {
    if (parsed.packages.length) {
      const q = await d.exec('dpkg-query', ['-W', '-f=${Package} ${Version}\n', ...parsed.packages.map((p) => p.name)]);
      const installed = parseDpkgVersions(q.stdout);
      for (const p of parsed.packages) p.installed = installed.get(p.name) ?? null;
    }
    return { source: 'pro', packages: parsed.packages, unavailable: parsed.unavailable, notes };
  }
  if (!pro.missing) notes.push(`pro security-status failed, used apt instead: ${reasonLine(pro.stderr) || `exit ${pro.code}`}`);
  const sim = await d.exec('apt-get', ['-s', '-q', 'dist-upgrade']);
  if (sim.code !== 0) {
    return { source: null, packages: [], unavailable: 0, notes, error: `apt-get -s dist-upgrade failed: ${reasonLine(sim.stderr) || `exit ${sim.code}`}` };
  }
  return { source: 'apt', packages: parseAptSimulate(sim.stdout).packages, unavailable: 0, notes };
}

export async function unattended(d) {
  const st = await d.exec('dpkg-query', ['-W', '-f=${Status}', 'unattended-upgrades']);
  const cfg = await d.exec('apt-config', ['dump', 'APT::Periodic']);
  const periodic = parseAptPeriodic(cfg.stdout);
  const installed = st.code === 0 && /install ok installed/.test(st.stdout);
  return { installed, ...periodic, enabled: installed && periodic.enabled };
}

// update-success-stamp is touched after every successful `apt-get update`
// (15update-stamp, update-notifier-common); the lists directory's mtime is the
// fallback on a box without it, and moves only when a list file changed.
function cacheAge(d, now) {
  for (const [source, p] of [['update-success-stamp', '/var/lib/apt/periodic/update-success-stamp'], ['lists', '/var/lib/apt/lists']]) {
    const t = tryMtime(d, p);
    if (t != null) {
      const ageMs = Math.max(0, now - t);
      return { updatedAt: new Date(t).toISOString(), ageHours: Math.round(ageMs / 36e5), stale: ageMs > STALE_CACHE_MS, source };
    }
  }
  return { updatedAt: null, ageHours: null, stale: true, source: null };
}

/**
 * @returns {Promise<{supported:false, reason:string} | {
 *   supported:true, at:string, os:object, source:'pro'|'apt'|null,
 *   packages:Array<{name,installed,candidate,service}>, unavailable:number,
 *   reboot:{required:boolean, packages:string[]}, unattended:object, cache:object,
 *   notes:string[], error?:string }>}
 */
export async function detectHostVulns(deps = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  if (d.platform !== 'linux') return { supported: false, reason: `not Linux (${d.platform})` };
  const osText = tryRead(d, '/etc/os-release');
  if (osText == null) return { supported: false, reason: '/etc/os-release not readable' };
  const os = parseOsRelease(osText);
  const family = [os.id, ...os.idLike];
  if (!family.includes('ubuntu') && !family.includes('debian')) {
    return { supported: false, reason: `not Ubuntu or Debian (${os.prettyName || os.id || 'unknown'})` };
  }

  const now = d.now();
  const sec = await securityUpdates(d);
  const rebootFlag = tryRead(d, '/var/run/reboot-required');
  const result = {
    supported: true,
    at: new Date(now).toISOString(),
    os: { id: os.id, versionId: os.versionId, prettyName: os.prettyName },
    source: sec.source,
    packages: sec.packages.sort((a, b) => a.name.localeCompare(b.name)),
    unavailable: sec.unavailable,
    reboot: {
      required: rebootFlag != null,
      packages: rebootFlag != null ? parseRebootPkgs(tryRead(d, '/var/run/reboot-required.pkgs')) : [],
    },
    unattended: await unattended(d),
    cache: cacheAge(d, now),
    notes: sec.notes,
  };
  if (sec.error) result.error = sec.error;
  return result;
}

/**
 * Something an admin should act on now: updates to install or a reboot.
 * unattended-upgrades being off is reported with it (and in Job Health), but
 * alone is not mailed: an operator may have turned it off on purpose, and a
 * weekly reminder about a deliberate choice is noise.
 */
export function isActionable(r) {
  return !!r?.supported && (r.packages.length > 0 || r.reboot.required);
}
