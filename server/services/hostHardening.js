// Settings > Job Health > Host limits: what scripts/host-hardening.sh sets on
// this host, read without root, and running the script on request.
//
// Status reads files and runs read-only commands only. Applying needs root:
// as root the repo copy is run directly; as any other user only the root-owned
// copy scripts/install-host-hardening.sh installs, through the sudoers rule it
// writes. The repo copy is never sudoed: self-update rewrites it as the run
// user. Without that rule the page shows the command to run by hand.

import { spawn } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, readdirSync, statSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { DEFAULT_DEPS as VULN_DEPS, unattended } from './hostVulns.js';

export const INSTALLED_SCRIPT = '/usr/local/lib/appcrane/host-hardening.sh';
export const SUDOERS_FILE = '/etc/sudoers.d/appcrane-host-hardening';
export const LAST_RUN_KEY = 'host_hardening_last_run';
export const RESERVE_BYTES = 1024 ** 3;
export const RUN_TIMEOUT_MS = 10 * 60_000;
export const OUTPUT_CAP = 64 * 1024;

const REPO_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export const DEFAULT_DEPS = {
  platform: process.platform,
  getuid: () => (typeof process.getuid === 'function' ? process.getuid() : null),
  exec: VULN_DEPS.exec,
  readFile: (p) => readFileSync(p, 'utf8'),
  readdir: (p) => readdirSync(p),
  stat: (p) => statSync(p),
  spawn,
  repoDir: REPO_DIR,
  // Resolved as the script resolves DATA_DIR from .env: relative to the repo.
  dataDir: () => resolve(REPO_DIR, process.env.DATA_DIR || 'data'),
};

export const ITEMS = [
  ['journal', 'Journal size limit'],
  ['syslog-rotation', 'Syslog size-based rotation'],
  ['logrotate-hourly', 'Hourly logrotate'],
  ['docker-log-defaults', 'Docker default log limits'],
  ['apt-news', 'Ubuntu Pro apt news off'],
  ['unattended-upgrades', 'Unattended security upgrades'],
  ['caddy-log-dir', 'Caddy access-log directory'],
  ['disk-reserve', '1 GiB disk reserve file'],
];

const applied = (detail) => ({ state: 'applied', detail });
const missing = (detail) => ({ state: 'missing', detail });
const na = (detail) => ({ state: 'not-applicable', detail });
const unknown = (detail) => ({ state: 'unknown', detail });

// { text } | { absent: true } | { error }
function readState(d, p) {
  try { return { text: d.readFile(p) }; } catch (e) {
    return e?.code === 'ENOENT' || e?.code === 'ENOTDIR' ? { absent: true } : { error: e?.code || e?.message || 'unreadable' };
  }
}

function statState(d, p) {
  try { return { st: d.stat(p) }; } catch (e) {
    return e?.code === 'ENOENT' || e?.code === 'ENOTDIR' ? { absent: true } : { error: e?.code || e?.message || 'unreadable' };
  }
}

function tryReaddir(d, p) {
  try { return d.readdir(p); } catch (_) { return []; }
}

function reasonLine(s) {
  const l = String(s || '').trim().split('\n').map((x) => x.trim()).filter(Boolean);
  return l.find((x) => /^E:|error/i.test(x)) || l.pop() || '';
}

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const UNITS = { B: 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4, P: 1024 ** 5, E: 1024 ** 6 };

/** journald / journalctl sizes ("500M", "1.2G", "4096") -> bytes, or null. */
export function parseSize(s) {
  const m = /^\s*(\d+(?:\.\d+)?)\s*([BKMGTPE])?\s*$/i.exec(String(s ?? ''));
  return m ? Math.round(Number(m[1]) * UNITS[(m[2] || 'B').toUpperCase()]) : null;
}

/** Every value of <key> inside [<section>] of a systemd-style ini text, in order. */
export function iniValues(text, section, key) {
  const out = [];
  let cur = null;
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const sec = /^\[(.+)\]$/.exec(line);
    if (sec) { cur = sec[1]; continue; }
    if (cur !== section) continue;
    const kv = /^([^=]+?)\s*=\s*(.*)$/.exec(line);
    if (kv && kv[1] === key) out.push(kv[2]);
  }
  return out;
}

// journald.conf, then the drop-ins sorted by file name; for one name /etc wins
// over /run over /usr/lib (systemd's order).
function journaldFiles(d) {
  const byName = new Map();
  for (const dir of ['/usr/lib/systemd/journald.conf.d', '/run/systemd/journald.conf.d', '/etc/systemd/journald.conf.d']) {
    for (const f of tryReaddir(d, dir)) if (f.endsWith('.conf')) byName.set(f, join(dir, f));
  }
  return ['/etc/systemd/journald.conf', ...[...byName.keys()].sort().map((k) => byName.get(k))];
}

async function journalItem(d) {
  let max = null;
  let from = null;
  let sawConfig = false;
  for (const p of journaldFiles(d)) {
    const r = readState(d, p);
    if (r.text == null) continue;
    sawConfig = true;
    const v = iniValues(r.text, 'Journal', 'SystemMaxUse');
    if (v.length) { max = v[v.length - 1] || null; from = max ? p : null; }
  }
  const du = await d.exec('journalctl', ['--disk-usage']);
  if (!sawConfig && du.missing) return na('no journald on this host');
  const used = du.code === 0 ? (/take up (\S+)/.exec(du.stdout) || [])[1] || null : null;
  const usedTxt = used
    ? `journal uses ${used}`
    : `journal size unknown (${du.missing ? 'journalctl not found' : reasonLine(du.stderr) || `exit ${du.code}`})`;
  if (!max) return missing(`no SystemMaxUse set, so journald may use up to 10% of the disk (4G at most); ${usedTxt}`);
  const maxB = parseSize(max);
  const usedB = parseSize(used);
  // A limit journald never re-read leaves the journal above it (the incident
  // the script exists for); a little over is normal while it rotates.
  if (maxB != null && usedB != null && usedB > maxB * 1.1) {
    return missing(`SystemMaxUse=${max} in ${from}, but ${usedTxt}: journald has not applied the limit (it needs a restart and a vacuum)`);
  }
  return applied(`SystemMaxUse=${max} in ${from}; ${usedTxt}`);
}

function syslogItem(d) {
  const p = '/etc/logrotate.d/rsyslog';
  const r = readState(d, p);
  if (r.absent) return na(`${p} not present (rsyslog not installed)`);
  if (r.error) return unknown(`${p} unreadable: ${r.error}`);
  const m = /^[ \t]*maxsize[ \t]+(\S+)/m.exec(r.text);
  return m ? applied(`maxsize ${m[1]} in ${p}`) : missing(`${p} rotates by time only (no maxsize), so one noisy day can fill the disk`);
}

function logrotateTimerItem(d) {
  const dir = '/etc/systemd/system/logrotate.timer.d';
  let cal = [];
  let from = null;
  for (const f of tryReaddir(d, dir).filter((x) => x.endsWith('.conf')).sort()) {
    const r = readState(d, join(dir, f));
    if (r.text == null) continue;
    for (const v of iniValues(r.text, 'Timer', 'OnCalendar')) {
      if (v === '') { cal = []; from = null; } else { cal.push(v); from = join(dir, f); }
    }
  }
  if (cal.includes('hourly')) return applied(`OnCalendar=hourly in ${from}`);
  if (readState(d, '/etc/logrotate.conf').absent) return na('logrotate not installed');
  return missing(cal.length
    ? `logrotate.timer drop-in sets OnCalendar=${cal.join(', ')}, not hourly`
    : 'logrotate runs on its packaged schedule (daily), so maxsize is checked once a day');
}

function dockerItem(d) {
  const p = '/etc/docker/daemon.json';
  const r = readState(d, p);
  if (r.absent) return missing(`${p} absent: containers AppCrane did not start log without a size limit`);
  if (r.error) return unknown(`${p} unreadable: ${r.error}`);
  let j;
  try { j = JSON.parse(r.text); } catch (_) { return unknown(`${p} is not valid JSON; the script leaves it untouched`); }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return unknown(`${p} is not a JSON object`);
  if (!('log-opts' in j) && !('log-driver' in j)) return missing(`no log-opts or log-driver in ${p}`);
  const parts = [];
  if ('log-driver' in j) parts.push(`log-driver ${j['log-driver']}`);
  if ('log-opts' in j) parts.push(`log-opts ${JSON.stringify(j['log-opts'])}`);
  return applied(`${parts.join('; ')} in ${p} (a change applies from the next Docker restart)`);
}

// `pro config show` prints one "<key> <value>" row per setting, Python bools
// as True/False (measured: ubuntu-pro-client 38ubuntu0~24.04, as root and as
// an ordinary user). It fails for a user without a writable HOME.
async function aptNewsItem(d) {
  const r = await d.exec('pro', ['config', 'show']);
  if (r.missing) return na('Ubuntu Pro client not installed');
  if (r.code !== 0) return unknown(`pro config show failed: ${reasonLine(r.stderr) || `exit ${r.code}`}`);
  const m = /^apt_news\s+(\S+)/m.exec(r.stdout);
  if (!m) return unknown('pro config show has no apt_news setting');
  if (m[1].toLowerCase() === 'false') return applied('apt_news is off');
  return missing(`apt_news is ${m[1]}: it runs hourly and logs an AppArmor denial each time`);
}

async function unattendedItem(d) {
  if (statState(d, '/var/lib/dpkg/status').absent) return na('not a dpkg/apt system');
  const u = await unattended(d);
  const periodic = `APT::Periodic::Unattended-Upgrade "${u.unattendedUpgrade ?? ''}", Update-Package-Lists "${u.updatePackageLists ?? ''}"`;
  if (u.enabled) return applied(`unattended-upgrades installed; ${periodic}`);
  if (!u.installed) return missing('unattended-upgrades package not installed: security updates stay manual');
  return missing(`unattended-upgrades installed but not enabled: ${periodic}`);
}

function caddyDirItem(d) {
  const p = '/var/log/caddy';
  const s = statState(d, p);
  if (s.absent) return missing(`${p} missing: Caddy writes no access log`);
  if (s.error) return unknown(`${p}: ${s.error}`);
  if (!s.st.isDirectory()) return missing(`${p} exists but is not a directory`);
  const mode = (s.st.mode & 0o777).toString(8);
  const passwd = readState(d, '/etc/passwd').text;
  const caddyUid = passwd ? (/^caddy:[^:]*:(\d+):/m.exec(passwd) || [])[1] : undefined;
  if (caddyUid != null && Number(caddyUid) !== s.st.uid) {
    return missing(`${p} is owned by uid ${s.st.uid}, not caddy: Caddy cannot open its access log there`);
  }
  return applied(`${p} exists (mode ${mode})`);
}

async function reserveItem(d) {
  let probe = d.dataDir();
  while (statState(d, probe).absent && dirname(probe) !== probe) probe = dirname(probe);
  const df = await d.exec('df', ['-P', probe]);
  if (df.code !== 0) return unknown(`df -P ${probe} failed: ${reasonLine(df.stderr) || `exit ${df.code}`}`);
  const row = String(df.stdout).trim().split('\n')[1];
  const mount = row ? row.trim().split(/\s+/).slice(5).join(' ') : '';
  if (!mount.startsWith('/')) return unknown(`could not read the mount point of ${probe} from df`);
  const reserve = `${mount.replace(/\/$/, '')}/appcrane-disk-reserve`;
  const s = statState(d, reserve);
  if (s.error) return unknown(`${reserve}: ${s.error}`);
  if (s.st && s.st.size >= RESERVE_BYTES) return applied(`1 GiB reserve at ${reserve}; if this disk fills, free it with: sudo rm ${reserve}`);
  return missing(s.st
    ? `${reserve} is ${s.st.size} bytes, smaller than 1 GiB`
    : `no reserve file at ${reserve} (the script skips it when less than 10 GiB would stay free)`);
}

const CHECKS = {
  journal: journalItem,
  'syslog-rotation': syslogItem,
  'logrotate-hourly': logrotateTimerItem,
  'docker-log-defaults': dockerItem,
  'apt-news': aptNewsItem,
  'unattended-upgrades': unattendedItem,
  'caddy-log-dir': caddyDirItem,
  'disk-reserve': reserveItem,
};

export async function checkItems(deps = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const out = [];
  for (const [id, label] of ITEMS) {
    let r;
    try { r = await CHECKS[id](d); } catch (e) { r = unknown(`check failed: ${e.message}`); }
    out.push({ id, label, ...r });
  }
  return out;
}

/** What scripts/install-host-hardening.sh writes for <repoDir>: the REPO_DIR line baked in. */
export function expectedInstalledCopy(src, repoDir) {
  const text = String(src).endsWith('\n') ? String(src) : `${src}\n`;
  return text.replace(/^REPO_DIR=.*$/m, () => `REPO_DIR='${repoDir}'`);
}

/**
 * How Apply can run here. argv is internal (never sent to the browser).
 * sudo -n -l <cmd> exits 0 only when the policy permits <cmd> exactly as given
 * (no arguments) without a password; 1 otherwise, also for a missing file.
 */
export async function detectRunMode(deps = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  if (d.platform !== 'linux') return { mode: 'unsupported', command: null, reason: `Host limits apply to Linux servers; this one runs ${d.platform}.` };
  const repoScript = join(d.repoDir, 'scripts', 'host-hardening.sh');
  if (d.getuid() === 0) return { mode: 'root', command: `bash ${repoScript}`, argv: ['bash', [repoScript]] };
  const manual = `sudo bash ${repoScript}`;
  const setup = `sudo bash ${join(d.repoDir, 'scripts', 'install-host-hardening.sh')}`;
  const installed = readState(d, INSTALLED_SCRIPT);
  if (installed.text == null) {
    return {
      mode: 'manual', command: manual, setup_command: setup,
      reason: `AppCrane runs without root and ${INSTALLED_SCRIPT} is not installed.`,
    };
  }
  const repo = readState(d, repoScript);
  const stale = repo.text == null || sha256(installed.text) !== sha256(expectedInstalledCopy(repo.text, d.repoDir));
  const allowed = await d.exec('sudo', ['-n', '-l', INSTALLED_SCRIPT]);
  if (allowed.code !== 0) {
    return {
      mode: 'manual', command: manual, setup_command: setup, installed_copy_stale: stale,
      reason: `AppCrane runs without root and has no sudo rule for ${INSTALLED_SCRIPT} (${SUDOERS_FILE}).`,
    };
  }
  return { mode: 'sudo', command: `sudo -n ${INSTALLED_SCRIPT}`, setup_command: setup, installed_copy_stale: stale, argv: ['sudo', ['-n', INSTALLED_SCRIPT]] };
}

export function publicRun(run) {
  const { argv, ...rest } = run;
  return rest;
}

// ---- one run at a time, process-wide ----

let running = false;
export const isRunning = () => running;
export function claimRun() {
  if (running) return false;
  running = true;
  return true;
}
export function releaseRun() { running = false; }

const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
export const stripAnsi = (s) => String(s).replace(ANSI, '');

/** Last <cap> bytes of <s>, marked when cut. */
export function capTail(s, cap = OUTPUT_CAP, cut = false) {
  const buf = Buffer.from(s, 'utf8');
  if (buf.length <= cap && !cut) return s;
  const tail = buf.length > cap ? buf.subarray(buf.length - cap).toString('utf8') : s;
  return `[output truncated: last ${Math.round(cap / 1024)} KiB shown]\n${tail}`;
}

/** Runs argv (no shell), output merged, ANSI stripped, tail-capped. */
export function runScript(argv, deps = {}, { timeoutMs = RUN_TIMEOUT_MS, cap = OUTPUT_CAP } = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const [cmd, args] = argv;
  return new Promise((res) => {
    let chunks = [];
    let size = 0;
    let cut = false;
    let timedOut = false;
    let done = false;
    const keep = (b) => {
      chunks.push(b);
      size += b.length;
      // Bounded memory: keep twice the cap (escape codes are removed later).
      if (size > cap * 2) {
        const all = Buffer.concat(chunks);
        chunks = [all.subarray(all.length - cap * 2)];
        size = chunks[0].length;
        cut = true;
      }
    };
    let child;
    try {
      child = d.spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, LC_ALL: 'C' } });
    } catch (e) {
      res({ exit_code: null, output: `failed to start ${cmd}: ${e.message}`, timed_out: false });
      return;
    }
    const finish = (code, extra = '') => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(killer);
      let out = stripAnsi(Buffer.concat(chunks).toString('utf8')) + extra;
      out = capTail(out, cap, cut);
      res({ exit_code: code, output: out, timed_out: timedOut });
    };
    let killer = null;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      killer = setTimeout(() => child.kill('SIGKILL'), 5000);
    }, timeoutMs);
    child.stdout?.on('data', keep);
    child.stderr?.on('data', keep);
    child.on('error', (e) => finish(null, `\nfailed to start ${cmd}: ${e.message}\n`));
    child.on('close', (code) => finish(typeof code === 'number' && !timedOut ? code : null,
      timedOut ? `\nstopped after ${Math.round(timeoutMs / 60_000)} minutes\n` : ''));
  });
}

// ---- last run, kept in the settings table (never writable via PUT /api/settings/:key) ----

export function readLastRun(db) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(LAST_RUN_KEY);
  if (!row) return null;
  try { return JSON.parse(row.value); } catch (_) { return null; }
}

export function writeLastRun(db, lastRun, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(LAST_RUN_KEY, JSON.stringify(lastRun), userId);
}
