// Server memory and disk, sampled every few minutes for Job Health, with
// e-mail to platform admins when something crosses into warning or critical.
//
// Memory: MemAvailable/MemTotal from /proc/meminfo on Linux (in production the
// AppCrane host is the Docker host); os.freemem()/os.totalmem() elsewhere.
// Committed: the memory-admission sum of container caps against capacity
// (memoryAdmission.js); more committed than capacity is a warning, since that
// is the state in which the host can be driven into a whole-host OOM.
// Disk: free space on the filesystems holding DATA_DIR, Docker's data root and
// /, each filesystem once (paths on the same device are reported together).
//
// Defaults (platform settings host_alert_*): memory warning below 10% available,
// critical below 5% or 512 MB, the floor where the kernel starts reclaiming hard
// on a small box. Disk warning below 10% free, critical below 5% or 5 GB, which
// is about one image build plus a nightly backup.
//
// Mail: one per resource, level and 6-hour window while it lasts, and one
// recovery mail when a resource seen in warning or critical by this process
// returns to ok. Sampling never throws; what cannot be read is "unknown".

import { readFileSync, statfsSync, statSync } from 'fs';
import { execFile } from 'child_process';
import { freemem, totalmem } from 'os';
import { resolve } from 'path';
import { getDb } from '../db.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import { measureMemory } from './memoryAdmission.js';
import { measureCpu, peekCpuMeasurement, containersWithoutWeight } from './cpuAdmission.js';
import { getHostCpuPriority } from './cpuPriority.js';
import { enqueueEmail } from './emailQueue.js';
import { recordHostEvent } from './eventStore.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, bulletList, renderBrandedEmail } from './mail/brandedLayout.js';
import { THRESHOLD_DEFAULTS, MiB, readThresholds, levelFor, diskLevel, belowDiskFloor, fmtBytes, diskFloorText } from './hostThresholds.js';
import { AppError } from '../utils/errors.js';
import { maybePruneForDisk } from './buildCachePrune.js';
import log from '../utils/logger.js';

export const HOST_MAIL_SOURCE = 'host-resources';
export const SAMPLE_MS = 5 * 60_000;
const WINDOW_MS = 6 * 60 * 60_000;

export { THRESHOLD_DEFAULTS, levelFor };

const previous = new Map();
let lastSample = null;
let timer = null;

export function getThresholds(db = getDb()) {
  return readThresholds(db);
}

export function parseMeminfo(text) {
  const kb = (key) => {
    const m = new RegExp(`^${key}:\\s+(\\d+)\\s*kB`, 'm').exec(String(text || ''));
    return m ? Number(m[1]) * 1024 : NaN;
  };
  return { availableBytes: kb('MemAvailable'), totalBytes: kb('MemTotal') };
}

function dockerRootDir() {
  return new Promise((res) => {
    execFile('docker', ['info', '--format', '{{.DockerRootDir}}'], { timeout: 10_000 }, (err, stdout) => {
      const p = String(stdout || '').trim();
      res(err || !p.startsWith('/') ? null : p);
    });
  });
}

const DEFAULT_DEPS = {
  platform: process.platform,
  readFile: (p) => readFileSync(p, 'utf8'),
  statfs: (p) => statfsSync(p),
  deviceOf: (p) => statSync(p).dev,
  freemem, totalmem,
  dockerRootDir,
  measure: () => measureMemory(),
  hostCpuPriority: () => getHostCpuPriority(),
  cpuMeasurement: () => peekCpuMeasurement(),
  dataDir: () => resolve(process.env.DATA_DIR || './data'),
};

function sampleMemory(deps, t) {
  let freeBytes = NaN;
  let totalBytes = NaN;
  let source = 'os';
  try {
    if (deps.platform === 'linux') {
      const m = parseMeminfo(deps.readFile('/proc/meminfo'));
      if (Number.isFinite(m.availableBytes) && Number.isFinite(m.totalBytes)) {
        freeBytes = m.availableBytes; totalBytes = m.totalBytes; source = '/proc/meminfo';
      }
    }
    if (!Number.isFinite(totalBytes)) { freeBytes = deps.freemem(); totalBytes = deps.totalmem(); }
  } catch (e) {
    return { id: 'memory', label: 'Memory available', level: 'unknown', error: e.message };
  }
  const level = levelFor({ freeBytes, totalBytes }, { warnPct: t.mem_warn_pct, critPct: t.mem_crit_pct, floorBytes: t.mem_floor_mb * MiB });
  return { id: 'memory', label: 'Memory available', freeBytes, totalBytes, source, level };
}

async function sampleCommitted(deps) {
  try {
    const m = await deps.measure();
    if (m.error) return { id: 'committed', label: 'Memory committed to containers', level: 'unknown', error: m.error };
    return {
      id: 'committed', label: 'Memory committed to containers',
      committedBytes: m.committedBytes, capacityBytes: m.capacityBytes, totalBytes: m.totalBytes,
      reserveBytes: m.reserveBytes, totalSource: m.totalSource,
      level: m.committedBytes > m.capacityBytes ? 'warning' : 'ok',
    };
  } catch (e) {
    return { id: 'committed', label: 'Memory committed to containers', level: 'unknown', error: e.message };
  }
}

// CPU reservation: did the host services get their CPUWeight drop-in
// (cpuPriority.js), and do AppCrane's running containers carry the low
// --cpu-shares weight? Shown in Job Health, never mailed: a non-root install
// stays in this state until an operator acts, and the README says how.
export function sampleCpuPriority(deps) {
  const label = 'CPU reservation for host services';
  let host = null;
  let m = null;
  try { host = deps.hostCpuPriority(); m = deps.cpuMeasurement(); } catch (e) {
    return { id: 'cpu-priority', label, level: 'unknown', notify: false, error: e.message };
  }
  const unweighted = m && !m.error ? containersWithoutWeight(m).map((c) => c.label) : null;
  const hostOk = host && (host.status === 'set' || host.status === 'already');
  const hostBad = host && (host.status === 'not-permitted' || host.status === 'failed');
  if (!host && unweighted === null) return { id: 'cpu-priority', label, level: 'unknown', notify: false, error: 'not measured yet' };
  const problems = [];
  if (hostBad) problems.push(`host services have no CPUWeight drop-in (${host.reason})`);
  if (host?.status === 'unsupported') problems.push(`drop-in not applicable: ${host.reason}`);
  if (unweighted?.length) problems.push(`${unweighted.length} AppCrane container(s) still run at Docker's default CPU weight until recreated: ${unweighted.slice(0, 5).join(', ')}`);
  return {
    id: 'cpu-priority', label, notify: false,
    level: hostBad || unweighted?.length ? 'warning' : (hostOk || host?.status === 'unsupported' ? 'ok' : 'unknown'),
    host: host ? { status: host.status, units: host.units || [], reason: host.reason || null, at: host.at } : null,
    unweighted, committedCores: m && !m.error ? m.committedCores : null, capacityCores: m && !m.error ? m.capacityCores : null,
    detail: problems.join('; ') || null,
  };
}

async function sampleDisks(deps, t) {
  let dockerDir = null;
  try { dockerDir = await deps.dockerRootDir(); } catch (_) {}
  const paths = [['DATA_DIR', deps.dataDir()], ['Docker data root', dockerDir], ['root filesystem', '/']].filter(([, p]) => p);
  const byDevice = new Map();
  const out = [];
  for (const [name, p] of paths) {
    let dev;
    try { dev = String(deps.deviceOf(p)); } catch (e) {
      out.push({ id: `disk:${name}`, label: `Disk free (${name})`, path: p, level: 'unknown', error: e.message });
      continue;
    }
    if (byDevice.has(dev)) { const r = byDevice.get(dev); r.label += `, ${name}`; r.paths.push(p); continue; }
    let r;
    try {
      const s = deps.statfs(p);
      const freeBytes = Number(s.bavail) * Number(s.bsize);
      const totalBytes = Number(s.blocks) * Number(s.bsize);
      const level = diskLevel(freeBytes, totalBytes, t);
      r = { id: `disk:${dev}`, label: `Disk free (${name}`, paths: [p], freeBytes, totalBytes, level };
    } catch (e) {
      r = { id: `disk:${dev}`, label: `Disk free (${name}`, paths: [p], level: 'unknown', error: e.message };
    }
    byDevice.set(dev, r);
    out.push(r);
  }
  for (const r of byDevice.values()) r.label += ')';
  return out;
}

// The low-disk guard: a deploy (release tree, image build) or a self-update
// (npm install, SPA rebuild, pre-update snapshot) writes to DATA_DIR and to
// Docker's data root, and running either below the disk floor is how a box
// ends up at 100% with the database unable to commit. Same filesystems as the
// Job Health sample and the same disk_floor_gb setting, but not its percent
// rule (see belowDiskFloor). A filesystem that cannot be read is
// reported as unknown and does not block: refusing every deploy because statfs
// failed would turn a monitoring problem into an outage.
export async function checkDiskHeadroom({ need = 0, deps = {}, db = getDb() } = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const t = getThresholds(db);
  let dockerDir = null;
  try { dockerDir = await d.dockerRootDir(); } catch (_) {}
  const byDevice = new Map();
  const filesystems = [];
  for (const [name, p] of [['DATA_DIR', d.dataDir()], ['Docker data root', dockerDir]]) {
    if (!p) continue;
    let dev;
    let s;
    try { dev = String(d.deviceOf(p)); s = byDevice.has(dev) ? null : d.statfs(p); } catch (e) {
      filesystems.push({ names: [name], path: p, level: 'unknown', error: e.message });
      continue;
    }
    if (byDevice.has(dev)) { byDevice.get(dev).names.push(name); continue; }
    const freeBytes = Number(s.bavail) * Number(s.bsize);
    const totalBytes = Number(s.blocks) * Number(s.bsize);
    const f = { names: [name], path: p, freeBytes, totalBytes, level: belowDiskFloor(freeBytes - need, t) ? 'critical' : 'ok' };
    byDevice.set(dev, f);
    filesystems.push(f);
  }
  const blocked = filesystems.filter((f) => f.level === 'critical');
  return { ok: blocked.length === 0, thresholds: t, need, filesystems, blocked };
}

export function diskRefusalMessage(action, f, t, need = 0) {
  const pct = ((f.freeBytes / f.totalBytes) * 100).toFixed(1);
  const after = need > 0 ? ` once the ${fmt(need)} it needs is written` : '';
  return `Refusing to ${action}: the filesystem holding ${f.names.join(' and ')} (${f.path}) has ${fmt(f.freeBytes)} free of ${fmt(f.totalBytes)} (${pct}%), `
    + `below the floor of ${diskFloorText(t)}${after}. Free space on that filesystem (old images, backups, logs) and retry; `
    + 'the floor is set in Settings > Job Health.';
}

/** Throws a 507 DISK_LOW AppError when a filesystem the action writes to is below the disk floor. */
export async function assertDiskHeadroom(action, opts = {}) {
  const r = await checkDiskHeadroom(opts);
  if (r.ok) return r;
  const msg = diskRefusalMessage(action, r.blocked[0], r.thresholds, r.need);
  log.warn(`[disk-guard] ${msg}`);
  const err = new AppError(msg, 507, 'DISK_LOW');
  err.filesystems = r.blocked.map(({ names, path, freeBytes, totalBytes }) => ({ names, path, freeBytes, totalBytes }));
  throw err;
}

const RANK = { ok: 0, unknown: 0, warning: 1, critical: 2 };

export async function sampleHost(deps = {}, db = getDb()) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const t = getThresholds(db);
  const resources = [sampleMemory(d, t), await sampleCommitted(d), ...(await sampleDisks(d, t)), sampleCpuPriority(d)];
  const worst = resources.reduce((w, r) => (RANK[r.level] > RANK[w] ? r.level : w), 'ok');
  const overall = worst === 'ok' && resources.every((r) => r.level === 'unknown') ? 'unknown' : worst;
  return { at: new Date().toISOString(), overall, thresholds: t, resources };
}

const fmt = fmtBytes;

export function describeResource(r) {
  if (r.level === 'unknown') return `${r.label}: unknown${r.error ? ` (${r.error})` : ''}`;
  if (r.id === 'committed') return `${r.label}: ${fmt(r.committedBytes)} of ${fmt(r.capacityBytes)} capacity`;
  if (r.id === 'cpu-priority') return `${r.label}: ${r.detail || 'in force'}`;
  const pct = ((r.freeBytes / r.totalBytes) * 100).toFixed(1);
  return `${r.label}: ${fmt(r.freeBytes)} of ${fmt(r.totalBytes)} (${pct}%)`;
}

function admins(db) {
  return db.prepare(`SELECT email FROM users WHERE role = 'platform_admin' AND active = 1
                     AND email IS NOT NULL AND trim(email) != ''`).all().map((r) => r.email);
}

function mail(db, r, level, now) {
  const window = Math.floor(now / WINDOW_MS);
  const recovered = level === 'ok';
  const line = describeResource(r);
  const subject = recovered
    ? `[AppCrane] Recovered: ${r.label}`
    : `[AppCrane] Server ${level}: ${r.label}`;
  const intro = recovered
    ? `${r.label} is back to normal.`
    : `${r.label} on this AppCrane server is ${level}.`;
  const sent = [];
  for (const to of admins(db)) {
    try {
      enqueueEmail({
        to, subject, appId: null, source: HOST_MAIL_SOURCE,
        text: `${intro}\n\n${line}\n\nSee Settings > Job Health.\n`,
        html: renderBrandedEmail({
          preheader: line, greeting: 'Hi,', intro,
          bodyHtml: bulletList([line])
            + `<p style="margin:12px 0 0;font-size:13px;color:${BRAND.dim};">Thresholds and the full picture are in Settings &gt; Job Health.</p>`,
          cta: { label: 'Open Job Health', url: `${dashboardBaseUrl()}/settings#jobs` },
          footer: 'You get this because you are a platform admin of this AppCrane.',
        }),
        idempotencyKey: `host-resources:${r.id}:${level}:${window}:${to.trim().toLowerCase()}`,
      });
      sent.push(to);
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[host-resources] alert to ${to} skipped: ${e.message}`);
    }
  }
  return sent;
}

/** One check: sample, publish to Job Health, mail admins. Returns the sample and what was mailed. */
export async function runHostCheck({ deps = {}, now = Date.now(), db = getDb() } = {}) {
  let sample;
  try {
    sample = await sampleHost(deps, db);
  } catch (e) {
    sample = { at: new Date(now).toISOString(), overall: 'unknown', resources: [], error: e.message };
  }
  lastSample = sample;
  setJobDetail('host-resources', sample);
  const mailed = [];
  for (const r of sample.resources) {
    if (r.level === 'unknown' || r.notify === false) continue;
    const prev = previous.get(r.id);
    recordHostEvent(r, prev);
    try {
      if (r.level === 'warning' || r.level === 'critical') {
        const to = mail(db, r, r.level, now);
        if (to.length) mailed.push({ id: r.id, level: r.level, to });
      } else if (prev === 'warning' || prev === 'critical') {
        const to = mail(db, r, 'ok', now);
        if (to.length) mailed.push({ id: r.id, level: 'ok', to });
      }
    } catch (e) {
      log.warn(`[host-resources] alert failed: ${e.message}`);
    }
    previous.set(r.id, r.level);
  }
  return { sample, mailed };
}

export function getLastHostSample() {
  return lastSample;
}

export function startHostResourceMonitor() {
  if (timer) return;
  jobStarted('host-resources');
  const tick = () => trackJob('host-resources', async () => { await measureCpu(); return runHostCheck(); })
    .then(({ sample }) => maybePruneForDisk(sample))
    .catch((e) => log.warn(`[host-resources] ${e.message}`));
  setTimeout(tick, 30_000).unref?.();
  timer = setInterval(tick, SAMPLE_MS);
  timer.unref?.();
}

export function _resetHostResourcesForTests() {
  previous.clear();
  lastSample = null;
  if (timer) { clearInterval(timer); timer = null; }
}
