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
import { enqueueEmail } from './emailQueue.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, bulletList, renderBrandedEmail } from './mail/brandedLayout.js';
import log from '../utils/logger.js';

export const HOST_MAIL_SOURCE = 'host-resources';
export const SAMPLE_MS = 5 * 60_000;
const WINDOW_MS = 6 * 60 * 60_000;
const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

export const THRESHOLD_DEFAULTS = Object.freeze({
  mem_warn_pct: 10, mem_crit_pct: 5, mem_floor_mb: 512,
  disk_warn_pct: 10, disk_crit_pct: 5, disk_floor_gb: 5,
});

const previous = new Map();
let lastSample = null;
let timer = null;

export function getThresholds(db = getDb()) {
  const out = {};
  for (const [k, def] of Object.entries(THRESHOLD_DEFAULTS)) {
    let v = null;
    try { v = db.prepare('SELECT value FROM settings WHERE key = ?').get(`host_alert_${k}`)?.value ?? null; } catch (_) {}
    const n = v === null || v === '' ? NaN : Number(v);
    out[k] = Number.isFinite(n) && n >= 0 ? n : def;
  }
  return out;
}

/** ok / warning / critical for a free-vs-total pair; unknown when either is missing. */
export function levelFor({ freeBytes, totalBytes }, { warnPct, critPct, floorBytes }) {
  if (!Number.isFinite(freeBytes) || !Number.isFinite(totalBytes) || totalBytes <= 0) return 'unknown';
  const pct = (freeBytes / totalBytes) * 100;
  if (pct < critPct || freeBytes < floorBytes) return 'critical';
  if (pct < warnPct) return 'warning';
  return 'ok';
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
      const level = levelFor({ freeBytes, totalBytes }, { warnPct: t.disk_warn_pct, critPct: t.disk_crit_pct, floorBytes: t.disk_floor_gb * GiB });
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

const RANK = { ok: 0, unknown: 0, warning: 1, critical: 2 };

export async function sampleHost(deps = {}, db = getDb()) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const t = getThresholds(db);
  const resources = [sampleMemory(d, t), await sampleCommitted(d), ...(await sampleDisks(d, t))];
  const worst = resources.reduce((w, r) => (RANK[r.level] > RANK[w] ? r.level : w), 'ok');
  const overall = worst === 'ok' && resources.every((r) => r.level === 'unknown') ? 'unknown' : worst;
  return { at: new Date().toISOString(), overall, thresholds: t, resources };
}

function fmt(bytes) {
  return bytes >= GiB ? `${(bytes / GiB).toFixed(1)} GB` : `${Math.round(bytes / MiB)} MB`;
}

export function describeResource(r) {
  if (r.level === 'unknown') return `${r.label}: unknown${r.error ? ` (${r.error})` : ''}`;
  if (r.id === 'committed') return `${r.label}: ${fmt(r.committedBytes)} of ${fmt(r.capacityBytes)} capacity`;
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
    if (r.level === 'unknown') continue;
    const prev = previous.get(r.id);
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
  const tick = () => trackJob('host-resources', () => runHostCheck()).catch((e) => log.warn(`[host-resources] ${e.message}`));
  setTimeout(tick, 30_000).unref?.();
  timer = setInterval(tick, SAMPLE_MS);
  timer.unref?.();
}

export function _resetHostResourcesForTests() {
  previous.clear();
  lastSample = null;
  if (timer) { clearInterval(timer); timer = null; }
}
