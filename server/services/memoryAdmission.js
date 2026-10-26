// Memory admission control: refuse to start a container whose memory cap would
// push the sum of all caps past what the Docker host can actually back.
//
// capacity  = docker info .MemTotal (the daemon's view: the host on Linux, the
//             VM on Docker Desktop; os.totalmem() only when docker info fails)
//             minus a reserve for the host itself (setting memory_reserve_mb;
//             default max(1 GiB, 10% of RAM): kernel, dockerd/containerd, sshd,
//             Caddy, AppCrane's own Node process and a security agent).
// committed = the sum of HostConfig.Memory over every RUNNING container on the
//             daemon, AppCrane's or not, since all of them draw on the same RAM.
//             A container with no limit (Memory=0) counts at its current usage
//             (docker stats); when that cannot be read, at DEFAULT_UNLIMITED_MB.
//
// A start is allowed when committed - replaced + new <= capacity, where
// `replaced` is the cap of the running container of the same name (the version
// a redeploy swaps out). It is also always allowed when new <= replaced: a start
// that does not raise the total cannot make things worse, and refusing it would
// freeze every redeploy and rollback on a host that is already over-committed.
//
// Modes (setting memory_admission_mode): refuse, warn (the default: start anyway,
// tell the platform admins), off (no measurement at all). A measurement that
// fails admits the start: this guards the host, it must never be the reason a
// deploy cannot happen when Docker answers oddly.

import { execFile } from 'child_process';
import { totalmem } from 'os';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';
import { recordAdmissionEvent } from './eventStore.js';
import { admitCpu } from './cpuAdmission.js';

export const MODE_KEY = 'memory_admission_mode';
export const RESERVE_KEY = 'memory_reserve_mb';
export const MODES = ['refuse', 'warn', 'off'];
export const DEFAULT_MODE = 'warn';
export const DEFAULT_UNLIMITED_MB = 512;
export const CACHE_MS = 15_000;
export const REFUSED_CODE = 'INSUFFICIENT_MEMORY';

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const DOCKER_TIMEOUT_MS = 10_000;
export const INSPECT_FORMAT = '{{.Name}}\t{{.HostConfig.Memory}}\t{{json .Config.Labels}}';

let cached = null;
const reservations = new Map();

export function toMb(bytes) {
  return Math.floor(Number(bytes || 0) / MiB);
}

function setting(db, key) {
  try { return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null; } catch (_) { return null; }
}

export function getAdmissionSettings(db = getDb()) {
  const rawMode = setting(db, MODE_KEY);
  const mode = MODES.includes(rawMode) ? rawMode : DEFAULT_MODE;
  const rawReserve = setting(db, RESERVE_KEY);
  const n = rawReserve === null || rawReserve === '' ? NaN : Number(rawReserve);
  const reserveMb = Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
  return { mode, reserveMb };
}

export function defaultReserveBytes(totalBytes) {
  return Math.max(GiB, Math.floor(totalBytes * 0.1));
}

function docker(args) {
  return new Promise((resolve, reject) => {
    execFile('docker', args, { timeout: DOCKER_TIMEOUT_MS, maxBuffer: 16 * MiB }, (err, stdout, stderr) => {
      if (err) { err.message = `${err.message}${stderr ? `: ${String(stderr).trim()}` : ''}`; reject(err); return; }
      resolve(String(stdout));
    });
  });
}

/** "123.4MiB / 7.6GiB" -> bytes of the first figure; null when unreadable. */
export function parseMemUsage(s) {
  const m = /^\s*([\d.]+)\s*([KMGT]?i?B)\b/i.exec(String(s || ''));
  if (!m) return null;
  const unit = m[2].toLowerCase();
  const mult = { b: 1, kib: 1024, mib: MiB, gib: GiB, tib: 1024 * GiB, kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12 }[unit];
  const v = Number(m[1]);
  return mult && Number.isFinite(v) ? Math.round(v * mult) : null;
}

function describe(name, labels) {
  const l = labels || {};
  if (l.slug && l.env) return { kind: 'app', label: `${l.slug} (${l.env})`, slug: l.slug, env: l.env };
  if (l['appcrane-db']) return { kind: 'db', label: `managed ${l['appcrane-db']}${l['appcrane-db-name'] ? ` ${l['appcrane-db-name']}` : ''}` };
  if (l['app.slug']) {
    const type = l['appcrane.container.type'];
    const kind = type === 'app' ? 'coder' : (type || 'helper');
    return { kind, label: `${kind} for ${l['app.slug']}`, slug: l['app.slug'] };
  }
  if (l['appcrane.gh-mcp']) return { kind: 'helper', label: 'GitHub MCP helper' };
  if (l.appcrane) return { kind: 'helper', label: name };
  return { kind: 'other', label: name };
}

/** Parse `docker inspect` lines of "<name>\t<memory bytes>\t<labels json>". */
export function parseInspect(out) {
  const rows = [];
  for (const line of String(out || '').split('\n')) {
    const parts = line.split('\t');
    if (parts.length < 3) continue;
    const name = parts[0].replace(/^\//, '').trim();
    const mem = Number(parts[1]);
    if (!name || !Number.isFinite(mem) || mem < 0) continue;
    let labels = {};
    try { labels = JSON.parse(parts.slice(2).join('\t')) || {}; } catch (_) { labels = {}; }
    rows.push({ name, capBytes: mem, unlimited: mem === 0, ...describe(name, labels) });
  }
  return rows;
}

async function readTotal() {
  try {
    const n = Number(String(await docker(['info', '--format', '{{.MemTotal}}'])).trim());
    if (Number.isFinite(n) && n > 0) return { totalBytes: n, totalSource: 'docker' };
    throw new Error('docker info returned no MemTotal');
  } catch (e) {
    log.warn(`[memory-admission] docker info failed (${e.message.split('\n')[0]}); using this machine's RAM instead`);
    return { totalBytes: totalmem(), totalSource: 'os' };
  }
}

async function readContainers() {
  const ids = String(await docker(['ps', '-q', '--no-trunc'])).split('\n').map((s) => s.trim()).filter(Boolean);
  if (!ids.length) return [];
  const rows = parseInspect(await docker(['inspect', '--format', INSPECT_FORMAT, ...ids]));
  const unlimited = rows.filter((r) => r.unlimited);
  if (unlimited.length) {
    const usage = await readUsage(unlimited.map((r) => r.name));
    for (const r of unlimited) {
      const u = usage.get(r.name);
      r.countedBytes = u ?? DEFAULT_UNLIMITED_MB * MiB;
      r.countedFrom = u != null ? 'usage' : 'default';
    }
  }
  for (const r of rows) if (!r.unlimited) { r.countedBytes = r.capBytes; r.countedFrom = 'cap'; }
  return rows;
}

/** Current memory use per container name, one `docker stats` call. Empty on failure. */
export async function readUsage(names) {
  const map = new Map();
  if (!names.length) return map;
  try {
    const out = await docker(['stats', '--no-stream', '--format', '{{.Name}}\t{{.MemUsage}}', ...names]);
    for (const line of out.split('\n')) {
      const [n, u] = line.split('\t');
      const b = parseMemUsage(u);
      if (n && b != null) map.set(n.trim(), b);
    }
  } catch (e) {
    log.debug?.(`[memory-admission] docker stats failed: ${e.message}`);
  }
  return map;
}

/** One measurement of the host, cached for CACHE_MS. Never throws: `error` is set instead. */
export async function measureMemory({ fresh = false, db = getDb() } = {}) {
  if (!fresh && cached && Date.now() - cached.at < CACHE_MS) return cached.value;
  const { reserveMb } = getAdmissionSettings(db);
  const { totalBytes, totalSource } = await readTotal();
  const reserveBytes = reserveMb != null ? reserveMb * MiB : defaultReserveBytes(totalBytes);
  let containers = [];
  let error = null;
  try {
    containers = await readContainers();
  } catch (e) {
    error = `could not list running containers: ${e.message.split('\n')[0]}`;
    log.warn(`[memory-admission] ${error}`);
  }
  const value = {
    totalBytes, totalSource, reserveBytes, reserveSource: reserveMb != null ? 'setting' : 'default',
    capacityBytes: Math.max(0, totalBytes - reserveBytes),
    committedBytes: containers.reduce((s, c) => s + c.countedBytes, 0),
    containers, error, measuredAt: new Date().toISOString(),
  };
  if (!error) cached = { at: Date.now(), value };
  return value;
}

export function invalidateMemoryMeasurement() {
  cached = null;
}

/**
 * Hold `bytes` against `name` while its container is being started, so two
 * starts racing on one stale measurement cannot both fit into the same space.
 */
export function reserveMemory(name, bytes) {
  const token = Symbol(name);
  reservations.set(name, { token, bytes });
  return () => {
    if (reservations.get(name)?.token === token) reservations.delete(name);
    invalidateMemoryMeasurement();
  };
}

/** Pure rule, exported for tests. */
export function decide({ measurement, name, newBytes }) {
  const running = measurement.containers.filter((c) => !reservations.has(c.name));
  const held = [...reservations.entries()].filter(([n]) => n !== name).reduce((s, [, r]) => s + r.bytes, 0);
  const replaced = running.find((c) => c.name === name)?.countedBytes || 0;
  const committedBytes = running.reduce((s, c) => s + c.countedBytes, 0) + held;
  const base = committedBytes - replaced;
  const afterBytes = base + newBytes;
  const fits = afterBytes <= measurement.capacityBytes;
  const notRaising = newBytes <= replaced;
  return {
    allowed: fits || notRaising,
    fits, notRaising,
    newBytes, replacedBytes: replaced, committedBytes, afterBytes,
    capacityBytes: measurement.capacityBytes,
    freeBytes: Math.max(0, measurement.capacityBytes - base),
  };
}

export function refusalMessage({ subject, what, verdict, replacing }) {
  const tail = replacing
    ? 'Nothing was changed — the current version is still running.'
    : 'Nothing was started.';
  return `Not enough memory on the server for this ${what}: ${subject} needs ${toMb(verdict.newBytes)} MB, `
    + `${toMb(verdict.freeBytes)} MB is free (${toMb(verdict.committedBytes)}/${toMb(verdict.capacityBytes)} MB committed). `
    + `${tail} Try again later, or ask a platform admin to free memory.`;
}

export function warningMessage({ subject, what, verdict }) {
  return `Memory warning: this ${what} takes the server past its memory capacity. ${subject} needs `
    + `${toMb(verdict.newBytes)} MB, ${toMb(verdict.freeBytes)} MB was free; ${toMb(verdict.afterBytes)}/`
    + `${toMb(verdict.capacityBytes)} MB is now committed. Started anyway (memory admission is set to warn only).`;
}

/**
 * Decide whether `name` may start with `memoryMb`, and act on the answer:
 * refuse (throws AppError 409 INSUFFICIENT_MEMORY) or warn, notifying people
 * through memoryAdmissionMail.js. Returns { mode, allowed, warned, message, verdict }.
 *
 * ctx: { kind, slug, env, appId, userId, automatic, what ('deploy' | 'coder
 *        start' | ...), subject, onWarn: 'notify' | 'silent', notify (test seam) }
 */
export async function admitContainer({ name, memoryMb, cpus, ...ctx }) {
  const cpu = cpus == null ? null : await admitCpu({ name, cpus, ...ctx });
  const result = await admitMemory({ name, memoryMb, ...ctx });
  return cpu ? { ...result, cpu } : result;
}

async function admitMemory({ name, memoryMb, ...ctx }) {
  const db = getDb();
  const { mode } = getAdmissionSettings(db);
  if (mode === 'off') return { mode, allowed: true, warned: false, skipped: true };
  const measurement = await measureMemory({ db });
  if (measurement.error) return { mode, allowed: true, warned: false, unknown: true, error: measurement.error };

  const verdict = decide({ measurement, name, newBytes: Math.max(0, Number(memoryMb) || 0) * MiB });
  if (verdict.allowed) return { mode, allowed: true, warned: false, verdict, overCommitted: !verdict.fits };

  const subject = ctx.subject || (ctx.slug ? `${ctx.slug}${ctx.env ? ` (${ctx.env})` : ''}` : name);
  const what = ctx.what || 'deploy';
  const replacing = verdict.replacedBytes > 0;
  const notify = ctx.notify || (await import('./memoryAdmissionMail.js')).notifyMemoryAdmission;

  if (mode === 'warn') {
    const message = warningMessage({ subject, what, verdict });
    if (ctx.onWarn !== 'silent') {
      try { await notify({ db, outcome: 'warned', message, verdict, measurement, name, subject, what, ...ctx }); } catch (e) { log.warn(`[memory-admission] notify failed: ${e.message}`); }
    }
    log.warn(`[memory-admission] ${message}`);
    recordAdmissionEvent('warned', ctx, message);
    return { mode, allowed: true, warned: true, message, verdict };
  }

  const message = refusalMessage({ subject, what, verdict, replacing });
  try { await notify({ db, outcome: 'refused', message, verdict, measurement, name, subject, what, ...ctx }); } catch (e) { log.warn(`[memory-admission] notify failed: ${e.message}`); }
  log.warn(`[memory-admission] refused ${name}: ${message}`);
  recordAdmissionEvent('refused', ctx, message);
  const err = new AppError(message, 409, REFUSED_CODE);
  err.admission = { verdict, mode };
  throw err;
}

export function _resetMemoryAdmissionForTests() {
  cached = null;
  reservations.clear();
}
