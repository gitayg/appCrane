// CPU admission: the sum of --cpus caps of running containers against the
// host's cores minus a reserve, the CPU twin of memoryAdmission.js.
//
// capacity  = host cores (docker info .NCPU; os cores when that fails) minus a
//             reserve (setting cpu_reserve_cores; default max(0.5, 25% of
//             cores): on the 2-core host of the 2026-08-03 incident that is
//             half a core for Caddy, sshd, AppCrane and dockerd, and it grows
//             with the host so a 16-core box keeps 4).
// committed = the sum of NanoCpus over every RUNNING container on the daemon.
//             A container with no CPU cap counts as 0 and is listed as
//             `uncapped`: its real draw is unknown, and the resource drift
//             report is where an uncapped container gets fixed.
//
// CPU is compressible: an over-committed host slows down, it does not kill
// anything, and the --cpu-shares weights (cpuPriority.js) keep the host
// services ahead regardless. So the default is warn, and refuse is opt-in.
//
// A cap is a ceiling, not a reservation: an app capped at 1 CPU uses nothing
// while idle. So the caps may total capacity x cpu_overcommit_ratio (default
// 4). At 1 a normal host warned on nearly every deploy (crane.glick.run,
// 2026-10-28: 8.9 CPU of caps on 6 of capacity, 235 warnings in a week) and an
// app could not be given room to burst.
// Same rule as memory: a start that does not raise the total (a same-size
// redeploy or rollback) is always allowed, and a measurement that fails admits.

import { execFile } from 'child_process';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';
import { recordEvent } from './eventStore.js';
import { hostCores, CPU_SHARES } from './cpuPriority.js';

export const CPU_MODE_KEY = 'cpu_admission_mode';
export const CPU_RESERVE_KEY = 'cpu_reserve_cores';
export const CPU_OVERCOMMIT_KEY = 'cpu_overcommit_ratio';
export const DEFAULT_CPU_OVERCOMMIT = 4;
export const CPU_MODES = ['refuse', 'warn', 'off'];
export const DEFAULT_CPU_MODE = 'warn';
export const CPU_REFUSED_CODE = 'INSUFFICIENT_CPU';
export const CACHE_MS = 15_000;
export const CPU_INSPECT_FORMAT = '{{.Name}}\t{{.HostConfig.NanoCpus}}\t{{.HostConfig.CpuQuota}}\t{{.HostConfig.CpuPeriod}}\t{{.HostConfig.CpuShares}}\t{{json .Config.Labels}}';

const NANO = 1e9;
let cached = null;

function setting(db, key) {
  try { return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null; } catch (_) { return null; }
}

export function getCpuAdmissionSettings(db = getDb()) {
  const raw = setting(db, CPU_MODE_KEY);
  const mode = CPU_MODES.includes(raw) ? raw : DEFAULT_CPU_MODE;
  const r = setting(db, CPU_RESERVE_KEY);
  const n = r === null || r === '' ? NaN : Number(r);
  const o = Number(setting(db, CPU_OVERCOMMIT_KEY) || NaN);
  return {
    mode, reserveCores: Number.isFinite(n) && n >= 0 ? n : null,
    overcommitRatio: Number.isFinite(o) && o >= 1 ? o : DEFAULT_CPU_OVERCOMMIT,
  };
}

export function defaultReserveCores(cores) {
  return Math.max(0.5, cores * 0.25);
}

function docker(args) {
  return new Promise((resolve, reject) => {
    execFile('docker', args, { timeout: 10_000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout) => (err ? reject(err) : resolve(String(stdout))));
  });
}

function labelOf(name, l = {}) {
  if (l.slug && l.env) return { kind: 'app', label: `${l.slug} (${l.env})` };
  if (l['appcrane-db']) return { kind: 'db', label: `managed ${l['appcrane-db']}${l['appcrane-db-name'] ? ` ${l['appcrane-db-name']}` : ''}` };
  if (l['app.slug']) return { kind: 'helper', label: `${l['appcrane.container.type'] === 'app' ? 'coder' : 'helper'} for ${l['app.slug']}` };
  if (l.appcrane || l['appcrane.gh-mcp']) return { kind: 'helper', label: name };
  return { kind: 'other', label: name };
}

/** `docker inspect` lines in CPU_INSPECT_FORMAT -> rows with the cap in cores (0 = uncapped). */
export function parseCpuInspect(out) {
  const rows = [];
  for (const line of String(out || '').split('\n')) {
    const p = line.split('\t');
    if (p.length < 6) continue;
    const name = p[0].replace(/^\//, '').trim();
    const nano = Number(p[1]);
    const quota = Number(p[2]);
    const period = Number(p[3]);
    const shares = Number(p[4]);
    if (!name || !Number.isFinite(nano)) continue;
    let labels = {};
    try { labels = JSON.parse(p.slice(5).join('\t')) || {}; } catch (_) { labels = {}; }
    const cores = nano > 0 ? nano / NANO : (quota > 0 && period > 0 ? quota / period : 0);
    const meta = labelOf(name, labels);
    rows.push({ name, cores, uncapped: cores === 0, shares: Number.isFinite(shares) ? shares : 0, ours: meta.kind !== 'other', ...meta });
  }
  return rows;
}

async function readCores() {
  try {
    const n = Number(String(await docker(['info', '--format', '{{.NCPU}}'])).trim());
    if (Number.isFinite(n) && n > 0) return { cores: n, coresSource: 'docker' };
  } catch (_) { /* fall through */ }
  return { cores: hostCores(), coresSource: 'os' };
}

/** One measurement, cached for CACHE_MS. Never throws: `error` is set instead. */
export async function measureCpu({ fresh = false, db = getDb() } = {}) {
  if (!fresh && cached && Date.now() - cached.at < CACHE_MS) return cached.value;
  const { reserveCores } = getCpuAdmissionSettings(db);
  const { cores, coresSource } = await readCores();
  const reserve = reserveCores != null ? reserveCores : defaultReserveCores(cores);
  let containers = [];
  let error = null;
  try {
    const ids = String(await docker(['ps', '-q', '--no-trunc'])).split('\n').map((s) => s.trim()).filter(Boolean);
    if (ids.length) containers = parseCpuInspect(await docker(['inspect', '--format', CPU_INSPECT_FORMAT, ...ids]));
  } catch (e) {
    error = `could not list running containers: ${String(e.message).split('\n')[0]}`;
  }
  const value = {
    cores, coresSource, reserveCores: reserve, reserveSource: reserveCores != null ? 'setting' : 'default',
    capacityCores: Math.max(0, cores - reserve),
    committedCores: containers.reduce((s, c) => s + c.cores, 0),
    containers, error, measuredAt: new Date().toISOString(),
  };
  if (!error) cached = { at: Date.now(), value };
  return value;
}

/** The last good measurement, without asking Docker. */
export function peekCpuMeasurement() {
  return cached?.value ?? null;
}

/** AppCrane containers running at Docker's default weight, i.e. created before the --cpu-shares flags. */
export function containersWithoutWeight(measurement) {
  const want = new Set(Object.values(CPU_SHARES));
  return (measurement?.containers || []).filter((c) => c.ours && !want.has(c.shares));
}

/** Pure rule, exported for tests. */
export function decideCpu({ measurement, name, newCores, overcommitRatio = 1 }) {
  const replaced = measurement.containers.find((c) => c.name === name)?.cores || 0;
  const base = measurement.committedCores - replaced;
  const after = base + newCores;
  const limit = measurement.capacityCores * overcommitRatio;
  const fits = after <= limit + 1e-9;
  const notRaising = newCores <= replaced + 1e-9;
  return {
    allowed: fits || notRaising, fits, notRaising,
    newCores, replacedCores: replaced, committedCores: measurement.committedCores, afterCores: after,
    capacityCores: measurement.capacityCores, overcommitRatio, limitCores: limit, freeCores: Math.max(0, limit - base),
    uncapped: measurement.containers.filter((c) => c.uncapped).length,
  };
}

const r2 = (n) => Math.round(n * 100) / 100;

export function cpuMessage({ outcome, subject, what, verdict }) {
  const nums = `${subject} asks for ${r2(verdict.newCores)} CPU, ${r2(verdict.freeCores)} is free `
    + `(${r2(verdict.committedCores)} of ${r2(verdict.limitCores)} CPU of caps allowed: ${r2(verdict.capacityCores)} CPU capacity x ${r2(verdict.overcommitRatio)}`
    + `${verdict.uncapped ? `; ${verdict.uncapped} running container(s) have no CPU cap and are not counted` : ''}).`;
  return outcome === 'refused'
    ? `Not enough CPU on the server for this ${what}: ${nums} Nothing was changed. Try again later, or ask a platform admin to lower other containers' CPU limits.`
    : `CPU warning: this ${what} takes the server past its CPU capacity. ${nums} Started anyway (CPU admission is set to warn only).`;
}

async function defaultNotify({ db, outcome, message, subject }) {
  const { enqueueEmail } = await import('./emailQueue.js');
  const hour = new Date().toISOString().slice(0, 13);
  const admins = db.prepare(`SELECT email FROM users WHERE role = 'platform_admin' AND active = 1
                             AND email IS NOT NULL AND trim(email) != ''`).all();
  const sent = [];
  for (const { email } of admins) {
    try {
      enqueueEmail({
        to: email, appId: null, source: 'host-resources',
        subject: `[AppCrane] CPU admission ${outcome === 'refused' ? 'refused' : 'warning'}: ${subject}`,
        text: `${message}\n\nLower a container's CPU limit, stop an unused sandbox, or change CPU admission in Settings > Job Health.\n`,
        idempotencyKey: `cpu-admission:${subject}:${hour}:${email.trim().toLowerCase()}`,
      });
      sent.push(email);
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[cpu-admission] mail to ${email} skipped: ${e.message}`);
    }
  }
  return sent;
}

/**
 * Decide whether `name` may start with `cpus` cores. Refuse throws AppError 409
 * INSUFFICIENT_CPU; warn returns { warned: true, message } and tells the
 * platform admins (once per subject per hour) unless onWarn is 'silent'.
 */
export async function admitCpu({ name, cpus, ...ctx }) {
  const db = getDb();
  const { mode, overcommitRatio } = getCpuAdmissionSettings(db);
  if (mode === 'off') return { mode, allowed: true, warned: false, skipped: true };
  const newCores = Math.max(0, Number(cpus) || 0);
  if (!newCores) return { mode, allowed: true, warned: false, skipped: true };
  const measurement = await measureCpu({ db });
  if (measurement.error) return { mode, allowed: true, warned: false, unknown: true, error: measurement.error };
  const verdict = decideCpu({ measurement, name, newCores, overcommitRatio });
  if (verdict.allowed) return { mode, allowed: true, warned: false, verdict };

  const subject = ctx.subject || (ctx.slug ? `${ctx.slug}${ctx.env ? ` (${ctx.env})` : ''}` : name);
  const what = ctx.what || 'deploy';
  const outcome = mode === 'warn' ? 'warned' : 'refused';
  const message = cpuMessage({ outcome, subject, what, verdict });
  const notify = ctx.notifyCpu || defaultNotify;
  if (outcome === 'refused' || ctx.onWarn !== 'silent') {
    try { await notify({ db, outcome, message, verdict, subject, what }); } catch (e) { log.warn(`[cpu-admission] notify failed: ${e.message}`); }
  }
  try {
    recordEvent({
      kind: 'cpu.admission', severity: outcome === 'refused' ? 'critical' : 'warning',
      appId: ctx.appId ?? null, appSlug: ctx.slug || null, userId: ctx.userId ?? null, summary: message,
      data: { outcome, what, env: ctx.env || null, automatic: !!ctx.automatic },
    });
  } catch (_) { /* the event store must not decide a start */ }
  log.warn(`[cpu-admission] ${message}`);
  if (outcome === 'warned') return { mode, allowed: true, warned: true, message, verdict };
  const err = new AppError(message, 409, CPU_REFUSED_CODE);
  err.admission = { verdict, mode, resource: 'cpu' };
  throw err;
}

export function _resetCpuAdmissionForTests(value = null) {
  cached = value ? { at: Date.now(), value } : null;
}
