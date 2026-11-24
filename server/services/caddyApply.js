// Applying a generated Caddyfile to the running Caddy, without ever taking the
// proxy down to do it.
//
// One restart storm took every site on a box down for hours: an app delete
// fired many reloads in a row, each one that failed fell back to `systemctl
// restart caddy`, a restart reads the config from disk and exits when it is
// bad, and systemd's default start limit (5 starts in 10 s, Restart=no) then
// refused every further start. Measured against caddy:2 v2.11.9:
//
//   caddy adapt   on a config whose cert file is missing  -> exit 0 (syntax only)
//   caddy validate on the same config                     -> exit 1
//   caddy reload  of it into a running Caddy               -> exit 1, still serving the old config
//   caddy run     of it (what a restart does)              -> exit 1, nothing serving
//
// So: validate first, apply with a reload only (Caddy rolls a failed load
// back), never restart on a failed reload, start Caddy only when it is not
// running and at most once a minute, put the last good file back when a load
// fails, and coalesce bursts of reload requests into one.

import { writeFileSync, readFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from 'fs';
import log from '../utils/logger.js';
import { jobStarted, trackJob } from './jobHealth.js';

const MIN = 60_000;

async function run(file, args, opts) {
  const { execFile } = await import('child_process');
  const { promisify } = await import('util');
  return promisify(execFile)(file, args, opts);
}

const DEFAULTS = () => ({
  run,
  adminUrl: process.env.CADDY_ADMIN_URL || 'http://localhost:2019',
  fetch: (...a) => fetch(...a),
  livePath: '/etc/caddy/Caddyfile',
  tmpPath: '/tmp/Caddyfile.appcrane-validate',
  backupDir: '/etc/caddy/.appcrane-backups',
  windowMs: Number(process.env.CADDY_RELOAD_DEBOUNCE_MS) || 750,
  maxWaitMs: 5000,
  startCooldownMs: MIN,
  watchdogMs: MIN,
  now: () => Date.now(),
  audit: async (action, detail) => {
    const { logAudit } = await import('../middleware/audit.js');
    logAudit(null, null, action, detail, 'system');
  },
});

let deps = DEFAULTS();
let lastStartAt = -Infinity;
let lastFailure = null;
let lastSuccessAt = null;

export function _setCaddyApplyDepsForTests(over) { deps = { ...deps, ...over }; }
export function _resetCaddyApplyForTests() {
  deps = DEFAULTS(); lastStartAt = -Infinity; lastFailure = null; lastSuccessAt = null;
  pending = null; inflight = null;
  if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = null; }
}

export function caddyApplyStatus() {
  return { last_success_at: lastSuccessAt, last_failure: lastFailure };
}

const detailOf = (e) => (e?.stderr?.toString().trim() || e?.message || String(e)).slice(-2000);

/** `systemctl is-active caddy`: 'active', 'inactive', 'failed', 'activating', ... */
export async function caddyUnitState() {
  try {
    const r = await deps.run('systemctl', ['is-active', 'caddy'], { timeout: 5000 });
    return String(r.stdout || '').trim() || 'active';
  } catch (e) {
    return String(e?.stdout || '').trim() || 'unknown';
  }
}

/**
 * Start Caddy when it is stopped. Never `restart`: that stops a running Caddy
 * first. At most once per startCooldownMs, process-wide, so no caller, loop
 * or watchdog tick can turn into a start storm. 'activating' is systemd's own
 * Restart= in progress and is left to it.
 */
export async function startCaddyIfStopped(reason) {
  const state = await caddyUnitState();
  if (!['inactive', 'failed'].includes(state)) return { started: false, state };
  const now = deps.now();
  if (now - lastStartAt < deps.startCooldownMs) return { started: false, state, cooldown: true };
  lastStartAt = now;
  try {
    // A unit that hit its start limit refuses `start` until reset.
    if (state === 'failed') await deps.run('systemctl', ['reset-failed', 'caddy'], { timeout: 10000 }).catch(() => {});
    await deps.run('systemctl', ['start', 'caddy'], { timeout: 15000 });
    log.warn(`[caddy] started a stopped Caddy (${state}): ${reason}`);
    return { started: true, state };
  } catch (e) {
    log.error(`[caddy] start failed (${state}): ${detailOf(e)}`);
    return { started: false, state, error: detailOf(e) };
  }
}

async function recordFailure(stage, error) {
  lastFailure = { at: new Date(deps.now()).toISOString(), stage, error };
  try { await deps.audit('caddy.apply-failed', { stage, error: String(error).slice(0, 500) }); } catch (_) { /* audit is best-effort here */ }
}

async function validate(caddyfile) {
  writeFileSync(deps.tmpPath, caddyfile);
  try {
    await deps.run('caddy', ['adapt', '--config', deps.tmpPath, '--adapter', 'caddyfile'], { timeout: 8000 });
  } catch (e) {
    return { ok: false, error: `Generated Caddyfile does not parse: ${detailOf(e)}` };
  }
  // `validate` also provisions (certificates, log files), which `adapt` never
  // does. It runs as AppCrane's user, not caddy's, so a file only caddy can
  // read fails here with "permission denied" and proves nothing about the
  // config; the reload below is then the check, and Caddy rolls it back.
  try {
    await deps.run('caddy', ['validate', '--config', deps.tmpPath, '--adapter', 'caddyfile'], { timeout: 15000 });
    return { ok: true };
  } catch (e) {
    const detail = detailOf(e);
    if (/permission denied/i.test(detail)) return { ok: true, provisioningUnchecked: detail };
    return { ok: false, error: `Generated Caddyfile is invalid: ${detail}` };
  }
}

function backup(prev) {
  try {
    if (!existsSync(deps.backupDir)) mkdirSync(deps.backupDir, { recursive: true });
    const stamp = new Date(deps.now()).toISOString().replace(/[:.]/g, '-');
    writeFileSync(`${deps.backupDir}/Caddyfile-${stamp}`, prev);
    const files = readdirSync(deps.backupDir).filter(f => f.startsWith('Caddyfile-')).sort();
    for (const f of files.slice(0, Math.max(0, files.length - 10))) {
      try { unlinkSync(`${deps.backupDir}/${f}`); } catch (_) { /* best-effort */ }
    }
  } catch (e) {
    log.warn(`Caddy backup failed (non-fatal): ${e.message}`);
  }
}

async function adminAnswers() {
  try {
    const r = await deps.fetch(`${deps.adminUrl}/config/`, { signal: AbortSignal.timeout(2000) });
    return r.ok;
  } catch (_) {
    return false;
  }
}

/** One apply: validate, write, reload (or start a stopped Caddy). Never throws. */
export async function applyCaddyfile(caddyfile, { force = false } = {}) {
  let result;
  try {
    await trackJob('caddy-reload', async () => {
      result = await applyOnce(caddyfile, { force });
      if (!result.success) throw new Error(`${result.stage}: ${result.error}`);
    });
  } catch (_) { /* recorded by trackJob; result carries it */ }
  if (result.success && !result.unchanged) lastSuccessAt = new Date(deps.now()).toISOString();
  return result;
}

async function applyOnce(caddyfile, { force }) {
  const v = await validate(caddyfile);
  if (!v.ok) {
    log.error(`Caddy validation failed, nothing applied, the running config is kept: ${v.error}`);
    await recordFailure('validate', v.error);
    return { success: false, stage: 'validate', error: v.error };
  }

  let prev = '';
  try { prev = readFileSync(deps.livePath, 'utf8'); } catch (_) { /* first run */ }
  const state = await caddyUnitState();
  // Only a unit systemd reports stopped is started; anything else (including
  // a host where the state cannot be read) gets the reload, which cannot take
  // a running Caddy down.
  const running = !['inactive', 'failed'].includes(state);

  // v2.21.31: `force` reloads an unchanged file, because what the RUNNING Caddy
  // loaded can differ from the file (a reload that failed earlier).
  if (prev === caddyfile && !force && running) {
    log.info('Caddy config unchanged — skipping reload.');
    return { success: true, unchanged: true };
  }

  if (prev && prev !== caddyfile) backup(prev);
  writeFileSync(deps.livePath, caddyfile);
  const restorePrev = () => { if (prev && prev !== caddyfile) { try { writeFileSync(deps.livePath, prev); } catch (e) { log.error(`Caddy: could not put the previous Caddyfile back: ${e.message}`); } } };

  if (!running) {
    const s = await startCaddyIfStopped('config apply');
    if (s.started && await adminAnswers()) return { success: true, started: true };
    // A config Caddy cannot start with must not stay on disk for systemd's
    // next start; the watchdog tries again with the previous one.
    restorePrev();
    const error = s.error || (s.cooldown ? `Caddy is ${state}; a start was attempted less than a minute ago`
      : s.started ? 'Caddy was started but its admin API does not answer' : `Caddy is ${state}`);
    await recordFailure('start', error);
    return { success: false, stage: 'start', error };
  }

  try {
    await deps.run('systemctl', ['reload', 'caddy'], { timeout: 15000 });
  } catch (e) {
    // Caddy refused the new config and kept serving the old one. Putting the
    // old file back keeps disk and process in step, so a later start (boot,
    // a crash restart) loads what is running now, not what was refused.
    restorePrev();
    const error = detailOf(e);
    log.error(`Caddy reload refused; the running config is kept and the previous Caddyfile restored: ${error}`);
    await recordFailure('reload', error);
    return { success: false, stage: 'reload', error };
  }

  if (!(await adminAnswers())) {
    const after = await caddyUnitState();
    if (after !== 'active') {
      restorePrev();
      const s = await startCaddyIfStopped('stopped during reload');
      const error = `Caddy is ${after} after a reload${s.started ? '; started it with the previous Caddyfile' : ''}`;
      await recordFailure('reload', error);
      return { success: false, stage: 'reload', error };
    }
    const error = 'Caddy reloaded but its admin API does not answer';
    await recordFailure('verify', error);
    return { success: false, stage: 'verify', error };
  }

  log.info('Caddy reloaded: ' + caddyfile.split('\n').filter(l => l.includes('{')).map(l => l.trim().split(' ')[0]).join(', '));
  return { success: true, ...(v.provisioningUnchecked ? { provisioning_unchecked: true } : {}) };
}

// ---- coalescing ----
//
// Every caller gets the result of an apply that STARTED after its call, so the
// config it changed is in it. Calls within windowMs of each other (bounded by
// maxWaitMs) share one apply; one runs at a time, and calls during it share
// the next. The config is generated when the apply starts: the last write wins.

let pending = null;
let inflight = null;

function startPending(apply) {
  const batch = pending;
  pending = null;
  clearTimeout(batch.timer);
  inflight = (async () => {
    let r;
    try { r = await apply({ force: batch.force }); } catch (e) { r = { success: false, error: e.message }; }
    return r;
  })();
  inflight.then((r) => {
    for (const w of batch.waiters) w(r);
    inflight = null;
    if (pending?.due) startPending(apply);
  });
}

export function coalescedApply(apply, { force = false } = {}) {
  return new Promise((resolve) => {
    const now = deps.now();
    if (!pending) pending = { waiters: [], force: false, first: now, timer: null, due: false };
    pending.waiters.push(resolve);
    pending.force ||= force;
    clearTimeout(pending.timer);
    const wait = Math.max(0, Math.min(deps.windowMs, pending.first + deps.maxWaitMs - now));
    const batch = pending;
    batch.timer = setTimeout(() => {
      if (pending !== batch) return;
      batch.due = true;
      if (!inflight) startPending(apply);
    }, wait);
  });
}

// ---- watchdog ----

let watchdogTimer = null;

export async function caddyWatchdogTick() {
  return trackJob('caddy-watchdog', async () => {
    const state = await caddyUnitState();
    if (state === 'active' || state === 'reloading' || state === 'activating') return { state };
    const s = await startCaddyIfStopped('watchdog');
    const msg = `Caddy was ${state}${s.started ? '; AppCrane started it' : s.cooldown ? '; a start is already pending its one-minute cooldown' : `; start failed: ${s.error || 'unknown'}`}`;
    await recordFailure('watchdog', msg);
    throw new Error(msg);
  });
}

/** Every minute: alert (Job Health mails platform admins) and start a stopped Caddy. */
export function startCaddyWatchdog() {
  if (watchdogTimer) return;
  jobStarted('caddy-reload', { cadenceMs: null });
  jobStarted('caddy-watchdog', { cadenceMs: deps.watchdogMs });
  watchdogTimer = setInterval(() => { caddyWatchdogTick().catch(() => {}); }, deps.watchdogMs);
  watchdogTimer.unref?.();
}
