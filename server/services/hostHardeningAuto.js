// Host limits applied automatically after an upgrade. On boot, when the
// running version differs from the version of the last automatic run, the
// same script Apply runs is run in the background, after AppCrane's first
// successful APPCRANE-PUBLISH sync. A run that ends with warnings (for
// example DOCKER-USER without the DROP) is not counted as done and runs again.
//
// Root installs run the repo copy, exactly as Apply does. Other installs run
// only the root-owned copy, through the existing sudoers rule, and only when
// install-host-hardening.sh's stamp and the copy itself both say it is the
// script this checkout ships. Otherwise nothing runs and the admin is told to
// refresh the copy once. Nothing here writes, chooses or widens what root runs.

import { createHash } from 'crypto';
import { join } from 'path';
import { getDb } from '../db.js';
import { logAudit } from '../middleware/audit.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';
import {
  DEFAULT_DEPS, INSTALLED_SCRIPT, RUN_TIMEOUT_MS, SUDOERS_FILE,
  detectRunMode, expectedInstalledCopy, claimRun, releaseRun, runScript, writeLastRun,
} from './hostHardening.js';
import log from '../utils/logger.js';

export const JOB_ID = 'host-hardening-auto';
export const SETTING_KEY = 'host_hardening_auto_apply';
export const STATE_KEY = 'host_hardening_auto_last';
export const STAMP_FILE = '/usr/local/lib/appcrane/host-hardening.version';
export const MAIL_SOURCE = 'host-hardening-auto';
export const SYNC_WAIT_MS = 3 * 60_000;
export const CLAIM_WAIT_MS = 15 * 60_000;
export const POLL_MS = 2_000;
export const WAITING_RETRY_MS = 10 * 60_000;
export const STALE_RETRY_MS = 60 * 60_000;
export const SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
export const NOT_ROOT_NOTE = 'On this server AppCrane is not root, so a release that changes the hardening script needs this one root command; upgrades that do not change it apply automatically.';
const SETUP = 'Run once as root, from the AppCrane directory: sudo bash scripts/install-host-hardening.sh';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const sleep = (ms) => new Promise((r) => { const t = setTimeout(r, ms); t.unref?.(); });

export function isEnabled(db) {
  const v = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTING_KEY)?.value;
  return !(v != null && ['0', 'false', 'off', 'no'].includes(String(v).trim().toLowerCase()));
}

export function setEnabled(db, enabled, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(SETTING_KEY, enabled ? '1' : '0', userId);
}

export function readState(db) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(STATE_KEY);
  if (!row) return null;
  try { return JSON.parse(row.value); } catch (_) { return null; }
}

function writeState(db, state) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, NULL, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = NULL, updated_at = datetime('now')`)
    .run(STATE_KEY, JSON.stringify(state));
}

/** version=, source_sha256=, installed_sha256=, publish_chain_sha256=, db_chain_sha256= lines of the stamp; null when absent or unreadable. */
export function parseStamp(text) {
  const out = {};
  for (const line of String(text).split('\n')) {
    const m = /^([a-z_0-9]+)=(.*)$/.exec(line.trim());
    if (m) out[m[1]] = m[2];
  }
  return out.source_sha256 ? out : null;
}

/** kind: 'no-stamp' (first boot, copy installed before stamps), 'manual' (no copy or no sudo rule), else 'stale'. */
export function staleMessage(version, kind = 'stale') {
  const lead = {
    'no-stamp': `Host limits were not applied automatically for AppCrane ${version}: the root-owned copy of the hardening script has no version stamp yet (it was installed before automatic apply existed), so AppCrane cannot tell whether it is this release's script.`,
    manual: `Host limits were not applied automatically for AppCrane ${version}: Apply is not set up on this server (no root-owned copy of the hardening script, or no sudo rule for it in ${SUDOERS_FILE}).`,
    stale: `Host limits were not applied automatically for AppCrane ${version}: the root-owned copy of the hardening script is older than this release.`,
  }[kind] || '';
  return `${lead} ${SETUP}. ${NOT_ROOT_NOTE} AppCrane checks again every hour, so no restart is needed.`;
}

/** The kind of stale for staleMessage, from detectRunMode's mode and installedCopyMatches' reason. */
export const staleKind = (mode, why) => (mode !== 'sudo' ? 'manual' : /^no stamp/.test(why || '') ? 'no-stamp' : 'stale');

/**
 * The environment the script runs with: a fixed PATH and the variables Apply
 * passes, nothing from .env (APPCRANE_INPUT_FORCE and friends are read from the
 * root-owned host-network.conf instead).
 */
export function scriptEnv(env = process.env) {
  return { PATH: SAFE_PATH, HOME: env.HOME || '/root', LANG: env.LANG || 'C', LC_ALL: 'C' };
}
const minimalSpawn = (spawn) => (cmd, args, o) => spawn(cmd, args, { ...o, env: scriptEnv() });

/** Warning lines (`!!`) of the script's output; whether the network section left out the DROP, and whether only because AppCrane had not synced yet. */
export function readWarnings(out) {
  const warnings = String(out || '').split('\n').map((l) => l.trim()).filter((l) => /^!!\s/.test(l)).map((l) => l.replace(/^!!\s+/, ''));
  const noDrop = warnings.find((w) => /WITHOUT the DROP/.test(w)) || null;
  return { warnings, no_drop: !!noDrop, unsynced: warnings.some((w) => /has not synced published ports yet/.test(w)), reason: noDrop || warnings.at(-1) || null };
}

/** When to check again after an outcome; null for no further check before the next boot. */
export function retryDelay(res, o = {}) {
  const soon = o.waitingRetryMs ?? WAITING_RETRY_MS;
  const later = o.staleRetryMs ?? STALE_RETRY_MS;
  switch (res?.outcome) {
    case 'waiting': case 'busy': return soon;
    case 'stale': return later;
    // A warning that never clears (no gVisor build for this CPU, Docker reload refused on 28.x/29.0-29.2) must not re-run
    // the whole script every hour: only a missing DROP is worth checking again.
    case 'applied-with-warnings': return res.state?.unsynced ? soon : (res.state?.no_drop ? later : null);
    default: return null;
  }
}

/**
 * Whether the root-owned copy may run unattended: the stamp names the
 * checkout's script (by sha256) and the installed bytes are that script with
 * only REPO_DIR baked in. Either check failing means do not run it.
 */
// The two root-owned helpers install-host-hardening.sh copies byte for byte
// next to the script, by the stamp key that records each one's sha256.
const HELPER_STAMPS = [['publish_chain_sha256', 'appcrane-publish-chain.sh'], ['db_chain_sha256', 'appcrane-db-chain.sh']];

export function installedCopyMatches(d) {
  const read = (p) => { try { return d.readFile(p); } catch (_) { return null; } };
  const repo = read(join(d.repoDir, 'scripts', 'host-hardening.sh'));
  const installed = read(INSTALLED_SCRIPT);
  const stamp = parseStamp(read(STAMP_FILE) ?? '');
  if (repo == null || installed == null) return { ok: false, why: 'no installed copy' };
  if (!stamp) return { ok: false, why: `no stamp at ${STAMP_FILE}` };
  if (stamp.source_sha256 !== sha256(repo)) return { ok: false, why: 'stamp names another script', stamp };
  if (stamp.installed_sha256 && stamp.installed_sha256 !== sha256(installed)) return { ok: false, why: 'installed copy changed since it was stamped', stamp };
  for (const [key, name] of HELPER_STAMPS) {
    const helper = read(join(d.repoDir, 'scripts', name));
    if (helper == null || stamp[key] !== sha256(helper)) return { ok: false, why: `stamp names another ${name}`, stamp };
  }
  if (installed !== expectedInstalledCopy(repo, d.repoDir)) return { ok: false, why: 'installed copy differs from the checkout', stamp };
  return { ok: true, stamp };
}

/** Linux with systemd and iptables, as Apply's own checks require. */
export async function applicable(d) {
  if (d.platform !== 'linux') return { ok: false, why: `not Linux (${d.platform})` };
  try { d.stat('/run/systemd/system'); } catch (_) { return { ok: false, why: 'no systemd on this host' }; }
  const ipt = await d.exec('iptables', ['--version']);
  if (ipt.missing) return { ok: false, why: 'iptables is not installed' };
  return { ok: true };
}

/**
 * Waits, at most waitMs, for a successful APPCRANE-PUBLISH sync since boot.
 * Only status ok counts: a failed sync, or none, leaves the chain possibly
 * empty, and the script's own unsynced check sees nothing on hosts without
 * docker-proxy (userland-proxy false).
 */
export async function waitForFirstSync(d, waitMs = SYNC_WAIT_MS, pollMs = POLL_MS) {
  const until = Date.now() + waitMs;
  let last = null;
  for (;;) {
    const s = await d.lastSync();
    if (s) last = s.status;
    if (s?.status === 'ok') return { synced: true, status: 'ok' };
    if (Date.now() >= until) return { synced: false, status: last || 'none' };
    await sleep(pollMs);
  }
}

async function claimWithin(waitMs, pollMs) {
  const until = Date.now() + waitMs;
  while (!claimRun()) {
    if (Date.now() >= until) return false;
    await sleep(pollMs);
  }
  return true;
}

function mailStale(db, version, message) {
  return import('./emailQueue.js').then(({ enqueueEmail }) => {
    const admins = db.prepare("SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL").all();
    for (const { email } of admins) {
      try {
        enqueueEmail({
          to: email, appId: null, source: MAIL_SOURCE,
          subject: `AppCrane ${version}: host limits were not applied automatically`,
          text: `${message}\n\nSee Settings > Job Health > Host limits.`,
          idempotencyKey: `${MAIL_SOURCE}:stale:${version}:${email}`,
        });
      } catch (e) {
        if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[host-hardening-auto] mail skipped: ${e.message}`);
      }
    }
  }).catch((e) => log.warn(`[host-hardening-auto] mail failed: ${e.message}`));
}

const errorLine = (out) => String(out || '').trim().split('\n').map((l) => l.trim()).filter(Boolean)
  .filter((l) => /^xx|error|failed/i.test(l)).pop() || '';

/**
 * One boot's decision and, when due, the run. Resolves to what happened;
 * never throws (failures are recorded in Job Health).
 */
const lastSync = async () => (await import('./hostFirewall/index.js')).getLastSync();

export async function autoApply(opts = {}) {
  const d = { ...DEFAULT_DEPS, lastSync, ...opts.deps };
  const db = opts.db || getDb();
  const version = opts.version;
  const prev = readState(db);
  const outcome = async () => {
    if (!isEnabled(db)) return { outcome: 'disabled' };
    if (prev?.version === version && prev.done !== false) return { outcome: 'up-to-date', last: prev };
    const app = await applicable(d);
    if (!app.ok) return { outcome: 'not-applicable', reason: app.why };
    const run = await detectRunMode(d);
    if (run.mode === 'sudo') {
      const m = installedCopyMatches(d);
      if (!m.ok) run.blocked = m.why;
    } else if (run.mode !== 'root') {
      run.blocked = run.reason || 'no sudo rule for the installed copy';
    }
    if (run.blocked) {
      // Mail only where Apply was set up (a sudo rule exists); elsewhere Job Health says it.
      if (run.mode === 'sudo') await mailStale(db, version, staleMessage(version, staleKind(run.mode, run.blocked)));
      return { outcome: 'stale', reason: run.blocked, message: staleMessage(version, staleKind(run.mode, run.blocked)), severity: 'warning' };
    }
    const sync = await waitForFirstSync(d, opts.syncWaitMs ?? SYNC_WAIT_MS, opts.pollMs ?? POLL_MS);
    if (!sync.synced) {
      return {
        outcome: 'waiting', severity: 'warning', publish_sync: sync.status,
        message: `Waiting for AppCrane's first successful APPCRANE-PUBLISH sync since it started (last: ${sync.status}) before applying host limits for ${version}; checks again every 10 minutes.`,
      };
    }
    if (!await claimWithin(opts.claimWaitMs ?? CLAIM_WAIT_MS, opts.pollMs ?? POLL_MS)) {
      return { outcome: 'busy', reason: 'an Apply was still running', severity: 'warning' };
    }
    const started = Date.now();
    let r;
    try {
      r = await runScript(run.argv, { ...d, spawn: minimalSpawn(d.spawn) }, { timeoutMs: opts.timeoutMs ?? RUN_TIMEOUT_MS });
    } finally {
      releaseRun();
    }
    const ok = r.exit_code === 0;
    const w = readWarnings(r.output);
    const warned = ok && w.warnings.length > 0;
    const at = new Date().toISOString();
    const state = {
      version, from_version: prev?.version === version ? (prev.from_version ?? null) : (prev?.version ?? null), at, ok,
      done: !warned, exit_code: r.exit_code, timed_out: r.timed_out, mode: run.mode, publish_sync: sync.status,
      warnings: w.warnings, no_drop: w.no_drop, unsynced: w.unsynced,
      reason: ok ? (warned ? w.reason : null) : (r.timed_out ? 'timed out' : errorLine(r.output) || `exit ${r.exit_code}`),
    };
    writeState(db, state);
    writeLastRun(db, { at, ok, exit_code: r.exit_code, by: `AppCrane, automatically after the upgrade to ${version}`, automatic: true, version }, null);
    logAudit(null, null, ok ? 'host-hardening-auto-applied' : 'host-hardening-auto-failed', {
      version, mode: run.mode, exit_code: r.exit_code, timed_out: r.timed_out, duration_ms: Date.now() - started, publish_sync: sync.status,
      warnings: w.warnings.length, no_drop: w.no_drop,
    }, 'system');
    if (warned) {
      return {
        outcome: 'applied-with-warnings', state, severity: 'warning',
        message: `host-hardening.sh ran for ${version} with ${w.warnings.length} warning(s)${w.no_drop ? ', and DOCKER-USER has no DROP on the public interface' : ''}: ${w.reason}. ${w.unsynced ? 'It runs again in 10 minutes.' : w.no_drop ? 'It runs again in an hour.' : 'It runs again after the next upgrade.'}`,
      };
    }
    return { outcome: ok ? 'applied' : 'failed', state };
  };
  try {
    return await trackJob(JOB_ID, async () => {
      const res = await outcome();
      const delay = retryDelay(res, opts);
      setJobDetail(JOB_ID, { ...res, version, severity: res.severity || null, next_check_at: delay == null ? null : new Date(Date.now() + delay).toISOString() });
      if (res.outcome === 'failed') throw new Error(`host-hardening.sh failed after the upgrade to ${version}: ${res.state.reason}`);
      return res;
    });
  } catch (e) {
    log.warn(`[host-hardening-auto] ${e.message}`);
    return { outcome: 'failed', error: e.message };
  }
}

let current = null;
let timer = null;
let lastOutcome = null;

function cycle(opts) {
  current = Promise.resolve().then(() => autoApply(opts)).then((res) => {
    lastOutcome = { ...res, at: new Date().toISOString() };
    const delay = retryDelay(res, opts);
    if (delay != null) {
      timer = setTimeout(() => { timer = null; cycle(opts); }, delay);
      timer.unref?.();
    }
    return res;
  });
  return current;
}

/**
 * Startup hook: returns at once; the decision and any run happen in the
 * background. Waiting (no successful sync yet), busy and an unsynced DROP are
 * checked again every 10 minutes; a stale root copy and other warnings hourly.
 */
export function startHostHardeningAuto(opts = {}) {
  const db = opts.db || getDb();
  stopHostHardeningAuto();
  jobStarted(JOB_ID, { cadenceMs: null, enabled: () => isEnabled(db) });
  return cycle({ ...opts, db });
}

export function stopHostHardeningAuto() {
  if (timer) clearTimeout(timer);
  timer = null;
}

export const _current = () => current;
export const _hasTimer = () => timer != null;

/** What the Host limits page shows: the setting, the last automatic run, and a pending warning. */
export async function autoStatus(db, d, version) {
  const last = readState(db);
  const pending = lastOutcome && ['waiting', 'busy'].includes(lastOutcome.outcome)
    ? { outcome: lastOutcome.outcome, message: lastOutcome.message || lastOutcome.reason || null, at: lastOutcome.at } : null;
  const body = { enabled: isEnabled(db), last, warning: null, pending };
  if (!body.enabled || (last?.version === version && last.done !== false)) return body;
  if (last?.version === version && last.done === false) {
    body.warning = `The last automatic apply for ${version} ended with warnings (${last.reason}); it runs again ${last.unsynced ? 'every 10 minutes' : 'every hour'} until it ends without them.`;
    return body;
  }
  const dd = { ...DEFAULT_DEPS, ...d };
  if (!(await applicable(dd)).ok) return body;
  const run = await detectRunMode(dd);
  const m = run.mode === 'sudo' ? installedCopyMatches(dd) : null;
  const blocked = run.mode === 'sudo' ? !m.ok : run.mode !== 'root';
  if (blocked) body.warning = staleMessage(version, staleKind(run.mode, m?.why));
  return body;
}
