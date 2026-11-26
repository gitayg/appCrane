import { existsSync } from 'node:fs';
import { getDb } from '../../db.js';
import { defaultRun } from './exec.js';
import { chainMissing, permissionDenied, sudoRefused } from './rules.js';
import { DB_CHAIN, DB_FAMILIES, DB_HELPER, renderDbRestore, parseDbChain, sameRules, dbHelperArgs, dbCounterArgs, parseDbCounters } from './dbRules.js';
import { dbPortSpecs, candidateNames, readContainerAddrs, computeDbPlan } from './dbDesired.js';
import { dbAllowlistMode } from './dbMode.js';
import { SKELETON_CHAIN } from './rules.js';
import { readHostNetworkState, defaultReadFile } from './hostNet.js';
import log from '../../utils/logger.js';

// Keeps APPCRANE-DB equal to the plan dbDesired.js computes. Never blocks a
// container start and never drops on a guess: a port whose allowlist could not
// be computed gets no lines at all.

export const DEFAULT_DB_DEPS = Object.freeze({
  platform: process.platform,
  run: defaultRun,
  uid: typeof process.getuid === 'function' ? process.getuid() : null,
  exists: existsSync,
  readFile: defaultReadFile,
});

export const START_SYNC_TIMEOUT_MS = 15_000;

let deps = DEFAULT_DB_DEPS;
let enabled = false;
const pending = new Map();
let lastDbSync = null;
// observe mode: packets enforce would have dropped, per port, since this
// process started. Rewriting the chain zeroes its counters, so each family's
// last reading is kept and only the increase is added.
let wouldDrop = { since: null, ports: new Map() };
let lastCounters = { v4: new Map(), v6: new Map() };

export function getLastDbSync() { return lastDbSync; }

/** Turned on by the host firewall scheduler; off, the start path does nothing. */
export function enableDbChain(d = {}) { deps = { ...DEFAULT_DB_DEPS, ...d }; enabled = true; }
export function disableDbChain() { enabled = false; }
export function dbChainEnabled() { return enabled; }
export function _resetDbChainForTests() { enabled = false; deps = DEFAULT_DB_DEPS; pending.clear(); lastDbSync = null; running = null; queued = null; wouldDrop = { since: null, ports: new Map() }; lastCounters = { v4: new Map(), v6: new Map() }; }

export function readDbChainArgs() { return ['-w', '-S', DB_CHAIN]; }
export function dbRestoreArgs() { return ['-w', '--noflush']; }

// ip6tables installed on a kernel booted without IPv6 (ipv6.disable=1), or
// without the ip6 filter table: there is no IPv6 path to filter.
export function familyUnusable(fam, stderr) {
  return fam.id === 'v6' && /can't initialize|Address family not supported|Table does not exist/i.test(String(stderr || ''));
}

async function readFamily(run, fam) {
  const r = await run(fam.bin, readDbChainArgs());
  if (r.missing) return { state: 'no_binary' };
  if (r.code === 0) return { state: 'read', ...parseDbChain(r.stdout) };
  if (familyUnusable(fam, r.stderr)) return { state: 'not_applicable', error: r.stderr.trim().split('\n')[0] };
  if (chainMissing(r.stderr)) return { state: 'read', exists: false, rules: [], foreign: [] };
  if (permissionDenied(r.stderr)) return { state: 'no_permission', error: r.stderr.trim().split('\n')[0] };
  return { state: 'error', error: (r.error || r.stderr || `exit ${r.code}`).trim().split('\n')[0] };
}

async function readCounters(run, fam) {
  const r = await run(fam.bin, dbCounterArgs());
  return r.code === 0 ? parseDbCounters(r.stdout) : null;
}

function addCounters(famId, now, at) {
  if (!now) return;
  const prev = lastCounters[famId];
  for (const [port, n] of now) {
    const p = prev.get(port) || 0;
    wouldDrop.ports.set(port, (wouldDrop.ports.get(port) || 0) + (n >= p ? n - p : n));
  }
  lastCounters[famId] = now;
  if (!wouldDrop.since) wouldDrop.since = at;
}

async function applyFamily(run, fam, plan, mode, at) {
  const before = await readFamily(run, fam);
  if (before.state !== 'read') return { family: fam.id, state: before.state, error: before.error || null };
  if (mode === 'observe') addCounters(fam.id, await readCounters(run, fam), at);
  if (!before.foreign.length && sameRules(before, fam.id, plan, mode)) return { family: fam.id, state: before.exists ? 'unchanged' : 'no_chain' };
  const w = await run(fam.restore, dbRestoreArgs(), { input: renderDbRestore(fam.id, plan, mode) });
  if (w.missing) return { family: fam.id, state: 'no_binary' };
  if (w.code !== 0) {
    const why = (w.error || w.stderr || `exit ${w.code}`).trim().split('\n')[0];
    if (familyUnusable(fam, w.stderr)) return { family: fam.id, state: 'not_applicable', error: why };
    return { family: fam.id, state: permissionDenied(w.stderr) ? 'no_permission' : 'error', error: why };
  }
  lastCounters[fam.id] = new Map();
  const after = await readFamily(run, fam);
  if (after.state !== 'read' || after.foreign.length || !sameRules(after, fam.id, plan, mode)) {
    return { family: fam.id, state: 'error', error: 'the chain read back different from what was written' };
  }
  return { family: fam.id, state: 'applied' };
}

async function applyViaHelper(d, plan, mode) {
  if (!d.exists(DB_HELPER)) return { state: 'unavailable', error: `${DB_HELPER} is not installed` };
  let args;
  try { args = dbHelperArgs(plan, mode); } catch (e) { return { state: 'error', error: e.message }; }
  const r = await d.run('sudo', args);
  if (r.missing) return { state: 'unavailable', error: 'sudo is not installed' };
  if (r.code === 0) return { state: 'applied', via: 'helper' };
  const why = (r.error || r.stderr || `exit ${r.code}`).trim().split('\n')[0];
  if (sudoRefused(r.stderr)) return { state: 'unavailable', error: `sudo refused the helper: ${why}` };
  return { state: 'error', error: r.code === 2 ? `the helper refused the allowlist: ${why}` : `the helper failed: ${why}` };
}

function summary(plan) {
  return plan.map(p => ({ port: p.port, engine: p.engine, state: p.state, allowed: p.allowed_containers }));
}

const JUMP_RE = new RegExp(`^-A ${SKELETON_CHAIN} .*-j ${DB_CHAIN}$`, 'm');

/**
 * Does DOCKER-USER send DNAT'd bridge traffic to APPCRANE-DB? From the rules
 * when AppCrane can read them (root), else from host hardening's state file
 * (db_chain=yes|no). { v4, v6: 'present'|'absent'|'unknown'|'not_applicable', source }.
 */
async function readDbJump(d, mode) {
  const out = { source: null };
  if (mode === 'direct') {
    for (const fam of DB_FAMILIES) {
      const r = await d.run(fam.bin, ['-w', '-S', SKELETON_CHAIN]);
      if (r.code === 0) out[fam.id] = JUMP_RE.test(String(r.stdout)) ? 'present' : 'absent';
      else if (r.missing || familyUnusable(fam, r.stderr)) out[fam.id] = 'not_applicable';
      else if (chainMissing(r.stderr)) out[fam.id] = 'absent';
      else out[fam.id] = 'unknown';
    }
    if (out.v4 !== 'unknown') { out.source = 'rules'; return out; }
  }
  const state = readHostNetworkState(d.readFile);
  const v = state?.db_chain === 'yes' ? 'present' : state?.db_chain === 'no' ? 'absent' : 'unknown';
  return { v4: v, v6: out.v6 && out.v6 !== 'unknown' ? out.v6 : v, source: state?.db_chain ? 'state' : null };
}

/**
 * What the chain does right now. Never 'enforced' unless the mode is enforce,
 * the last write succeeded and DOCKER-USER is known to jump to the chain.
 */
export function enforcementOf(allowlistMode, status, jump) {
  if (status === 'not_applicable' && allowlistMode !== 'off') return { state: 'not_enforced', why: `AppCrane cannot write ${DB_CHAIN} on this host.` };
  if (allowlistMode === 'off') return { state: 'off', why: `${DB_CHAIN} is kept empty (db_allowlist_mode is off).` };
  if (jump.v4 === 'absent') return { state: 'not_enforced', why: `${SKELETON_CHAIN} does not jump to ${DB_CHAIN}${jump.source === 'state' ? ' (host hardening\'s state file says db_chain=no)' : ''}, so its rules see no traffic. Apply Host limits again.` };
  if (jump.v4 !== 'present') return { state: 'unknown', why: `Could not tell whether ${SKELETON_CHAIN} jumps to ${DB_CHAIN}: the rules are unreadable and host hardening's state file has no db_chain key.` };
  if (status !== 'ok') return { state: 'not_enforced', why: `The last write of ${DB_CHAIN} did not succeed.` };
  if (allowlistMode === 'observe') return { state: 'observing', why: 'Sources not on the allowlist are counted and logged (prefix APPCRANE-DB-WOULD-DROP), not dropped.' };
  return { state: 'enforced', why: null };
}

function wouldDropView(mode) {
  if (mode !== 'direct') return { since: null, ports: null, why: 'AppCrane is not root, so it cannot read the counters. The kernel log has a rate-limited line with the prefix APPCRANE-DB-WOULD-DROP for each.' };
  return { since: wouldDrop.since, ports: Object.fromEntries(wouldDrop.ports), why: null };
}

/**
 * One sync. { status: 'ok'|'not_applicable'|'failed', at, mode, reason, plan, families }.
 * Throws nothing.
 */
export async function syncDbChain({ deps: over = {}, db = getDb(), now = Date.now(), pendingNames = null } = {}) {
  const d = { ...deps, ...over };
  const at = new Date(now).toISOString();
  if (d.platform !== 'linux') {
    lastDbSync = { status: 'not_applicable', at, mode: null, reason: 'AppCrane is not running on Linux, so there is no host firewall between containers and the managed databases.', plan: [], families: {} };
    return lastDbSync;
  }
  let plan;
  let allowlistMode = null;
  try {
    allowlistMode = dbAllowlistMode(db);
    const specs = dbPortSpecs(db);
    const addrs = await readContainerAddrs(d.run, candidateNames(specs));
    plan = computeDbPlan(specs, addrs, pendingNames || new Set(pending.keys()));
  } catch (e) {
    lastDbSync = { status: 'failed', at, mode: null, allowlist_mode: allowlistMode, reason: `Could not compute the ${DB_CHAIN} allowlist: ${e.message}`, plan: [], families: {} };
    return lastDbSync;
  }
  const mode = d.uid === 0 ? 'direct' : 'helper';
  const families = {};
  let status = 'ok';
  let reason = null;
  if (mode === 'direct') {
    for (const fam of DB_FAMILIES) families[fam.id] = await applyFamily(d.run, fam, plan, allowlistMode, at);
    if (families.v4.state === 'no_binary') {
      status = 'not_applicable';
      reason = 'iptables is not installed on this host.';
    } else {
      const bad = Object.values(families).find(f => f.state === 'error' || f.state === 'no_permission');
      if (bad) { status = 'failed'; reason = `Could not update ${DB_CHAIN} (${bad.family}): ${bad.error}`; }
    }
  } else {
    const h = await applyViaHelper(d, plan, allowlistMode);
    for (const fam of DB_FAMILIES) families[fam.id] = { family: fam.id, ...h };
    if (h.state === 'unavailable') {
      status = 'not_applicable';
      reason = `AppCrane is not running as root and cannot use the database-chain helper (${h.error}). ${DB_CHAIN} was left as it is; empty, it lets every container reach the managed databases, and credentials and certificates remain the barrier.`;
    } else if (h.state === 'error') {
      status = 'failed';
      reason = `Could not update ${DB_CHAIN} (helper): ${h.error}`;
    }
  }
  const jump = await readDbJump(d, mode);
  lastDbSync = {
    status, at, mode, allowlist_mode: allowlistMode, reason, plan, families, ports: summary(plan),
    jump, enforcement: enforcementOf(allowlistMode, status, jump),
    would_drop: allowlistMode === 'observe' ? wouldDropView(mode) : null,
  };
  return lastDbSync;
}

// One run at a time. A request made while a run is in flight gets the NEXT
// run, which starts after the current one: the in-flight run read Docker and
// the pending set before the request, so it cannot stand in for it.
let running = null;
let queued = null;

export function requestDbChainSync(opts = {}) {
  if (!running) {
    running = syncDbChain(opts).finally(() => { running = null; });
    return running;
  }
  if (!queued) {
    queued = running.then(() => {
      queued = null;
      running = syncDbChain(opts).finally(() => { running = null; });
      return running;
    });
  }
  return queued;
}

function bounded(p, ms) {
  let t;
  return Promise.race([p, new Promise((res) => { t = setTimeout(() => res({ status: 'failed', reason: `timed out after ${ms} ms` }), ms); t.unref?.(); })])
    .finally(() => clearTimeout(t));
}

/**
 * Wrap an app container start. Its address is only assigned when Docker
 * starts it (measured: a created container has none, and a stopped one gives
 * its address back for reuse), so:
 *   1. mark it starting and sync: its ports get no lines (fail open), so the
 *      new container cannot be refused its own database;
 *   2. start it;
 *   3. unmark it and sync again with its address read back, which closes the
 *      ports to everything not on the allowlist.
 * A failed or slow sync is logged and never fails or blocks the start beyond
 * START_SYNC_TIMEOUT_MS.
 */
export async function withDbAccessDuringStart(name, start) {
  if (!enabled) return start();
  pending.set(name, (pending.get(name) || 0) + 1);
  const pre = await bounded(requestDbChainSync(), START_SYNC_TIMEOUT_MS).catch(e => ({ status: 'failed', reason: e.message }));
  if (pre.status === 'failed') log.warn(`[host-network] ${DB_CHAIN} before starting ${name}: ${pre.reason}`);
  try {
    return await start();
  } finally {
    const n = (pending.get(name) || 1) - 1;
    if (n > 0) pending.set(name, n); else pending.delete(name);
    const post = await bounded(requestDbChainSync(), START_SYNC_TIMEOUT_MS).catch(e => ({ status: 'failed', reason: e.message }));
    if (post.status === 'failed') log.warn(`[host-network] ${DB_CHAIN} after starting ${name}: ${post.reason}`);
  }
}
