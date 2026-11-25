import { existsSync } from 'node:fs';
import { getDb } from '../../db.js';
import { defaultRun } from './exec.js';
import { dbPorts, readDockerPublishes, computeDesired } from './desired.js';
import { readHostNet, defaultReadFile, readHostNetworkState, stateSaysEnforcing, HOST_NETWORK_STATE } from './hostNet.js';
import {
  CHAIN, FAMILIES, renderRestore, parseChain, sameEntries, chainMissing, permissionDenied,
  HELPER, HELPER_MAX_ARGS, helperArgs, sudoRefused,
} from './rules.js';

// Keep APPCRANE-PUBLISH equal to the ports AppCrane itself publishes on
// 0.0.0.0. Owner decision: publishing a tcp/dual port as a platform admin is
// the admit step, so the ACCEPT follows the publish; every other port stays
// dropped by host hardening's DOCKER-USER skeleton. This module never adds a
// DROP of its own.

export const DEFAULT_DEPS = Object.freeze({
  platform: process.platform,
  run: defaultRun,
  uid: typeof process.getuid === 'function' ? process.getuid() : null,
  exists: existsSync,
  readFile: defaultReadFile,
});

export function readChainArgs() {
  return ['-w', '-S', CHAIN];
}

export function restoreArgs() {
  return ['-w', '--noflush'];
}

async function readFamilyChain(run, fam) {
  const r = await run(fam.bin, readChainArgs());
  if (r.missing) return { state: 'no_binary' };
  if (r.code === 0) return { state: 'read', ...parseChain(r.stdout) };
  if (chainMissing(r.stderr)) return { state: 'read', exists: false, entries: [], foreign: [] };
  if (permissionDenied(r.stderr)) return { state: 'no_permission', error: r.stderr.trim().split('\n')[0] };
  return { state: 'error', error: (r.error || r.stderr || `exit ${r.code}`).trim().split('\n')[0] };
}

export async function readCurrentChains(run) {
  const out = {};
  for (const fam of FAMILIES) out[fam.id] = await readFamilyChain(run, fam);
  return out;
}

async function applyFamily(run, fam, accept) {
  const before = await readFamilyChain(run, fam);
  if (before.state !== 'read') return { family: fam.id, ...before, changed: false };
  if (before.exists && !before.foreign.length && sameEntries(before.entries, accept)) {
    return { family: fam.id, state: 'unchanged', changed: false, entries: before.entries };
  }
  const w = await run(fam.restore, restoreArgs(), { input: renderRestore(accept) });
  if (w.missing) return { family: fam.id, state: 'no_binary', changed: false };
  if (w.code !== 0) {
    const why = (w.error || w.stderr || `exit ${w.code}`).trim().split('\n')[0];
    return { family: fam.id, state: permissionDenied(w.stderr) ? 'no_permission' : 'error', error: why, changed: false };
  }
  const after = await readFamilyChain(run, fam);
  if (after.state !== 'read' || !after.exists || after.foreign.length || !sameEntries(after.entries, accept)) {
    return { family: fam.id, state: 'error', error: 'the chain read back different from what was written', changed: true };
  }
  return { family: fam.id, state: 'applied', changed: true, entries: after.entries };
}

// Not root: the helper, through sudo -n (never a prompt). Exit 2 is the
// helper refusing its arguments; sudo's own refusal says "sudo: ...".
async function applyViaHelper(d, accept) {
  if (!d.exists(HELPER)) return { state: 'unavailable', error: `${HELPER} is not installed` };
  if (accept.length > HELPER_MAX_ARGS) return { state: 'error', error: `${accept.length} ports is more than the helper takes (${HELPER_MAX_ARGS})` };
  const r = await d.run('sudo', helperArgs(accept));
  if (r.missing) return { state: 'unavailable', error: 'sudo is not installed' };
  if (r.code === 0) return { state: 'applied', changed: true, via: 'helper', entries: accept.map(e => ({ proto: e.proto, port: e.port })) };
  const why = (r.error || r.stderr || `exit ${r.code}`).trim().split('\n')[0];
  if (sudoRefused(r.stderr)) return { state: 'unavailable', error: `sudo refused the helper: ${why}` };
  return { state: 'error', error: r.code === 2 ? `the helper refused the port list: ${why}` : `the helper failed: ${why}` };
}

let lastSync = null;
export function getLastSync() { return lastSync; }
export function _resetPublishChainForTests() { lastSync = null; }

/**
 * One sync. Returns { status, at, mode, accept, strays, docker, families }.
 * status: 'ok' | 'not_applicable' | 'failed'. Throws nothing; the caller
 * decides how a 'failed' is reported.
 *
 * Root writes the chain directly. Otherwise the helper does. When neither can
 * and the DOCKER-USER skeleton does not drop what the chain leaves, an
 * out-of-date chain drops nothing, so the status is 'not_applicable'.
 */
export async function syncPublishChain({ deps = {}, db = getDb(), now = Date.now() } = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const at = new Date(now).toISOString();
  if (d.platform !== 'linux') {
    lastSync = { status: 'not_applicable', at, mode: null, reason: 'AppCrane is not running on Linux, so there is no host firewall for it to manage (Docker Desktop publishes ports through its own VM).', accept: [], strays: [], families: {} };
    return lastSync;
  }
  const dockerRead = await readDockerPublishes(d.run);
  const net = await readHostNet(d.run);
  const desired = computeDesired(dbPorts(db), dockerRead, net);
  const families = {};
  let mode = d.uid === 0 ? 'direct' : 'helper';
  let blocked = null;

  if (mode === 'direct') {
    for (const fam of FAMILIES) families[fam.id] = await applyFamily(d.run, fam, desired.accept);
    if (families.v4.state === 'no_binary') {
      lastSync = { status: 'not_applicable', at, mode, reason: 'iptables is not installed on this host.', accept: desired.accept, strays: desired.strays, docker: desired.docker, docker_error: desired.docker_error, families };
      return lastSync;
    }
    const denied = Object.values(families).find(f => f.state === 'no_permission');
    if (denied) blocked = `AppCrane runs as root but cannot change the host firewall (${denied.family}): ${denied.error}`;
  } else {
    const h = await applyViaHelper(d, desired.accept);
    for (const fam of FAMILIES) families[fam.id] = { family: fam.id, ...h };
    if (h.state === 'unavailable') blocked = `AppCrane is not running as root and cannot use the publish-chain helper (${h.error}).`;
  }

  let status = 'ok';
  let reason = null;
  if (blocked) {
    const state = readHostNetworkState(d.readFile);
    if (!stateSaysEnforcing(state)) {
      status = 'not_applicable';
      reason = `${blocked} Nothing depends on it: host hardening's network section does not drop what ${CHAIN} leaves (${state ? 'installed without the DROP' : `${HOST_NETWORK_STATE} is missing`}), so published ports stay reachable.`;
    } else {
      status = 'failed';
      reason = `${blocked} Host hardening's network section drops what ${CHAIN} does not accept, so ports AppCrane publishes may be dropped.`;
    }
  } else {
    const bad = Object.values(families).find(f => f.state === 'error');
    if (bad) {
      status = 'failed';
      reason = `Could not update ${CHAIN} (${mode === 'helper' ? 'helper' : bad.family}): ${bad.error}`;
    }
  }
  lastSync = { status, at, mode, reason, accept: desired.accept, strays: desired.strays, docker: desired.docker, docker_error: desired.docker_error, families };
  return lastSync;
}
