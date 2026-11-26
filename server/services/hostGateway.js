// The --add-host value app, coder and builder containers get for
// host.docker.internal, and a Job Health check for containers created with a
// broken one.
//
// Docker's "host-gateway" magic value is resolved by the daemon from its
// host-gateway-ips setting. Measured on a production Linux box (Docker 29.1.3):
// after a dockerd reload that setting read [""], and every container created
// from then on had "invalid IP host.docker.internal" in /etc/hosts, so it could
// reach neither AppCrane (CRANE_INTERNAL_URL) nor the managed databases.
//
// So on Linux the address is passed explicitly: the default bridge's gateway,
// the same address managedDb.js publishes the database servers on (see its
// header). On Docker Desktop the bridge gateway lives in the VM and is not this
// host, so "host-gateway" (192.168.65.254 there) stays. HOST_GATEWAY_IP
// overrides both, for a daemon whose host is reached some other way.
//
// The check also repairs: a broken app environment container is recreated
// through containerRecreate.js (what Restart on the app page runs), within the
// guards in repairBrokenContainers. Helper containers are only reported.

import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { isIPv4, isIP } from 'net';
import log from '../utils/logger.js';
import { jobStarted, trackJob, setJobDetail } from './jobHealth.js';

const execFileAsync = promisify(execFile);

export const JOB_ID = 'host-gateway';
export const HOST_NAME = 'host.docker.internal';
export const FALLBACK_ADD_HOST = `${HOST_NAME}:host-gateway`;
const CACHE_TTL_MS = 60_000;
const CHECK_MS = 60 * 60_000;
const EXEC_TIMEOUT_MS = 10_000;
const INFO_ARGS = ['info', '--format', '{{.OperatingSystem}}'];
const GATEWAY_ARGS = ['network', 'inspect', 'bridge', '--format', '{{range .IPAM.Config}}{{.Gateway}} {{end}}'];

async function defaultExec(args) {
  const { stdout } = await execFileAsync('docker', args, { timeout: EXEC_TIMEOUT_MS });
  return stdout;
}

function defaultExecSync(args) {
  return execFileSync('docker', args, { encoding: 'utf8', timeout: EXEC_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'pipe'] });
}

let execImpl = defaultExec;
let execSyncImpl = defaultExecSync;
let cache = null;

/** Test seam: replace the docker runner (args -> stdout). One fn serves both paths when it returns a string. */
export function _setHostGatewayExecForTests(fn) {
  execImpl = fn ? async (args) => fn(args) : defaultExec;
  execSyncImpl = fn || defaultExecSync;
  cache = null;
}

export function _resetHostGatewayCacheForTests() {
  cache = null;
}

const isDesktop = (os) => /docker desktop/i.test(String(os || ''));

function firstIPv4(out) {
  return String(out || '').split(/\s+/).find((s) => isIPv4(s) && !s.startsWith('127.')) || null;
}

/**
 * Pure decision. `os` is `docker info`'s OperatingSystem, `gatewayOut` the
 * bridge inspect output (null when it could not be read), `error` why not.
 */
export function decideAddHost({ override, os, gatewayOut, error }) {
  if (override) {
    if (isIPv4(override)) return { value: `${HOST_NAME}:${override}`, source: 'override' };
    return { value: FALLBACK_ADD_HOST, source: 'fallback', warning: `HOST_GATEWAY_IP=${JSON.stringify(override)} is not an IPv4 address; ignored` };
  }
  if (isDesktop(os)) return { value: FALLBACK_ADD_HOST, source: 'docker-desktop' };
  const gw = firstIPv4(gatewayOut);
  if (gw) return { value: `${HOST_NAME}:${gw}`, source: 'bridge-gateway' };
  return {
    value: FALLBACK_ADD_HOST,
    source: 'fallback',
    warning: `could not read the default bridge network's gateway (${error || `got ${JSON.stringify(String(gatewayOut || '').trim())}`}); containers get ${FALLBACK_ADD_HOST}, which depends on the daemon's host-gateway-ip setting`,
  };
}

function remember(decision) {
  if (decision.warning) log.warn(`[host-gateway] ${decision.warning}`);
  cache = { at: Date.now(), decision };
  return decision;
}

const fresh = () => cache && Date.now() - cache.at < CACHE_TTL_MS;
const errText = (e) => String(e?.stderr || e?.message || e).trim().split('\n')[0].slice(0, 200);

/** How the value was chosen: { value, source, warning? }. */
export async function resolveHostGatewayDecision() {
  if (fresh()) return cache.decision;
  const override = (process.env.HOST_GATEWAY_IP || '').trim();
  if (override) return remember(decideAddHost({ override }));
  let os = '';
  try { os = await execImpl(INFO_ARGS); } catch (_) {}
  if (isDesktop(os)) return remember(decideAddHost({ os }));
  try {
    return remember(decideAddHost({ os, gatewayOut: await execImpl(GATEWAY_ARGS) }));
  } catch (e) {
    return remember(decideAddHost({ os, gatewayOut: null, error: errText(e) }));
  }
}

/** The --add-host value for host.docker.internal, e.g. 'host.docker.internal:172.17.0.1'. */
export async function resolveHostGatewayAddHost() {
  return (await resolveHostGatewayDecision()).value;
}

/** Synchronous twin, for the container starts that are synchronous. Shares the cache. */
export function resolveHostGatewayAddHostSync() {
  if (fresh()) return cache.decision.value;
  const override = (process.env.HOST_GATEWAY_IP || '').trim();
  if (override) return remember(decideAddHost({ override })).value;
  let os = '';
  try { os = execSyncImpl(INFO_ARGS); } catch (_) {}
  if (isDesktop(os)) return remember(decideAddHost({ os })).value;
  try {
    return remember(decideAddHost({ os, gatewayOut: execSyncImpl(GATEWAY_ARGS) })).value;
  } catch (e) {
    return remember(decideAddHost({ os, gatewayOut: null, error: errText(e) })).value;
  }
}

/**
 * The address /etc/hosts gives host.docker.internal: the first line naming it,
 * as a resolver reads the file. { mapped: false } when no line names it.
 */
export function parseHostsMapping(text) {
  for (const raw of String(text || '').split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    const fields = line.split(/\s+/);
    if (!fields.slice(1).includes(HOST_NAME)) continue;
    return { mapped: true, address: fields[0], valid: isIP(fields[0]) !== 0, line };
  }
  return { mapped: false };
}

const NO_CAT = /executable file not found|no such file or directory|not found in \$PATH/i;

/**
 * Every running appcrane-* container whose /etc/hosts maps host.docker.internal
 * to something that is not an IP address. Read with `docker exec <c> cat
 * /etc/hosts` (argv, no shell); a container without cat is skipped and listed.
 */
export async function checkContainerGateways({ exec = execImpl } = {}) {
  const names = String(await exec(['ps', '--filter', 'name=^appcrane-', '--format', '{{.Names}}']))
    .split('\n').map((s) => s.trim()).filter((s) => s.startsWith('appcrane-'));
  const broken = [];
  const skipped = [];
  let ok = 0;
  let unmapped = 0;
  for (const name of names) {
    let text;
    try {
      text = await exec(['exec', name, 'cat', '/etc/hosts']);
    } catch (e) {
      const why = errText(e);
      skipped.push({ name, reason: NO_CAT.test(why) ? 'no cat in the image' : why });
      continue;
    }
    const m = parseHostsMapping(text);
    if (!m.mapped) unmapped++;
    else if (m.valid) ok++;
    else broken.push({ name, line: m.line });
  }
  return { checked: names.length, ok, unmapped, broken, skipped };
}

export const AUTO_REPAIR_SETTING = 'host_gateway_auto_repair';
export const REPAIR_STATE_KEY = 'host_gateway_repairs';
export const REPAIR_WINDOW_MS = 6 * 60 * 60_000;
export const MAX_REPAIRS_PER_RUN = 3;
export const REPAIR_ACTOR = 'system:host-gateway';
export const REPAIR_REASON = 'host-gateway-repair';
const APP_CONTAINER_RE = /^appcrane-([a-z0-9][a-z0-9-]*)-(production|sandbox)$/;

export const RECREATE_FIX = 'AppCrane recreates broken app containers itself (stop, remove, start a new one with the current mapping, as Restart on the app page does), at most 3 per run. It does not when host_gateway_auto_repair is off, new containers would get host-gateway themselves, a deploy, database restore, restart, sleep or wake of that environment is in progress, or it already recreated that container in the last 6 hours. For those, and for helper containers (managed database servers, coder, Crew, builders): Restart on the app page stops, removes and starts a new container with the current mapping. A plain docker restart (or the health check\'s auto-restart) keeps the container and its broken mapping.';

export function autoRepairEnabled(db) {
  const v = db.prepare('SELECT value FROM settings WHERE key = ?').get(AUTO_REPAIR_SETTING)?.value;
  return !['0', 'false', 'off'].includes(String(v ?? '').trim().toLowerCase());
}

function readRepairState(db) {
  try { return JSON.parse(db.prepare('SELECT value FROM settings WHERE key = ?').get(REPAIR_STATE_KEY)?.value || '{}') || {}; } catch (_) { return {}; }
}

function noteRepair(db, name, at) {
  const state = readRepairState(db);
  for (const [k, t] of Object.entries(state)) if (!(at - Number(t) < REPAIR_WINDOW_MS)) delete state[k];
  state[name] = at;
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(REPAIR_STATE_KEY, JSON.stringify(state));
}

async function defaultRepairDeps() {
  const { getDb } = await import('../db.js');
  const { recreateEnvContainer, recreateInFlight, envBusyReason } = await import('./containerRecreate.js');
  const { logAudit } = await import('../middleware/audit.js');
  const { recordIncident, expectPlanned } = await import('./restartIncidents.js');
  const { notifyHostGatewayRepair } = await import('./hostGatewayRepairMail.js');
  return {
    db: getDb(),
    busy: envBusyReason,
    restarting: recreateInFlight,
    recreate: recreateEnvContainer,
    audit: logAudit,
    incident: recordIncident,
    expect: expectPlanned,
    notify: notifyHostGatewayRepair,
    now: () => Date.now(),
  };
}

let repairDepsOverride = null;
/** Test seam: override any of the repair's dependencies (db, recreate, now, ...). */
export function _setRepairDepsForTests(d) { repairDepsOverride = d; }

// Why app+env may not be recreated now, or null when it may.
async function blockedBy(d, app, env) {
  if (d.restarting(app.id, env)) return 'a restart is in progress';
  return d.busy(d.db, app, env);
}

// The --add-host decision read again from Docker (not the cached one), and the
// reason a recreate would not fix the mapping, or null when it is an IP.
async function gatewayRefusal() {
  cache = null;
  const decision = await resolveHostGatewayDecision();
  const ok = isIP(String(decision.value).slice(HOST_NAME.length + 1)) !== 0;
  return ok ? null : `new containers would get ${decision.value} (${decision.source}), so recreating would not fix it`;
}

function unnoteRepair(db, name) {
  const state = readRepairState(db);
  delete state[name];
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(REPAIR_STATE_KEY, JSON.stringify(state));
}

/**
 * Recreate the broken app containers that may be recreated, one at a time, and
 * read each one's /etc/hosts again. Returns { repaired, skipped, still_broken }:
 * repaired and still_broken name the containers recreated, skipped the ones
 * left alone with the reason.
 */
export async function repairBrokenContainers(broken, { exec = execImpl } = {}) {
  const d = { ...(await defaultRepairDeps()), ...(repairDepsOverride || {}) };
  const repaired = [];
  const skipped = [];
  const stillBroken = [];
  const enabled = autoRepairEnabled(d.db);
  let attempts = 0;
  for (const b of broken) {
    const skip = (reason) => skipped.push({ name: b.name, reason });
    const m = APP_CONTAINER_RE.exec(b.name);
    const app = m ? d.db.prepare('SELECT * FROM apps WHERE slug = ?').get(m[1]) : null;
    if (!app) { skip('not an app environment container (helper or database server): recreate it by hand'); continue; }
    const env = m[2];
    if (!enabled) { skip(`auto-repair is off (${AUTO_REPAIR_SETTING})`); continue; }
    const busy = await blockedBy(d, app, env);
    if (busy) { skip(busy); continue; }
    const last = Number(readRepairState(d.db)[b.name]);
    if (d.now() - last < REPAIR_WINDOW_MS) { skip(`already recreated at ${new Date(last).toISOString()}; at most once in 6 hours`); continue; }
    if (attempts >= MAX_REPAIRS_PER_RUN) { skip(`${MAX_REPAIRS_PER_RUN} recreated in this run already; the next run takes it`); continue; }
    const noGateway = await gatewayRefusal();
    if (noGateway) { skip(noGateway); continue; }
    attempts++;
    const at = d.now();
    noteRepair(d.db, b.name, at);
    const base = { env, container: b.name, reason: REPAIR_REASON, actor: REPAIR_ACTOR, line_before: b.line };
    let stopped = false;
    // Right before the stop, after the recreate's own last checks: the restart
    // watcher is told this stop is recorded here, and the 'restart' audit row
    // marks it as a planned restart for anything else that reads the log.
    const onStop = () => {
      stopped = true;
      try { d.expect(app.id, env, REPAIR_REASON); } catch (_) { /* never decides a repair */ }
      try { d.audit(null, app.id, 'restart', base, 'system'); } catch (_) { /* auditing never decides a repair */ }
    };
    const out = { name: b.name, slug: app.slug, env };
    try {
      await d.recreate({ app, env, actor: REPAIR_ACTOR, reason: REPAIR_REASON, precheck: gatewayRefusal, onStop });
      try {
        const after = parseHostsMapping(await exec(['exec', b.name, 'cat', '/etc/hosts']));
        out.line_after = after.line || null;
        out.outcome = after.mapped && after.valid ? 'fixed' : 'still broken';
      } catch (e) {
        out.outcome = 'still broken';
        out.error = `recreated, but /etc/hosts could not be read again: ${errText(e)}`;
      }
    } catch (e) {
      if (e?.code === 'RECREATE_SKIPPED' || e?.code === 'RECREATE_IN_PROGRESS') {
        unnoteRepair(d.db, b.name);
        attempts--;
        log.info(`[host-gateway] ${b.name}: ${e.message}`);
        skip(String(e.message).replace(/^Not recreated: /, '').replace(/\. The running container was left alone\.$/, ''));
        continue;
      }
      out.outcome = 'still broken';
      out.error = `recreate failed: ${errText(e)}`;
    }
    log[out.outcome === 'fixed' ? 'info' : 'warn'](`[host-gateway] ${b.name}: ${out.outcome}${out.error ? ` (${out.error})` : ''}`);
    try {
      d.audit(null, app.id, REPAIR_REASON, { ...base, outcome: out.outcome, line_after: out.line_after ?? null, ...(out.error && { error: out.error }) }, 'system');
    } catch (_) { /* auditing never decides a repair */ }
    if (stopped) {
      const detail = { container: b.name, outcome: out.outcome, line_before: b.line, line_after: out.line_after ?? null, ...(out.error && { error: out.error }) };
      await d.incident({ appId: app.id, env, trigger: REPAIR_REASON, action: out.outcome === 'fixed' ? 'restarted' : 'failed', detail, db: d.db, now: at });
      try {
        await d.notify({ db: d.db, appId: app.id, env, outcome: out.outcome, lineBefore: b.line, lineAfter: out.line_after ?? null, error: out.error ?? null, at });
      } catch (e) { log.warn(`[host-gateway] owner notice for ${b.name} failed: ${e.message}`); }
    }
    (out.outcome === 'fixed' ? repaired : stillBroken).push(out);
  }
  return { repaired, skipped, still_broken: stillBroken };
}

let runInFlight = null;

/** One Job Health run: finds broken containers, repairs what it may, fails while any stays broken. */
export function runHostGatewayCheck(opts = {}) {
  if (!runInFlight) runInFlight = runCheck(opts).finally(() => { runInFlight = null; });
  return runInFlight;
}

async function runCheck({ exec } = {}) {
  const decision = await resolveHostGatewayDecision();
  const r = await checkContainerGateways(exec ? { exec } : {});
  const skippedNote = r.skipped.length
    ? ` Not checked (${r.skipped.length}): ${r.skipped.map((s) => `${s.name} (${s.reason})`).join(', ')}.` : '';
  const newOnes = ` New containers get ${decision.value} (${decision.source}).`;
  const fix = r.broken.length ? await repairBrokenContainers(r.broken, exec ? { exec } : {}) : null;
  const left = fix ? [...fix.still_broken.map((x) => x.name), ...fix.skipped.map((x) => x.name)] : [];
  let message;
  if (r.broken.length) {
    const parts = [`${r.broken.length} running container(s) mapped ${HOST_NAME} to an invalid address and could not reach AppCrane or managed databases: ${r.broken.map((b) => b.name).join(', ')}.`];
    if (fix.repaired.length) parts.push(`Recreated and fixed (${fix.repaired.length}): ${fix.repaired.map((x) => x.name).join(', ')}.`);
    if (fix.still_broken.length) parts.push(`Recreated but still broken (${fix.still_broken.length}): ${fix.still_broken.map((x) => `${x.name}${x.error ? ` (${x.error})` : ''}`).join(', ')}.`);
    if (fix.skipped.length) parts.push(`Not recreated (${fix.skipped.length}): ${fix.skipped.map((x) => `${x.name} (${x.reason})`).join(', ')}.`);
    if (left.length) parts.push(RECREATE_FIX);
    message = `${parts.join(' ')}${newOnes}${skippedNote}`;
  } else {
    message = `${r.checked} running container(s) checked: ${r.ok} map ${HOST_NAME} to an IP address, ${r.unmapped} do not use it.${newOnes}${skippedNote}`;
  }
  const detail = { message, checked: r.checked, broken: r.broken, skipped: r.skipped, add_host: decision.value, source: decision.source };
  if (fix) Object.assign(detail, { repaired: fix.repaired, not_repaired: fix.skipped, still_broken: fix.still_broken });
  if (decision.warning && !left.length) detail.severity = 'warning';
  setJobDetail(JOB_ID, detail);
  if (left.length) {
    // Without the appcrane- prefix: sanitizeError redacts 32+ character tokens, which most full names are.
    throw new Error(`${left.length} container(s) still cannot resolve ${HOST_NAME}: ${left.map((n) => n.replace(/^appcrane-/, '')).join(', ')}. Restart each from its app page (a plain docker restart does not fix it).`);
  }
  return detail;
}

let timer = null;

export function startHostGatewayCheck() {
  if (timer) return;
  jobStarted(JOB_ID, { cadenceMs: CHECK_MS });
  const tick = () => trackJob(JOB_ID, () => runHostGatewayCheck()).catch((e) => log.warn(`[host-gateway] ${e.message}`));
  setTimeout(tick, 30_000).unref?.();
  timer = setInterval(tick, CHECK_MS);
  timer.unref?.();
}
