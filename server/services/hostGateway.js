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

export const RECREATE_FIX = 'Recreate each one: Restart on the app page stops, removes and starts a new container with the current mapping. A plain docker restart (or the health check\'s auto-restart) keeps the container and its broken mapping.';

/** One Job Health run: detail names the broken containers; a broken one fails the run. */
export async function runHostGatewayCheck({ exec } = {}) {
  const decision = await resolveHostGatewayDecision();
  const r = await checkContainerGateways(exec ? { exec } : {});
  const skippedNote = r.skipped.length
    ? ` Not checked (${r.skipped.length}): ${r.skipped.map((s) => `${s.name} (${s.reason})`).join(', ')}.` : '';
  const newOnes = ` New containers get ${decision.value} (${decision.source}).`;
  let message;
  if (r.broken.length) {
    message = `${r.broken.length} running container(s) map ${HOST_NAME} to an invalid address and cannot reach AppCrane or managed databases: ${r.broken.map((b) => b.name).join(', ')}. ${RECREATE_FIX}${newOnes}${skippedNote}`;
  } else {
    message = `${r.checked} running container(s) checked: ${r.ok} map ${HOST_NAME} to an IP address, ${r.unmapped} do not use it.${newOnes}${skippedNote}`;
  }
  const detail = { message, checked: r.checked, broken: r.broken, skipped: r.skipped, add_host: decision.value, source: decision.source };
  if (decision.warning && !r.broken.length) detail.severity = 'warning';
  setJobDetail(JOB_ID, detail);
  if (r.broken.length) {
    // Without the appcrane- prefix: sanitizeError redacts 32+ character tokens, which most full names are.
    throw new Error(`${r.broken.length} container(s) cannot resolve ${HOST_NAME}: ${r.broken.map((b) => b.name.replace(/^appcrane-/, '')).join(', ')}. Restart each from its app page (a plain docker restart does not fix it).`);
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
