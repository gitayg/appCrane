import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { jobStarted, trackJob, setJobDetail } from '../jobHealth.js';
import { probeImds } from '../secretsProvider/imdsProbe.js';
import { syncPublishChain, getLastSync, DEFAULT_DEPS } from './publishChain.js';
import { computePosture, getCachedImds, setCachedImds } from './posture.js';
import { mailPostureFindings } from './alerts.js';
import { requestDbChainSync, enableDbChain, disableDbChain } from './dbChain.js';
import log from '../../utils/logger.js';

export { syncPublishChain, getLastSync } from './publishChain.js';
export { computePosture } from './posture.js';
export { getLastDbSync, withDbAccessDuringStart } from './dbChain.js';

export const JOB_ID = 'host-network';
export const BACKSTOP_MS = 5 * 60_000;
export const DEBOUNCE_MS = 2_000;
export const IMDS_MAX_AGE_MS = 6 * 60 * 60_000;
export const EVENTS_ARGS = Object.freeze([
  'events', '--filter', 'type=container', '--filter', 'event=start', '--filter', 'event=die', '--format', '{{json .}}',
]);

let deps = DEFAULT_DEPS;
let running = null;
let again = false;
let debounceTimer = null;
let backstopTimer = null;
let child = null;
let retryTimer = null;
let retryMs = 5000;
let stopped = true;

/** One run: sync the chain, then read posture and mail what is new. Failures are recorded, never thrown. */
export async function runHostNetwork({ withPosture = true, d = deps } = {}) {
  try {
    return await trackJob(JOB_ID, async () => {
      const sync = await syncPublishChain({ deps: d });
      const dbSync = await requestDbChainSync({ deps: d });
      let posture = null;
      if (withPosture && sync.status !== 'not_applicable') {
        const cached = getCachedImds();
        if (!cached || Date.now() - cached.at > IMDS_MAX_AGE_MS) setCachedImds(await (d.probeImds || probeImds)());
        posture = await computePosture({ deps: { ...d, lastSync: sync } });
        mailPostureFindings(posture);
      }
      setJobDetail(JOB_ID, {
        status: sync.status, at: sync.at, reason: sync.reason,
        accepted: sync.accept.map(e => `${e.proto}/${e.port}`),
        strays: sync.strays.map(s => `${s.container} ${s.proto}/${s.port}`),
        findings: posture ? posture.findings.filter(f => f.severity === 'high' || f.severity === 'medium').length : null,
        db: {
          status: dbSync.status, reason: dbSync.reason,
          allowlist_mode: dbSync.allowlist_mode ?? null, enforcement: dbSync.enforcement?.state ?? null,
          ports: Object.fromEntries(dbSync.plan.map(p => [p.port, p.state === 'closed' ? p.allowed_containers : 'open'])),
        },
      });
      const failed = [sync, dbSync].filter(s => s.status === 'failed').map(s => s.reason);
      if (failed.length) throw new Error(failed.join(' '));
      return { sync, dbSync, posture };
    });
  } catch (e) {
    log.warn(`[host-network] ${e.message}`);
    return null;
  }
}

function runSerialized(opts) {
  if (running) { again = true; return running; }
  running = runHostNetwork(opts).finally(() => {
    running = null;
    if (again) { again = false; runSerialized({ withPosture: false }); }
  });
  return running;
}

/** Ask for a chain sync soon. Bursts of container events collapse into one run. */
export function requestHostFirewallSync() {
  if (stopped) return;
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => { debounceTimer = null; runSerialized({ withPosture: false }); }, DEBOUNCE_MS);
  debounceTimer.unref?.();
}

// A container Docker itself started (a wake, an on-failure restart) may have
// been given a new address: its database chain is synced at once, without the
// debounce, so the window in which it can be refused is one sync long.
export function isStartEvent(line) {
  try { const e = JSON.parse(line); return (e.Action || e.status) === 'start'; } catch (_) { return false; }
}

function connect(spawnFn, reconnect = false) {
  if (stopped) return;
  const p = spawnFn('docker', [...EVENTS_ARGS], { stdio: ['ignore', 'pipe', 'pipe'] });
  child = p;
  // Start and die events while the stream was down were never seen: sync
  // both chains now rather than at the next 5-minute backstop.
  if (reconnect) { requestDbChainSync(); requestHostFirewallSync(); }
  let stderr = '';
  p.stderr?.on('data', (b) => { stderr = (stderr + b).slice(-500); });
  createInterface({ input: p.stdout }).on('line', (line) => {
    retryMs = 5000;
    if (isStartEvent(line)) requestDbChainSync();
    requestHostFirewallSync();
  });
  p.on('error', (err) => log.warn(`[host-network] docker events failed to start: ${err.message}`));
  p.on('close', (code) => {
    if (child === p) child = null;
    if (stopped) return;
    log.warn(`[host-network] docker events exited (${code}${stderr ? `: ${stderr.trim()}` : ''}); reconnecting in ${retryMs / 1000}s`);
    retryTimer = setTimeout(() => connect(spawnFn, true), retryMs);
    retryTimer.unref?.();
    retryMs = Math.min(retryMs * 2, 5 * 60_000);
  });
}

/** Startup: sync now, on every container start/die, and every 5 minutes. A no-op off Linux. */
export function startHostFirewall(opts = {}) {
  if (!stopped) return false;
  deps = { ...DEFAULT_DEPS, ...(opts.deps || {}) };
  if (deps.platform !== 'linux') return false;
  stopped = false;
  enableDbChain(deps);
  jobStarted(JOB_ID, { cadenceMs: BACKSTOP_MS });
  runSerialized({ withPosture: true });
  backstopTimer = setInterval(() => runSerialized({ withPosture: true }), opts.backstopMs ?? BACKSTOP_MS);
  backstopTimer.unref?.();
  connect(opts.spawn || spawn);
  process.once('exit', () => child?.kill());
  return true;
}

export function stopHostFirewall() {
  stopped = true;
  disableDbChain();
  for (const t of [debounceTimer, retryTimer]) if (t) clearTimeout(t);
  if (backstopTimer) clearInterval(backstopTimer);
  debounceTimer = retryTimer = backstopTimer = null;
  if (child) child.kill();
  child = null;
}

export function _waitForIdle() { return running || Promise.resolve(); }
