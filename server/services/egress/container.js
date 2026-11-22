// How an egress-enforced app container is started (docker.js runAppContainer
// calls egressPlan / applyEgressPlan / startAnchor).
//
// Measured on Docker Desktop 29.9.2 before choosing this (see the live test):
//   - `--internal` networks block egress but also make `-p` publishes inert
//     (`docker port` shows nothing), so Caddy could not reach the app. Ruled out.
//   - a bridge with ip masquerade off still reaches the internet on Docker
//     Desktop (its VM translates again). Not a control there; kept as defence
//     in depth for Linux, where un-NATed packets do not come back.
//   - DNS-only filtering is bypassable by dialling an IP. Ruled out.
// What holds on both: the app joins (`--network container:`) the network
// namespace of a small anchor container that deletes the namespace's default
// route before the app starts. The app has no CAP_NET_ADMIN (Docker's default
// set lacks it) and no CAP_NET_RAW (dropped), so it cannot add a route back:
// anything off the bridge's own subnet is "Network unreachable" for TCP, UDP
// and ICMP alike. Publishes live on the anchor, so Caddy's 127.0.0.1 path is
// unchanged; inter-container isolation is the bridge's enable_icc=false as for
// every app. The anchor's resolver is pointed at 192.0.2.1 (TEST-NET-1), so
// Docker's embedded DNS cannot forward a query out either (a DNS tunnel).
//
// The only door is the bridge gateway: host.docker.internal maps to it, and
// there AppCrane answers (CRANE_INTERNAL_URL) together with the egress proxy.
// On Linux the host owns that address, so the proxy binds it directly. On
// Docker Desktop the gateway lives in the VM, so a relay container on the VM's
// host network forwards gateway:<port> to the Mac (host-gateway); the proxy then
// binds 127.0.0.1 only.

import { execFile } from 'child_process';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { HELPER_IMAGE } from '../volumeHelper.js';
import { isEnforced, egressToken } from './policy.js';
import { ensureEgressProxy } from './proxy.js';
import { CPU_APP_FLAG } from '../cpuPriority.js';
import { OOM_APP_FLAG } from '../oomPriority.js';

export const EGRESS_NETWORK = 'appcrane-apps-egress';
export const EGRESS_BRIDGE = 'appcrane-egr0';
export const RELAY_NAME = 'crane-egress-relay';
export const ANCHOR_LABEL = 'appcrane.egress-anchor=1';
const UNROUTABLE_DNS = '192.0.2.1';
const ICC = 'com.docker.network.bridge.enable_icc';
const MASQ = 'com.docker.network.bridge.enable_ip_masquerade';
const READY = 'EGRESS_ANCHOR_READY';
// Fixed scripts: every variable part arrives through the environment.
const ANCHOR_SCRIPT = 'ip route del default 2>/dev/null; ip -6 route del default 2>/dev/null; '
  + 'if ip route | grep -q "^default" || ip -6 route 2>/dev/null | grep -q "^default"; then echo EGRESS_ANCHOR_FAILED; exit 1; fi; '
  + `echo ${READY}; exec sleep 2147483647`;
const RELAY_SCRIPT = 'for p in $RELAY_PORTS; do nc -lk -s "$RELAY_GW" -p "$p" -e nc host.docker.internal "$p" & done; echo EGRESS_RELAY_READY; wait';

const defaultDocker = (args, timeout = 60_000) => new Promise((res, rej) => {
  execFile('docker', args, { timeout, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => (err
    ? rej(new Error(String(stderr || '').trim().split('\n').slice(-2).join(' ') || err.message))
    : res(String(stdout).trim())));
});
let docker = defaultDocker;
/** Test seam. */
export function _setDockerForTests(fn) { docker = fn || defaultDocker; }

export const anchorName = (slug, env) => `crane-egress-anchor.${slug}.${env}`;
export const proxyPort = () => Number(process.env.APPCRANE_EGRESS_PROXY_PORT) || 5003;
export const cranePort = () => Number(process.env.PORT) || 5001;

async function inspectNetwork() {
  try {
    const out = await docker(['network', 'inspect', EGRESS_NETWORK, '--format', `{{index .Options "${ICC}"}}|{{index .Options "${MASQ}"}}|{{(index .IPAM.Config 0).Gateway}}|{{.Internal}}`], 10_000);
    const [icc, masq, gateway, internal] = out.split('|');
    return { icc, masq, gateway, internal };
  } catch (_) { return null; }
}

/** The shared enforced-app network: inter-container traffic off, no masquerade. Throws when it cannot be had. */
export async function ensureEgressNetwork() {
  let net = await inspectNetwork();
  if (!net) {
    try {
      await docker(['network', 'create', '--label', 'appcrane=true', '--opt', `${ICC}=false`, '--opt', `${MASQ}=false`,
        '--opt', `com.docker.network.bridge.name=${EGRESS_BRIDGE}`, EGRESS_NETWORK], 20_000);
    } catch (e) {
      if (!/already exists/i.test(e.message)) throw new Error(`cannot create the egress network ${EGRESS_NETWORK}: ${e.message}`);
    }
    net = await inspectNetwork();
  }
  if (!net || net.icc !== 'false' || !/^\d+\.\d+\.\d+\.\d+$/.test(net.gateway || '')) {
    throw new Error(`docker network ${EGRESS_NETWORK} exists without enable_icc=false or without an IPv4 gateway: remove it ('docker network rm ${EGRESS_NETWORK}') and start the app again`);
  }
  return { name: EGRESS_NETWORK, gateway: net.gateway };
}

let relayDecision = null;
/** Docker Desktop (daemon in a VM): the gateway is not this host, so a relay is needed. APPCRANE_EGRESS_RELAY=1/0 decides instead. */
export async function relayNeeded() {
  if (process.env.APPCRANE_EGRESS_RELAY === '1') return true;
  if (process.env.APPCRANE_EGRESS_RELAY === '0') return false;
  if (relayDecision === null) {
    try { relayDecision = /docker desktop/i.test(await docker(['info', '--format', '{{.OperatingSystem}}'], 15_000)); } catch (_) { relayDecision = false; }
  }
  return relayDecision;
}

/** The relay on the daemon host's network: gateway:<port> -> host.docker.internal:<port>, for each port. */
export async function ensureRelay(gateway, ports) {
  const want = `RELAY_GW=${gateway}|RELAY_PORTS=${ports.join(' ')}`;
  let have = null;
  try {
    const out = await docker(['inspect', RELAY_NAME, '--format', '{{.State.Running}}|{{range .Config.Env}}{{.}};{{end}}'], 10_000);
    const [running, env] = out.split('|');
    const vars = env.split(';');
    have = running === 'true' ? `${vars.find((v) => v.startsWith('RELAY_GW=')) || ''}|${vars.find((v) => v.startsWith('RELAY_PORTS=')) || ''}` : null;
  } catch (_) { have = null; }
  if (have === want) return;
  await docker(['rm', '-f', RELAY_NAME], 20_000).catch(() => {});
  await docker(['run', '-d', '--name', RELAY_NAME, '--label', 'appcrane.egress-relay=1', '--restart', 'unless-stopped',
    '--network', 'host', '--add-host', 'host.docker.internal:host-gateway', '--user', '65534:65534', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--read-only', '--memory', '64m', '--pids-limit', '512', CPU_APP_FLAG, OOM_APP_FLAG,
    '-e', `RELAY_GW=${gateway}`, '-e', `RELAY_PORTS=${ports.join(' ')}`, HELPER_IMAGE, 'sh', '-c', RELAY_SCRIPT], 120_000);
  log.info(`[egress] relay ${RELAY_NAME} forwards ${gateway}:{${ports.join(',')}} to this host`);
}

/**
 * null when the app is not egress-enforced (its start is exactly as before),
 * else { network, gateway, anchor, env } with the proxy and relay already up.
 * Throws when enforcement is on and cannot be set up: the start must fail
 * rather than run the app open.
 */
export async function egressPlan({ slug, env }, db = getDb()) {
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app || !isEnforced(app, db)) return null;
  const net = await ensureEgressNetwork();
  const relay = await relayNeeded();
  const port = proxyPort();
  if (relay) await ensureRelay(net.gateway, [cranePort(), port]);
  await ensureEgressProxy(process.env.APPCRANE_EGRESS_PROXY_HOST || (relay ? '127.0.0.1' : net.gateway), port);
  const proxy = `http://egress:${egressToken(app.id, env, db)}@host.docker.internal:${port}`;
  return {
    network: net.name,
    gateway: net.gateway,
    anchor: anchorName(slug, env),
    env: {
      HTTP_PROXY: proxy, HTTPS_PROXY: proxy, http_proxy: proxy, https_proxy: proxy,
      NO_PROXY: 'host.docker.internal,localhost,127.0.0.1', no_proxy: 'host.docker.internal,localhost,127.0.0.1',
      NODE_USE_ENV_PROXY: '1',
      APPCRANE_EGRESS: 'enforced',
    },
  };
}

/**
 * Rewrite an app's `docker run` argv for the plan: the network becomes the
 * anchor's namespace, and the -p publishes and --add-host move to the anchor
 * (Docker refuses both with --network container:). Returns { appArgs, publish }.
 */
export function applyEgressPlan(args, plan) {
  const appArgs = [];
  const publish = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--network') { appArgs.push('--network', `container:${plan.anchor}`); i++; continue; }
    if (a === '-p') { publish.push('-p', args[i + 1]); i++; continue; }
    if (a === '--add-host') { i++; continue; }
    appArgs.push(a);
  }
  return { appArgs, publish };
}

/** Start (or restart) the anchor and wait until its namespace has no default route. */
export async function startAnchor(plan, publish, { slug, env }) {
  await docker(['rm', '-f', plan.anchor], 20_000).catch(() => {});
  await docker(['run', '-d', '--name', plan.anchor, '--label', ANCHOR_LABEL, '--label', `appcrane.slug=${slug}`, '--label', `appcrane.env=${env}`,
    '--restart', 'unless-stopped', '--network', plan.network, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
    '--security-opt', 'no-new-privileges', '--dns', UNROUTABLE_DNS, '--add-host', `host.docker.internal:${plan.gateway}`,
    '--memory', '16m', '--pids-limit', '16', CPU_APP_FLAG, OOM_APP_FLAG, ...publish, HELPER_IMAGE, 'sh', '-c', ANCHOR_SCRIPT], 120_000);
  const deadline = Date.now() + 15_000;
  for (;;) {
    const logs = await docker(['logs', plan.anchor], 10_000).catch(() => '');
    if (logs.includes(READY)) break;
    if (logs.includes('EGRESS_ANCHOR_FAILED') || Date.now() > deadline) {
      await docker(['rm', '-f', plan.anchor], 20_000).catch(() => {});
      throw new Error(`egress anchor ${plan.anchor} could not remove its default route; the app was not started`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  const routes = await docker(['exec', plan.anchor, 'ip', 'route'], 10_000);
  if (/^default/m.test(routes)) {
    await docker(['rm', '-f', plan.anchor], 20_000).catch(() => {});
    throw new Error(`egress anchor ${plan.anchor} still has a default route; the app was not started`);
  }
}

/** Remove the anchor, where one can exist: on a platform that never touched egress, stopping an app runs no extra docker call. */
export async function removeAnchor(slug, env, db = getDb()) {
  const touched = db.prepare(`SELECT 1 FROM settings WHERE key = 'egress_mode'
    UNION ALL SELECT 1 FROM app_egress e JOIN apps a ON a.id = e.app_id WHERE a.slug = ? LIMIT 1`).get(slug);
  if (!touched) return;
  await docker(['rm', '-f', anchorName(slug, env)], 20_000).catch(() => {});
}

/** At boot: when anything is enforced, bring the network, relay and proxy back for the containers already running. */
export async function resumeEgress(db = getDb()) {
  const any = db.prepare("SELECT 1 FROM settings WHERE key = 'egress_mode' AND value = 'enforced' UNION ALL SELECT 1 FROM app_egress WHERE enforced = 1 LIMIT 1").get();
  if (!any) return false;
  const net = await ensureEgressNetwork();
  const relay = await relayNeeded();
  if (relay) await ensureRelay(net.gateway, [cranePort(), proxyPort()]);
  await ensureEgressProxy(process.env.APPCRANE_EGRESS_PROXY_HOST || (relay ? '127.0.0.1' : net.gateway), proxyPort());
  return true;
}
