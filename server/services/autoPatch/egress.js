// Registry-only egress for the auto-patch npm helper.
//
// Docker's own definition of the network the helper runs on (docker network
// create, "Network internal mode"): "Containers on an internal network may
// communicate between each other, but not with any other network, as no
// default route is configured and firewall rules are set up to drop all
// traffic to or from other networks." The same page adds: "Communication with
// the gateway IP address (and thus appropriately configured host services) is
// possible" - so the host's own listeners stay reachable; the internet does not.
//
// The proxy (egressProxyServer.cjs) is started per bump on the default bridge,
// then connected to the internal network, and is the helper's only route out:
// it tunnels CONNECT registry.npmjs.org:443 and refuses everything else. npm
// reaches it through npm_config_https_proxy / npm_config_proxy.
//
// Anything here that cannot be set up throws EgressError; the worker turns a
// failed bump into a fallback to a person, so the helper never runs unconfined.

import { execFile } from 'child_process';
import { mkdtempSync, copyFileSync, chmodSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { randomBytes } from 'crypto';
import { createRequire } from 'module';
import { OOM_APP_FLAG } from '../oomPriority.js';
import { CPU_BUILD_FLAG } from '../cpuPriority.js';

export const INTERNAL_NETWORK = 'appcrane-auto-patch-internal';
export const PROXY_PORT = 3128;
export const PROXY_LABEL = 'appcrane.container.type=auto-patch-proxy';
export const EGRESS_ALLOW = 'registry.npmjs.org:443';
const PROXY_SOURCE = join(dirname(fileURLToPath(import.meta.url)), 'egressProxyServer.cjs');
const READY_MS = 30_000;

export class EgressError extends Error {
  constructor(message) { super(`the npm helper's network could not be confined to the npm registry (${message}); nothing ran`); this.code = 'EGRESS_UNCONFINED'; }
}

export function dockerErrorMessage(err, stderr, args) {
  const tail = String(stderr || '').trim().split('\n').slice(-3).join(' ').replace(/(?:\/[^\s:'"]+){2,}/g, '<path>');
  if (tail) return tail;
  if (err.killed) return `docker ${args[0]} timed out`;
  return `docker ${args[0]} exited with code ${err.code ?? 'unknown'}`;
}

const defaultDocker = (args, timeout = 60_000) => new Promise((res, rej) => {
  execFile('docker', args, { timeout, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => (err
    ? rej(Object.assign(new Error(dockerErrorMessage(err, stderr, args)), { code: err.code }))
    : res(String(stdout).trim())));
});
let docker = defaultDocker;
/** Test seam. */
export function _setDockerForTests(fn) { docker = fn || defaultDocker; }

/** The argv that starts the proxy. Asserted by the tests. */
export function proxyRunArgs({ name, image, sourceDir }) {
  return [
    'run', '-d', '--rm',
    '--name', name,
    '--label', PROXY_LABEL,
    OOM_APP_FLAG,
    CPU_BUILD_FLAG,
    '--network', 'bridge',
    '--pull', 'missing',
    '--user', '1000:1000',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--read-only',
    '--pids-limit', '64',
    '--memory', '128m',
    '--cpus', '0.5',
    '-v', `${sourceDir}:/proxy:ro`,
    '-e', `PORT=${PROXY_PORT}`,
    '-e', `APPCRANE_EGRESS_ALLOW=${EGRESS_ALLOW}`,
    '--entrypoint', 'node',
    image,
    '/proxy/egressProxyServer.cjs',
  ];
}

/** The network the helper joins; created --internal, refused if it exists without it. */
export async function ensureInternalNetwork() {
  let internal = null;
  try { internal = await docker(['network', 'inspect', '--format', '{{.Internal}}', INTERNAL_NETWORK]); } catch (_) { internal = null; }
  if (internal === null) {
    try {
      await docker(['network', 'create', '--internal', '--label', 'appcrane.network=auto-patch', INTERNAL_NETWORK]);
    } catch (e) {
      throw new EgressError(`docker network create --internal ${INTERNAL_NETWORK} failed: ${e.message}`);
    }
    try { internal = await docker(['network', 'inspect', '--format', '{{.Internal}}', INTERNAL_NETWORK]); } catch (e) { throw new EgressError(e.message); }
  }
  if (internal !== 'true') throw new EgressError(`network ${INTERNAL_NETWORK} exists but is not internal`);
  return INTERNAL_NETWORK;
}

/**
 * Start a proxy for one bump. Returns { name, url, stop }.
 * `scratch` is a directory under DATA_DIR the proxy source is copied into.
 */
export async function startEgressProxy({ image, scratch }) {
  const network = await ensureInternalNetwork();
  const name = `appcrane-auto-patch-proxy-${randomBytes(6).toString('hex')}`;
  const sourceDir = mkdtempSync(join(scratch, 'proxy-'));
  let started = false;
  const stop = async () => {
    if (started) { try { await docker(['rm', '-f', name], 30_000); } catch (_) {} }
    rmSync(sourceDir, { recursive: true, force: true });
  };
  try {
    copyFileSync(PROXY_SOURCE, join(sourceDir, 'egressProxyServer.cjs'));
    chmodSync(sourceDir, 0o755);
    chmodSync(join(sourceDir, 'egressProxyServer.cjs'), 0o644);
    await docker(proxyRunArgs({ name, image, sourceDir }), 180_000);
    started = true;
    await docker(['network', 'connect', network, name]);
    const deadline = Date.now() + READY_MS;
    for (;;) {
      const logs = await docker(['logs', name]).catch(() => '');
      if (logs.includes('appcrane-auto-patch-proxy listening')) break;
      if (Date.now() > deadline) throw new Error('the proxy did not start listening');
      await new Promise((r) => setTimeout(r, 500));
    }
  } catch (e) {
    await stop();
    throw e instanceof EgressError ? e : new EgressError(e.message);
  }
  return { name, network, url: `http://${name}:${PROXY_PORT}`, stop };
}

/** The proxy's own module, for the tests (the file the container runs). */
export const _proxyModule = createRequire(import.meta.url)('./egressProxyServer.cjs');
