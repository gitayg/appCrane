import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import { getDb } from '../db.js';
import { publicPortForApp, releasePendingPortAfterRecreate } from './tcpIngress.js';
import log from '../utils/logger.js';

const execFileAsync = promisify(execFile);
const CONTAINER_PORT = 3000;
const APPCRANE_LABEL = 'appcrane=true';

// v2.42.1 SECURITY. Every app container used to be started with no --network at
// all, which put all of them on Docker's default `bridge`. Containers there can
// route to each other freely, so any one app could open
// http://<other-app-ip>:3000 directly and reach a sibling's origin — behind
// Caddy's back, with no forward_auth, no identity headers, no audit entry and no
// rate limit. One compromised app owned every app on the box.
//
// The obvious fix — a network per app — does not survive this platform's size.
// A user-defined network isolates its members from OTHER networks, but members
// of the same network still reach each other, so isolation would mean ~one
// network per app; and Docker's DEFAULT address pools only subnet into roughly
// 16-31 bridge networks before `docker network create` starts failing with "all
// predefined address pools have been fully subnetted". At ~57 apps that design
// dies partway through, at deploy time, with an error about subnets that reads
// like nothing to do with the app being deployed.
//
// So: ONE shared network, with the bridge driver's own inter-container
// connectivity switch turned off. `enable_icc=false` makes the daemon drop
// container-to-container traffic across that bridge. Measured on Docker 29.6.1,
// each against a control container on an otherwise identical network with the
// option left at its default, where every one of these SUCCEEDS:
//   - sibling -> victim's container IP:3000        blocked (times out)
//   - sibling -> victim by container DNS name      blocked (name still resolves
//     via 127.0.0.11, the connection does not complete)
//   - sibling -> bridge gateway:<published port>   blocked. This is the one
//     worth naming: a tcp-ingress app also publishes on 0.0.0.0, and the
//     hairpin back in through the gateway looks like it should re-open the door
//     for a sibling container. It does not.
// while everything that must keep working does, all four verified against the
// exact argv below:
//   - the 127.0.0.1:<hostPort> publish Caddy proxies to
//   - v2.42.0's second 0.0.0.0:<public_port> publish for tcp-ingress apps
//   - --add-host host.docker.internal:host-gateway, i.e. container -> AppCrane
//   - outbound DNS and internet egress
// One network also means nothing to tear down when an app is deleted: a per-app
// design leaks a subnet per deleted app until the pool is exhausted, which is a
// second way the same design breaks.
//
// SCALING LIMIT, stated plainly: capacity is now one subnet for the whole
// platform — every app container, production and sandbox, takes one address in
// it. Docker's default pools hand this network a /16 or a /20 (thousands of
// addresses) so there is no practical ceiling, but an operator who has narrowed
// `default-address-pools` in daemon.json to small blocks can create a network
// too small to hold the fleet. ensureAppNetwork() measures the allocated subnet
// and warns while there is still room to widen it.
const APP_NETWORK = 'appcrane-apps';
const ICC_OPTION = 'com.docker.network.bridge.enable_icc';
const MIN_NETWORK_ADDRESSES = 256;

// Cap on processes/threads per container, so a fork bomb in one app cannot
// exhaust the host's pid space and take the other 56 down with it. Deliberately
// generous: a node:20 http server measured 11 threads (V8 plus the libuv pool)
// and nginx runs one worker per core, so 512 is far above anything legitimate
// here. Enforced by the kernel, not advisory — cgroup pids.max reads 512 inside
// the container, against "max" without the flag.
const PIDS_LIMIT = 512;

async function dockerExec(args, opts = {}) {
  try {
    const { stdout } = await execFileAsync('docker', args, {
      timeout: 60000,
      ...opts,
    });
    return stdout.trim();
  } catch (e) {
    // stderr FIRST. `docker run -d` writes the new container id to stdout even
    // when the run fails, so a stdout-first pick returned a bare 64-char hex
    // string and threw away the reason on stderr — "Bind for 0.0.0.0:31000
    // failed: port is already allocated" became an unreadable id in the deploy
    // log. v2.42.0's public publish is the first routine way to hit a host-port
    // collision (loopback ports are slot-derived and effectively never clash),
    // which is what surfaced it. Matches index.js, spaBuilder.js and
    // appstudio/worker.js, which all already read stderr first.
    const output = e.stderr?.toString().trim() || e.stdout?.toString().trim() || e.message;
    log.debug(`docker ${args[0]} failed: ${output}`);
    throw new Error(output);
  }
}

function containerName(slug, env) {
  return `appcrane-${slug}-${env}`;
}

async function inspectAppNetwork() {
  try {
    const out = await dockerExec(
      ['network', 'inspect', APP_NETWORK, '--format',
        `{{index .Options "${ICC_OPTION}"}}|{{range .IPAM.Config}}{{.Subnet}} {{end}}`],
      { timeout: 10000 }
    );
    const [icc = '', subnets = ''] = out.split('|');
    return { icc: icc.trim(), subnet: subnets.trim().split(/\s+/)[0] || '' };
  } catch (_) {
    return null;
  }
}

/**
 * Create the shared, inter-container-isolated app network if it is not there,
 * and verify an existing one is actually isolating. Idempotent, and re-checked
 * on every container start rather than cached: this is a deploy-path call, one
 * `docker network inspect` next to a docker build, and a cached "it was fine
 * once" would go on asserting isolation after someone removed or replaced the
 * network by hand.
 *
 * Throws if the network cannot be created. That is deliberate: AppCrane cannot
 * configure the Docker daemon from here, so the alternative is falling back to
 * the default bridge, which would leave every app reachable from every other
 * app while the deploy still reported success — the security fix silently inert,
 * which is worse than a deploy that stops and says what to fix.
 */
export async function ensureAppNetwork() {
  let net = await inspectAppNetwork();

  if (!net) {
    try {
      await dockerExec(
        ['network', 'create', '--label', APPCRANE_LABEL, '--opt', `${ICC_OPTION}=false`, APP_NETWORK],
        { timeout: 20000 }
      );
      log.info(`docker network ${APP_NETWORK} created with inter-container connectivity disabled`);
    } catch (e) {
      // Two deploys racing: whoever loses the create still wants the network.
      if (!/already exists/i.test(e.message)) {
        throw new Error(
          `Cannot create the isolated app network '${APP_NETWORK}': ${e.message}. ` +
          `AppCrane will not start app containers on Docker's default bridge, where every app ` +
          `can reach every other app's port ${CONTAINER_PORT} directly and bypass Caddy's ` +
          `forward_auth. Free a daemon address pool ('docker network prune' to drop unused ` +
          `networks) or widen "default-address-pools" in /etc/docker/daemon.json, then deploy again.`
        );
      }
    }
    net = await inspectAppNetwork();
  }

  if (net && net.icc !== 'false') {
    // Docker has no `network update`, so this cannot be repaired in place while
    // containers are attached — warn on every start until an operator acts,
    // rather than pretending the platform is isolated when it is not.
    log.warn(
      `SECURITY: docker network ${APP_NETWORK} exists with inter-container connectivity ENABLED. ` +
      `App containers on it can reach each other's port ${CONTAINER_PORT} directly, bypassing Caddy ` +
      `auth. Docker cannot change this on a live network: stop the app containers, run ` +
      `'docker network rm ${APP_NETWORK}', then redeploy — AppCrane recreates it isolated.`
    );
  }

  // Usable hosts in a /N, minus network, broadcast and the bridge gateway.
  const prefix = Number(net?.subnet?.split('/')[1]);
  if (prefix > 0) {
    const usable = 2 ** (32 - prefix) - 3;
    if (usable < MIN_NETWORK_ADDRESSES) {
      log.warn(
        `docker network ${APP_NETWORK} has subnet ${net.subnet} — only ${usable} container ` +
        `addresses for the whole platform, and each app uses one per environment. Widen ` +
        `"default-address-pools" in /etc/docker/daemon.json, then remove and let AppCrane ` +
        `recreate the network, before container starts begin failing for lack of an address.`
      );
    }
  }

  return APP_NETWORK;
}

function imageTag(slug, env, commitHash) {
  const raw = commitHash && commitHash !== 'unknown' ? commitHash : `t${Date.now()}`;
  const safe = raw.replace(/[^a-zA-Z0-9._-]/g, '-');
  // Must be env-scoped: Vite/other bundlers bake APP_BASE_PATH into the artifact
  // at build time, so sandbox (/<slug>-sandbox/) and production (/<slug>/) MUST
  // have different images even when built from the same commit.
  return `appcrane-${slug}-${env}:${safe}`;
}

// v2.21.10: exposed so the Nixpacks path can tag its image identically.
export function imageTagFor(slug, env, commitHash) { return imageTag(slug, env, commitHash); }

export async function buildImageIfNeeded({ slug, env, contextDir, commitHash, appBasePath, onLog }) {
  const tag = imageTag(slug, env, commitHash);
  if (commitHash && commitHash !== 'unknown') {
    try {
      await dockerExec(['image', 'inspect', tag, '--format', '{{.Id}}'], { timeout: 5000 });
      onLog?.(`Using cached image: ${tag} (skipping rebuild)`);
      return tag;
    } catch (_) {}
  }
  return buildImage({ slug, env, contextDir, commitHash, appBasePath, onLog });
}

export async function getContainerImage(slug, env) {
  const name = containerName(slug, env);
  return dockerExec(['inspect', name, '--format', '{{.Config.Image}}'], { timeout: 5000 });
}

export async function buildImage({ slug, env, contextDir, commitHash, appBasePath, onLog }) {
  const tag = imageTag(slug, env, commitHash);
  const args = ['build', '-t', tag, '--label', APPCRANE_LABEL, '--label', `slug=${slug}`, '--label', `env=${env}`];
  // Build-time only: bundlers (Vite, CRA, Next) need APP_BASE_PATH to emit
  // correct asset URLs. Caddy strips this prefix at runtime, so it must NOT
  // appear in the runtime container env — see bugs/2026-04-26-appcrane-app-base-path-resolution.md
  if (appBasePath) {
    args.push('--build-arg', `APP_BASE_PATH=${appBasePath}`);
    args.push('--build-arg', `PUBLIC_URL=${appBasePath}`);
    args.push('--build-arg', `VITE_BASE_PATH=${appBasePath}`);
  }
  args.push(contextDir);

  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: 'pipe' });
    let outputBuf = '';

    const emit = (line) => { if (line.trim()) onLog?.(line); };
    child.stdout.on('data', (c) => {
      const s = c.toString();
      outputBuf += s;
      s.split('\n').forEach(emit);
    });
    child.stderr.on('data', (c) => {
      const s = c.toString();
      outputBuf += s;
      s.split('\n').forEach(emit);
    });

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('docker build timed out after 10 minutes'));
    }, 600000);

    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`docker build failed: ${outputBuf.slice(-3000)}`));
      resolve(tag);
    });
  });
}

/**
 * The 0.0.0.0 port this app publishes in addition to its loopback bind, or
 * null. Resolved from the database here rather than taken as a parameter: every
 * container recreation — deploy, rollback, the env-var restart in
 * routes/deploy.js — funnels through startApp(), and a caller that forgot to
 * pass it would silently bring a tcp app back loopback-only, taking it off the
 * network its clients are pinned to with no error anywhere.
 *
 * Production only. There is one public_port per app but two containers, so
 * publishing it for both would make the second `docker run` fail with "port is
 * already allocated" — and the loser could be production. Sandbox stays
 * loopback-only and therefore cannot take the port production's clients use.
 */
function publishedTcpPort(slug, env) {
  if (env !== 'production') return null;
  const app = getDb().prepare('SELECT ingress_type, public_port FROM apps WHERE slug = ?').get(slug);
  return publicPortForApp(app);
}

export async function startApp({ slug, env, image, hostPort, envVars = {}, volumes = [], memoryMb = 512, cpus = 0.5, addHostGateway = false }) {
  const name = containerName(slug, env);

  // Before the old container goes away, so a host that cannot provide the
  // isolated network fails with that explained and the app still running,
  // instead of being torn down for a start that was never going to happen.
  const network = await ensureAppNetwork();

  await stopApp(slug, env).catch(() => {});

  const args = [
    'run', '-d',
    '--name', name,
    '--label', APPCRANE_LABEL,
    '--label', `slug=${slug}`,
    '--label', `env=${env}`,
    '--restart=on-failure:5',
    '--network', network,
    `--memory=${memoryMb}m`,
    `--cpus=${cpus}`,
    `--pids-limit=${PIDS_LIMIT}`,
    // Blocks the setuid/setgid escalation path: a process in the container can
    // no longer gain privileges by exec'ing a setuid binary. Verified not to
    // disturb the usual root -> app-user drop in an entrypoint (su-exec/gosu
    // keep working, since dropping privileges is not gaining them); what it does
    // break is an entrypoint that calls `sudo`, which is the escalation this is
    // here to stop.
    '--security-opt', 'no-new-privileges',
    // Removes AF_PACKET and SOCK_RAW (measured: both fail EPERM with this flag
    // and both open without it). enable_icc=false drops ROUTED traffic between
    // containers, but they still share one bridge's L2 broadcast domain, so
    // without this an app could craft raw frames and ARP-spoof its way around
    // an L3-only block. Cost is smaller than it looks: `ping` still works
    // (measured), because busybox/iputils use ICMP *datagram* sockets under
    // net.ipv4.ping_group_range, which do not need CAP_NET_RAW. Verified
    // harmless to node:20 and nginx:alpine; --cap-drop=ALL was measured and
    // rejected below.
    '--cap-drop', 'NET_RAW',
    '-p', `127.0.0.1:${hostPort}:${CONTAINER_PORT}`,
    '--log-opt', 'max-size=10m',
    '--log-opt', 'max-file=3',
  ];

  // Deliberately NOT added, both measured against real base images rather than
  // assumed:
  //   --read-only    breaks apps that write anywhere outside their volume, and
  //                  adding a tmpfs for /tmp is not enough: WITH --tmpfs /tmp,
  //                  nginx:alpine still dies at boot on mkdir("/var/cache/nginx/
  //                  client_temp") EROFS, and a Node app creating a cache dir
  //                  outside /tmp throws the same way. Covering that needs a
  //                  per-image list of writable paths nobody has. Too broad to
  //                  enable for 57 existing apps.
  //   --cap-drop=ALL breaks nginx:alpine at startup: chown("/var/cache/nginx/
  //                  client_temp") fails with EPERM, which takes out every
  //                  static-serve app. NET_RAW alone is the part that buys
  //                  isolation here anyway.

  // v2.42.0: a tcp app publishes a SECOND binding on 0.0.0.0 so raw TCP
  // clients (a CONNECT proxy's tunnel, say) reach the container directly —
  // Caddy is an HTTP reverse proxy and cannot express a tunnel. The loopback
  // publish above is deliberately kept: it is what the health probe, the
  // Caddy vhost and every internal caller still use, so nothing about an
  // http app's argv changes and a tcp app keeps its private door.
  //
  // SECURITY: this bypasses Caddy entirely, so the published port has no
  // forward_auth, no identity headers, no request audit, no rate limiting, no
  // security headers and no TLS from AppCrane — the app owns authentication.
  // AppCrane publishes the port; it does NOT open the host firewall. That is
  // deliberately a separate operator step so a mis-click in the dashboard
  // cannot put an app on the internet.
  const publicPort = publishedTcpPort(slug, env);
  if (publicPort) {
    args.push('-p', `0.0.0.0:${publicPort}:${CONTAINER_PORT}`);
  }

  // v2.8.0: only email-enabled apps need to reach AppCrane from inside the
  // container (for the email service). host-gateway maps host.docker.internal
  // to the host so CRANE_INTERNAL_URL resolves. Off by default — every other
  // container start is unchanged.
  if (addHostGateway) {
    args.push('--add-host', 'host.docker.internal:host-gateway');
  }

  for (const vol of volumes) {
    args.push('-v', `${vol.host}:${vol.container}`);
  }

  const runtimeEnv = {
    ...envVars,
    PORT: String(CONTAINER_PORT),
    NODE_ENV: env === 'production' ? 'production' : 'development',
    DATA_DIR: '/data',  // platform guarantee — every app container has /data mounted
  };
  for (const [k, v] of Object.entries(runtimeEnv)) {
    args.push('-e', `${k}=${v}`);
  }

  args.push(image);
  const id = await dockerExec(args);
  log.info(`docker started: ${name} (${id.slice(0, 12)}) from ${image}`);
  if (publicPort) {
    log.info(`[tcp-ingress] ${name} also published on 0.0.0.0:${publicPort} — NOT behind AppCrane auth; restricting it is still the operator's firewall job. On Linux this publish is a DNAT rule evaluated in FORWARD and never in INPUT, so a plain 'ufw deny' does NOT block it — filter in DOCKER-USER or in an upstream security group.`);
  }

  // v2.42.0: this is where a tcp -> http flip actually takes effect, and so
  // where the port it left reserved goes back in the pool. The flip cannot
  // close a port on its own — the publish is an argv flag — so it keeps the
  // reservation instead of handing a still-bound port to the next app that
  // asks. The container just created is the proof the old one is gone.
  if (env === 'production') {
    const released = releasePendingPortAfterRecreate(getDb(), slug);
    if (released) {
      log.info(`[tcp-ingress] ${name} was recreated with no public publish — port ${released} is now closed and back in the allocation pool.`);
    }
  }
  return id;
}

export async function stopApp(slug, env) {
  const name = containerName(slug, env);
  try { await dockerExec(['stop', name], { timeout: 15000 }); } catch (e) {}
  try { await dockerExec(['rm', '-f', name]); } catch (e) {}
  log.debug(`docker stopped: ${name}`);
}

export async function restartApp(slug, env) {
  const name = containerName(slug, env);
  try {
    await dockerExec(['restart', name], { timeout: 20000 });
    log.info(`docker restarted: ${name}`);
  } catch (e) {
    log.warn(`docker restart ${name} failed: ${e.message}`);
    throw e;
  }
}

export async function getProcessMetrics(slug, env) {
  const name = containerName(slug, env);
  try {
    const inspectOut = await dockerExec(['inspect', name, '--format', '{{.State.Status}}|{{.State.Pid}}|{{.State.StartedAt}}|{{.RestartCount}}']);
    const [status, pid, startedAt, restarts] = inspectOut.split('|');
    if (status !== 'running') return { status, cpu: 0, memory: 0, pid: Number(pid) || 0, uptime: 0, restarts: Number(restarts) || 0 };
    const statsOut = await dockerExec(['stats', '--no-stream', '--format', '{{.CPUPerc}}|{{.MemUsage}}', name]);
    const [cpuPerc, memUsage] = statsOut.split('|');
    const cpu = parseFloat(cpuPerc.replace('%', '')) || 0;
    const memory = parseMemoryUsage(memUsage);
    const uptime = startedAt ? Date.now() - new Date(startedAt).getTime() : 0;
    return { status: 'online', cpu, memory, pid: Number(pid) || 0, uptime, restarts: Number(restarts) || 0 };
  } catch (e) {
    return { status: 'stopped', cpu: 0, memory: 0 };
  }
}

function parseMemoryUsage(s) {
  if (!s) return 0;
  const m = s.trim().split('/')[0].trim().match(/([\d.]+)\s*(B|KiB|MiB|GiB|KB|MB|GB)/i);
  if (!m) return 0;
  const n = parseFloat(m[1]);
  const unit = m[2].toLowerCase();
  const mul = { b: 1, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3, kb: 1000, mb: 1000 ** 2, gb: 1000 ** 3 }[unit] || 1;
  return Math.round(n * mul);
}

export async function getAppLogs(slug, env, lines = 100, search = '') {
  const name = containerName(slug, env);
  try {
    const output = await dockerExec(['logs', '--tail', String(lines), name]);
    const allLines = output.split('\n');
    if (!search) return allLines;
    const q = search.toLowerCase();
    return allLines.filter(l => l.toLowerCase().includes(q));
  } catch (e) {
    return [];
  }
}

export async function listAll() {
  try {
    const format = '{{.Names}}|{{.Label "slug"}}|{{.Label "env"}}|{{.Status}}|{{.ID}}';
    const output = await dockerExec(['ps', '-a', '--filter', `label=${APPCRANE_LABEL}`, '--format', format]);
    if (!output) return [];
    return output.split('\n').map(line => {
      const [name, slug, env, status, id] = line.split('|');
      return { name, slug, env, status, id };
    });
  } catch (e) {
    return [];
  }
}

export async function pruneOldImages(slug, env, keep = 2) {
  try {
    const filters = ['--filter', `label=slug=${slug}`];
    if (env) filters.push('--filter', `label=env=${env}`);
    const out = await dockerExec(['images', ...filters, '--format', '{{.ID}} {{.CreatedAt}}']);
    if (!out) return;
    const rows = out.split('\n').map(l => {
      const sp = l.indexOf(' ');
      return { id: l.slice(0, sp), created: l.slice(sp + 1) };
    });
    rows.sort((a, b) => b.created.localeCompare(a.created));
    for (const row of rows.slice(keep)) {
      try { await dockerExec(['rmi', '-f', row.id]); } catch (e) {}
    }
  } catch (e) {}
}

// Reclaim dangling/untagged images left behind by failed or interrupted builds.
// Safe by default — `docker image prune -f` only removes images with no tags
// AND no descendant tagged images, never touches anything in use by a container.
export async function pruneDanglingImages() {
  try { await dockerExec(['image', 'prune', '-f']); } catch (e) {}
}

export async function dockerAvailable() {
  try {
    await execFileAsync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 5000 });
    return true;
  } catch (e) {
    return false;
  }
}
