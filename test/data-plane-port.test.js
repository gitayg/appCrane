import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { execFileSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import http from 'http';
import dns from 'dns';

import { HTTP_BASELINE_V2_44_2, httpBaselineFor } from './fixtures/docker-run.http-baseline.v2.44.2.js';

// The PER-APP DATA-PLANE CONTAINER PORT (v2.45.0), end to end.
//
// v2.42.0 could publish an app's port on the host, but both publishes targeted
// the same hardcoded container port (docker.js CONTAINER_PORT = 3000), so tcp
// ingress could only re-expose the very port Caddy already serves. That fits an
// app that is entirely non-HTTP and nothing else.
//
// A DUAL-plane app is the case that did not fit:
//   CONTROL plane — ordinary HTTP on container :3000, published on loopback and
//                   served through Caddy, keeping TLS, the security headers,
//                   forward_auth and the per-request audit.
//   DATA plane    — raw passthrough. The clients are ALREADY configured for a
//                   specific host port, and the bytes must reach a DIFFERENT
//                   port inside the same container, with Caddy nowhere in the
//                   path. Stock Caddy cannot carry that (layer4 plugin + a
//                   custom xcaddy build — BACKLOG.md), so a direct Docker
//                   publish IS the passthrough.
//
// Two things have to be true for that app to be safe, and this file measures
// both against real artefacts rather than reading the source:
//
//   1. THE PUBLISH. `-p 0.0.0.0:<public_port>:<data_plane_port>`, and the
//      container side must never be 3000. A dual app published at :3000 is not
//      a data plane at all — it is the HTTP control plane re-published raw, with
//      no TLS, no forward_auth, no identity headers and no audit entry, and the
//      operator gets no signal that they did it. The argv here comes from a
//      `docker` shim on PATH that records what it was called with.
//
//   2. THE HEALTH SIGNAL. It must follow the CONTROL plane. Both probe branches
//      aim at the same loopback port — the difference is an HTTP request versus
//      a bare TCP handshake — so giving a dual app the handshake is a pure
//      downgrade: a container that accepts connections and answers nothing
//      passes it. The wedged-control-plane case below is that failure, asserted
//      directly against a real socket, with the data plane simultaneously up so
//      "the app is reachable" cannot rescue it.
//
// Regression cover for the other ~57 apps is the vendored v2.44.2 argv: an app
// that sets nothing must start with a byte-identical command line.
//
// dns: the HTTP probe fetches `http://localhost:<port>` while the TCP probe
// connects to 127.0.0.1. Pinning resolution keeps both aimed at the same
// listener, so a failure here is always about ingress and never about which
// stack `localhost` resolved to.
dns.setDefaultResultOrder('ipv4first');

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-dpp-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
// probeFrontendAssets and reloadCaddy run AFTER the deploy gate and are not
// under test. Point the Caddy probe at a port nothing serves so it fails fast
// instead of hitting whatever is on :80 on the machine running this.
process.env.CADDY_HTTP_PORT = '9';

// ---------------------------------------------------------------------------
// A `docker` that records instead of running
// ---------------------------------------------------------------------------
//
// `inspect --format {{.Config.Image}}` answers with a previous image so the
// deploy gate's rollback branch is live; every other `inspect` exits non-zero,
// which bootWatch reads as "no state yet" — so boot-watch never wins the race
// and the health probe is always what decides the gate.

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const PREV_IMAGE = 'appcrane-previous:deadbeef';
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/bin/sh\n' +
  '{ for a in "$@"; do printf \'%s\\n\' "$a"; done; printf \'\\0\'; } >> "$CRANE_TEST_DOCKER_LOG"\n' +
  'case "$1" in\n' +
  '  version) echo "24.0.7" ;;\n' +
  '  build)   echo "Successfully built" ;;\n' +
  '  logs)    exit 1 ;;\n' +
  '  inspect)\n' +
  `    case "$*" in *Config.Image*) echo "${PREV_IMAGE}" ;; *) exit 1 ;; esac ;;\n` +
  '  *) echo "0123456789abcdef" ;;\n' +
  'esac\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

// Blast-radius guard, not part of the fixture. A PATH shim is a soft
// interception: anything that makes it miss — the directory going away, an
// absolute path to the binary, a child process with a scrubbed env — falls
// through to the real `docker` CLI silently. This file drives deployApp(),
// which BUILDS IMAGES, CREATES A NETWORK and RUNS CONTAINERS, so a miss does
// not produce a red test, it produces appcrane-* containers on whatever machine
// ran the suite. Measured, not hypothetical: it happened here.
//
// A DOCKER_HOST the daemon cannot possibly be on makes that failure loud and
// inert instead. The shim ignores the variable entirely, so when interception
// works this changes nothing.
process.env.DOCKER_HOST = 'unix:///nonexistent-appcrane-test-daemon.sock';

function dockerCalls() {
  if (!existsSync(ARGV_LOG)) return [];
  return readFileSync(ARGV_LOG, 'utf8')
    .split('\0')
    .filter(rec => rec.trim() !== '')
    .map(rec => rec.split('\n').filter(l => l !== ''));
}
function clearDockerCalls() {
  if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG);
}
/** The argv of the single `docker run` recorded so far. */
function runArgs() {
  const runs = dockerCalls().filter(c => c[0] === 'run');
  assert.equal(runs.length, 1, `expected exactly one \`docker run\`, saw ${runs.length}`);
  return runs[0];
}
/** `docker run` invocations for one app's container, selected by --name. */
function runsFor(slug, env) {
  const name = `appcrane-${slug}-${env}`;
  return dockerCalls().filter(c => c[0] === 'run' && c[c.indexOf('--name') + 1] === name);
}
/** Just the values that follow a `-p`, in order. */
function publishes(args) {
  return args.filter((a, i) => args[i - 1] === '-p');
}

// ---------------------------------------------------------------------------
// Log capture
// ---------------------------------------------------------------------------

const logger = (await import('../server/utils/logger.js')).default;
const lines = { warn: [], info: [] };
for (const lvl of ['warn', 'info']) {
  logger[lvl] = (msg) => { lines[lvl].push(String(msg)); };
}
const clearLogs = () => { lines.warn.length = 0; lines.info.length = 0; };

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { startApp } = await import('../server/services/docker.js');
const { deployApp } = await import('../server/services/deployer.js');
const { startHealthChecker, stopHealthChecker } = await import('../server/services/healthChecker.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { isPortSafe } = await import('../server/services/blockedPorts.js');
const { CONTROL_PLANE_PORT } = await import('../server/services/tcpIngress.js');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const openServers = [];

test('every `docker` in this file is the recording shim, not the real CLI', () => {
  // The canary for the guard above. If this fails, nothing below means what it
  // says: the argv assertions would be reading an empty log, and the deploy
  // tests would be reporting the real daemon's opinions as the product's.
  const resolved = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker']).toString().trim();
  assert.equal(resolved, join(SHIM_DIR, 'docker'),
    `docker resolves to ${resolved} — the shim is not intercepting, so this suite ` +
    `would build images and start containers on this machine`);
  assert.ok(existsSync(join(SHIM_DIR, 'docker')), 'the shim was deleted mid-run');
});

test('the control-plane port this whole feature is defined against is 3000', () => {
  // Everything below — the loopback publish, the "never publish 3000 raw" guard
  // and the HTTP health branch — is about ONE number. If it ever moves, the
  // literals in this file and in the vendored baseline are wrong, and the
  // failure would otherwise show up as an unrelated-looking argv mismatch.
  assert.equal(CONTROL_PLANE_PORT, 3000);
  assert.ok(HTTP_BASELINE_V2_44_2.includes('127.0.0.1:4321:3000'));
  assert.ok(HTTP_BASELINE_V2_44_2.includes('PORT=3000'));
});

function listen(server, port, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { openServers.push(server); resolve(server); });
  });
}

/**
 * A listener that completes the TCP handshake and then answers NOTHING.
 *
 * This is a WEDGED CONTROL PLANE: the container is up, the socket is bound, and
 * no HTTP request will ever be answered — an app deadlocked on a database
 * handle, an event loop blocked, a process that bound the port during boot and
 * never finished starting. It is precisely the state a TCP handshake cannot
 * distinguish from health, which is why the health rule exists.
 */
function wedgedServer() {
  return net.createServer(sock => { sock.on('error', () => {}); });
}

/** A listener that accepts and greets with something definitively not HTTP. */
function bannerServer(greeting) {
  return net.createServer(sock => {
    sock.on('error', () => {});   // the probe RSTs the instant the handshake lands
    sock.write(greeting);
  });
}

/**
 * Bind an ephemeral port and hold it, returning the number.
 *
 * Used for the DATA plane in the health tests: "the data port is accepting
 * connections" has to be a fact about a real socket, or the assertion that a
 * live data plane does not rescue a wedged control plane proves nothing.
 */
async function liveEphemeralPort(makeServer = () => bannerServer('DATA-PLANE-READY\r\n')) {
  const server = await listen(makeServer(), 0);
  return { port: server.address().port, server };
}

/** A port nothing is listening on, proven by binding and releasing it. */
async function deadPort() {
  const s = net.createServer();
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise(r => s.close(r));
  assert.ok(isPortSafe(port), `ephemeral port ${port} is on the WHATWG blocklist`);
  return port;
}

/**
 * Claim the first slot whose production backend port is free AND clear of the
 * WHATWG blocked list, and bind `makeServer` there.
 *
 * The health probe's loopback port is DERIVED from the slot — 4000 + (2N-1) —
 * so a test that wants a real listener behind a real probe has to bind exactly
 * that port. Skipping blocked ports keeps this file off the slot-23 -> 4045
 * rake: Node's fetch refuses those outright, which would fail the HTTP branch
 * for a reason that has nothing to do with ingress.
 *
 * Offset per process, because slot ports are a fixed function of the slot
 * number and two copies of this file must not pick the same ones.
 *
 * The BASE is disjoint from test/tcp-ingress-runtime.test.js on purpose, and
 * that is load-bearing rather than tidy. `npm test` runs the files
 * concurrently, that file's band is 400 + (pid % 500) * 4 → slots 400-2396,
 * and its DEAD app asserts that NOTHING is listening on its slot port. A
 * listener this file binds inside that band makes its "nothing listening"
 * app read HEALTHY — measured: four of its tests failed that way in a full
 * suite run, with error "Expected actual to be strictly unequal to: 200",
 * while it passed alone. Nothing about either file was wrong; they were
 * binding the same ports. Starting at 3000 puts this band at slots 3000-4596
 * (ports 9999-13191), clear of its 8791 ceiling.
 */
let slotCursor = 3000 + (process.pid % 400) * 4;
async function claimSlot(makeServer) {
  for (let tries = 0; tries < 400; tries++) {
    const slot = slotCursor++;
    const port = getPortsForSlot(slot).prod_be;
    if (!isPortSafe(port)) continue;
    try {
      const server = await listen(makeServer(), port);
      return { slot, port, server };
    } catch (_) { continue; }
  }
  throw new Error('no free slot port for the test');
}

let nextSlot = 8200;
function mkApp(slug, { slot = ++nextSlot, ingress_type = 'http', public_port = null, data_plane_port = null } = {}) {
  const id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,ingress_type,public_port,data_plane_port) VALUES (?,?,?,?,?,?,?)'
  ).run(slug, slug, slot, 'managed', ingress_type, public_port, data_plane_port).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

const setIngress = (app, type) =>
  db.prepare('UPDATE apps SET ingress_type = ? WHERE id = ?').run(type, app.id);

after(() => {
  stopHealthChecker();
  for (const s of openServers) s.close();
  // DATA_DIR is deliberately NOT deleted here, and that is a safety property
  // rather than laziness. It holds the `docker` shim, and this hook does not
  // reliably run last: measured under `--test-name-pattern`, node starts the
  // matching tests via startSubtestAfterBootstrap and fires the file's after()
  // while they are still in flight. Deleting the directory then left PATH
  // pointing at a directory that no longer existed, `docker` resolved to
  // /usr/local/bin/docker, and the deploy-gate tests drove the REAL daemon —
  // they created appcrane-* containers, images and a network on the machine
  // running them, and reported the daemon's errors as product failures.
  // os.tmpdir() is the OS's to reclaim; the shim outliving the run is worth
  // more than the megabyte.
});

// ===========================================================================
// 1. The publish
// ===========================================================================

const DOCKER_ARGS = { image: 'appcrane-x:abc123', memoryMb: 512, cpus: 0.5 };

async function start(app, env = 'production', hostPort = 4321) {
  clearDockerCalls();
  clearLogs();
  await startApp({ ...DOCKER_ARGS, slug: app.slug, env, hostPort });
  return runArgs();
}

// The motivating numbers: clients pinned to host 8080, the data plane on 8081
// inside the container, and the control plane still on 3000 behind Caddy.
const PUBLIC = 8080;
const DATA = 8081;

const HTTP_APP = mkApp('dp-http', { slot: 8100 });
const HTTP_STALE = mkApp('dp-http-stale', { ingress_type: 'http', public_port: 8099, data_plane_port: DATA });
const DUAL_APP = mkApp('dp-dual', { ingress_type: 'dual', public_port: PUBLIC, data_plane_port: DATA });
const DUAL_AT_CONTROL = mkApp('dp-dual-3000', { ingress_type: 'dual', public_port: 8082, data_plane_port: 3000 });
const DUAL_NO_DATA = mkApp('dp-dual-nodata', { ingress_type: 'dual', public_port: 8083, data_plane_port: null });
const TCP_APP = mkApp('dp-tcp', { ingress_type: 'tcp', public_port: 31000 });

test('an app that sets nothing starts with the argv v2.44.2 actually shipped', async () => {
  // The regression that would touch every app on the platform. Compared against
  // a RECORDED v2.44.2 command line, element for element — an extra flag, a
  // reordered publish or a changed bind address all have to fail here. The slug
  // and hostPort match the fixture exactly, so this is a literal comparison
  // with no substitution in the way.
  assert.deepEqual(await start(HTTP_APP), HTTP_BASELINE_V2_44_2);
});

test('an http app carrying a leftover data_plane_port publishes nothing public', async () => {
  // The column can hold a value the app is no longer entitled to: an operator
  // configured a data plane and then flipped the type back, or the row was
  // hand-edited. ingress_type is what decides, and it says http.
  const args = await start(HTTP_STALE);
  assert.deepEqual(args, httpBaselineFor('dp-http-stale', 'production', 4321));
  assert.ok(!args.some(a => a.includes('0.0.0.0')),
    'an http app published on 0.0.0.0 because a data-plane port was left on the row');
  assert.ok(!args.some(a => a.includes(String(DATA))), JSON.stringify(args));
});

test('a dual app publishes the loopback control plane AND 0.0.0.0:<public>:<data>', async () => {
  const args = await start(DUAL_APP);

  // The control plane, untouched. This is the binding Caddy proxies to, and
  // with it the app keeps TLS, the security headers, forward_auth and audit.
  assert.ok(args.includes(`127.0.0.1:4321:${CONTROL_PLANE_PORT}`),
    'the loopback publish was replaced rather than added to — Caddy, the health ' +
    'probe and every internal caller still use it');

  // The data plane: the host port the clients are already configured for, wired
  // to the app's OWN port inside the container.
  assert.ok(args.includes(`0.0.0.0:${PUBLIC}:${DATA}`),
    `the dual app got no data-plane publish; -p values were ${JSON.stringify(publishes(args))}`);

  // Both must be `-p` VALUES, in this order, and there must be exactly two.
  assert.deepEqual(publishes(args), [
    `127.0.0.1:4321:${CONTROL_PLANE_PORT}`,
    `0.0.0.0:${PUBLIC}:${DATA}`,
  ]);
});

test('SECURITY: the data-plane publish never targets the control-plane port', async () => {
  // The hole this guard exists for. `-p 0.0.0.0:8080:3000` on a dual app is the
  // app's ordinary HTTP origin on a public host port with no TLS, no
  // forward_auth, no identity headers and no audit — the exact surface Caddy is
  // in the path to protect — and nothing in the dashboard would say so.
  //
  // Pin the container side back to CONTAINER_PORT in docker.js and this goes
  // red; it is the mutation guard for the whole feature.
  const args = await start(DUAL_APP);
  const publicPublish = publishes(args).find(p => p.startsWith('0.0.0.0:'));
  assert.ok(publicPublish, JSON.stringify(args));
  const container = Number(publicPublish.split(':')[2]);
  assert.notEqual(container, CONTROL_PLANE_PORT,
    `the control plane was published raw on the host as ${publicPublish}`);
  assert.equal(container, DATA);
});

test('the data-plane publish is the ONLY difference from the v2.44.2 argv', async () => {
  // The strongest available statement of "nothing else changed for a dual app":
  // strike the public `-p` pair and what is left must be the recorded v2.44.2
  // command line — same labels, same limits, same env, same image position.
  const args = await start(DUAL_APP);
  const i = args.indexOf(`0.0.0.0:${PUBLIC}:${DATA}`);
  assert.equal(args[i - 1], '-p');
  const withoutPublic = [...args.slice(0, i - 1), ...args.slice(i + 1)];
  assert.deepEqual(withoutPublic, httpBaselineFor('dp-dual', 'production', 4321));
});

test('a v2.42.0-shaped pure-tcp app still publishes exactly as it did', async () => {
  // Backwards compatibility for the apps this feature already shipped for. A
  // pure-tcp app has no control plane to protect: the container is told
  // PORT=3000 and the whole of it IS the data plane, so its publish still
  // targets 3000 and its argv is the v2.44.2 line plus the one extra `-p`.
  const args = await start(TCP_APP);
  assert.deepEqual(publishes(args), [
    `127.0.0.1:4321:${CONTROL_PLANE_PORT}`,
    `0.0.0.0:31000:${CONTROL_PLANE_PORT}`,
  ]);
  const i = args.indexOf(`0.0.0.0:31000:${CONTROL_PLANE_PORT}`);
  const withoutPublic = [...args.slice(0, i - 1), ...args.slice(i + 1)];
  assert.deepEqual(withoutPublic, httpBaselineFor('dp-tcp', 'production', 4321));
});

test('a dual row whose data_plane_port IS 3000 publishes nothing at all', async () => {
  // Fail closed at the runtime edge. The write path refuses this value, so such
  // a row can only arrive by hand-edit or a future bug — and the wrong answer
  // here is not "publish something slightly off", it is "publish the control
  // plane raw". Publishing nothing is a visibly broken data plane; publishing
  // 3000 is an invisible open door.
  const args = await start(DUAL_AT_CONTROL);
  assert.deepEqual(args, httpBaselineFor('dp-dual-3000', 'production', 4321));
  assert.ok(!args.some(a => a.includes('0.0.0.0')),
    'a dual app configured with the control-plane port as its data plane was published anyway');
});

test('a dual row with no data_plane_port yet publishes nothing rather than guessing', async () => {
  // A real intermediate state: the type is set, the data plane is not configured
  // yet. Defaulting the container side to 3000 is the same hole as above;
  // interpolating the null would produce `-p 0.0.0.0:8083:null` and a container
  // that refuses to start.
  const args = await start(DUAL_NO_DATA);
  assert.deepEqual(args, httpBaselineFor('dp-dual-nodata', 'production', 4321));
  assert.ok(!args.some(a => /null|undefined|NaN/.test(a)), JSON.stringify(args));
});

test("a dual app's sandbox container stays loopback-only", async () => {
  // One public_port, two containers: publishing it for both makes the second
  // `docker run` die with "port is already allocated", and the loser could be
  // production. Sandbox is therefore structurally unable to take the host port
  // production's clients are pinned to.
  const args = await start(DUAL_APP, 'sandbox', 4322);
  assert.deepEqual(args, httpBaselineFor('dp-dual', 'sandbox', 4322));
  assert.ok(!args.some(a => a.includes('0.0.0.0')));
});

test('the publish notice names WHICH plane was exposed', async () => {
  // The container port is the one fact in that line that says whether the
  // operator just exposed a data plane or their control plane. An operator
  // reading `-> container port 3000` on a dual app is reading a security
  // incident, and they can only read it if the number is printed.
  await start(DUAL_APP);
  const notice = lines.info.find(l => l.includes('[tcp-ingress]'));
  assert.ok(notice, 'no [tcp-ingress] notice was logged when a public port was published');
  assert.ok(notice.includes(`0.0.0.0:${PUBLIC}`), notice);
  assert.ok(notice.includes(`${DATA}`), `the notice does not say which container port was exposed: ${notice}`);
  // AppCrane publishes the port; it does NOT open the firewall. An operator who
  // never sees that said concludes the feature is broken when the port does not
  // answer from outside.
  assert.match(notice, /firewall/i, notice);
});

// ===========================================================================
// 2. Health follows the control plane
// ===========================================================================
//
// The rule: use the weaker TCP-handshake probe if and only if the app literally
// cannot answer HTTP. A pure-tcp app cannot, so v2.42.0 gave it the handshake.
// A dual app CAN — it speaks HTTP on the loopback port, because that is what
// Caddy proxies to — so handing it the handshake buys nothing and costs the
// only signal that distinguishes "serving" from "bound but wedged".

/**
 * `interval_sec` is a correctness knob here, not a speed one.
 *
 * The HTTP probe gives up after PROBE_TIMEOUT_MS (5s), and the wedged control
 * plane below burns every millisecond of it. scheduleCheck() uses a bare
 * setInterval with no in-flight guard, so an interval shorter than the probe
 * stacks four or five probes on top of each other — they then read
 * `consecutive_fails` before each other's writes, the count advances in
 * duplicate steps, and the auto-restart (which fires on `newFails ===
 * fail_threshold`, an exact equality) is skipped or doubled at random. Late
 * completions also spill their warn lines into the NEXT test's window.
 *
 * So an interval longer than the probe timeout for anything wedged: one probe
 * at a time, and every count below is deterministic.
 */
function mkHealth(app, { interval_sec = 1, fail_threshold = 2, down_threshold = 2 } = {}) {
  db.prepare(`INSERT INTO health_configs (app_id,env,endpoint,interval_sec,fail_threshold,down_threshold,enabled)
              VALUES (?,'production','/api/health',?,?,?,0)`)
    .run(app.id, interval_sec, fail_threshold, down_threshold);
  db.prepare("INSERT INTO health_state (app_id,env) VALUES (?,'production')").run(app.id);
}

const stateOf = (app) =>
  db.prepare("SELECT * FROM health_state WHERE app_id = ? AND env = 'production'").get(app.id);

function resetState(app) {
  db.prepare(`UPDATE health_state SET consecutive_fails = 0, is_down = 0,
              last_check_at = NULL, last_status = NULL, last_response_ms = NULL
              WHERE app_id = ? AND env = 'production'`).run(app.id);
}
function enableOnly(...apps) {
  db.prepare('UPDATE health_configs SET enabled = 0').run();
  for (const a of apps) {
    db.prepare('UPDATE health_configs SET enabled = 1 WHERE app_id = ?').run(a.id);
  }
}

/** Run the REAL scheduler until this app has been probed exactly once. */
async function probeOnce(app) {
  enableOnly(app);
  resetState(app);
  clearLogs();
  startHealthChecker();
  try {
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      const s = stateOf(app);
      if (s.last_check_at !== null) return s;
      await sleep(20);
    }
    throw new Error(`no health probe ran for ${app.slug} within 30s`);
  } finally {
    stopHealthChecker();
  }
}

// A wedged CONTROL plane on the app's loopback port...
const wedged = await claimSlot(() => wedgedServer());
// ...and a data plane that is genuinely up at the same time. Both are real
// listeners held open for the whole file.
const dataPlane = await liveEphemeralPort();
const publicSide = await liveEphemeralPort();

const DUAL_WEDGED = mkApp('dp-wedged', {
  slot: wedged.slot, ingress_type: 'dual',
  public_port: publicSide.port, data_plane_port: dataPlane.port,
});

const serving = await claimSlot(() =>
  http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', version: '9.9.9' }));
  }));
const dataPlane2 = await liveEphemeralPort();
const DUAL_SERVING = mkApp('dp-serving', {
  slot: serving.slot, ingress_type: 'dual',
  public_port: dataPlane2.port + 1, data_plane_port: dataPlane2.port,
});

mkHealth(DUAL_WEDGED, { interval_sec: 6 });
mkHealth(DUAL_SERVING);

/** Probe-failure lines for one app only — other apps' probes may still land. */
const probeWarnings = (slug) =>
  lines.warn.filter(l => l.includes('[health-probe]') && l.includes(` ${slug} `));

test('preconditions: the wedged control plane accepts TCP, and the data plane is up', async () => {
  // Without this the headline test below is unfalsifiable — "unhealthy" would
  // be indistinguishable from "the test forgot to bind anything".
  for (const [label, port] of [
    ['the wedged control plane', wedged.port],
    ['the data plane', dataPlane.port],
    ['the public-side listener', publicSide.port],
  ]) {
    await new Promise((resolve, reject) => {
      const s = net.createConnection({ host: '127.0.0.1', port });
      s.setTimeout(5000);
      s.once('connect', () => { s.destroy(); resolve(); });
      s.once('timeout', () => { s.destroy(); reject(new Error(`${label} did not accept a connection`)); });
      s.once('error', reject);
    });
  }
});

test('a dual app with a WEDGED control plane reads UNHEALTHY while its data plane is up', async () => {
  // THE test this rule exists for.
  //
  // The container is accepting connections on every port it owns: the control
  // plane completes a TCP handshake (proven above) and the data plane is
  // serving. The only thing wrong is that the control plane — the plane Caddy
  // fronts and users actually reach — answers no HTTP. A TCP-handshake probe
  // records that as 200 and the app is permanently, silently "healthy": the
  // deploy gate goes green over a working previous image and the periodic
  // checker never restarts it.
  //
  // Widen `ingress_type === 'tcp'` to `!== 'http'` in healthChecker.js and this
  // goes red.
  const s = await probeOnce(DUAL_WEDGED);

  assert.notEqual(s.last_status, 200,
    'a dual app whose control plane accepts connections but answers nothing was ' +
    'recorded HEALTHY — the probe took the TCP-handshake branch, so a wedged ' +
    'control plane can never be detected or auto-restarted');
  assert.equal(s.consecutive_fails, 1);

  const [warn] = probeWarnings('dp-wedged');
  assert.ok(warn, 'a failed probe logged nothing at all');
  // ...and it failed as an HTTP request to the CONTROL plane, not a handshake.
  assert.ok(warn.includes(`http://localhost:${wedged.port}/api/health`),
    `a dual app must be probed over HTTP at its control-plane loopback port, got: ${warn}`);
  assert.ok(!warn.includes('tcp://'), `the dual app got the weaker handshake probe: ${warn}`);

  // The probe went nowhere near the data plane or the published host port —
  // asserted on this same probe rather than a second one, since it is the same
  // measurement. Both of those ARE answering, so a probe that drifted onto
  // either would read healthy for the wrong reason. The probe must also work
  // before the operator opens the firewall, and must not depend on a
  // public_port allocation existing at all.
  assert.ok(!warn.includes(String(dataPlane.port)), `the probe went at the data plane: ${warn}`);
  assert.ok(!warn.includes(String(publicSide.port)), `the probe went at the public port: ${warn}`);
  assert.ok(!warn.includes('0.0.0.0'), warn);
});

test('the SAME wedged listener reads HEALTHY as a pure-tcp app — the branch really switches', async () => {
  // Nothing about the socket changes here; only ingress_type does. This is what
  // makes the test above mean something: it proves the listener is alive and
  // handshaking, so "unhealthy" for the dual app is the HTTP branch being
  // chosen and not a dead socket. It is also v2.42.0 compatibility — a pure-tcp
  // app must keep passing on a bare listener, which is the strongest signal it
  // can give.
  setIngress(DUAL_WEDGED, 'tcp');
  try {
    const s = await probeOnce(DUAL_WEDGED);
    assert.equal(s.last_status, 200,
      'a pure-tcp app with a live listener was recorded unhealthy — v2.42.0 behaviour regressed');
    assert.equal(s.consecutive_fails, 0);
  } finally {
    setIngress(DUAL_WEDGED, 'dual');
  }
});

test('a dual app whose control plane actually serves reads HEALTHY', async () => {
  // The other half: the rule must not simply fail dual apps. A real HTTP
  // control plane on the loopback port passes, with its data plane up alongside.
  const s = await probeOnce(DUAL_SERVING);
  assert.equal(s.last_status, 200, 'a dual app serving HTTP on its control plane was marked down');
  assert.equal(s.is_down, 0);
  assert.equal(s.consecutive_fails, 0);
  assert.deepEqual(probeWarnings('dp-serving'), [], 'a successful probe logged a failure');
});

test('a wedged dual app accumulates failures and trips AUTO-RESTART', async () => {
  // The consequence of the rule, not just the reading. Both apps are dual, both
  // have fail_threshold 2, both are probed by the same scheduler in the same
  // window — so the serving app staying at zero cannot be the scheduler never
  // ticking, and the wedged one reaching the restart is the recovery action a
  // handshake probe would have withheld forever.
  enableOnly(DUAL_WEDGED, DUAL_SERVING);
  resetState(DUAL_WEDGED);
  resetState(DUAL_SERVING);
  clearDockerCalls();
  clearLogs();
  db.prepare("DELETE FROM audit_log WHERE action = 'health-restart'").run();

  const restartAudits = () =>
    db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'health-restart' AND app_id = ?")
      .get(DUAL_WEDGED.id).n;

  startHealthChecker();
  try {
    // Wait for the LAST thing the restart branch does, not for the first sign
    // of it. `consecutive_fails` is written BEFORE `await restartApp(...)`, so
    // a wait on the count and an assertion about the docker call is a race the
    // slower machine loses — measured: it lost it here on the first run. The
    // audit row is written after the restart resolves, so waiting for it means
    // everything asserted below has already happened. Both the count and the
    // serving app's probe are in the predicate, because both are asserted.
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      if (restartAudits() >= 1
        && stateOf(DUAL_WEDGED).consecutive_fails >= 2
        && stateOf(DUAL_SERVING).last_check_at !== null) break;
      await sleep(50);
    }
  } finally {
    stopHealthChecker();
  }

  const gone = stateOf(DUAL_WEDGED);
  assert.ok(gone.consecutive_fails >= 2,
    `the wedged dual app never accumulated failures (fails: ${gone.consecutive_fails})`);
  assert.equal(gone.is_down, 1, 'a dual app with a wedged control plane was never marked DOWN');
  assert.ok(dockerCalls().some(c => c[0] === 'restart' && c.includes('appcrane-dp-wedged-production')),
    'a dual app with a wedged control plane was never auto-restarted');
  assert.equal(restartAudits(), 1, 'the auto-restart of a dual app was not audited');

  // Control: the serving dual app in the same window is untouched.
  const live = stateOf(DUAL_SERVING);
  assert.equal(live.consecutive_fails, 0, 'a healthy dual app accumulated failures');
  assert.equal(live.is_down, 0);
  assert.ok(!dockerCalls().some(c => c[0] === 'restart' && c.includes('appcrane-dp-serving-production')),
    'a healthy dual app was auto-restarted');
});

// ===========================================================================
// 3. The deploy gate agrees with the periodic checker
// ===========================================================================
//
// Two independent implementations of the same rule live in deployer.js and
// healthChecker.js. If they disagree, an app deploys green and is then
// restart-looped by the checker, or is admitted by the gate and never watched.
// These run the REAL deployApp() against the SAME app rows and the SAME sockets
// the checker just probed above.

let releaseSeq = 0;
async function runDeploy(app, port) {
  const releaseDir = join(
    process.env.DATA_DIR, 'apps', app.slug, 'sandbox', 'releases', `${Date.now()}-${++releaseSeq}-test`,
  );
  mkdirSync(releaseDir, { recursive: true });
  writeFileSync(join(releaseDir, 'package.json'), JSON.stringify({ name: app.slug, version: '9.9.9' }));
  writeFileSync(join(releaseDir, 'deployhub.json'), JSON.stringify({ name: app.slug }));

  const deployId = db.prepare(
    "INSERT INTO deployments (app_id, env, status) VALUES (?, 'sandbox', 'pending')"
  ).run(app.id).lastInsertRowid;

  let result = null;
  let error = null;
  try {
    result = await deployApp(deployId, app, 'sandbox', { prod_be: 1, sand_be: port }, { preExtractedDir: releaseDir });
  } catch (e) {
    error = e;
  }
  const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(deployId);
  return { result, error, status: row.status, log: row.log || '' };
}

test('the deploy gate FAILS the same wedged dual app the checker calls unhealthy', async () => {
  // Same app row, same socket. The gate is pointed at the wedged listener as
  // its sandbox loopback port, so the only difference from the periodic-checker
  // test above is which of the two implementations is running.
  //
  // If the gate took the handshake branch this app would deploy GREEN — promoted
  // over a working previous image, with a control plane that answers nothing —
  // and only then be restart-looped by the checker.
  const d = await runDeploy(DUAL_WEDGED, wedged.port);

  assert.ok(d.error, 'a dual app whose control plane answers nothing deployed green');
  assert.equal(d.status, 'failed');
  assert.match(d.error.message, /failed health check at \/api\/health/,
    `the gate must fail a dual app at its HTTP control plane, got: ${d.error.message}`);
  // The gate log has to say it used the HTTP branch, not the handshake.
  assert.match(d.log, /Validating new container health at \/api\/health/, d.log);
  assert.ok(!/TCP connect/.test(d.log),
    `the gate gave a dual app the weaker handshake probe:\n${d.log}`);
  // A dual app is not a tcp app, so it must not be handed the tcp guidance.
  assert.ok(!/only has to accept a TCP connection/.test(d.error.message), d.error.message);

  // v2.2.11's revert-on-failure is why the gate is mandatory, and it must not be
  // bypassed for a new ingress type.
  assert.equal(runsFor(DUAL_WEDGED.slug, 'sandbox').filter(c => c.includes(PREV_IMAGE)).length, 1,
    'a failed dual deploy did not restore the previous image');
});

test('the deploy gate PASSES the same serving dual app the checker calls healthy', async () => {
  // The agreement in the other direction: the two implementations must not
  // merely both be strict, they must both admit the same app.
  const d = await runDeploy(DUAL_SERVING, serving.port);

  assert.equal(d.error, null, `a healthy dual app failed to deploy: ${d.error?.message}`);
  assert.equal(d.status, 'live');
  assert.match(d.log, /Health check passed/);
  assert.match(d.log, /Validating new container health at \/api\/health/, d.log);
  assert.ok(!runsFor(DUAL_SERVING.slug, 'sandbox').some(c => c.includes(PREV_IMAGE)),
    'a passing gate still reverted to the previous image');
});

test('a pure-tcp app still passes the gate on a bare handshake', async () => {
  // v2.42.0 compatibility at the gate, and the discriminator for the two tests
  // above: the same class of listener that FAILS as a dual app must still PASS
  // as a tcp app, or "dual takes the HTTP branch" would be indistinguishable
  // from "the gate got stricter for everyone".
  const banner = await listen(bannerServer('SSH-2.0-notHTTP\r\n'), 0);
  const tcpApp = mkApp('dp-gate-tcp', { ingress_type: 'tcp', public_port: 31001 });
  try {
    const d = await runDeploy(tcpApp, banner.address().port);
    assert.equal(d.error, null, `a tcp app with a healthy listener failed to deploy: ${d.error?.message}`);
    assert.equal(d.status, 'live');
    assert.match(d.log, new RegExp(`TCP connect to 127\\.0\\.0\\.1:${banner.address().port}`), d.log);
    // The gate must not be silently read as a stronger claim than it is.
    assert.match(d.log, /no status\/version assertion/i, d.log);
  } finally {
    banner.close();
  }
});
