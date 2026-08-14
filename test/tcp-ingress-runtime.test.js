import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import http from 'http';
import dns from 'dns';

// runCheck's HTTP branch fetches `http://localhost:<port>`, while its TCP
// branch connects to 127.0.0.1. Pinning resolution to IPv4 keeps both probes
// pointed at the same loopback listener, so a failure here is always about
// ingress and never about which stack `localhost` happened to resolve to.
dns.setDefaultResultOrder('ipv4first');

// TCP (layer-4) ingress — the RUNTIME half (v2.42.0).
//
// Schema, allocator and authz are pinned in test/tcp-ingress-schema.test.js.
// This file covers the two things that have to happen for a tcp app to actually
// run: the container gets a second, public publish, and the health checker stops
// speaking HTTP at an app that does not speak HTTP.
//
// The second one is the blocker the whole feature rests on. runCheck() used to
// be an unconditional fetch(), so a CONNECT proxy — an app whose entire reason
// to be here is that it is not HTTP — would fail every probe, hit
// [AUTO-RESTART] on the third, and be restart-looped forever while its listener
// was perfectly healthy. "A live tcp app accumulates zero consecutive failures"
// is therefore asserted directly, against a real socket, in the same scheduler
// window as a dead app that DOES trip the restart, so the contrast cannot be an
// artefact of the test never ticking.
//
// Everything here drives the real exported functions. The docker argv is taken
// from a shim `docker` on PATH that records its argv, not from reading the
// source: what matters is the command line an app is actually started with.
//
// Nothing here asserts anything about the host firewall. AppCrane publishes the
// port and deliberately does NOT open it — two keys, so a mis-click in the
// dashboard cannot put an app on the internet.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tcprt-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

// ---------------------------------------------------------------------------
// A `docker` that records instead of running
// ---------------------------------------------------------------------------

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/bin/sh\n' +
  '{ for a in "$@"; do printf \'%s\\n\' "$a"; done; printf \'\\0\'; } >> "$CRANE_TEST_DOCKER_LOG"\n' +
  'echo 0123456789abcdef\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

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
/** The argv of the single `docker run` in the calls recorded so far. */
function runArgs() {
  const runs = dockerCalls().filter(c => c[0] === 'run');
  assert.equal(runs.length, 1, `expected exactly one \`docker run\`, saw ${runs.length}`);
  return runs[0];
}

// ---------------------------------------------------------------------------
// Log capture — the probe's cause and the publish notice are operator-facing
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
const { startHealthChecker, stopHealthChecker } = await import('../server/services/healthChecker.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { isPortSafe } = await import('../server/services/blockedPorts.js');

const CONTAINER_PORT = 3000;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const openServers = [];

/**
 * A stand-in for the motivating app: accepts a connection and greets with a
 * non-HTTP banner, the way an SSH or proxy listener does. The connection error
 * handler is not decoration — probeTcp destroys the socket the instant the
 * handshake completes, which arrives at the server as an RST mid-write.
 */
function bannerServer(greeting) {
  return net.createServer(sock => {
    sock.on('error', () => {});
    sock.write(greeting);
  });
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { openServers.push(server); resolve(server); });
  });
}

/**
 * Claim the first slot whose production backend port is free AND not on the
 * WHATWG blocked list. The health probe's loopback port is DERIVED from the
 * slot — 4000 + (2N-1) — so a test that wants a real listener behind a real
 * probe has to bind exactly that port. Skipping blocked ports keeps this file
 * off the slot-23 -> 4045 rake: Node's fetch refuses those outright, which
 * would make the HTTP control case fail for a reason that has nothing to do
 * with ingress.
 */
// Offset per process. Slot ports are a fixed function of the slot number, so
// two copies of this file running at once would otherwise pick the same ones —
// and the "nothing is listening" app is the one case a free-port check cannot
// keep free, since holding the port would defeat the test.
let slotCursor = 400 + (process.pid % 500) * 4;
async function claimSlot(makeServer) {
  for (let tries = 0; tries < 400; tries++) {
    const slot = slotCursor++;
    const port = getPortsForSlot(slot).prod_be;
    if (!isPortSafe(port)) continue;
    if (!makeServer) {
      // "Nothing is listening here" still has to be true, so prove the port is
      // free by binding it and letting go again.
      try {
        const probe = net.createServer();
        await new Promise((res, rej) => {
          probe.once('error', rej);
          probe.listen(port, '127.0.0.1', res);
        });
        await new Promise(res => probe.close(res));
        return { slot, port, server: null };
      } catch (_) { continue; }
    }
    try {
      const server = await listen(makeServer(), port, '127.0.0.1');
      return { slot, port, server };
    } catch (_) { continue; }
  }
  throw new Error('no free slot port for the test');
}

let nextAppSlot = 9000;
function mkApp(slug, { slot = ++nextAppSlot, ingress_type = 'http', public_port = null } = {}) {
  const id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,ingress_type,public_port) VALUES (?,?,?,?,?,?)'
  ).run(slug, slug, slot, 'managed', ingress_type, public_port).lastInsertRowid;
  return { id, slug, slot, port: getPortsForSlot(slot).prod_be };
}

function mkHealth(app, { interval_sec = 1, fail_threshold = 2, down_threshold = 2 } = {}) {
  db.prepare(`INSERT INTO health_configs (app_id,env,endpoint,interval_sec,fail_threshold,down_threshold,enabled)
              VALUES (?,'production','/api/health',?,?,?,0)`)
    .run(app.id, interval_sec, fail_threshold, down_threshold);
  db.prepare("INSERT INTO health_state (app_id,env) VALUES (?,'production')").run(app.id);
}

const stateOf = (app) =>
  db.prepare("SELECT * FROM health_state WHERE app_id = ? AND env = 'production'").get(app.id);

/** Clear only the "a probe has run" marker, leaving the failure bookkeeping. */
function arm(app) {
  db.prepare(`UPDATE health_state SET last_check_at = NULL, last_status = NULL,
              last_response_ms = NULL WHERE app_id = ? AND env = 'production'`).run(app.id);
}
function resetState(app) {
  db.prepare(`UPDATE health_state SET consecutive_fails = 0, is_down = 0,
              last_check_at = NULL, last_status = NULL, last_response_ms = NULL
              WHERE app_id = ? AND env = 'production'`).run(app.id);
}
function enableOnly(...apps) {
  db.prepare('UPDATE health_configs SET enabled = 0').run();
  for (const a of apps) {
    db.prepare("UPDATE health_configs SET enabled = 1 WHERE app_id = ?").run(a.id);
  }
}
const setIngress = (app, type) =>
  db.prepare('UPDATE apps SET ingress_type = ? WHERE id = ?').run(type, app.id);

/**
 * Run the real scheduler until this app has been probed exactly once.
 * `keepState` preserves consecutive_fails / is_down, which the recovery test
 * needs — zeroing is_down first would make "it came back up" unfalsifiable.
 */
async function probeOnce(app, { keepState = false } = {}) {
  enableOnly(app);
  if (keepState) arm(app); else resetState(app);
  clearLogs();
  startHealthChecker();
  try {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      const s = stateOf(app);
      if (s.last_check_at !== null) return s;
      await sleep(20);
    }
    throw new Error(`no health probe ran for ${app.slug} within 15s`);
  } finally {
    stopHealthChecker();
  }
}

after(async () => {
  stopHealthChecker();
  for (const s of openServers) s.close();
});

// ===========================================================================
// docker run argv
// ===========================================================================

const DOCKER_ARGS = {
  slug: null, env: 'production', image: 'appcrane-x:abc123',
  hostPort: 4321, memoryMb: 512, cpus: 0.5,
};

/**
 * The argv every app is started with, tcp ingress aside.
 *
 * v2.42.1 added the isolation and hardening flags below, so the constant this
 * file compares against moved with them. What these tests assert is unchanged:
 * that tcp ingress adds the public publish and NOTHING else, measured against
 * whatever the current common baseline is.
 */
function baselineArgs(slug, env, hostPort) {
  return [
    'run', '-d',
    '--name', `appcrane-${slug}-${env}`,
    '--label', 'appcrane=true',
    '--label', `slug=${slug}`,
    '--label', `env=${env}`,
    '--restart=on-failure:5',
    '--network', 'appcrane-apps',
    '--memory=512m',
    '--cpus=0.5',
    '--pids-limit=512',
    '--security-opt', 'no-new-privileges',
    '--cap-drop', 'NET_RAW',
    '-p', `127.0.0.1:${hostPort}:${CONTAINER_PORT}`,
    '--log-opt', 'max-size=10m',
    '--log-opt', 'max-file=3',
    '-e', `PORT=${CONTAINER_PORT}`,
    '-e', `NODE_ENV=${env === 'production' ? 'production' : 'development'}`,
    '-e', 'DATA_DIR=/data',
    'appcrane-x:abc123',
  ];
}

const HTTP_APP = mkApp('rt-http');
const HTTP_STALE = mkApp('rt-http-stale', { ingress_type: 'http', public_port: 31500 });
const TCP_APP = mkApp('rt-tcp', { ingress_type: 'tcp', public_port: 31000 });
const TCP_UNALLOCATED = mkApp('rt-tcp-pending', { ingress_type: 'tcp', public_port: null });

async function start(app, env = 'production', hostPort = 4321) {
  clearDockerCalls();
  clearLogs();
  await startApp({ ...DOCKER_ARGS, slug: app.slug, env, hostPort });
  return runArgs();
}

test('an http app is started with byte-identical argv to before tcp ingress existed', async () => {
  // The regression that would break every app on the platform. The expected
  // list is written out in full on purpose: an accidental extra flag, a
  // reordered publish or a changed bind address all have to fail here.
  assert.deepEqual(await start(HTTP_APP), baselineArgs('rt-http', 'production', 4321));
});

test('an http app in sandbox is unchanged too', async () => {
  assert.deepEqual(await start(HTTP_APP, 'sandbox', 4322), baselineArgs('rt-http', 'sandbox', 4322));
});

test('a tcp app publishes BOTH the loopback bind and 0.0.0.0:<public_port>', async () => {
  const args = await start(TCP_APP);

  assert.ok(args.includes(`127.0.0.1:4321:${CONTAINER_PORT}`),
    'the loopback publish was replaced rather than added to — the health probe, ' +
    'the Caddy vhost and every internal caller still use it');
  assert.ok(args.includes(`0.0.0.0:31000:${CONTAINER_PORT}`),
    'the tcp app got no public publish, so raw TCP clients cannot reach it at all');

  // Both must be `-p` VALUES, not stray strings that happen to be present.
  const publishes = args.filter((a, i) => args[i - 1] === '-p');
  assert.deepEqual(publishes, [`127.0.0.1:4321:${CONTAINER_PORT}`, `0.0.0.0:31000:${CONTAINER_PORT}`]);
});

test('the public publish is the ONLY difference from an http app of the same shape', async () => {
  // Strongest available statement of "nothing else changed for a tcp app":
  // strike the public -p pair and what is left must be the baseline argv,
  // exactly — same labels, same limits, same env, same image position.
  const args = await start(TCP_APP);
  const i = args.indexOf(`0.0.0.0:31000:${CONTAINER_PORT}`);
  assert.equal(args[i - 1], '-p');
  const withoutPublic = [...args.slice(0, i - 1), ...args.slice(i + 1)];
  assert.deepEqual(withoutPublic, baselineArgs('rt-tcp', 'production', 4321));
});

test('a tcp app whose allocation has not landed publishes nothing public', async () => {
  // ingress_type='tcp' with public_port NULL is a real intermediate state.
  // Interpolating it would produce `-p 0.0.0.0:null:3000` and a container that
  // refuses to start.
  const args = await start(TCP_UNALLOCATED);
  assert.deepEqual(args, baselineArgs('rt-tcp-pending', 'production', 4321));
  assert.ok(!args.some(a => a.includes('0.0.0.0')), 'a port-less tcp app published on 0.0.0.0 anyway');
  assert.ok(!args.some(a => /null|undefined|NaN/.test(a)));
});

test('a stale public_port left on an http app is not published', async () => {
  // The column can hold a value the app is no longer entitled to — allocation
  // failing after the ingress_type write, a hand-edited row. ingress_type is
  // what decides, and it says http.
  const args = await start(HTTP_STALE);
  assert.deepEqual(args, baselineArgs('rt-http-stale', 'production', 4321));
  assert.ok(!args.some(a => a.includes('31500')), 'a stale port on an http app was published on the host');
});

test("a tcp app's sandbox container stays loopback-only", async () => {
  // One public_port, two containers: publishing it for both makes the second
  // `docker run` die with "port is already allocated", and the loser could be
  // production. Sandbox is therefore structurally unable to take the port
  // production's clients are pinned to.
  const args = await start(TCP_APP, 'sandbox', 4322);
  assert.deepEqual(args, baselineArgs('rt-tcp', 'sandbox', 4322));
  assert.ok(!args.some(a => a.includes('0.0.0.0')));
});

test('starting a tcp app tells the operator the firewall is still their job', async () => {
  // AppCrane publishes the port; it does not open it. That is deliberate, and
  // an operator who never sees it said will conclude the feature is broken
  // when the port does not answer from outside.
  await start(TCP_APP);
  const notice = lines.info.find(l => l.includes('[tcp-ingress]'));
  assert.ok(notice, 'no [tcp-ingress] notice was logged when a public port was published');
  assert.ok(notice.includes('0.0.0.0:31000'), notice);
  assert.match(notice, /firewall/i,
    'the notice must say the port is not reachable until the operator opens the firewall');
});

test('starting an http app logs no tcp-ingress notice', async () => {
  await start(HTTP_APP);
  assert.equal(lines.info.find(l => l.includes('[tcp-ingress]')), undefined);
});

// ===========================================================================
// The health probe
// ===========================================================================
//
// One socket server, probed as both protocols. A server that accepts TCP and
// then greets with a non-HTTP banner is exactly the shape of app this feature
// exists for, and it discriminates the two probes perfectly: a TCP connect
// succeeds against it, an HTTP fetch cannot.

const banner = await claimSlot(() => bannerServer('PROXY-READY not-http\r\n'));
const web = await claimSlot(() =>
  http.createServer((req, res) => { res.writeHead(200); res.end('ok'); }));
const dead = await claimSlot(null);

const PROXY = mkApp('rt-proxy', { slot: banner.slot, ingress_type: 'tcp', public_port: 31001 });
const WEB = mkApp('rt-web', { slot: web.slot, ingress_type: 'http' });
const DEAD = mkApp('rt-dead', { slot: dead.slot, ingress_type: 'tcp', public_port: 31002 });

mkHealth(PROXY);
mkHealth(WEB);
mkHealth(DEAD);

test('a tcp app is probed with a TCP connect and reads healthy against a live listener', async () => {
  const s = await probeOnce(PROXY);
  assert.equal(s.last_status, 200,
    'a listener that completed a TCP handshake was recorded as unhealthy — ' +
    'health_state.last_status is compared to 200 by the dashboard, the health ' +
    'panel and the auto-restart threshold, so a handshake has to record 200');
  assert.equal(s.is_down, 0);
  assert.equal(s.consecutive_fails, 0);
  assert.ok(s.last_response_ms !== null && s.last_response_ms >= 0);
  assert.equal(lines.warn.find(l => l.includes('[health-probe]')), undefined,
    'a successful probe logged a failure');
});

test('the SAME server fails the probe as an http app — the protocol really is switched', async () => {
  // Nothing about the listener changes here; only ingress_type does. If the
  // probe were TCP-connect for both, this would pass as healthy and the tcp
  // test above would prove nothing.
  setIngress(PROXY, 'http');
  try {
    const s = await probeOnce(PROXY);
    assert.notEqual(s.last_status, 200,
      'an HTTP fetch against a listener that speaks no HTTP was recorded healthy');
    assert.equal(s.consecutive_fails, 1);
    const warn = lines.warn.find(l => l.includes('[health-probe]'));
    assert.ok(warn, 'the failure was not logged');
    assert.ok(warn.includes(`http://localhost:${banner.port}/api/health`),
      `an http app must be probed at its HTTP health endpoint, got: ${warn}`);
  } finally {
    setIngress(PROXY, 'tcp');
  }
});

test('flipping back to tcp takes effect on the next probe, with no restart of AppCrane', async () => {
  // scheduleCheck() closes over the row it was built from. Reading ingress_type
  // out of that closure would keep an app that has just been flipped to tcp on
  // HTTP probes — failing them into a restart loop — until the process
  // restarted.
  const s = await probeOnce(PROXY);
  assert.equal(s.last_status, 200,
    'the probe was still HTTP after the app was flipped to tcp — the checker is ' +
    'reading a stale ingress_type');
});

test('an http app is still probed over HTTP and still reads 200', async () => {
  // The other half of the switch: the untouched path must stay untouched.
  const s = await probeOnce(WEB);
  assert.equal(s.last_status, 200);
  assert.equal(s.consecutive_fails, 0);
  assert.equal(s.is_down, 0);
});

test('a tcp app with nothing listening reads unhealthy WITH a cause, not a bare 0', async () => {
  // The v2.6.10 lesson. "status 0" alone sent operators chasing wrong
  // hypotheses for hours; ECONNREFUSED (never bound / exited) and ETIMEDOUT
  // (bound but wedged) are completely different investigations.
  const s = await probeOnce(DEAD);
  assert.notEqual(s.last_status, 200);
  assert.equal(s.consecutive_fails, 1);

  const warn = lines.warn.find(l => l.includes('[health-probe]'));
  assert.ok(warn, 'a failed TCP probe logged nothing at all');
  assert.ok(warn.includes(`tcp://127.0.0.1:${dead.port}`),
    `the log must name what was probed, got: ${warn}`);
  assert.match(warn, /ECONNREFUSED/,
    `the log must carry the errno, not just "down", got: ${warn}`);
});

test('the tcp probe targets the LOOPBACK port, never the published one', async () => {
  // The probe has to work before the operator opens the firewall, and must not
  // depend on an allocation existing at all.
  await probeOnce(DEAD);
  const warn = lines.warn.find(l => l.includes('[health-probe]'));
  assert.ok(warn.includes(`tcp://127.0.0.1:${dead.port}`), warn);
  assert.ok(!warn.includes('31002'), `the probe went at the public port: ${warn}`);
  assert.ok(!warn.includes('0.0.0.0'), warn);
});

test('a healthy tcp app NEVER accumulates failures, while a dead one still trips AUTO-RESTART', async () => {
  // The blocker this whole workstream exists to fix, and its control.
  //
  // Both apps are tcp, both have fail_threshold 2, both are probed by the same
  // scheduler in the same window. The dead one reaching [AUTO-RESTART] is the
  // proof that enough ticks elapsed for the live one too — so "the live app
  // stayed at zero" cannot be the test simply never running a probe. Before
  // this fix the live app was the one being restart-looped.
  enableOnly(PROXY, DEAD);
  resetState(PROXY);
  resetState(DEAD);
  clearDockerCalls();
  clearLogs();
  db.prepare("DELETE FROM audit_log WHERE action = 'health-restart'").run();

  startHealthChecker();
  await sleep(4500);   // interval_sec = 1, so ~4 probes of each
  stopHealthChecker();

  const live = stateOf(PROXY);
  assert.equal(live.consecutive_fails, 0,
    'a tcp app with a healthy listener accumulated failures — this is the restart loop');
  assert.equal(live.is_down, 0, 'a tcp app with a healthy listener was marked DOWN');
  assert.equal(live.last_status, 200);

  const restarts = dockerCalls().filter(c => c[0] === 'restart');
  assert.ok(!restarts.some(c => c.includes('appcrane-rt-proxy-production')),
    `a healthy tcp app was auto-restarted: ${JSON.stringify(restarts)}`);
  assert.equal(lines.warn.filter(l => l.includes('[AUTO-RESTART]') && l.includes('rt-proxy')).length, 0);
  assert.equal(
    db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'health-restart' AND app_id = ?").get(PROXY.id).n,
    0, 'a healthy tcp app was restarted and audited for it');

  // Control: the bookkeeping is shared, not bypassed for tcp apps.
  const gone = stateOf(DEAD);
  assert.ok(gone.consecutive_fails >= 2,
    `the scheduler did not tick enough for this test to mean anything (dead app fails: ${gone.consecutive_fails})`);
  assert.equal(gone.is_down, 1, 'a tcp app whose listener is gone was never marked down');
  assert.ok(restarts.some(c => c.includes('appcrane-rt-dead-production')),
    'a dead tcp app was never auto-restarted — the tcp path skips the restart bookkeeping');
  assert.equal(
    db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'health-restart' AND app_id = ?").get(DEAD.id).n,
    1, 'the auto-restart of a tcp app was not audited');
});

test('a tcp app recovers on the probe after its listener comes back', async () => {
  // Same is_down / recovery bookkeeping as an http app: a down tcp app must be
  // able to come back without a human, or the auto-restart it just got is
  // pointless.
  assert.equal(stateOf(DEAD).is_down, 1, 'precondition: the dead app is down');
  const revived = await listen(bannerServer('back\r\n'), dead.port, '127.0.0.1');
  try {
    const s = await probeOnce(DEAD, { keepState: true });
    assert.equal(s.last_status, 200);
    assert.equal(s.is_down, 0, 'a tcp app whose listener returned was never marked back up');
    assert.equal(s.consecutive_fails, 0);
  } finally {
    revived.close();
  }
});
