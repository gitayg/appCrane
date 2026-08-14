import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import http from 'http';
import dns from 'dns';

// The DEPLOY-TIME half of TCP (layer-4) ingress (v2.42.0).
//
// test/tcp-ingress-runtime.test.js pins the periodic health checker. This file
// pins the OTHER gate — the mandatory one in deployApp() — and it is the gate
// that decided whether the feature worked at all.
//
// The bug: v2.2.11 made the post-start health check mandatory and
// revert-on-failure. It was an unconditional `probeHealthEndpoint(healthUrl)`,
// i.e. GET <health path> expecting 200 + JSON carrying {status, version}. A
// CONNECT proxy — the app class this whole feature exists for — cannot answer
// an HTTP GET. So every tcp app's first deploy failed the gate, rolled back to
// the previous image and threw, and the periodic checker's tcp branch never
// got a chance to run against anything. "A tcp app can never deploy."
//
// Everything here drives the real exported deployApp(). Nothing is stubbed at
// the module boundary: `docker` is a recording shim on PATH, the release is a
// real directory, the probe target is a real socket, and the assertions read
// the persisted deployments row — the same row an operator reads. In
// particular the probe is never handed a canned result, because the thing
// under test IS which probe gets chosen.
//
// The listener used for the tcp cases accepts a connection and then writes a
// non-HTTP banner, the way an SSH or proxy listener does. That is the perfect
// discriminator: a TCP connect succeeds against it and an HTTP fetch cannot,
// so one socket proves both "the tcp branch was taken" and "it was not the
// HTTP branch getting lucky".
//
// dns: probeHealthEndpoint fetches `http://localhost:<port>` while the tcp
// probe connects to 127.0.0.1. Pinning to IPv4 keeps both aimed at the same
// listener, so a failure here is always about ingress and never about which
// stack `localhost` happened to resolve to.
dns.setDefaultResultOrder('ipv4first');

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tcpgate-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
// probeFrontendAssets and reloadCaddy run AFTER the gate and are not under
// test. Point the Caddy probe at a port nothing serves so it fails fast and
// inconclusively instead of hitting whatever is on :80 on the test machine.
process.env.CADDY_HTTP_PORT = '9';

// ---------------------------------------------------------------------------
// A `docker` that records instead of running
// ---------------------------------------------------------------------------
//
// `inspect --format {{.Config.Image}}` answers with a previous image so the
// rollback branch is live: a failed gate must stop the new container and put
// the old image back, and that behaviour has to stay identical for both
// protocols. Every other `inspect` exits non-zero, which is what bootWatch
// treats as "no state yet" — so boot-watch never wins the race and the probe
// is always the thing that decides, which is the point of the file.

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

function dockerCalls() {
  if (!existsSync(ARGV_LOG)) return [];
  return readFileSync(ARGV_LOG, 'utf8')
    .split('\0')
    .filter(rec => rec.trim() !== '')
    .map(rec => rec.split('\n').filter(l => l !== ''));
}

/**
 * `docker run` invocations for one app's sandbox container. Selected by the
 * --name value rather than by clearing the log between deploys, so two deploys
 * can run concurrently — which is how the two "nothing is listening" cases
 * share a single 30s wall-clock window instead of taking 30s each.
 */
function runsFor(slug) {
  const name = `appcrane-${slug}-sandbox`;
  return dockerCalls().filter(c => c[0] === 'run' && c[c.indexOf('--name') + 1] === name);
}

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { deployApp } = await import('../server/services/deployer.js');
const { isPortSafe } = await import('../server/services/blockedPorts.js');

const openServers = [];
function listen(server, port, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { openServers.push(server); resolve(server); });
  });
}

/**
 * A port nothing is listening on. Bound and released so "nothing is listening"
 * is a proven fact rather than a hopeful guess — the one case that cannot be
 * held open, since holding it would defeat the test.
 */
async function deadPort() {
  const s = net.createServer();
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise(r => s.close(r));
  assert.ok(isPortSafe(port), `ephemeral port ${port} is on the WHATWG blocklist`);
  return port;
}

/** Accepts, then greets with something that is definitively not HTTP. */
function bannerServer(greeting) {
  return net.createServer(sock => {
    sock.on('error', () => {});   // the probe RSTs the moment the handshake lands
    sock.write(greeting);
  });
}

let nextSlot = 7000;
function mkApp(slug, { ingress_type = 'http', public_port = null } = {}) {
  const id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,ingress_type,public_port) VALUES (?,?,?,?,?,?)'
  ).run(slug, slug, ++nextSlot, 'managed', ingress_type, public_port).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

const setIngress = (app, type) =>
  db.prepare('UPDATE apps SET ingress_type = ? WHERE id = ?').run(type, app.id);

let releaseSeq = 0;

/**
 * Run the real deploy pipeline against a real port, via the preExtractedDir
 * path (no clone, no network). `ports.sand_be` is the loopback port the gate
 * probes, so the test owns exactly what the probe finds there.
 *
 * Returns the persisted deployments row alongside the outcome, because the
 * deploy log and the final status are what an operator actually sees.
 */
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

after(() => {
  for (const s of openServers) s.close();
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

// ===========================================================================
// The blocker: a tcp app must be able to deploy at all
// ===========================================================================

const TCP_APP = mkApp('gate-tcp', { ingress_type: 'tcp', public_port: 31000 });
const banner = await listen(bannerServer('SSH-2.0-notHTTP\r\n'), 0);
const BANNER_PORT = banner.address().port;

test('a tcp app with a live listener PASSES the deploy gate', async () => {
  // THE blocker. Before this fix the gate was an unconditional HTTP GET, so
  // this deploy reverted to the previous image and threw — a tcp app could
  // never reach 'live' even with a perfectly healthy listener.
  const d = await runDeploy(TCP_APP, BANNER_PORT);

  assert.equal(d.error, null, `a tcp app with a healthy listener failed to deploy: ${d.error?.message}`);
  assert.equal(d.status, 'live');
  assert.equal(d.result.success, true);
  assert.match(d.log, /Health check passed/);

  // ...and it passed because a TCP connect was made, not because an HTTP probe
  // somehow succeeded against a listener that speaks no HTTP.
  assert.match(d.log, new RegExp(`TCP connect to 127\\.0\\.0\\.1:${BANNER_PORT}`),
    `the deploy log must say a TCP connect was used, got:\n${d.log}`);

  // The gate must not be silently upgraded into a stronger claim than it is:
  // a handshake proves nothing about status/version, and the log has to say so
  // or an operator will read a green tcp deploy as a green http deploy.
  assert.match(d.log, /no status\/version assertion/i, d.log);

  // Nothing rolled back: the previous image was never restarted.
  assert.ok(!runsFor(TCP_APP.slug).some(c => c.includes(PREV_IMAGE)),
    'a passing gate still reverted to the previous image');
});

test('the tcp gate probes the LOOPBACK port, never the published one', async () => {
  // The gate has to pass before the operator opens the firewall, and must not
  // depend on a public_port allocation existing at all. TCP_APP is allocated
  // 31000; the probe must be nowhere near it.
  const d = await runDeploy(TCP_APP, BANNER_PORT);
  assert.equal(d.status, 'live');
  const gateLine = d.log.split('\n').find(l => l.includes('Validating new container health'));
  assert.ok(gateLine, d.log);
  assert.ok(gateLine.includes(`127.0.0.1:${BANNER_PORT}`), gateLine);
  assert.ok(!gateLine.includes('31000'), `the gate probed the public port: ${gateLine}`);
});

// ===========================================================================
// The protocol switch is real
// ===========================================================================

test('the SAME listener FAILS the gate as an http app — the branch really switches', async () => {
  // Nothing about the socket changes here; only ingress_type does. If the gate
  // took the HTTP path for both, the test above would prove nothing — a tcp app
  // would be "passing" for some unrelated reason. If it took the TCP path for
  // both, an http app would deploy green while serving nothing but a banner.
  //
  // This is also the mutation guard: point the tcp branch at
  // probeHealthEndpoint and the pass-case above goes red; point the http branch
  // at probeTcpListener and this one does.
  setIngress(TCP_APP, 'http');
  try {
    const d = await runDeploy(TCP_APP, BANNER_PORT);

    assert.ok(d.error, 'an HTTP gate accepted a listener that speaks no HTTP');
    assert.equal(d.status, 'failed');
    assert.match(d.error.message, /failed health check at \/api\/health/,
      `an http app must fail at its HTTP health endpoint, got: ${d.error.message}`);
    // The pre-existing http guidance, unchanged — no TCP wording leaking in.
    assert.match(d.error.message, /\{"status":"ok","version":"1\.0\.0"\}/);
    assert.ok(!/TCP/.test(d.error.message), d.error.message);
  } finally {
    setIngress(TCP_APP, 'tcp');
  }
});

test('flipping back to tcp takes effect on the next deploy', async () => {
  // ingress_type is read from the row at gate time, not carried on the `app`
  // object the caller built — callers assemble that object from several
  // different queries, so a stale copy would strand a just-flipped app on the
  // wrong probe until the process restarted.
  const stale = { ...TCP_APP, ingress_type: 'http' };
  const d = await runDeploy(stale, BANNER_PORT);
  assert.equal(d.status, 'live',
    'the gate used a stale ingress_type from the caller-supplied app object instead of the row');
});

// ===========================================================================
// The http contract is untouched
// ===========================================================================

const HTTP_APP = mkApp('gate-http');

test('an http app still passes on 200 + JSON with {status, version}', async () => {
  const srv = await listen(http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', version: '9.9.9' }));
  }), 0);
  try {
    const d = await runDeploy(HTTP_APP, srv.address().port);
    assert.equal(d.error, null, d.error?.message);
    assert.equal(d.status, 'live');
    assert.match(d.log, /Validating new container health at \/api\/health/);
    assert.match(d.log, /Health check passed/);
  } finally {
    srv.close();
  }
});

test('an http app still fails on 200 with a non-JSON body', async () => {
  // The gate has always asserted more than "something answered". A tcp app
  // cannot be held to this, which is exactly why a green tcp deploy is the
  // weaker statement — but an http app still is.
  const srv = await listen(http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html>hello</html>');
  }), 0);
  try {
    const d = await runDeploy(HTTP_APP, srv.address().port);
    assert.ok(d.error, 'an http app deployed green while returning HTML from its health endpoint');
    assert.equal(d.status, 'failed');
    assert.match(d.error.message, /wasn't JSON/);
  } finally {
    srv.close();
  }
});

test('an http app still fails on 200 + JSON that omits version', async () => {
  const srv = await listen(http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  }), 0);
  try {
    const d = await runDeploy(HTTP_APP, srv.address().port);
    assert.ok(d.error, 'an http app deployed green without reporting its version');
    assert.equal(d.status, 'failed');
    assert.match(d.error.message, /missing required fields/);
  } finally {
    srv.close();
  }
});

// ===========================================================================
// Nothing listening — both protocols fail, each in its own language
// ===========================================================================

test('with nothing listening BOTH protocols fail, each carrying a cause and rolling back', async () => {
  // Run as one test on purpose: the two deploys are independent (own app, own
  // port, own container name) and each burns the full 30s gate envelope, so
  // sharing one wall-clock window halves the file's runtime. The docker log is
  // filtered by container name rather than cleared, which is what makes that
  // safe.
  const tcpDead = mkApp('gate-tcp-dead', { ingress_type: 'tcp', public_port: 31001 });
  const httpDead = mkApp('gate-http-dead');
  const [tcpPort, httpPort] = [await deadPort(), await deadPort()];

  const [t, h] = await Promise.all([runDeploy(tcpDead, tcpPort), runDeploy(httpDead, httpPort)]);

  // --- the tcp half -------------------------------------------------------
  assert.ok(t.error, 'a tcp app with nothing listening deployed green');
  assert.equal(t.status, 'failed');
  assert.match(t.error.message, new RegExp(`TCP health check on 127\\.0\\.0\\.1:${tcpPort}`), t.error.message);

  // The v2.6.10 lesson, carried onto the tcp path: a probe that fails has to
  // say WHY. ECONNREFUSED (never bound / already exited) and ETIMEDOUT (bound
  // but wedged, or packets black-holed) are completely different
  // investigations, and "health check failed" alone sent operators chasing the
  // wrong one for hours.
  assert.match(t.error.message, /ECONNREFUSED/,
    `the tcp failure must carry the errno, not a bare "failed": ${t.error.message}`);
  assert.ok(!/status.*0\b/.test(t.error.message.split('\n')[0]), t.error.message);

  // Actionable, and specific to what a tcp app has to get right.
  assert.match(t.error.message, /0\.0\.0\.0 inside the container/, t.error.message);
  // The http-only advice must NOT be handed to an app that cannot speak HTTP.
  assert.ok(!/\/api\/health/.test(t.error.message),
    `a tcp app was told to add a JSON health route: ${t.error.message}`);

  // --- the http half ------------------------------------------------------
  assert.ok(h.error, 'an http app with nothing listening deployed green');
  assert.equal(h.status, 'failed');
  assert.match(h.error.message, /failed health check at \/api\/health/, h.error.message);
  assert.match(h.error.message, /connection refused|ECONNREFUSED/, h.error.message);
  assert.match(h.error.message, /\{"status":"ok","version":"1\.0\.0"\}/, h.error.message);

  // --- rollback is shared, not bypassed for tcp --------------------------
  // v2.2.11's revert-on-failure is the reason the gate is mandatory. Both
  // protocols must restore the previous image, or a tcp app's failed deploy
  // would leave the env with no container at all.
  for (const [label, app] of [['tcp', tcpDead], ['http', httpDead]]) {
    const reverts = runsFor(app.slug).filter(c => c.includes(PREV_IMAGE));
    assert.equal(reverts.length, 1,
      `the ${label} app did not revert to the previous image after a failed gate`);
  }
});
