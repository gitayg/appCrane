import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, copyFileSync, mkdirSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import net from 'net';

const execFileAsync = promisify(execFile);

// The dual data plane against a REAL Docker daemon.
//
// data-plane-port.test.js proves the argv, via a `docker` shim that records what
// it was called with. That is the right test for "did we build the command line
// we meant to" and the wrong one for "does that command line do what we think" —
// a shim agrees with whatever the code says. Everything here starts actual
// containers and connects an actual socket, because the two claims the feature
// rests on are claims about a running host:
//
//   1. ONE container serves TWO planes, and they are separately addressable —
//      the HTTP control plane on loopback (Caddy's door) and the raw data plane
//      on 0.0.0.0 (the client's door), each answering with its own marker so a
//      pass cannot come from reaching the wrong one.
//
//   2. THE GUARD HOLDS AT THE DAEMON. A dual row whose data_plane_port is the
//      control-plane port must publish NOTHING. This is asserted against a row
//      written straight into the database — no route, no validator, no MCP tool
//      in the path — because that is the case a write-boundary check cannot
//      catch: a restored backup, a migration, a hand-edited row. If the runtime
//      edge ever silently falls back to a default here, the HTTP origin Caddy
//      exists to protect lands on a public port with no TLS, no forward_auth, no
//      identity headers and no audit.
//
// Ports are ALLOCATED, never chosen. Writing a literal in here was tried by hand
// and a stray unrelated listener on the same number answered the probe instead of
// the container — the test then measures the wrong process and can pass while the
// feature is broken. freePort() removes the coincidence.
//
// NOT asserted here, deliberately: reachability from a non-loopback address.
// Proving "0.0.0.0 really is off-box" needs a second host or a route back in, and
// a GitHub runner has neither — the shape of local-only assumption
// check-test-portability.sh exists to reject. The authoritative fact is the
// binding itself (HostIp 127.0.0.1 vs 0.0.0.0), which docker inspect reports and
// which is asserted below.

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-dpe2e-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

// A daemon that RESPONDS, not a binary that exists. `docker` is installed on the
// GitHub runner, so testing for the CLI would run these everywhere and fail
// wherever the daemon is absent or unreachable.
let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker'],
    { encoding: 'utf8' }).trim() || null;
  if (REAL_DOCKER) execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'],
    { timeout: 15000, stdio: 'pipe' });
} catch (_) {
  REAL_DOCKER = null;
}
let skipReason = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

const dk = (args, timeout = 60000) =>
  execFileAsync(REAL_DOCKER, args, { timeout }).then(r => r.stdout.trim());

const TAG = `appcrane-dualplane-test:${process.pid}`;
const SUFFIX = `e2e${process.pid}`;
const started = [];

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.once('error', reject);
  s.listen(0, '127.0.0.1', () => {
    const p = s.address().port;
    s.close(() => resolve(p));
  });
});

/**
 * Connect, optionally send, read until the peer closes.
 *
 * Reports `connected` SEPARATELY from `data`, and the distinction is the whole
 * point of the guard test below. A published port whose container is not
 * listening still ACCEPTS — Docker's userland proxy completes the handshake and
 * only then finds it has nowhere to forward — so "read nothing" cannot tell a
 * port that was never published from one that was. `connected: false` (the
 * kernel refused) is the only thing that means "not published".
 */
function probe(port, { send = null, ms = 5000 } = {}) {
  return new Promise(resolve => {
    let buf = '';
    let connected = false;
    let settled = false;
    const s = net.connect({ port, host: '127.0.0.1' });
    const done = () => {
      if (settled) return;
      settled = true;
      s.destroy();
      resolve({ connected, data: buf });
    };
    s.setTimeout(ms, done);
    s.once('error', done);
    s.once('connect', () => { connected = true; if (send) s.write(send); });
    s.on('data', d => { buf += d.toString(); });
    s.once('close', done);
  });
}

/**
 * Poll until the port answers with something matching `expect`, and return that
 * same payload for the caller to assert on.
 *
 * Waiting on `expect` rather than on the connection is deliberate: an earlier
 * draft waited for the port to accept and then asserted on the body, which the
 * proxy's early accept turns into a race the slower machine loses — the exact
 * pattern scripts/check-test-portability.sh rejects. Wait for the thing you are
 * about to assert.
 */
async function awaitAnswer(port, expect, { send = null, ms = 30000 } = {}) {
  const deadline = Date.now() + ms;
  let last = { connected: false, data: '' };
  for (;;) {
    last = await probe(port, { send });
    if (expect.test(last.data)) return last.data;
    if (Date.now() > deadline) {
      throw new Error(
        `port ${port} never answered with ${expect} within ${ms}ms ` +
        `(last attempt: connected=${last.connected}, read=${JSON.stringify(last.data.slice(0, 120))})`);
    }
    await new Promise(r => setTimeout(r, 250));
  }
}

/** docker inspect's own record of what got published. */
async function bindings(name) {
  return JSON.parse(await dk(['inspect', '-f', '{{json .HostConfig.PortBindings}}', name]));
}

let startApp, getDb;

before(async () => {
  if (skipReason) return;
  // A build, not a pull of some prepared image: the fixture has to be readable
  // next to the test that depends on it.
  const ctx = join(process.env.DATA_DIR, 'img');
  mkdirSync(ctx, { recursive: true });
  copyFileSync(join(ROOT, 'test/fixtures/dual-plane.Dockerfile'), join(ctx, 'Dockerfile'));
  try {
    await dk(['build', '-q', '-t', TAG, ctx], 300000);
  } catch (e) {
    // No registry reachable is an environment fact, not a failure of the code.
    skipReason = `could not build the two-plane test image: ${String(e.message).slice(0, 120)}`;
    return;
  }
  const db = await import('../server/db.js');
  db.initDb();
  getDb = db.getDb;
  ({ startApp } = await import('../server/services/docker.js'));
});

after(async () => {
  if (!REAL_DOCKER) return;
  for (const c of started) await dk(['rm', '-f', c], 30000).catch(() => {});
  await dk(['rmi', '-f', TAG], 60000).catch(() => {});
  // The shared appcrane-apps network is deliberately NOT removed. startApp
  // creates it on demand and every other app on a developer's machine is
  // attached to it; tearing it down here would detach them.
});

/**
 * Insert an app exactly as the database would hold it and start it for real.
 * The row is written directly on purpose — see the header: the guard has to
 * hold for rows no write path ever validated.
 */
async function launch({ slug, slot, ingress_type, public_port, data_plane_port, hostPort, dataPort }) {
  const db = getDb();
  const id = db.prepare(
    `INSERT INTO apps (name, slug, slot, source_type, ingress_type, public_port, data_plane_port)
     VALUES (?, ?, ?, 'managed', ?, ?, ?)`
  ).run(slug, slug, slot, ingress_type, public_port, data_plane_port).lastInsertRowid;
  db.prepare(
    "INSERT INTO deployments (app_id, env, status, version) VALUES (?, 'production', 'live', '1.0.0')"
  ).run(id);

  const name = `appcrane-${slug}-production`;
  started.push(name);
  await startApp({
    slug, env: 'production', image: TAG, hostPort,
    envVars: dataPort ? { DATA_PLANE_PORT: String(dataPort) } : {},
    memoryMb: 256, cpus: 0.5,
  });
  return name;
}

test('LIVE: one container answers on BOTH planes, each on its own door', { skip: skipReason }, async () => {
  const [hostPort, publicPort] = [await freePort(), await freePort()];
  const dataPort = 8081;
  const name = await launch({
    slug: `dual-${SUFFIX}`, slot: 601, ingress_type: 'dual',
    public_port: publicPort, data_plane_port: dataPort, hostPort, dataPort,
  });

  const pb = await bindings(name);
  assert.deepEqual(pb['3000/tcp'], [{ HostIp: '127.0.0.1', HostPort: String(hostPort) }],
    'the control plane must stay on loopback — that is what keeps Caddy the only way in to it');
  assert.deepEqual(pb[`${dataPort}/tcp`], [{ HostIp: '0.0.0.0', HostPort: String(publicPort) }],
    'the data plane must be published on 0.0.0.0 at the container port the app chose');

  const control = await awaitAnswer(hostPort, /CONTROL/, { send: 'GET / HTTP/1.0\r\n\r\n' });
  const data = await awaitAnswer(publicPort, /DATAPLANE/);

  // The two markers are distinct, so this rules out both ports having landed on
  // the same listener — the failure mode that would make everything above look
  // right while the container served one plane twice.
  assert.doesNotMatch(data, /CONTROL/,
    'the public port reached the CONTROL plane — the publish targeted the wrong container port');
  assert.doesNotMatch(control, /DATAPLANE/,
    'the loopback port reached the DATA plane — the two publishes are crossed');
});

test('LIVE: the data plane is not an HTTP server, so nothing HTTP-shaped leaks through it',
  { skip: skipReason }, async () => {
    const [hostPort, publicPort] = [await freePort(), await freePort()];
    const name = await launch({
      slug: `dualhttp-${SUFFIX}`, slot: 602, ingress_type: 'dual',
      public_port: publicPort, data_plane_port: 8082, hostPort, dataPort: 8082,
    });
    const spoken = await awaitAnswer(publicPort, /DATAPLANE/,
      { send: 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' });
    assert.ok(spoken, `${name}: the data plane did not answer at all`);
    assert.doesNotMatch(spoken, /HTTP\/1\.[01] \d\d\d/,
      'the data plane answered with an HTTP status line — it is not the raw passthrough it claims to be');
  });

test('LIVE SECURITY: a dual row pinned to the control-plane port publishes NOTHING',
  { skip: skipReason }, async () => {
    // Written straight into the database, which is the point: no validator ran.
    const [hostPort, publicPort] = [await freePort(), await freePort()];
    const name = await launch({
      slug: `bad-${SUFFIX}`, slot: 603, ingress_type: 'dual',
      public_port: publicPort, data_plane_port: 3000, hostPort, dataPort: 8081,
    });

    const pb = await bindings(name);

    // Asserted as "no 0.0.0.0 binding anywhere" rather than as a key count, and
    // that is not a stylistic choice. When the guard is removed the extra publish
    // lands under the SAME '3000/tcp' key as the loopback one — both target
    // container port 3000 — so Object.keys(pb) still reads ['3000/tcp'] and a
    // key-shape assertion passes while the origin is exposed. Mutation-tested in
    // both directions.
    const exposed = Object.entries(pb).flatMap(([containerPort, binds]) =>
      (binds || []).filter(b => b.HostIp !== '127.0.0.1')
        .map(b => `${b.HostIp}:${b.HostPort} -> ${containerPort}`));
    assert.deepEqual(exposed, [],
      `a dual app pinned to the control-plane port published ${JSON.stringify(exposed)} — ` +
      'the HTTP origin Caddy fronts is now on a public port with no TLS, no forward_auth, ' +
      'no identity headers and no audit');
    assert.deepEqual(pb['3000/tcp'], [{ HostIp: '127.0.0.1', HostPort: String(hostPort) }],
      'the control plane must still be published on loopback exactly as before');

    // The container is up and serving FIRST, so the refusal below is about the
    // publish being absent and not about a container that failed to start.
    await awaitAnswer(hostPort, /CONTROL/, { send: 'GET / HTTP/1.0\r\n\r\n' });

    // `connected`, not `data`: see probe(). A published-but-unbacked port would
    // read empty too, so asserting on the payload here would pass for the very
    // failure this test exists to catch.
    const reached = await probe(publicPort);
    assert.equal(reached.connected, false,
      `something accepted a connection on ${publicPort} — the control-plane port was ` +
      `published after all (read ${JSON.stringify(reached.data.slice(0, 80))})`);
  });

test('LIVE: a plain http app gets no public binding at all', { skip: skipReason }, async () => {
  // The regression that matters most by volume: every ordinary app takes this
  // path, and its binding must be what it was before the data plane existed.
  const hostPort = await freePort();
  const name = await launch({
    slug: `http-${SUFFIX}`, slot: 604, ingress_type: 'http',
    public_port: null, data_plane_port: null, hostPort,
  });

  const pb = await bindings(name);
  assert.deepEqual(pb, { '3000/tcp': [{ HostIp: '127.0.0.1', HostPort: String(hostPort) }] },
    'an http app published something other than the single loopback binding');

  assert.ok(await awaitAnswer(hostPort, /CONTROL/, { send: 'GET / HTTP/1.0\r\n\r\n' }),
    'the ordinary http path stopped serving');
});
