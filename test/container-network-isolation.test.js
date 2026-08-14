import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import net from 'net';
import express from 'express';

const execFileAsync = promisify(execFile);

// Container network isolation (v2.42.1 SECURITY).
//
// Until this release app containers were started with no `--network` at all,
// which put all ~57 of them on Docker's default `bridge`. Containers there route
// to each other freely, so any one app could open http://<sibling-ip>:3000 and
// reach another app's origin directly — behind Caddy's back, with no
// forward_auth, no identity headers, no audit entry and no rate limit. One
// compromised app owned every app on the box.
//
// The shipped fix is ONE shared user-defined bridge, `appcrane-apps`, created
// with the bridge driver's own inter-container switch off
// (com.docker.network.bridge.enable_icc=false), plus --pids-limit,
// --security-opt no-new-privileges and --cap-drop NET_RAW on every container.
//
// Two kinds of test here, and the difference matters:
//
//   * The isolation claim is proven against a REAL Docker daemon, not by
//     reading argv — argv only shows what was asked for. A victim container
//     serving a recognisable body is placed on an isolated network and on a
//     CONTROL network identical but for the one option, and attacked from a
//     sibling on each. The control must return the body. A test where both
//     sides are blocked proves nothing (the attacker could be misconfigured),
//     so the control is what makes the blocked case evidence.
//
//   * Everything else — the exact argv, the fail-loud path, the warnings, the
//     idempotency — runs against a recording `docker` shim that also emulates
//     `network inspect` / `network create`, so the branches that only fire on a
//     broken host can be driven at all.
//
// The argv assertion is a DIFF against HEAD's docker.js, imported from git into
// a temp file and run side by side. Every existing app goes through this path,
// so "only the flags we deliberately added changed" has to be mechanical rather
// than eyeballed.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-netiso-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

// Resolved BEFORE the shim goes on PATH: the live-Docker tests must reach the
// real daemon, while the server code under test must reach the shim.
let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/which', ['docker'], { encoding: 'utf8' }).trim();
  execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'], { timeout: 10000 });
} catch (_) {
  REAL_DOCKER = null;
}
const noDocker = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

// ---------------------------------------------------------------------------
// A `docker` that records, and fakes just enough of the network subcommands
// ---------------------------------------------------------------------------

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const NET_STATE = join(process.env.DATA_DIR, 'network-state');
mkdirSync(SHIM_DIR, { recursive: true });

// Node, not sh: this has to parse flags and keep state, and a subtly wrong
// shell quoting bug here would look like a bug in the code under test.
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.CRANE_TEST_DOCKER_LOG,
  args.map(a => a + '\\n').join('') + '\\0');

const STATE = process.env.CRANE_TEST_NET_STATE;
const exists = () => fs.existsSync(STATE);

if (args[0] === 'network' && args[1] === 'inspect') {
  if (!exists()) {
    process.stderr.write('Error response from daemon: network ' + args[2] + ' not found\\n');
    process.exit(1);
  }
  process.stdout.write(fs.readFileSync(STATE, 'utf8'));
  process.exit(0);
}

if (args[0] === 'network' && args[1] === 'create') {
  if (exists()) {
    process.stderr.write('Error response from daemon: network with name ' +
      args[args.length - 1] + ' already exists\\n');
    process.exit(1);
  }
  if (process.env.CRANE_TEST_NET_CREATE_FAIL) {
    process.stderr.write(process.env.CRANE_TEST_NET_CREATE_FAIL + '\\n');
    process.exit(1);
  }
  const opt = args.find(a => a.startsWith('com.docker.network.bridge.enable_icc='));
  // Docker's \`{{index .Options "..."}}\` prints <no value> when the option was
  // never set, which is exactly what a hand-created network looks like.
  const icc = opt ? opt.split('=')[1] : '<no value>';
  fs.writeFileSync(STATE, icc + '|' + (process.env.CRANE_TEST_NET_SUBNET || '172.20.0.0/16') + ' ');
  process.stdout.write('netid0123456789abcdef\\n');
  process.exit(0);
}

process.stdout.write('0123456789abcdef\\n');
`, { mode: 0o755 });

process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.CRANE_TEST_NET_STATE = NET_STATE;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

function dockerCalls() {
  if (!existsSync(ARGV_LOG)) return [];
  return readFileSync(ARGV_LOG, 'utf8')
    .split('\0')
    .filter(rec => rec.trim() !== '')
    .map(rec => rec.split('\n').filter(l => l !== ''));
}
const clearDockerCalls = () => { if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG); };

/** The argv of the single `docker run` recorded so far. */
function runArgs() {
  const runs = dockerCalls().filter(c => c[0] === 'run');
  assert.equal(runs.length, 1, `expected exactly one \`docker run\`, saw ${runs.length}`);
  return runs[0];
}

/** Put the fake daemon into a known state, or into "no such network". */
function setNetworkState(content) {
  if (content === null) { if (existsSync(NET_STATE)) rmSync(NET_STATE); return; }
  writeFileSync(NET_STATE, content);
}
const ISOLATED_STATE = 'false|172.20.0.0/16 ';

// ---------------------------------------------------------------------------
// Log capture — every failure mode here is operator-facing
// ---------------------------------------------------------------------------

const logger = (await import('../server/utils/logger.js')).default;
const lines = { warn: [], info: [] };
for (const lvl of ['warn', 'info']) {
  logger[lvl] = (msg) => { lines[lvl].push(String(msg)); };
}
const clearLogs = () => { lines.warn.length = 0; lines.info.length = 0; };
const warned = (re) => lines.warn.filter(l => re.test(l));

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const { startApp, ensureAppNetwork } = await import('../server/services/docker.js');

const CONTAINER_PORT = 3000;
const NETWORK = 'appcrane-apps';

let nextSlot = 7000;
function mkApp(slug, { ingress_type = 'http', public_port = null } = {}) {
  const id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,ingress_type,public_port) VALUES (?,?,?,?,?,?)'
  ).run(slug, slug, ++nextSlot, 'managed', ingress_type, public_port).lastInsertRowid;
  return { id, slug };
}

const HTTP_APP = mkApp('ni-http');
const OTHER_APP = mkApp('ni-other');
const TCP_APP = mkApp('ni-tcp', { ingress_type: 'tcp', public_port: 31777 });

const BASE = { env: 'production', image: 'appcrane-x:abc123', hostPort: 4321, memoryMb: 512, cpus: 0.5 };

/** Start an app against the shim with the network already present and isolated. */
async function start(app, extra = {}) {
  setNetworkState(ISOLATED_STATE);
  clearDockerCalls();
  clearLogs();
  await startApp({ ...BASE, slug: app.slug, ...extra });
  return runArgs();
}

// ---------------------------------------------------------------------------
// HEAD's docker.js, side by side with the working tree's
// ---------------------------------------------------------------------------

/**
 * Import the pre-fix module so the argv can be DIFFED rather than described.
 *
 * Its relative specifiers are rewritten to the repo's real absolute paths, which
 * resolve to the same module URLs the live graph already loaded — so HEAD's
 * startApp talks to the same initialised database and the same patched logger,
 * and the only thing that differs between the two argvs is this release's edit.
 */
const HEAD_MODULE = await (async () => {
  // Sourced from a VENDORED snapshot, not `git show HEAD:` — that was wrong in
  // two ways at once. HEAD moves: the moment this fix was committed, HEAD
  // contained it, so the diff compared the change against itself and the anchor
  // test ("HEAD really did start containers with no --network") became false.
  // And CI's actions/checkout is shallow with no tags, so neither HEAD~1 nor a
  // release tag is reachable there — pinning either would have failed on the
  // runner while passing locally, which is the same shape of bug.
  //
  // The snapshot is server/services/docker.js as of v2.42.0, the last release
  // before container isolation. It is a frozen baseline on purpose: it should
  // change only if someone deliberately re-baselines this comparison.
  const src = readFileSync(join(ROOT, 'test/fixtures/docker.pre-isolation.js'), 'utf8');
  const rewritten = src.replace(/from '(\.[^']+)'/g, (_m, spec) => {
    const abs = join(ROOT, 'server/services', spec);
    assert.ok(existsSync(abs), `HEAD docker.js imports ${spec}, which no longer exists at ${abs}`);
    return `from '${pathToFileURL(abs).href}'`;
  });
  assert.ok(!/from '\.\.?\//.test(rewritten), 'a relative import survived the rewrite');
  const file = join(process.env.DATA_DIR, 'docker.head.mjs');
  writeFileSync(file, rewritten);
  return import(pathToFileURL(file).href);
})();

async function startAtHead(app, extra = {}) {
  clearDockerCalls();
  clearLogs();
  await HEAD_MODULE.startApp({ ...BASE, slug: app.slug, ...extra });
  return runArgs();
}

/**
 * The flags v2.42.1 adds, as the token runs they appear in. Removing exactly
 * these from the new argv must leave HEAD's argv untouched — which is a much
 * stronger statement than "the new flags are present": it also catches a
 * removed flag, a reordered publish or a changed bind address.
 */
const ADDED = [
  ['--network', NETWORK],
  ['--pids-limit=512'],
  ['--security-opt', 'no-new-privileges'],
  ['--cap-drop', 'NET_RAW'],
];

function stripAdded(args) {
  const out = [...args];
  for (const run of ADDED) {
    const at = out.findIndex((_a, i) => run.every((tok, k) => out[i + k] === tok));
    assert.notEqual(at, -1, `expected ${run.join(' ')} in the argv: ${JSON.stringify(args)}`);
    out.splice(at, run.length);
  }
  return out;
}

// ===========================================================================
// The argv every existing app is started with
// ===========================================================================

test('HEAD really did start containers with no --network — the hole being closed', async () => {
  // Anchors the whole file. If HEAD already isolated containers, every diff
  // below would be measuring nothing.
  const head = await startAtHead(HTTP_APP);
  assert.ok(!head.includes('--network'),
    'HEAD passed a --network; this release is not the fix it claims to be');
  assert.ok(!head.includes('--pids-limit=512'));
  assert.ok(!head.includes('no-new-privileges'));
});

test('an http app differs from HEAD by the added flags and NOTHING else', async () => {
  const head = await startAtHead(HTTP_APP);
  const now = await start(HTTP_APP);
  assert.deepEqual(stripAdded(now), head);
});

test('a sandbox http app differs from HEAD by the same flags and nothing else', async () => {
  const head = await startAtHead(HTTP_APP, { env: 'sandbox', hostPort: 4322 });
  const now = await start(HTTP_APP, { env: 'sandbox', hostPort: 4322 });
  assert.deepEqual(stripAdded(now), head);
});

test('an email-enabled app (--add-host) differs from HEAD by the same flags and nothing else', async () => {
  const head = await startAtHead(HTTP_APP, { addHostGateway: true });
  const now = await start(HTTP_APP, { addHostGateway: true });
  assert.deepEqual(stripAdded(now), head);
});

test('a tcp-ingress app differs from HEAD by the same flags and nothing else', async () => {
  const head = await startAtHead(TCP_APP);
  const now = await start(TCP_APP);
  assert.deepEqual(stripAdded(now), head);
});

test('Caddy keeps its door: the loopback publish is still a -p value, unchanged', async () => {
  // Caddy proxies to 127.0.0.1:<hostPort>. Publishing works on a user-defined
  // network, but a --network that had swallowed or rebound this publish would
  // take every app on the platform off the internet.
  const args = await start(HTTP_APP);
  const publishes = args.filter((a, i) => args[i - 1] === '-p');
  assert.deepEqual(publishes, [`127.0.0.1:4321:${CONTAINER_PORT}`]);
});

test("v2.42.0's second 0.0.0.0 publish survives the network change", async () => {
  const args = await start(TCP_APP);
  const publishes = args.filter((a, i) => args[i - 1] === '-p');
  assert.deepEqual(publishes, [
    `127.0.0.1:4321:${CONTAINER_PORT}`,
    `0.0.0.0:31777:${CONTAINER_PORT}`,
  ]);
});

test('--add-host host.docker.internal:host-gateway still appears, and only when asked for', async () => {
  // The route an email-enabled app uses to reach /api/service on the host. A
  // user-defined network changes the gateway address, so this is exactly the
  // flag most likely to be broken by the change.
  const on = await start(HTTP_APP, { addHostGateway: true });
  const i = on.indexOf('host.docker.internal:host-gateway');
  assert.notEqual(i, -1, 'an email-enabled app lost its route back to AppCrane');
  assert.equal(on[i - 1], '--add-host');

  const off = await start(HTTP_APP);
  assert.ok(!off.some(a => a.includes('host.docker.internal')),
    'host-gateway leaked onto an app that did not ask for it');
});

// ===========================================================================
// The isolation mechanism, as emitted
// ===========================================================================

test('every container is attached to the isolated network, by name', async () => {
  const args = await start(HTTP_APP);
  const i = args.indexOf('--network');
  assert.notEqual(i, -1, 'the container was left on Docker\'s default bridge');
  assert.equal(args[i + 1], NETWORK);
});

test('the network is created with inter-container connectivity OFF', async () => {
  // The single option the entire fix rests on. Created with it set to anything
  // but false, or omitted, and the network is a plain bridge: every app reaches
  // every other app again, while every argv assertion above still passes.
  setNetworkState(null);
  clearDockerCalls();
  clearLogs();

  await ensureAppNetwork();

  const create = dockerCalls().find(c => c[0] === 'network' && c[1] === 'create');
  assert.ok(create, 'the network was never created');
  const opt = create[create.indexOf('--opt') + 1];
  assert.equal(opt, 'com.docker.network.bridge.enable_icc=false',
    'the network was created without inter-container connectivity disabled — ' +
    'it is a plain bridge and the isolation is inert');
  assert.equal(create[create.length - 1], NETWORK, 'the network name must be the last argument');
  assert.ok(create.includes('appcrane=true'), 'the network is unlabelled and invisible to operator tooling');
});

test('a network that already exists is reused, never recreated', async () => {
  setNetworkState(ISOLATED_STATE);
  clearDockerCalls();
  clearLogs();
  await ensureAppNetwork();
  assert.equal(dockerCalls().filter(c => c[1] === 'create').length, 0);
  assert.equal(dockerCalls().filter(c => c[1] === 'inspect').length, 1);
});

test('the isolated network is SHARED, not per-app — the design that survives 57 apps', async () => {
  // The scaling limit, asserted rather than described. A per-app network would
  // be the obvious design, and Docker's default address pools only subnet into
  // roughly 16-31 bridge networks, so it would break at about the 16th app with
  // an error about subnets. One network for the fleet has no such ceiling.
  //
  // Twenty starts across two apps and both environments: exactly one create in
  // the whole log, and a name with no slug in it.
  setNetworkState(null);
  clearDockerCalls();
  clearLogs();

  for (let i = 0; i < 10; i++) {
    await startApp({ ...BASE, slug: HTTP_APP.slug, hostPort: 4400 + i });
    await startApp({ ...BASE, slug: OTHER_APP.slug, env: 'sandbox', hostPort: 4500 + i });
  }

  const creates = dockerCalls().filter(c => c[0] === 'network' && c[1] === 'create');
  assert.equal(creates.length, 1,
    `20 container starts issued ${creates.length} \`docker network create\`s — a per-app ` +
    'network exhausts the daemon address pool at around the 16th app');

  const networks = new Set(
    dockerCalls().filter(c => c[0] === 'run').map(c => c[c.indexOf('--network') + 1]));
  assert.deepEqual([...networks], [NETWORK]);
  assert.ok(!NETWORK.includes(HTTP_APP.slug) && !NETWORK.includes(OTHER_APP.slug),
    'the network name is slug-derived, so this is a per-app network after all');
});

// ===========================================================================
// The prerequisite is missing: loud, not silent
// ===========================================================================

test('a network that cannot be created FAILS the deploy instead of falling back to the bridge', async () => {
  // The one outcome that must never happen quietly. Falling back to the default
  // bridge would report a successful deploy while leaving every app reachable
  // from every other app — the security fix silently inert.
  setNetworkState(null);
  process.env.CRANE_TEST_NET_CREATE_FAIL =
    'Error response from daemon: all predefined address pools have been fully subnetted';
  clearDockerCalls();
  clearLogs();
  try {
    await assert.rejects(
      () => startApp({ ...BASE, slug: HTTP_APP.slug }),
      (e) => {
        assert.match(e.message, /appcrane-apps/, `the error must name the network: ${e.message}`);
        assert.match(e.message, /default-address-pools/,
          `the error must say what to change on the host: ${e.message}`);
        assert.match(e.message, /fully subnetted/,
          `the daemon's own reason must survive into the message: ${e.message}`);
        return true;
      });

    assert.equal(dockerCalls().filter(c => c[0] === 'run').length, 0,
      'a container was started anyway — on the default bridge, unisolated');
  } finally {
    delete process.env.CRANE_TEST_NET_CREATE_FAIL;
  }
});

test('the network is settled BEFORE the running container is torn down', async () => {
  // Ordering, not cosmetics. ensureAppNetwork() after stopApp() means a host
  // that cannot provide the network has its app stopped for a start that was
  // never going to happen — a failed deploy becomes an outage.
  setNetworkState(null);
  process.env.CRANE_TEST_NET_CREATE_FAIL = 'Error response from daemon: pool overlaps';
  clearDockerCalls();
  clearLogs();
  try {
    await assert.rejects(() => startApp({ ...BASE, slug: HTTP_APP.slug }));
    const verbs = dockerCalls().map(c => c[0]);
    assert.ok(!verbs.includes('stop'),
      'the old container was stopped before the network failure surfaced — the app is now down');
    assert.ok(!verbs.includes('rm'),
      'the old container was removed before the network failure surfaced — the app is now gone');
  } finally {
    delete process.env.CRANE_TEST_NET_CREATE_FAIL;
  }
});

test('two deploys racing to create the network do not fail each other', async () => {
  // The loser of the create sees "already exists". That is the network being
  // there, not an error, and treating it as one would fail a legitimate deploy.
  setNetworkState(null);
  clearDockerCalls();
  clearLogs();
  const [a, b] = await Promise.all([ensureAppNetwork(), ensureAppNetwork()]);
  assert.equal(a, NETWORK);
  assert.equal(b, NETWORK);
});

test('an existing network with inter-container connectivity ON warns loudly, every start', async () => {
  // Docker has no `network update`, so this cannot be repaired in place. The
  // warning is the only signal an operator gets that the platform is running
  // unisolated, so it has to name the network AND the way out.
  for (const state of ['true|172.20.0.0/16 ', '<no value>|172.20.0.0/16 ']) {
    setNetworkState(state);
    clearDockerCalls();
    clearLogs();
    await startApp({ ...BASE, slug: HTTP_APP.slug });

    const w = warned(/SECURITY/);
    assert.equal(w.length, 1, `no SECURITY warning for a network in state ${state}: ${JSON.stringify(lines.warn)}`);
    assert.match(w[0], /appcrane-apps/);
    assert.match(w[0], /network rm/, `the warning must say how to fix it: ${w[0]}`);
    assert.equal(dockerCalls().filter(c => c[0] === 'run').length, 1,
      'a start was blocked on a warning — this path is deliberately non-blocking');
  }
});

test('an isolated network produces NO security warning — the control', async () => {
  // Without this the warning test above would pass on an implementation that
  // warns unconditionally, which is the same as never warning.
  setNetworkState(ISOLATED_STATE);
  clearDockerCalls();
  clearLogs();
  await startApp({ ...BASE, slug: HTTP_APP.slug });
  assert.deepEqual(warned(/SECURITY/), []);
});

test('a subnet too small for the fleet warns while there is still room to widen it', async () => {
  // The stated scaling limit of the shared-network design: capacity is one
  // subnet, one address per app per environment. An operator who narrowed
  // default-address-pools can get a network the fleet outgrows, and the failure
  // when it happens is a container start that cannot get an address.
  setNetworkState('false|10.9.9.0/25 ');
  clearDockerCalls();
  clearLogs();
  await startApp({ ...BASE, slug: HTTP_APP.slug });

  const w = warned(/addresses/);
  assert.equal(w.length, 1, `no capacity warning for a /25: ${JSON.stringify(lines.warn)}`);
  assert.match(w[0], /10\.9\.9\.0\/25/, `the warning must name the subnet: ${w[0]}`);
  assert.match(w[0], /default-address-pools/, `the warning must say what to widen: ${w[0]}`);
  assert.match(w[0], /\b125\b/, `the warning must quantify the room left: ${w[0]}`);
});

test('a roomy subnet warns about nothing — the control', async () => {
  setNetworkState(ISOLATED_STATE);   // /16
  clearDockerCalls();
  clearLogs();
  await startApp({ ...BASE, slug: HTTP_APP.slug });
  assert.deepEqual(warned(/addresses/), []);
});

// ===========================================================================
// Teardown
// ===========================================================================

test('deleting an app removes its containers and leaves the shared network alone', async () => {
  // The teardown question a per-app design would answer with "remove the app's
  // network". This design has no per-app resource, so the invariant is the
  // opposite one and it is the dangerous one: removing `appcrane-apps` on a
  // single app's delete would detach every other app on the platform.
  const key = generateApiKey('dhk_user');
  const uid = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run('ni-admin', 'ni-admin@t.test', 'admin', hashApiKey(key)).lastInsertRowid;
  const doomed = mkApp('ni-doomed');
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(doomed.id, uid);

  const appsRouter = (await import('../server/routes/apps.js')).default;
  const { errorHandler } = await import('../server/utils/errors.js');
  const api = express();
  api.use(express.json());
  api.use('/api/apps', appsRouter);
  api.use(errorHandler);
  const server = await new Promise(r => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
  const port = server.address().port;

  setNetworkState(ISOLATED_STATE);
  clearDockerCalls();
  clearLogs();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/apps/${doomed.slug}?confirm=true`, {
      method: 'DELETE', headers: { 'X-API-Key': key },
    });
    assert.equal(res.status, 200, await res.text());
  } finally {
    server.close();
  }

  assert.equal(db.prepare('SELECT COUNT(*) n FROM apps WHERE id = ?').get(doomed.id).n, 0);

  const calls = dockerCalls();
  for (const env of ['production', 'sandbox']) {
    assert.ok(calls.some(c => c[0] === 'rm' && c.includes(`appcrane-${doomed.slug}-${env}`)),
      `the ${env} container was never removed`);
  }
  const netOps = calls.filter(c => c[0] === 'network' && c[1] !== 'inspect');
  assert.deepEqual(netOps, [],
    `deleting one app touched the shared network — that detaches the other apps: ${JSON.stringify(netOps)}`);
  assert.ok(existsSync(NET_STATE), 'the shared network was removed when a single app was deleted');
});

// ===========================================================================
// Against a real Docker daemon
// ===========================================================================
//
// Everything above is argv. These prove the argv actually does what it is for.

const LIVE = `crane-nitest-${process.pid}`;
const liveNets = [];
const liveCtrs = [];

const dk = (args, timeout = 60000) =>
  execFileAsync(REAL_DOCKER, args, { timeout }).then(r => r.stdout.trim());

after(async () => {
  if (!REAL_DOCKER) return;
  for (const c of liveCtrs) await dk(['rm', '-f', c], 20000).catch(() => {});
  for (const n of liveNets) await dk(['network', 'rm', n], 20000).catch(() => {});
});

/** A container that answers one recognisable body per connection on :3000. */
const SERVE = (body) =>
  `while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}' | nc -l -p 3000; done`;

async function liveNetwork(name, isolated) {
  const args = ['network', 'create'];
  if (isolated) args.push('--opt', 'com.docker.network.bridge.enable_icc=false');
  args.push(name);
  await dk(args, 30000);
  liveNets.push(name);
  return name;
}

async function liveContainer(name, extra, cmd) {
  await dk(['run', '-d', '--name', name, ...extra, 'alpine:latest', 'sh', '-c', cmd], 60000);
  liveCtrs.push(name);
  return name;
}

/** Reach `url` from a throwaway sibling on `network`; null when blocked. */
async function reachFrom(network, url) {
  try {
    return await dk(['run', '--rm', '--network', network, 'alpine:latest',
      'wget', '-T', '4', '-q', '-O', '-', url], 60000);
  } catch (_) {
    return null;
  }
}

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.once('error', reject);
  s.listen(0, '127.0.0.1', () => {
    const p = s.address().port;
    s.close(() => resolve(p));
  });
});

test('LIVE: a sibling container cannot reach another app, and CAN without the option', { skip: noDocker }, async () => {
  // The whole point of the release, measured. Identical victims on identical
  // networks; the only difference is enable_icc. The control returning the body
  // is what makes the blocked side evidence rather than a broken attacker.
  const iso = await liveNetwork(`${LIVE}-iso`, true);
  const ctl = await liveNetwork(`${LIVE}-ctl`, false);

  const victims = {};
  for (const [tag, netw] of [['iso', iso], ['ctl', ctl]]) {
    const name = `${LIVE}-victim-${tag}`;
    await liveContainer(name, ['--network', netw], SERVE('PWNED'));
    victims[tag] = await dk(['inspect', '-f',
      `{{(index .NetworkSettings.Networks "${netw}").IPAddress}}`, name]);
    assert.match(victims[tag], /^\d+\.\d+\.\d+\.\d+$/, `victim ${tag} has no address`);
  }

  assert.equal(await reachFrom(ctl, `http://${victims.ctl}:${CONTAINER_PORT}/`), 'PWNED',
    'the CONTROL sibling could not reach the victim either — the attack itself is broken, ' +
    'so the isolated result below would prove nothing');
  assert.equal(await reachFrom(iso, `http://${victims.iso}:${CONTAINER_PORT}/`), null,
    'a sibling reached another app\'s port 3000 directly on the isolated network — ' +
    'this is the lateral path the release exists to close');

  // By name too: Docker's embedded DNS still resolves siblings on the network,
  // so an attacker does not need to discover the address.
  assert.equal(await reachFrom(ctl, `http://${LIVE}-victim-ctl:${CONTAINER_PORT}/`), 'PWNED');
  assert.equal(await reachFrom(iso, `http://${LIVE}-victim-iso:${CONTAINER_PORT}/`), null,
    'the container-name route around the isolation is open');
});

test('LIVE: the argv AppCrane actually emits produces a working, hardened container', { skip: noDocker }, async () => {
  // Taken from the recorded argv, not retyped: everything except the container
  // name, the network name, the two host ports and the image is byte-for-byte
  // what startApp built. So this is the platform's real command line, run.
  const emitted = await start(TCP_APP, { addHostGateway: true });

  const netw = await liveNetwork(`${LIVE}-app`, true);
  const name = `${LIVE}-app-ctr`;
  const loopPort = await freePort();
  const pubPort = await freePort();

  const argv = emitted.slice(1, -1)   // drop 'run' and the image
    .map(a => a === 'appcrane-ni-tcp-production' ? name : a)
    .map(a => a === NETWORK ? netw : a)
    .map(a => a === `127.0.0.1:4321:${CONTAINER_PORT}` ? `127.0.0.1:${loopPort}:${CONTAINER_PORT}` : a)
    .map(a => a === `0.0.0.0:31777:${CONTAINER_PORT}` ? `0.0.0.0:${pubPort}:${CONTAINER_PORT}` : a)
    .filter(a => a !== '-d');
  // The substitutions above are the only edits; prove none of them silently
  // matched nothing.
  assert.ok(argv.includes(name) && argv.includes(netw));
  assert.ok(argv.includes(`127.0.0.1:${loopPort}:${CONTAINER_PORT}`));
  assert.ok(argv.includes(`0.0.0.0:${pubPort}:${CONTAINER_PORT}`));
  assert.ok(argv.includes('--pids-limit=512') && argv.includes('no-new-privileges')
    && argv.includes('NET_RAW') && argv.includes('host.docker.internal:host-gateway'));

  await liveContainer(name, argv, SERVE('APP-OK'));

  assert.match(await dk(['inspect', '-f', '{{.State.Status}}', name]), /running/,
    'the container died under the hardening flags');

  // Caddy's door and v2.42.0's public door, both from the host.
  // SERVE is a `nc -l` loop: it answers one connection, exits, and the shell
  // re-listens. A second request issued in that gap gets ECONNRESET from the
  // container, not from the port mapping — so retry briefly. Bounded, so a
  // publish that genuinely does not answer still fails.
  const fetchBody = async (url) => {
    for (let i = 0; ; i++) {
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
        return await r.text();
      } catch (e) {
        if (i === 9) throw e;
        await new Promise(r => setTimeout(r, 200));
      }
    }
  };
  assert.equal(await fetchBody(`http://127.0.0.1:${loopPort}/`), 'APP-OK',
    'the loopback publish does not answer on a user-defined network — Caddy cannot reach any app');
  assert.equal(await fetchBody(`http://127.0.0.1:${pubPort}/`), 'APP-OK',
    'the tcp-ingress public publish does not answer');

  // The route back to AppCrane that email-enabled apps depend on.
  const hosts = await dk(['exec', name, 'getent', 'hosts', 'host.docker.internal']);
  assert.ok(hosts.includes('host.docker.internal'),
    'host.docker.internal no longer resolves inside a container on the user-defined network');

  // The hardening flags are kernel-enforced, not decorative.
  const pids = await dk(['exec', name, 'sh', '-c',
    'cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max']);
  assert.equal(pids, '512', `--pids-limit is not being enforced (pids.max=${pids})`);
  const nnp = await dk(['exec', name, 'sh', '-c', 'grep NoNewPrivs /proc/self/status']);
  assert.match(nnp, /NoNewPrivs:\s*1/, nnp);
});

test('LIVE: --cap-drop NET_RAW removes raw sockets but leaves ping working', { skip: noDocker }, async () => {
  // enable_icc=false blocks ROUTED traffic; the containers still share one
  // bridge's L2 domain, so raw frames are the way around an L3-only block. The
  // cost is commonly overstated: ping uses ICMP datagram sockets under
  // net.ipv4.ping_group_range and does not need CAP_NET_RAW.
  const probe = (extra) => dk(['run', '--rm', ...extra, 'python:3.12-alpine', 'python3', '-c',
    'import socket\n' +
    'try:\n'
    + '    socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close(); print("RAW-OPEN")\n'
    + 'except PermissionError:\n'
    + '    print("RAW-DENIED")\n'], 60000);

  assert.equal(await probe(['--cap-drop', 'NET_RAW']), 'RAW-DENIED');
  assert.equal(await probe([]), 'RAW-OPEN',
    'raw sockets were denied WITHOUT the flag too — the flag is not what is doing the work here');

  const ping = await dk(['run', '--rm', '--cap-drop', 'NET_RAW', 'alpine:latest',
    'sh', '-c', 'ping -c1 -W2 127.0.0.1 >/dev/null 2>&1 && echo PING-OK || echo PING-BROKEN'], 60000);
  assert.equal(ping, 'PING-OK',
    'dropping NET_RAW broke ping, so the documented cost of this flag is understated');
});
