import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';

// The two resource flags on every app container (v2.48.0), measured rather than
// described: the argv comes from a recording `docker` shim, and the LIVE half at
// the bottom hands that same argv to a real daemon and reads the cgroup back.
//
// Why this file exists. An August 2026 OOM review found a container running
// --memory=512m --memory-swap=1g on a host with ZERO swap. On paper it had a
// 512 MB swap budget; the kernel had none to give, so the real ceiling was
// 512 MB of RAM and the other half of the promise was undeliverable. The theme
// of that review — a number that reads as a guarantee and is not one — is what
// these assertions are pointed at:
//
//   * --memory-swap pinned EQUAL to --memory, so "512m" means 512m of total
//     commit on every host, swap or no swap. Omitting the flag is NOT the same
//     as setting it: Docker then defaults the combined ceiling to 2x memory
//     (measured below — memory.swap.max goes from 0 to 536870912).
//   * --restart=on-failure:2, down from :5. A process that OOMs under load OOMs
//     again on the way back up, and five attempts re-pressure a host that has
//     nothing left, five times, while the fleet already commits ~25 GB of
//     per-container limits against 7.6 GB of RAM.
//
// The byte-for-byte argv comparisons live in test/tcp-ingress-runtime.test.js,
// test/data-plane-port.test.js and test/container-network-isolation.test.js.
// This file asserts the PROPERTIES those literals have to keep having, across
// memory sizes and container shapes no fixture happens to cover.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-resflags-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// The real docker, resolved BEFORE the shim goes on PATH
// ---------------------------------------------------------------------------

let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/which', ['docker'], { encoding: 'utf8' }).trim();
  execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'], { timeout: 10000 });
} catch {
  REAL_DOCKER = null;
}
const noDocker = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

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
function runArgs() {
  const runs = dockerCalls().filter(c => c[0] === 'run');
  assert.equal(runs.length, 1, `expected exactly one \`docker run\`, saw ${runs.length}`);
  return runs[0];
}

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { startApp } = await import('../server/services/docker.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

let nextSlot = 700;
function mkApp(slug, { ingress_type = 'http', public_port = null, data_plane_port = null } = {}) {
  const slot = ++nextSlot;
  db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,ingress_type,public_port,data_plane_port) VALUES (?,?,?,?,?,?,?)'
  ).run(slug, slug, slot, 'managed', ingress_type, public_port, data_plane_port);
  return { slug, slot, port: getPortsForSlot(slot).prod_be };
}

const BASE = { env: 'production', image: 'appcrane-x:abc123', hostPort: 4321, memoryMb: 512, cpus: 0.5 };

async function start(slug, extra = {}) {
  clearDockerCalls();
  await startApp({ ...BASE, slug, ...extra });
  return runArgs();
}

/** The single token with this prefix, or null. Two of them is itself a failure. */
function flag(args, prefix) {
  const hits = args.filter(a => a.startsWith(prefix));
  assert.ok(hits.length <= 1, `${prefix} appears ${hits.length} times: ${JSON.stringify(args)}`);
  return hits[0] ?? null;
}

/** "512m" -> 536870912. The only unit startApp emits, so anything else is a bug. */
function bytes(token, prefix) {
  const raw = token.slice(prefix.length);
  assert.match(raw, /^\d+m$/, `${prefix} value is not <n>m: ${token}`);
  return Number(raw.slice(0, -1)) * 1024 * 1024;
}

const HTTP_APP = mkApp('rf-http');
const TCP_APP = mkApp('rf-tcp', { ingress_type: 'tcp', public_port: 31810 });
const DUAL_APP = mkApp('rf-dual', { ingress_type: 'dual', public_port: 31811, data_plane_port: 5432 });

// ===========================================================================
// --memory and --memory-swap are one number, not two
// ===========================================================================

test('--memory-swap is present and equal to --memory, at every size a caller can ask for', async () => {
  // Swept rather than pinned at 512: max_ram_mb is operator-set per app, so the
  // pairing has to be a function of the argument, not a literal that happens to
  // match the default. A hardcoded `--memory-swap=512m` passes at 512 and fails
  // here at every other size.
  for (const memoryMb of [128, 256, 512, 1024, 2048, 4096]) {
    const args = await start(HTTP_APP.slug, { memoryMb });
    const mem = flag(args, '--memory=');
    const swap = flag(args, '--memory-swap=');
    assert.equal(mem, `--memory=${memoryMb}m`);
    assert.equal(swap, `--memory-swap=${memoryMb}m`);
    assert.equal(bytes(swap, '--memory-swap='), bytes(mem, '--memory='),
      `at ${memoryMb}m the container has a swap budget of ` +
      `${bytes(swap, '--memory-swap=') - bytes(mem, '--memory=')} bytes beyond its RAM limit`);
  }
});

test('the swap budget beyond the RAM limit is exactly zero, which is the whole point', async () => {
  // Stated as the derived quantity rather than as "the two tokens match",
  // because the derived quantity is what the incident was about: --memory=512m
  // --memory-swap=1g reads as a 512 MB fallback that a swapless host cannot
  // deliver. Zero means the configured number is the ceiling everywhere.
  const args = await start(HTTP_APP.slug, { memoryMb: 768 });
  const budget = bytes(flag(args, '--memory-swap='), '--memory-swap=')
    - bytes(flag(args, '--memory='), '--memory=');
  assert.equal(budget, 0);
});

test('--memory-swap is emitted right after --memory, so the pair cannot drift apart', async () => {
  // Adjacency is not cosmetic here: it is what makes the two impossible to edit
  // independently by accident. A future change that moves one and forgets the
  // other fails this before it reaches a host.
  const args = await start(HTTP_APP.slug);
  const at = args.indexOf('--memory=512m');
  assert.notEqual(at, -1, JSON.stringify(args));
  assert.equal(args[at + 1], '--memory-swap=512m', JSON.stringify(args));
});

// ===========================================================================
// The pairing is not accidental — no shape of container escapes it
// ===========================================================================

test('no container is started with --memory set and --memory-swap absent', async () => {
  // Every branch startApp has: ingress type, environment, the email-only
  // --add-host, volumes, a non-default cpus. If any of them built its argv
  // separately, or a future one did, this is where an unpaired --memory shows
  // up. The pairing is a property of the start, not of one code path.
  const shapes = [
    ['plain http', HTTP_APP.slug, {}],
    ['http in sandbox', HTTP_APP.slug, { env: 'sandbox', hostPort: 4322 }],
    ['tcp with a public publish', TCP_APP.slug, {}],
    ['dual with a data-plane publish', DUAL_APP.slug, {}],
    ['email-enabled (--add-host)', HTTP_APP.slug, { addHostGateway: true }],
    ['with volumes', HTTP_APP.slug, { volumes: [{ host: '/srv/x', container: '/data' }] }],
    ['non-default cpus and memory', HTTP_APP.slug, { cpus: 2, memoryMb: 1536 }],
  ];

  for (const [what, slug, extra] of shapes) {
    const args = await start(slug, extra);
    const mem = flag(args, '--memory=');
    const swap = flag(args, '--memory-swap=');
    assert.ok(mem, `${what}: started with no --memory at all — unlimited RAM: ${JSON.stringify(args)}`);
    assert.ok(swap, `${what}: --memory is set but --memory-swap is not, so Docker defaults the ` +
      `combined ceiling to 2x and the configured limit is not the real one: ${JSON.stringify(args)}`);
    assert.equal(bytes(swap, '--memory-swap='), bytes(mem, '--memory='), what);
  }
});

// ===========================================================================
// Restart policy
// ===========================================================================

test('the restart policy is on-failure:2', async () => {
  const args = await start(HTTP_APP.slug);
  assert.equal(flag(args, '--restart'), '--restart=on-failure:2', JSON.stringify(args));
});

test('the restart count is 2 for every shape, and never the old 5', async () => {
  // :5 was the value the OOM review found: five consecutive restarts of a
  // process that OOMs under load, against a host that has no memory to give.
  // Asserted as "not 5" as well as "is 2" so a partial revert reads clearly.
  for (const [slug, extra] of [
    [HTTP_APP.slug, {}],
    [HTTP_APP.slug, { env: 'sandbox', hostPort: 4322 }],
    [TCP_APP.slug, {}],
    [DUAL_APP.slug, {}],
  ]) {
    const args = await start(slug, extra);
    assert.ok(!args.includes('--restart=on-failure:5'), JSON.stringify(args));
    assert.equal(flag(args, '--restart'), '--restart=on-failure:2', JSON.stringify(args));
  }
});

test('the policy is still on-failure — a crash loop is bounded, not disabled', async () => {
  // The count came down; the behaviour did not go away. `no` or `always` would
  // both pass a naive "the count is not 5" check.
  const args = await start(HTTP_APP.slug);
  assert.match(flag(args, '--restart'), /^--restart=on-failure:/);
});

// ===========================================================================
// LIVE: what the kernel actually enforces
// ===========================================================================

const LIVE = `crane-resflags-${process.pid}`;
const live = [];

const dk = (args, timeout = 60000) =>
  execFileAsync(REAL_DOCKER, args, { timeout }).then(r => r.stdout.trim());

after(async () => {
  if (!REAL_DOCKER) return;
  for (const name of live) await dk(['rm', '-f', name], 20000).catch(() => {});
});

async function runLive(name, extraArgs) {
  live.push(name);
  await dk(['rm', '-f', name]).catch(() => {});
  await dk(['run', '-d', '--name', name, ...extraArgs, 'alpine:3', 'sleep', '120']);
  return name;
}

const inspect = (name, tpl) => dk(['inspect', '-f', tpl, name]);

test('LIVE: the emitted argv gives the container a cgroup with NO swap, and the control shows omission does not',
  { skip: noDocker }, async () => {
    // The measurement the flag exists for, with its control. Both containers are
    // identical except for the one flag, so the difference cannot be anything
    // else. Read from the container's own cgroup, not from HostConfig: what the
    // kernel enforces is the claim, and HostConfig is only Docker's record of
    // what it was asked for.
    const args = await start(HTTP_APP.slug, { memoryMb: 512 });
    const mem = flag(args, '--memory=');
    const swap = flag(args, '--memory-swap=');

    const paired = await runLive(`${LIVE}-paired`, [mem, swap]);
    const omitted = await runLive(`${LIVE}-omitted`, [mem]);

    const cg = (n, f) => dk(['exec', n, 'cat', `/sys/fs/cgroup/${f}`]);

    assert.equal(await cg(paired, 'memory.max'), String(512 * 1024 * 1024));
    assert.equal(await cg(paired, 'memory.swap.max'), '0',
      'the container AppCrane starts can still swap past its RAM limit');

    // The control. If this also read 0, the paired result would prove nothing —
    // it would just mean this host has no swap for anyone.
    assert.notEqual(await cg(omitted, 'memory.swap.max'), '0',
      'omitting --memory-swap produced no swap budget either, so the paired ' +
      'result above is a property of this host and not of the flag');
    assert.equal(await inspect(omitted, '{{.HostConfig.MemorySwap}}'), String(1024 * 1024 * 1024),
      'Docker no longer defaults the combined ceiling to 2x memory; the reason ' +
      'this flag is passed explicitly needs re-measuring');
    assert.equal(await inspect(paired, '{{.HostConfig.MemorySwap}}'), String(512 * 1024 * 1024));
  });

test('LIVE: the emitted restart flag is recorded by the daemon as on-failure, max 2 retries',
  { skip: noDocker }, async () => {
    // The argv token is a string until a daemon parses it. This is the parse.
    const args = await start(HTTP_APP.slug);
    const name = await runLive(`${LIVE}-restart`, [flag(args, '--restart')]);
    assert.equal(await inspect(name, '{{.HostConfig.RestartPolicy.Name}}'), 'on-failure');
    assert.equal(await inspect(name, '{{.HostConfig.RestartPolicy.MaximumRetryCount}}'), '2');
  });
