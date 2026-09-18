import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

// The deploy critical path: what a deploy waits for, and in which order.
//
// Two independent claims, both measured off a recording `docker` shim rather
// than read out of the source:
//
//  1. THE SUPPLY-CHAIN VERIFICATION OVERLAPS THE BUILD. It is a GitHub round
//     trip whose answer the build does not consume. It used to be awaited the
//     moment the clone finished, so its latency was pure serial cost on every
//     deploy. It now runs concurrently and is awaited at the container gate.
//     The proof is timestamps: the branch read must still be IN FLIGHT when
//     `docker build` is spawned. Restore the old `await` and that assertion
//     goes red, because the fetch will have settled before the build starts.
//
//  2. NOTHING WEAKENED. A verification failure still aborts the deploy with the
//     verifier's own message, the deployment still lands 'failed', and — the
//     part concurrency could plausibly have broken — NO CONTAINER IS EVER
//     STARTED. Not the ephemeral `docker run --rm` the pre-flight entry check
//     uses, not `docker stop` against the version currently serving traffic,
//     not `docker run` for the new one. The image gets built (that work is
//     wasted on a failed deploy, and was before too); nothing runs.
//
// And the BuildKit decision (item 2), which is about the environment `docker
// build` is spawned with rather than about ordering.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-critpath-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

// How long the shimmed build sleeps, and how long the shimmed GitHub branch
// read takes. The build must outlast the fetch for the overlap to be visible at
// all; both are far above the millisecond noise floor of a `spawn`.
// The fetch must still be in flight when `docker build` is spawned, and the
// deployer does real work in between (icon pickup, manifest read, dist check,
// Dockerfile generation). Under the full suite — 23 test files in parallel —
// that gap was measured at 518ms, so the fetch is given several times that.
const BUILD_SLEEP_MS = 1500;
const FETCH_DELAY_MS = 2500;

const SHIM_DIR = join(ROOT, 'bin');
const DOCKER_EVENTS = join(ROOT, 'docker-events.jsonl');
mkdirSync(SHIM_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// A `docker` that records WHEN, not just WHAT
// ---------------------------------------------------------------------------
// CommonJS: the file is named `docker` with no extension, so Node parses it as
// CJS and an `import` here would be a syntax error at spawn time — surfacing as
// an unexplained docker failure rather than as a test error.
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const { appendFileSync } = require('fs');
const argv = process.argv.slice(2);
const t0 = Date.now();
let code = 0, out = '0123456789abcdef\\n';

if (argv[0] === 'build') {
  // A build that takes real wall-clock time, so "did the verification overlap
  // it?" is a question timestamps can answer.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${BUILD_SLEEP_MS});
  out = 'Successfully built deadbeef\\n';
} else if (argv[0] === 'version') {
  out = '29.0.0\\n';
} else if (argv[0] === 'image' && argv[1] === 'inspect') {
  // Must MISS, or buildImageIfNeeded answers from cache and never builds.
  code = 1; out = '';
} else if (argv[0] === 'inspect') {
  code = 1; out = '';
} else if (argv[0] === 'network' && argv[1] === 'inspect') {
  out = 'false|172.20.0.0/16\\n';
} else if (argv[0] === 'images' || argv[0] === 'ps') {
  out = '';
}

appendFileSync(process.env.CRANE_DOCKER_EVENTS, JSON.stringify({
  verb: argv[0], sub: argv[1] || null, argv, t0, t1: Date.now(),
  buildkit: process.env.DOCKER_BUILDKIT === undefined ? null : process.env.DOCKER_BUILDKIT,
}) + '\\n');

process.stdout.write(out);
process.exit(code);
`, { mode: 0o755 });

// ---------------------------------------------------------------------------
// A `git` that clones a working tree instead of reaching the network
// ---------------------------------------------------------------------------
const CLONE_SHA = 'ab'.repeat(20);
writeFileSync(join(SHIM_DIR, 'git'), `#!/usr/bin/env node
const { mkdirSync, writeFileSync } = require('fs');
const { join } = require('path');
const argv = process.argv.slice(2);
const SHA = '${CLONE_SHA}';

if (argv[0] === 'clone') {
  const dir = argv[argv.length - 1];
  mkdirSync(dir, { recursive: true });
  // Enough for the deployer to treat this as a Node app with a declared entry:
  // package.json makes isNodeApp true (so the generator runs instead of
  // Nixpacks), deployhub.json's be.entry makes the pre-flight check run — and
  // the pre-flight check is a \`docker run --rm\`, which is exactly the
  // container start a failed verification must prevent.
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'critpath', version: '1.0.0', main: 'server.js' }));
  writeFileSync(join(dir, 'deployhub.json'), JSON.stringify({ version: '1.0.0', port: 3000, be: { entry: 'node server.js' } }));
  writeFileSync(join(dir, 'server.js'), 'require("http").createServer((q,s)=>s.end("ok")).listen(3000);\\n');
  process.exit(0);
}
if (argv[0] === '-C') {
  if (argv[2] === 'rev-parse') { process.stdout.write((argv[3] === '--short' ? SHA.slice(0, 7) : SHA) + '\\n'); process.exit(0); }
  if (argv[2] === 'log') { process.stdout.write('critpath fixture commit\\n'); process.exit(0); }
}
process.exit(0);
`, { mode: 0o755 });

process.env.CRANE_DOCKER_EVENTS = DOCKER_EVENTS;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const dockerEvents = () => (existsSync(DOCKER_EVENTS) ? readFileSync(DOCKER_EVENTS, 'utf8') : '')
  .split('\n').filter(Boolean).map((l) => JSON.parse(l));
const clearDockerEvents = () => { if (existsSync(DOCKER_EVENTS)) rmSync(DOCKER_EVENTS); };

// Every docker verb that runs, stops or destroys a container. `build` is
// deliberately absent: a failed deploy is allowed to have built an image.
const CONTAINER_VERBS = new Set(['run', 'create', 'start', 'stop', 'rm', 'kill', 'restart']);
const containerEvents = () => dockerEvents().filter((e) => CONTAINER_VERBS.has(e.verb));

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { deployApp } = await import('../server/services/deployer.js');
const { startCommitVerification } = await import('../server/services/supplyChainGate.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

db.prepare("INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled','1') ON CONFLICT(key) DO UPDATE SET value='1'").run();

// ---------------------------------------------------------------------------
// GitHub, at the fetch boundary, with timestamps
// ---------------------------------------------------------------------------
let fetchWindows = [];
let branchSha = CLONE_SHA;
const realFetch = global.fetch;
global.fetch = async (url, init) => {
  const u = String(url);
  // Only the GitHub branch read is stubbed. Everything else — most importantly
  // the deploy's own health probe against the loopback servers below — goes to
  // the real fetch, or the deploy would fail for a reason this file invented.
  if (!/^https:\/\/api\.github\.com\/repos\/.*\/branches\//.test(u)) {
    return realFetch(url, init);
  }
  const w = { t0: Date.now(), t1: null };
  fetchWindows.push(w);
  await new Promise((r) => setTimeout(r, FETCH_DELAY_MS));
  w.t1 = Date.now();
  return { ok: true, status: 200, statusText: '200', text: async () => '', json: async () => ({ commit: { sha: branchSha } }) };
};
after(() => { global.fetch = realFetch; });

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

// ===========================================================================
// 1. The gate itself
// ===========================================================================

describe('supplyChainGate', () => {
  test('a verification failure is rethrown UNCHANGED, not swallowed or rewrapped', async () => {
    // The single most important property. A concurrent path that catches its
    // own rejection to keep the pipeline moving is a fail-open verifier wearing
    // a concurrency label, and it would look identical in a passing deploy.
    const boom = new Error('Supply-chain verify FAILED: local HEAD aaa… does not match GitHub');
    const gate = startCommitVerification({
      app: {}, releaseDir: '/x', branch: 'main', appendLog: () => {},
      verify: async () => { throw boom; },
    });
    await assert.rejects(() => gate.settle(), (e) => {
      assert.equal(e, boom, 'the gate must rethrow the verifier\'s own Error object, not a copy or a wrapper');
      return true;
    });
  });

  test('the verifier\'s deploy-log lines survive, byte for byte, in order', async () => {
    const written = [];
    const gate = startCommitVerification({
      app: {}, releaseDir: '/x', branch: 'main', appendLog: (l) => written.push(l),
      verify: async (_a, _d, _b, appendLog) => {
        appendLog('Supply-chain verify: OK (HEAD abcdef0 matches GitHub o/r@main).');
        appendLog('second line');
        return { verified: true };
      },
    });
    assert.deepEqual(written, [], 'lines must be buffered, not interleaved into streamed build output');
    const r = await gate.settle();
    assert.equal(r.verified, true);
    assert.deepEqual(written, [
      'Supply-chain verify: OK (HEAD abcdef0 matches GitHub o/r@main).',
      'second line',
    ]);
  });

  test('flush() writes the lines but never throws — it must not mask a build failure', async () => {
    const written = [];
    const gate = startCommitVerification({
      app: {}, releaseDir: '/x', branch: 'main', appendLog: (l) => written.push(l),
      verify: async (_a, _d, _b, appendLog) => {
        appendLog('Supply-chain verify: NOT VERIFIED (github-unreachable).');
        throw new Error('Supply-chain verify FAILED: could not confirm');
      },
    });
    await gate.flush();
    assert.deepEqual(written, ['Supply-chain verify: NOT VERIFIED (github-unreachable).']);
  });

  test('lines are flushed exactly once even if settle() and flush() both run', async () => {
    // The deploy's failure handler calls flush() after settle() may already have
    // thrown. A double flush would duplicate every verify line in the log.
    const written = [];
    const gate = startCommitVerification({
      app: {}, releaseDir: '/x', branch: 'main', appendLog: (l) => written.push(l),
      verify: async (_a, _d, _b, appendLog) => { appendLog('once'); throw new Error('nope'); },
    });
    await assert.rejects(() => gate.settle());
    await gate.flush();
    assert.deepEqual(written, ['once']);
  });

  test('a rejection is observed immediately, so it can never surface as an unhandled rejection', async () => {
    // Between start and settle the promise is unawaited. If nothing had a
    // handler attached, Node's default --unhandled-rejections=throw would kill
    // the process mid-build. Give it a full turn of the loop to blow up.
    const gate = startCommitVerification({
      app: {}, releaseDir: '/x', branch: 'main', appendLog: () => {},
      verify: async () => { throw new Error('early rejection'); },
    });
    await new Promise((r) => setTimeout(r, 50));
    await assert.rejects(() => gate.settle(), /early rejection/);
  });
});

// ===========================================================================
// 2. A real deploy: overlap, and the container gate
// ===========================================================================

describe('a real deploy', () => {
  let userId;
  let slot = null;
  let ports = null;
  const servers = [];

  const startHealthServer = (port) => new Promise((res) => {
    const s = http.createServer((_req, out) => {
      out.writeHead(200, { 'content-type': 'application/json' });
      out.end(JSON.stringify({ status: 'ok', version: '1.0.0' }));
    });
    s.on('error', () => res(null));
    s.listen(port, '127.0.0.1', () => res(s));
  });

  before(async () => {
    // Searched for, not hardcoded: deployApp derives the host port from
    // apps.slot, so a fixed slot fails with EADDRINUSE on a concurrent run.
    for (let s = 13300; s < 13400 && slot === null; s++) {
      const p = getPortsForSlot(s);
      const sand = await startHealthServer(p.sand_be);
      if (!sand) continue;
      const prod = await startHealthServer(p.prod_be);
      if (!prod) { sand.close(); continue; }
      slot = s; ports = p; servers.push(sand, prod);
    }
    assert.ok(slot !== null, 'no slot with both ports free');
    userId = db.prepare(
      "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','cp@example.com','platform_admin','unused',1,'human')",
    ).run().lastInsertRowid;
  });

  after(() => {
    for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); }
  });

  async function runDeploy(slug) {
    db.prepare(
      'INSERT INTO apps (name,slug,slot,source_type,github_url,branch,container_port,health_path) '
      + "VALUES (?,?,?,'github','https://github.com/example-owner/example-repo','main',3000,'/health')",
    ).run(slug, slug, slot);
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
    const depId = db.prepare(
      "INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)",
    ).run(app.id, userId).lastInsertRowid;
    clearDockerEvents();
    fetchWindows = [];
    let error = null;
    try { await deployApp(depId, app, 'sandbox', ports, {}); } catch (e) { error = e; }
    const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(depId);
    db.prepare('DELETE FROM apps WHERE id = ?').run(app.id);
    return { row, error, events: dockerEvents() };
  }

  test('the verification is still IN FLIGHT when docker build is spawned', async () => {
    branchSha = CLONE_SHA;
    const { row, events } = await runDeploy('cp-overlap');
    assert.equal(row.status, 'live', `deploy did not go live:\n${row.log}`);

    const build = events.find((e) => e.verb === 'build');
    assert.ok(build, `no docker build ran: ${JSON.stringify(events.map((e) => e.verb))}`);
    assert.equal(fetchWindows.length, 1, 'expected exactly one GitHub branch read');
    const [v] = fetchWindows;

    assert.ok(v.t0 < build.t0,
      `the verification must START before the build is spawned (verify ${v.t0}, build ${build.t0})`);
    assert.ok(v.t1 > build.t0,
      'the verification had already FINISHED before docker build was spawned — it is still serial. '
      + `verify ${v.t0}..${v.t1}, build spawned ${build.t0}`);

    const overlapMs = Math.min(v.t1, build.t1) - Math.max(v.t0, build.t0);
    assert.ok(overlapMs > 0, `no overlap at all: ${overlapMs}ms`);
    // Deliberately NOT asserted: a minimum FRACTION of the verification hidden.
    // How much overlaps is a property of the machine — the gap between starting
    // the verification and spawning the build is whatever the deployer's own
    // work costs under whatever load, measured from 30ms idle to 518ms under the
    // full parallel suite. Pinning a fraction here makes the file fail on a busy
    // CI box while the thing it is meant to protect is intact. The property that
    // IS the change is `v.t1 > build.t0` above: the verification had not settled
    // when the build was spawned. Restore the old serial await and that is false
    // no matter how fast or slow the machine is.
    console.log(`  [measured] verify ${v.t1 - v.t0}ms, build ${build.t1 - build.t0}ms, overlap ${overlapMs}ms`);
  });

  test('a SHA mismatch aborts the deploy, and no container is touched', async () => {
    branchSha = 'cd'.repeat(20);
    try {
      const { row, error, events } = await runDeploy('cp-mismatch');

      assert.ok(error, 'a mismatched commit deployed successfully');
      assert.match(error.message, /Supply-chain verify FAILED/,
        `the abort did not carry the verifier's message: ${error.message}`);
      assert.equal(row.status, 'failed', 'the deployment row must record the failure');
      assert.match(row.log, /Supply-chain verify FAILED/,
        `the verifier's finding is missing from the deploy log:\n${row.log}`);

      // The claim concurrency could plausibly have broken.
      assert.deepEqual(containerEvents().map((e) => e.argv.join(' ')), [],
        'a failed verification let docker touch a container — the gate is not ahead of '
        + 'preflightEntryCheck / dockerStop / dockerStart');

      // …and it really did get as far as building, which is what makes the
      // previous assertion meaningful rather than vacuous.
      assert.ok(events.some((e) => e.verb === 'build'),
        'the build never ran, so "no container started" proves nothing about the gate');
    } finally {
      branchSha = CLONE_SHA;
    }
  });
});

// ===========================================================================
// 3. BuildKit (item 2)
// ===========================================================================

describe('the build environment', () => {
  test('docker build is spawned with DOCKER_BUILDKIT=1', async () => {
    // AppCrane used to set nothing, so the builder was whatever the host CLI
    // happened to default to — BuildKit on modern Docker Desktop, the classic
    // builder on an older Linux daemon. Two operators on two hosts got two
    // different builders from one platform. The shim records the variable it was
    // spawned with; this asserts the platform decided rather than inherited.
    const { buildImage } = await import('../server/services/docker.js');
    const ctx = join(ROOT, 'bkctx');
    mkdirSync(ctx, { recursive: true });
    writeFileSync(join(ctx, 'Dockerfile'), 'FROM scratch\n');
    clearDockerEvents();
    await buildImage({ slug: 'bk', env: 'sandbox', contextDir: ctx, commitHash: 'abc1234', onLog: () => {} });
    const build = dockerEvents().find((e) => e.verb === 'build');
    assert.ok(build, 'no docker build recorded');
    assert.equal(build.buildkit, '1',
      `docker build inherited DOCKER_BUILDKIT=${JSON.stringify(build.buildkit)} instead of being told`);
  });

  test('APPCRANE_DOCKER_BUILDKIT overrides the default, so an operator is not stuck with it', async () => {
    const { buildImage } = await import('../server/services/docker.js');
    const ctx = join(ROOT, 'bkctx2');
    mkdirSync(ctx, { recursive: true });
    writeFileSync(join(ctx, 'Dockerfile'), 'FROM scratch\n');
    process.env.APPCRANE_DOCKER_BUILDKIT = '0';
    try {
      clearDockerEvents();
      await buildImage({ slug: 'bk2', env: 'sandbox', contextDir: ctx, commitHash: 'abc1235', onLog: () => {} });
      const build = dockerEvents().find((e) => e.verb === 'build');
      assert.equal(build.buildkit, '0',
        'the documented override is inert — an operator on a daemon where BuildKit misbehaves has no way out');
    } finally {
      delete process.env.APPCRANE_DOCKER_BUILDKIT;
    }
  });

  test('nothing parses build stdout for correctness — it is display and error text only', () => {
    // The reason the builder can be changed at all. BuildKit's progress output
    // (#1 [internal] load build definition) looks nothing like the classic
    // builder's (Step 1/9 : FROM node:22-alpine). If any decision were made by
    // matching on those lines, switching builders would change behaviour rather
    // than just appearance.
    const src = readFileSync(new URL('../server/services/docker.js', import.meta.url), 'utf8');
    const build = src.slice(src.indexOf('export async function buildImage'));
    const body = build.slice(0, build.indexOf('\n}\n') + 3);
    for (const pattern of [/Step \d/, /Successfully built/, /\bmatch\(/, /\.test\(/, /includes\(['"]/, /JSON\.parse/]) {
      assert.doesNotMatch(body, pattern,
        `buildImage inspects its own build output (${pattern}) — the builder is then load-bearing, not cosmetic`);
    }
  });
});
