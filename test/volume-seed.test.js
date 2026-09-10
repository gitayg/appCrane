import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync,
} from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import http from 'node:http';

const execFileAsync = promisify(execFile);

// Seeding a NEW bind mount from the image's own content.
//
// The measured fact this whole file hangs off, re-proved live in section 3
// below rather than taken on trust: Docker populates a NAMED volume from the
// image the first time it is used, and a BIND mount MASKS whatever the image
// put there. AppCrane mounts declared volume paths as bind mounts, so before
// this change, declaring '/config' on bookstack or '/var/lib/odoo' on odoo —
// the entire point of the volume_paths column — handed the first boot an EMPTY
// directory where the image had put its default configuration.
//
// Three claims have to hold, and only the daemon can settle the first two:
//
//   1. A new mount comes up carrying the image's content.
//   2. A mount that already has content is NEVER written to. That is the app's
//      live state, and getting this wrong turns a data-loss bug into a
//      data-destruction bug.
//   3. A non-root image can write into what was seeded for it.
//
// Section 3 runs a real container against a real image built locally (no
// registry pull: this box has hit Docker Hub's anonymous rate limit) and proves
// 1 and 2 with a negative control — the same image, the same mount, seeding
// switched off — so a pass cannot come from the content having been there
// anyway.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-seed-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker'],
    { encoding: 'utf8' }).trim() || null;
  if (REAL_DOCKER) execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'],
    { timeout: 15000, stdio: 'pipe' });
} catch (_) {
  REAL_DOCKER = null;
}
const REAL_PATH = process.env.PATH;
const liveSkip = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb } = await import('../server/db.js');
initDb();

const { seedNewVolumeMounts, mountIsEmpty, MOUNT_OWNER } =
  await import('../server/services/volumeSeeder.js');
const { copyFromImage, startApp, stopApp } = await import('../server/services/docker.js');
const spec = await import('../server/services/containerRuntimeSpec.js');

const scratch = (name) => {
  const d = join(process.env.DATA_DIR, 'scratch', name);
  rmSync(d, { recursive: true, force: true });
  mkdirSync(d, { recursive: true });
  return d;
};

// ===========================================================================
// 1. The once-only gate, as a decision about the disk
// ===========================================================================

describe('when a mount counts as new', () => {
  test('a directory that does not exist, and one that exists empty, are the same answer', () => {
    const d = scratch('gate');
    assert.equal(mountIsEmpty(join(d, 'never-created')), true);
    assert.equal(mountIsEmpty(d), true, 'an existing empty directory is a mount nothing has written to yet');
  });

  test('anything at all in the directory means "not new"', () => {
    const d = scratch('gate-content');
    writeFileSync(join(d, '.hidden'), 'x');
    assert.equal(mountIsEmpty(d), false,
      'a dotfile is content. readdir must not be filtered — an image that seeds only a dotfile ' +
      'would otherwise be re-seeded over the app\'s state on every deploy');
    rmSync(join(d, '.hidden'));
    mkdirSync(join(d, 'subdir'));
    assert.equal(mountIsEmpty(d), false);
  });
});

describe('the seeding policy', () => {
  /** A recording stand-in for docker.copyFromImage, so the POLICY can be
   *  measured without a daemon: which mounts were offered for copying at all is
   *  the load-bearing question, and the answer must be "only the empty ones". */
  const recorder = (impl = () => []) => {
    const calls = [];
    const fn = async (args) => { calls.push(args); return impl(args); };
    fn.calls = calls;
    return fn;
  };

  test('a mount that already has content is never even offered to the copier', async () => {
    const live = scratch('policy-live');
    const fresh = scratch('policy-fresh');
    writeFileSync(join(live, 'app-state.db'), 'REAL-STATE');

    const copy = recorder(({ copies }) => copies.map((c) => ({ ...c, found: false })));
    const res = await seedNewVolumeMounts({
      image: 'img:1',
      volumes: [{ host: live, container: '/config' }, { host: fresh, container: '/var/lib/odoo' }],
      copy,
    });

    assert.equal(copy.calls.length, 1);
    assert.deepEqual(copy.calls[0].copies.map((c) => c.containerPath), ['/var/lib/odoo'],
      'the copier must never be handed a mount that holds live state — a copy over it is the ' +
      'data destruction this feature exists to prevent');
    assert.deepEqual(res.occupied, ['/config']);
    assert.equal(readFileSync(join(live, 'app-state.db'), 'utf8'), 'REAL-STATE');
    assert.match(res.log.join('\n'), /\/config already holds data/);
  });

  test('every mount already populated means no docker work at all', async () => {
    const d = scratch('policy-all-live');
    writeFileSync(join(d, 'x'), 'x');
    const copy = recorder();
    const res = await seedNewVolumeMounts({ image: 'img:1', volumes: [{ host: d, container: '/config' }], copy });
    assert.equal(copy.calls.length, 0, 'no container should be created when there is nothing to seed');
    assert.deepEqual(res.seeded, []);
  });

  test('an image with nothing at the path is not an error — the mount stays empty', async () => {
    const d = scratch('policy-absent');
    const copy = recorder(({ copies }) => copies.map((c) => ({ ...c, found: false, reason: 'Could not find the file' })));
    const res = await seedNewVolumeMounts({ image: 'img:1', volumes: [{ host: d, container: '/config' }], copy });
    assert.deepEqual(res.absent, ['/config']);
    assert.deepEqual(res.seeded, []);
    assert.deepEqual(readdirSync(d), []);
    assert.match(res.log.join('\n'), /ships nothing there/);
  });

  test('a directory the image ships EMPTY is reported as absent, not as seeded', async () => {
    // `docker cp` of an empty directory succeeds and copies nothing. Reporting
    // that as "seeded" would put a claim about content in the deploy log where
    // there is none.
    const d = scratch('policy-empty-src');
    const copy = recorder(({ copies }) => copies.map((c) => ({ ...c, found: true })));
    const res = await seedNewVolumeMounts({ image: 'img:1', volumes: [{ host: d, container: '/config' }], copy });
    assert.deepEqual(res.seeded, []);
    assert.deepEqual(res.absent, ['/config']);
  });

  test('a seed that fails throws, and leaves the mount empty rather than half-written', async () => {
    // The failure policy, and the reason it is not "log it and carry on": a
    // container started over a half-copied /config looks exactly like a healthy
    // first boot, and the NEXT deploy would see a non-empty directory and treat
    // the wreckage as the app's state forever.
    const d = scratch('policy-fail');
    const copy = async ({ copies }) => {
      writeFileSync(join(copies[0].destDir, 'half-written.conf'), 'partial');
      throw new Error('write /var/lib/docker: no space left on device');
    };
    await assert.rejects(
      () => seedNewVolumeMounts({ image: 'img:1', volumes: [{ host: d, container: '/config' }], copy }),
      /VOLUME_SEED_FAILED.*no space left on device/s,
    );
    assert.deepEqual(readdirSync(d), [],
      'the partial copy must be cleared, so the next deploy still sees an empty mount and retries');
  });
});

// ===========================================================================
// 2. The docker verbs, and the ones that must NOT appear
// ===========================================================================

describe('the argv seeding issues', () => {
  const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
  const ARGV_LOG = join(process.env.DATA_DIR, 'shim-argv.log');
  mkdirSync(SHIM_DIR, { recursive: true });
  // CommonJS on purpose: the file has no extension, so Node parses it as CJS
  // and an `import` here would be a syntax error at spawn time.
  const shim = (extra = '') =>
    '#!/usr/bin/env node\n' +
    'const { appendFileSync } = require("fs");\n' +
    'const argv = process.argv.slice(2);\n' +
    'appendFileSync(process.env.CRANE_SEED_LOG, JSON.stringify(argv) + "\\n");\n' +
    extra +
    'process.stdout.write("0123456789abcdef\\n");\n';
  writeFileSync(join(SHIM_DIR, 'docker'), shim(), { mode: 0o755 });
  writeFileSync(join(SHIM_DIR, 'chown'), shim(), { mode: 0o755 });
  process.env.CRANE_SEED_LOG = ARGV_LOG;

  const calls = () => (existsSync(ARGV_LOG)
    ? readFileSync(ARGV_LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : []);

  before(() => { process.env.PATH = `${SHIM_DIR}:${REAL_PATH}`; });
  after(() => { process.env.PATH = REAL_PATH; });

  test('seeding never issues a `docker run` or a `docker pull`', async () => {
    rmSync(ARGV_LOG, { force: true });
    const a = scratch('argv-a');
    const b = scratch('argv-b');
    await seedNewVolumeMounts({
      image: 'odoo@sha256:abc',
      volumes: [{ host: a, container: '/data' }, { host: b, container: '/var/lib/odoo' }],
    });
    const verbs = calls().filter((c) => c[0] !== '-R').map((c) => c[0]);
    assert.deepEqual(verbs, ['create', 'cp', 'cp', 'rm'],
      'a `docker run` here would start the image being seeded FROM — with no mounts, no limits and ' +
      'no network policy — and a `docker pull` would re-resolve a tag the deploy has already pinned. ' +
      'test/image-deploy.test.js asserts a deploy issues exactly one of each.');
    assert.ok(!verbs.includes('run') && !verbs.includes('pull'));
  });

  test('the create cannot pull, and the rm cannot leak the image\'s anonymous volume', async () => {
    rmSync(ARGV_LOG, { force: true });
    const d = scratch('argv-flags');
    await seedNewVolumeMounts({ image: 'img:1', volumes: [{ host: d, container: '/config' }] });
    const create = calls().find((c) => c[0] === 'create');
    const rm = calls().find((c) => c[0] === 'rm');
    assert.ok(create.includes('--pull') && create[create.indexOf('--pull') + 1] === 'never',
      '--pull never is what makes "no second registry round-trip" a guarantee instead of a hope');
    assert.equal(create.at(-1), 'img:1', 'the image is the last argument, after every flag');
    assert.ok(rm.includes('-fv'),
      'measured: an image declaring VOLUME gets an anonymous volume at `docker create` time, and ' +
      '`docker rm -f` leaves it dangling — one leaked volume per seeded deploy');
  });

  test('one throwaway container serves every mount, and its name is unique per call', async () => {
    rmSync(ARGV_LOG, { force: true });
    const dirs = ['n1', 'n2', 'n3'].map(scratch);
    await seedNewVolumeMounts({
      image: 'img:1',
      volumes: dirs.map((h, i) => ({ host: h, container: `/m${i}` })),
    });
    const names = calls().filter((c) => c[0] === 'create').map((c) => c[c.indexOf('--name') + 1]);
    assert.equal(names.length, 1, 'docker create is the expensive part; one container serves every copy');
    const first = names[0];
    rmSync(ARGV_LOG, { force: true });
    await seedNewVolumeMounts({ image: 'img:1', volumes: [{ host: scratch('n4'), container: '/m0' }] });
    const second = calls().find((c) => c[0] === 'create')[calls().find((c) => c[0] === 'create').indexOf('--name') + 1];
    assert.notEqual(first, second, 'a fixed name collides between two concurrent deploys');
  });

  test('a cp failure that is NOT "the image has nothing there" throws', async () => {
    // The classification in docker.js is the whole failure policy, and it is the
    // one place where getting it wrong is INVISIBLE: read a disk-full or a
    // permission error as "the image ships nothing at that path" and seeding
    // reports success over an empty mount — which is the exact outcome this
    // feature exists to prevent, reached from the other direction.
    //
    // Found by mutation: widening IMAGE_PATH_ABSENT to match every message left
    // the whole suite green, because the failure tests above inject their own
    // copier and never reach this code. This one goes through copyFromImage.
    rmSync(ARGV_LOG, { force: true });
    const d = scratch('argv-cp-hard-fail');
    writeFileSync(join(SHIM_DIR, 'docker'), shim(
      'if (argv[0] === "cp") { process.stderr.write("write /var/lib/docker: no space left on device\\n"); process.exit(1); }\n',
    ), { mode: 0o755 });
    try {
      await assert.rejects(
        () => copyFromImage({ image: 'img:1', copies: [{ containerPath: '/config', destDir: d }] }),
        /no space left on device/,
        'a copy that failed for a real reason must not be reported as "the image has nothing there"',
      );
      // ...and the throwaway container is still cleaned up on the way out.
      assert.ok(calls().some((c) => c[0] === 'rm'), 'the container must be removed even when a copy fails');
    } finally {
      writeFileSync(join(SHIM_DIR, 'docker'), shim(), { mode: 0o755 });
    }
  });

  test('the daemon\'s "no such path" messages ARE classified as absent', async () => {
    // The other side of the same boundary: if everything threw, an image that
    // simply ships no /config could never be deployed at all.
    rmSync(ARGV_LOG, { force: true });
    const d = scratch('argv-cp-absent');
    for (const msg of [
      'Error response from daemon: Could not find the file /config/. in container x',
      'Error response from daemon: lstat /config/.: not a directory',
    ]) {
      writeFileSync(join(SHIM_DIR, 'docker'), shim(
        `if (argv[0] === "cp") { process.stderr.write(${JSON.stringify(msg)} + "\\n"); process.exit(1); }\n`,
      ), { mode: 0o755 });
      const out = await copyFromImage({ image: 'img:1', copies: [{ containerPath: '/config', destDir: d }] });
      assert.deepEqual(out.map((r) => r.found), [false], `should be absent, not an error: ${msg}`);
    }
    writeFileSync(join(SHIM_DIR, 'docker'), shim(), { mode: 0o755 });
  });

  test('the seeded directory is chowned, with -R, after the copy', async () => {
    // Ownership is not decoration. Measured on a real Linux filesystem: a
    // uid-1000 container writing into a directory of root-owned seeded files
    // gets "Permission denied"; after `chown -R 1000:1000` the identical write
    // succeeds. `docker cp` writes as the user running AppCrane (measured: uid
    // 502 here, NOT the image's uid), so without this an image that drops
    // privileges cannot write what was just seeded for it.
    rmSync(ARGV_LOG, { force: true });
    const d = scratch('argv-chown');
    // The docker shim copies nothing, so put content there to stand in for what
    // `docker cp` would have written — the chown only fires on a mount that
    // actually received content.
    writeFileSync(join(SHIM_DIR, 'docker'), shim(
      'if (argv[0] === "cp") { require("fs").writeFileSync(argv[2] + "/seeded.conf", "x"); }\n',
    ), { mode: 0o755 });
    const res = await seedNewVolumeMounts({ image: 'img:1', volumes: [{ host: d, container: '/config' }] });
    writeFileSync(join(SHIM_DIR, 'docker'), shim(), { mode: 0o755 });

    assert.deepEqual(res.seeded, ['/config']);
    const chowns = calls().filter((c) => c[0] === '-R');
    assert.deepEqual(chowns, [['-R', MOUNT_OWNER, d]]);
    assert.equal(MOUNT_OWNER, '1000:1000', 'the same ownership deployer.js applies to the mount itself');
    // Order matters: a chown before the copy covers an empty directory.
    const seq = calls().map((c) => c[0]);
    assert.ok(seq.indexOf('cp') < seq.indexOf('-R'), 'the chown must come after the files exist');
  });
});

// ===========================================================================
// 3. The daemon. A real image, a real container, and the negative control.
// ===========================================================================

describe('LIVE', { skip: liveSkip }, () => {
  const SUFFIX = `${process.pid}${Date.now().toString(36)}`;
  const IMAGE = `crane-seed-test-${SUFFIX}:v1`;
  const BASE = 'alpine:3.20';
  const SLUG = `seed-${SUFFIX}`;
  const NAME = `appcrane-${SLUG}-production`;

  const dk = (args, timeout = 180000) =>
    execFileAsync(REAL_DOCKER, args, { timeout }).then((r) => r.stdout.trim());

  const freePort = () => new Promise((res, rej) => {
    const s = net.createServer();
    s.once('error', rej);
    // Loopback explicitly: a hostless listen(0) binds [::] and can silently
    // collide with a Docker-published port.
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
  });

  const shared = join(process.env.DATA_DIR, 'apps', SLUG, 'production', 'shared');
  // Straight through the production resolver, so the host layout under test is
  // the one config backup archives, not a layout invented here.
  const { mounts } = spec.resolveVolumeMounts({ sharedDir: shared, paths: ['/seeded'] });
  const SEEDED_HOST = mounts[1].host;

  let problem = null;
  before(async () => {
    process.env.PATH = REAL_PATH;
    try {
      await dk(['image', 'inspect', BASE], 30000);
    } catch (_) {
      problem = `${BASE} is not present locally and this box has been hitting Docker Hub's ` +
        'anonymous pull limit — refusing to pull rather than reporting a rate-limit as a failure';
      return;
    }
    // Built locally from a base that is already here: no registry round-trip.
    // The image ships content at /seeded, DECLARES it as a VOLUME (which is what
    // makes the named-volume/bind-mount difference visible at all) and runs as
    // uid 1000, so the non-root write is exercised rather than assumed.
    const ctx = scratch('fixture');
    writeFileSync(join(ctx, 'Dockerfile'),
      `FROM ${BASE}\n` +
      'RUN mkdir -p /seeded/sub /empty-in-image \\\n' +
      ' && echo IMAGE-CONTENT > /seeded/from-image.txt \\\n' +
      ' && echo NESTED > /seeded/sub/nested.txt \\\n' +
      ' && adduser -D -u 1000 appuser \\\n' +
      ' && chown -R 1000:1000 /seeded\n' +
      'VOLUME /seeded\n' +
      'USER appuser\n');
    try {
      await dk(['build', '-q', '-t', IMAGE, ctx], 300000);
    } catch (e) {
      problem = `could not build the fixture image: ${String(e.message).split('\n')[0].slice(0, 160)}`;
    }
  });

  after(async () => {
    await dk(['rm', '-f', NAME], 30000).catch(() => {});
    await dk(['image', 'rm', '-f', IMAGE], 60000).catch(() => {});
  });

  const launch = async () => startApp({
    slug: SLUG, env: 'production', image: IMAGE, hostPort: await freePort(),
    command: ['sleep', '600'], memoryMb: 256, cpus: 0.5, volumes: mounts,
  });

  test('CONTROL: an unseeded bind mount masks what the image ships there', async (t) => {
    if (problem) return t.skip(problem);
    // The bug, reproduced. Without this the rest of the section proves nothing:
    // a seeded mount that reads IMAGE-CONTENT could just as well be a mount
    // Docker had populated on its own.
    for (const m of mounts) mkdirSync(m.host, { recursive: true });
    await launch();
    const listing = await dk(['exec', NAME, 'sh', '-c', 'ls -A /seeded | wc -l']);
    assert.equal(listing, '0', 'a bind mount of an empty host directory must MASK the image content');
    const cat = await dk(['exec', NAME, 'sh', '-c', 'cat /seeded/from-image.txt 2>&1 || true']);
    assert.ok(!cat.includes('IMAGE-CONTENT'), `expected the image file to be masked, got ${JSON.stringify(cat)}`);
    await stopApp(SLUG, 'production');
  });

  test('a mount seeded before the container starts carries the image\'s content', async (t) => {
    if (problem) return t.skip(problem);
    const res = await seedNewVolumeMounts({ image: IMAGE, volumes: mounts });
    assert.deepEqual(res.seeded, ['/seeded']);
    // /data is in `mounts` too, and this image has nothing there — the
    // "an image with nothing at that path is not an error" case, live.
    assert.deepEqual(res.absent, ['/data']);

    // On the HOST, in the layout config backup archives.
    assert.equal(readFileSync(join(SEEDED_HOST, 'from-image.txt'), 'utf8').trim(), 'IMAGE-CONTENT');
    assert.equal(readFileSync(join(SEEDED_HOST, 'sub', 'nested.txt'), 'utf8').trim(), 'NESTED',
      'nested content must come across too — an image seeds trees, not single files');

    // And inside the container, which is the only view the app has.
    await launch();
    assert.equal(await dk(['exec', NAME, 'cat', '/seeded/from-image.txt']), 'IMAGE-CONTENT');
  });

  test('the non-root image can write into what was seeded for it', async (t) => {
    if (problem) return t.skip(problem);
    assert.equal(await dk(['exec', NAME, 'id', '-u']), '1000',
      'the image must actually be running as a non-root user, or this proves nothing');
    await dk(['exec', NAME, 'sh', '-c', 'echo APP-WROTE-THIS > /seeded/live.txt']);
    assert.equal(readFileSync(join(SEEDED_HOST, 'live.txt'), 'utf8').trim(), 'APP-WROTE-THIS');
  });

  test('a second deploy does not clobber what the first one wrote', async (t) => {
    if (problem) return t.skip(problem);
    // The app edits the file the image seeded, which is what a first-run setup
    // does. If seeding ran again it would be overwritten with IMAGE-CONTENT and
    // look like nothing had happened.
    await dk(['exec', NAME, 'sh', '-c', 'echo USER-EDITED > /seeded/from-image.txt']);
    await stopApp(SLUG, 'production');

    const res = await seedNewVolumeMounts({ image: IMAGE, volumes: mounts });
    assert.deepEqual(res.seeded, [], 'nothing may be seeded on a redeploy');
    assert.ok(res.occupied.includes('/seeded'));

    await launch();
    assert.equal(await dk(['exec', NAME, 'cat', '/seeded/from-image.txt']), 'USER-EDITED',
      'the image would have re-seeded this back to IMAGE-CONTENT');
    assert.equal(await dk(['exec', NAME, 'cat', '/seeded/live.txt']), 'APP-WROTE-THIS');
  });

  test('the throwaway container is gone and its anonymous volume with it', async (t) => {
    if (problem) return t.skip(problem);
    const before = (await dk(['volume', 'ls', '-q'])).split('\n').filter(Boolean).length;
    const fresh = scratch('leak-check');
    await copyFromImage({ image: IMAGE, copies: [{ containerPath: '/seeded', destDir: fresh }] });
    const after = (await dk(['volume', 'ls', '-q'])).split('\n').filter(Boolean).length;
    assert.equal(after, before,
      'this image declares VOLUME /seeded, so `docker create` makes an anonymous volume — measured: ' +
      '`docker rm -f` leaves it dangling and only `docker rm -fv` removes it');
    const left = (await dk(['ps', '-a', '--filter', 'label=appcrane-seed=true', '-q'])).trim();
    assert.equal(left, '', 'the throwaway container must not survive the copy');
  });

  test('an image path that does not exist leaves the mount empty and does not throw', async (t) => {
    if (problem) return t.skip(problem);
    const d = scratch('live-absent');
    const res = await seedNewVolumeMounts({ image: IMAGE, volumes: [{ host: d, container: '/no-such-path' }] });
    assert.deepEqual(res.absent, ['/no-such-path']);
    assert.deepEqual(readdirSync(d), []);
  });

  test('a directory the image ships EMPTY seeds nothing, live', async (t) => {
    if (problem) return t.skip(problem);
    const d = scratch('live-empty');
    const res = await seedNewVolumeMounts({ image: IMAGE, volumes: [{ host: d, container: '/empty-in-image' }] });
    assert.deepEqual(res.seeded, []);
    assert.deepEqual(readdirSync(d), []);
  });

  test('a copy that fails for a DESTINATION reason throws, against the real daemon', async (t) => {
    if (problem) return t.skip(problem);
    // The daemon's own wording for a bad destination ("invalid output path:
    // directory ... does not exist") must not be swallowed as "the image has
    // nothing there". Measured here rather than asserted from the regex.
    await assert.rejects(
      () => copyFromImage({
        image: IMAGE,
        copies: [{ containerPath: '/seeded', destDir: join(process.env.DATA_DIR, 'no-such-dir-xyz', 'deeper') }],
      }),
      /invalid output path|no such file or directory|does not exist/i,
    );
  });

  test('an image that is not on the host fails the seed rather than pulling it', async (t) => {
    if (problem) return t.skip(problem);
    const d = scratch('live-missing-image');
    await assert.rejects(
      () => seedNewVolumeMounts({ image: `crane-seed-absent-${SUFFIX}:v9`, volumes: [{ host: d, container: '/seeded' }] }),
      /VOLUME_SEED_FAILED/,
      'a missing image must fail the deploy — starting anyway produces an empty mount that reads ' +
      'as a healthy first boot with the app\'s configuration silently gone',
    );
  });
});

// ===========================================================================
// 4. The wiring: a real deployApp seeds, and does not disturb the deploy's
//    one-pull/one-run shape
// ===========================================================================

describe('a real deploy seeds its new mounts', () => {
  const SHIM_DIR = join(process.env.DATA_DIR, 'bin2');
  const ARGV_LOG = join(process.env.DATA_DIR, 'deploy-argv.log');
  mkdirSync(SHIM_DIR, { recursive: true });
  const DIGEST = `sha256:${'c7'.repeat(32)}`;

  // A `docker` that records its argv, answers the two inspects the deploy path
  // needs, and — the part this section turns on — actually writes a file when
  // asked to `cp`, so the seeded/not-seeded distinction is visible on disk
  // without a daemon.
  writeFileSync(join(SHIM_DIR, 'docker'),
    '#!/usr/bin/env node\n' +
    'const fs = require("fs");\n' +
    'const argv = process.argv.slice(2);\n' +
    'fs.appendFileSync(process.env.CRANE_DEPLOY_LOG, JSON.stringify(argv) + "\\n");\n' +
    'if (argv[0] === "image" && argv[1] === "inspect") { process.stdout.write("bs@' + DIGEST + '\\n"); process.exit(0); }\n' +
    'if (argv[0] === "network" && argv[1] === "inspect") { process.stdout.write("false|172.20.0.0/16\\n"); process.exit(0); }\n' +
    'if (argv[0] === "images") { process.exit(0); }\n' +
    'if (argv[0] === "cp" && argv[1].includes(":/config/")) { fs.writeFileSync(argv[2] + "/default.conf", "FROM-IMAGE"); process.exit(0); }\n' +
    'if (argv[0] === "cp") { process.stderr.write("Error response from daemon: Could not find the file " + argv[1] + " in container x\\n"); process.exit(1); }\n' +
    'process.stdout.write("0123456789abcdef\\n");\n',
    { mode: 0o755 });
  writeFileSync(join(SHIM_DIR, 'chown'), '#!/usr/bin/env node\nprocess.exit(0);\n', { mode: 0o755 });
  process.env.CRANE_DEPLOY_LOG = ARGV_LOG;

  const calls = () => (existsSync(ARGV_LOG)
    ? readFileSync(ARGV_LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : []);

  let db;
  let deployApp;
  let getPortsForSlot;
  let userId;
  const slots = [];
  const servers = [];

  const startHealthServer = (port) => new Promise((res) => {
    const s = http.createServer((req, out) => {
      out.writeHead(200, { 'content-type': 'application/json' });
      out.end(JSON.stringify({ status: 'ok', version: '1.0.0' }));
    });
    s.on('error', () => res(null));
    // Loopback explicitly — a hostless listen(0) binds [::] and can collide
    // with a Docker-published port, which reads as a phantom failure here.
    s.listen(port, '127.0.0.1', () => res(s));
  });

  before(async () => {
    process.env.PATH = `${SHIM_DIR}:${REAL_PATH}`;
    ({ getDb: db } = await import('../server/db.js'));
    db = db();
    ({ deployApp } = await import('../server/services/deployer.js'));
    ({ getPortsForSlot } = await import('../server/services/portAllocator.js'));
    // TWO slots: apps.slot is UNIQUE, so the two apps this section deploys
    // cannot share one. Searched for rather than hardcoded — a fixed slot fails
    // with EADDRINUSE whenever anything else on the box holds that port,
    // including a second run of this suite.
    for (let s = 14200; s < 14400 && slots.length < 2; s++) {
      const p = getPortsForSlot(s);
      const sand = await startHealthServer(p.sand_be);
      if (!sand) continue;
      const prod = await startHealthServer(p.prod_be);
      if (!prod) { sand.close(); continue; }
      slots.push({ slot: s, ports: p });
      servers.push(sand, prod);
    }
    assert.equal(slots.length, 2, 'no two slots with all four ports free');
    userId = db.prepare(
      "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','seed@x.io','platform_admin','unused',1,'human')",
    ).run().lastInsertRowid;
  });

  after(() => {
    process.env.PATH = REAL_PATH;
    for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); }
  });

  async function deploy(slug, which = 0) {
    const { slot, ports } = slots[which];
    const existing = db.prepare('SELECT id FROM apps WHERE slug = ?').get(slug);
    if (!existing) {
      db.prepare(
        'INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,health_path,volume_paths) ' +
        "VALUES (?,?,?,'image','bs:1',3000,'/health',?)",
      ).run(slug, slug, slot, JSON.stringify(['/config']));
    }
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
    const depId = db.prepare(
      "INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)",
    ).run(app.id, userId).lastInsertRowid;
    rmSync(ARGV_LOG, { force: true });
    await deployApp(depId, app, 'sandbox', ports, {});
    return {
      row: db.prepare('SELECT * FROM deployments WHERE id = ?').get(depId),
      shared: join(process.env.DATA_DIR, 'apps', slug, 'sandbox', 'shared'),
    };
  }

  test('the first deploy populates the new /config mount from the image', async () => {
    const { row, shared } = await deploy('seed-wire');
    assert.equal(row.status, 'live', row.log);
    assert.equal(readFileSync(join(shared, 'volumes', 'config', 'default.conf'), 'utf8'), 'FROM-IMAGE',
      'deployApp must seed the mount before the container is created — without this the app boots ' +
      'onto an empty /config where its image had put the default configuration');
    assert.match(row.log, /Volume seed: \/config populated from the image/,
      'the deploy log is the only place an operator can see that a mount was seeded');
  });

  test('seeding does not add a `docker run` or a `docker pull` to the deploy', async () => {
    // test/image-deploy.test.js asserts a deploy issues EXACTLY ONE of each and
    // is a known tripwire — four confusing failures if this shape moves. Held
    // here too, against the same deploy that just seeded.
    const { row } = await deploy('seed-wire-shape', 1);
    assert.equal(row.status, 'live', row.log);
    const verbs = calls().map((c) => c[0]);
    assert.equal(verbs.filter((v) => v === 'run').length, 1);
    assert.equal(verbs.filter((v) => v === 'pull').length, 1);
    assert.ok(verbs.includes('create') && verbs.includes('cp'),
      'the seed happens via create + cp + rm, which are different verbs and so cannot inflate either count');
    // And it happens BEFORE the container exists.
    assert.ok(verbs.lastIndexOf('cp') < verbs.indexOf('run'),
      'seeding after the container starts is seeding into a mount the app is already using');
  });

  test('a redeploy leaves what the app wrote in place', async () => {
    const shared = join(process.env.DATA_DIR, 'apps', 'seed-wire', 'sandbox', 'shared');
    writeFileSync(join(shared, 'volumes', 'config', 'default.conf'), 'USER-EDITED');
    writeFileSync(join(shared, 'volumes', 'config', 'app-state.db'), 'LIVE');
    const { row } = await deploy('seed-wire');
    assert.equal(row.status, 'live', row.log);
    assert.equal(readFileSync(join(shared, 'volumes', 'config', 'default.conf'), 'utf8'), 'USER-EDITED');
    assert.equal(readFileSync(join(shared, 'volumes', 'config', 'app-state.db'), 'utf8'), 'LIVE');
    assert.match(row.log, /\/config already holds data/);
    assert.ok(!calls().some((c) => c[0] === 'cp' && c[1].includes(':/config/')),
      'no copy may even be attempted against a mount that holds state');
  });
});
