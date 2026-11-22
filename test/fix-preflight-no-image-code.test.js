import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

// Pre-flight must not run the image's code, and whatever docker does it must
// not stop the event loop: forward_auth for every app runs on that loop. An
// image whose /bin/sh ignored SIGTERM held execFileSync for 73 s.

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = mkdtempSync(join(tmpdir(), 'crane-fix-preflight-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));

// Runs the real check in a child, because old-style blocking would freeze this
// test process too and it could then not report anything at all.
const CHILD = join(ROOT, 'child.mjs');
writeFileSync(CHILD, `
const { preflightEntryCheck } = await import(${JSON.stringify(join(HERE, '../server/services/preflightCheck.js'))});
let ticks = 0;
const iv = setInterval(() => { ticks++; }, 50);
const started = Date.now();
const result = await preflightEntryCheck({ image: 'any:image', entry: process.argv[2], timeoutMs: 1500 });
clearInterval(iv);
console.log(JSON.stringify({ ms: Date.now() - started, ticks, result }));
process.exit(0);
`);

function runChild(entry, shimBody, parentLimitMs = 25000) {
  const bin = mkdtempSync(join(ROOT, 'bin-'));
  const events = join(bin, 'events');
  writeFileSync(join(bin, 'docker'), `#!/bin/bash\necho "$*" >> "${events}"\n${shimBody}\n`);
  chmodSync(join(bin, 'docker'), 0o755);
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CHILD, entry], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, LOG_LEVEL: 'error' }, stdio: ['ignore', 'pipe', 'inherit'] });
    let out = '';
    let blocked = false;
    const killer = setTimeout(() => { blocked = true; c.kill('SIGKILL'); }, parentLimitMs);
    c.stdout.on('data', (d) => { out += d; });
    c.on('close', () => {
      clearTimeout(killer);
      resolve({ blocked, report: out ? JSON.parse(out) : null, events: existsSync(events) ? readFileSync(events, 'utf8').trim().split('\n') : [] });
    });
  });
}

// A docker client that never exits, and shrugs off SIGTERM like the one in the
// finding (it waits on a container that ignores it).
const HANG_ON_READ = `
case "$1" in
  create) echo cid; exit 0 ;;
  rm) exit 0 ;;
esac
trap '' TERM
while :; do sleep 1; done`;

test('a docker client that hangs does not stop the event loop, and the container is removed', async () => {
  const { blocked, report, events } = await runChild('node server.js', HANG_ON_READ, 15000);
  assert.equal(blocked, false, 'the check never returned: its parent had to kill it');
  assert.ok(report.ms < 8000, `took ${report.ms} ms`);
  assert.ok(report.ticks >= report.ms / 50 * 0.5, `event loop stalled: ${report.ticks} ticks in ${report.ms} ms`);
  assert.equal(report.result.ok, false);
  assert.match(report.result.shortReason, /could not read the built image/);
  assert.ok(!/not found/.test(report.result.shortReason), 'a timeout is not evidence the file is missing');
  assert.ok(events.some((e) => e.startsWith('create ')), events.join('\n'));
  assert.ok(events.some((e) => /^rm -f -v appcrane-preflight-[0-9a-f]+$/.test(e)), `no rm -f on timeout:\n${events.join('\n')}`);
});

test('no argv ever starts the image: no docker run, no docker start', async () => {
  const { events } = await runChild('node server.js', 'exit 1');
  assert.ok(events.length > 0);
  for (const e of events) assert.ok(!/^(run|start|exec)\b/.test(e), e);
});

test('the same hang through the npm start path', async () => {
  const { blocked, report } = await runChild('npm start', HANG_ON_READ, 15000);
  assert.equal(blocked, false);
  assert.ok(report.ticks >= report.ms / 50 * 0.5, `event loop stalled: ${report.ticks} ticks in ${report.ms} ms`);
  assert.equal(report.result.ok, false);
});

const docker = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
const dockerUp = docker.status === 0 && !!docker.stdout.trim();

function leftovers(image) {
  return execFileSync('docker', ['ps', '-a', '--filter', `ancestor=${image}`, '--format', '{{.Names}}'], { encoding: 'utf8' }).trim();
}

// `ADD <tar> /` on scratch: no base image, no network, and it keeps the links and
// the fifo that COPY from a build context resolves or refuses.
function buildRootfsImage(tag, build, extra = '') {
  const ctx = mkdtempSync(join(ROOT, 'ctx-'));
  const root = join(ctx, 'root');
  mkdirSync(root);
  build(root);
  execFileSync('tar', ['--no-xattrs', '-cf', join(ctx, 'rootfs.tar'), '-C', root, '.']);
  rmSync(root, { recursive: true });
  writeFileSync(join(ctx, 'Dockerfile'), `FROM scratch\nADD rootfs.tar /\n${extra}\n`);
  execFileSync('docker', ['build', '-q', '-t', tag, ctx], { stdio: 'pipe', timeout: 110000 });
}

function put(root, path, body = 'x') {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), body);
}

// One component too long for either ustar field, so only a PAX record can carry it.
const LONG_DIR = `pkg/${'d'.repeat(200)}`;

// One image for every case, because builds are what is slow here. It has no
// shell, no node, no binary of any kind: a check that ran image code could not
// answer about it at all.
const TAG = `crane-fix-preflight:${process.pid}`;
const NO_START = `crane-fix-preflight-nostart:${process.pid}`;

describe('real docker', { skip: !dockerUp && 'docker not available' }, () => {
  before(() => {
    buildRootfsImage(TAG, (root) => {
      put(root, 'app/package.json', JSON.stringify({ name: 'a', scripts: { start: 'node real.js' } }));
      put(root, 'app/real.js');
      put(root, 'app/dist/server.js');
      put(root, 'app/node_modules/x/index.js');
      put(root, `app/${LONG_DIR}/main.js`);
      put(root, 'app/a/b/c/d/e/server.js');
      put(root, 'app/a/b/c/d/e/f/server.js');
      symlinkSync('real.js', join(root, 'app/app-link.js'));
      symlinkSync('/nonexistent/target.js', join(root, 'app/app-dangling.js'));
      execFileSync('mkfifo', [join(root, 'app/fifo.js')]);
    }, 'VOLUME /data-anon');
    buildRootfsImage(NO_START, (root) => put(root, 'app/package.json', '{"name":"a"}'));
  });
  after(() => { spawnSync('docker', ['rmi', '-f', TAG, NO_START], { stdio: 'ignore' }); });

  const check = async (image, entry) => {
    const { preflightEntryCheck } = await import('../server/services/preflightCheck.js');
    return preflightEntryCheck({ image, entry });
  };

  test('an entry that exists, directly, through npm start and through a link', async () => {
    assert.deepEqual(await check(TAG, 'node real.js'), { ok: true });
    assert.deepEqual(await check(TAG, 'npm start'), { ok: true });
    assert.deepEqual(await check(TAG, 'node ./app-link.js'), { ok: true });
  });

  test('a fifo for an entry cannot hang the check', async () => {
    let ticks = 0;
    const iv = setInterval(() => { ticks++; }, 20);
    const started = Date.now();
    const result = await check(TAG, 'node fifo.js');
    clearInterval(iv);
    assert.deepEqual(result, { ok: true });
    assert.ok(ticks >= 1 || Date.now() - started < 40, 'the event loop never ran during the check');
  });

  test('a dangling link is missing, as it was for test -e', async () => {
    assert.equal((await check(TAG, 'node app-dangling.js')).ok, false);
  });

  test('a missing entry lists candidates by find\'s rules, long paths included', async () => {
    const missing = await check(TAG, 'node nope.js');
    assert.equal(missing.ok, false);
    assert.match(missing.shortReason, /\/app\/nope\.js not found in built image/);
    assert.match(missing.message, /\/app\/dist\/server\.js/);
    assert.match(missing.message, /\/app\/a\/b\/c\/d\/e\/server\.js/, 'depth 6 is inside find -maxdepth 6');
    assert.ok(!missing.message.includes('/e/f/server.js'), 'depth 7 is outside it');
    assert.ok(!missing.message.includes('node_modules'), missing.message);
    assert.ok(missing.message.includes(`/app/${LONG_DIR}/main.js`), `a path past the ustar name and prefix fields was lost:\n${missing.message}`);
  });

  test('package.json without scripts.start', async () => {
    const noStart = await check(NO_START, 'npm start');
    assert.equal(noStart.ok, false);
    assert.match(noStart.shortReason, /no scripts\.start/);
  });

  test('AppCrane killed mid-check: the Created container and its volume stay, and the sweep removes both and nothing else', async () => {
    const { MIN_AGE_MS, sweepPreflightLeftovers } = await import('../server/services/preflightSweep.js');
    const real = execFileSync('which', ['docker'], { encoding: 'utf8' }).trim();
    const bin = mkdtempSync(join(ROOT, 'crash-'));
    const reached = join(bin, 'reached');
    const events = join(bin, 'events');
    // create is the real one; the first read never answers, so the kill lands mid-check.
    writeFileSync(join(bin, 'docker'), `#!/bin/bash\ncase "$1" in\n  create) echo "$*" >> "${events}"; exec "${real}" "$@" ;;\n  cp) touch "${reached}"; sleep 20; exit 1 ;;\nesac\nexit 0\n`);
    chmodSync(join(bin, 'docker'), 0o755);
    const crashChild = join(bin, 'child.mjs');
    writeFileSync(crashChild, `
const { preflightEntryCheck } = await import(${JSON.stringify(join(HERE, '../server/services/preflightCheck.js'))});
await preflightEntryCheck({ image: ${JSON.stringify(TAG)}, entry: 'node real.js', timeoutMs: 60000 });
`);
    const c = spawn(process.execPath, [crashChild], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, LOG_LEVEL: 'error' }, stdio: 'ignore' });
    const closed = new Promise((r) => c.on('close', r));
    for (let i = 0; i < 1200 && !existsSync(reached) && c.exitCode === null; i++) await new Promise((r) => setTimeout(r, 50));
    assert.ok(existsSync(reached), 'the check never got as far as reading the image');
    c.kill('SIGKILL');
    await closed;

    const name = /--name (appcrane-preflight-[0-9a-f]+)/.exec(readFileSync(events, 'utf8'))[1];
    const unlabelled = `crane-fix-preflight-keep-${process.pid}`;
    const id = execFileSync('docker', ['inspect', '--format', '{{.Id}}', name], { encoding: 'utf8' }).trim();
    let volume = null;
    try {
      assert.equal(execFileSync('docker', ['inspect', '--format', '{{.State.Status}}', name], { encoding: 'utf8' }).trim(), 'created');
      volume = execFileSync('docker', ['inspect', '--format', '{{range .Mounts}}{{.Name}}{{end}}', name], { encoding: 'utf8' }).trim();
      assert.ok(volume, 'the image declares a VOLUME, so the container should hold an anonymous one');
      execFileSync('docker', ['create', '--pull', 'never', '--name', unlabelled, '--entrypoint', '/never', TAG], { stdio: 'pipe' });

      // Only ever shown this test's own container: other test files share the daemon.
      const { runDocker } = await import('../server/services/buildCachePrune.js');
      const run = async (args) => {
        const out = await runDocker(args);
        if (args[0] !== 'ps') return out;
        const seen = out.stdout.split('\n').map((s) => s.trim());
        assert.ok(seen.includes(id), 'the crashed check\'s container was not listed');
        return { ...out, stdout: `${id}\n` };
      };
      assert.deepEqual(await sweepPreflightLeftovers({ run, now: Date.now() }), { removed: 0, failed: 0 }, 'too young to sweep');
      assert.deepEqual(await sweepPreflightLeftovers({ run, now: Date.now() + MIN_AGE_MS + 60000 }), { removed: 1, failed: 0 });

      assert.equal(spawnSync('docker', ['inspect', id], { stdio: 'ignore' }).status, 1, 'the container is still there');
      assert.equal(spawnSync('docker', ['volume', 'inspect', volume], { stdio: 'ignore' }).status, 1, 'the anonymous volume is still there');
      assert.equal(spawnSync('docker', ['inspect', unlabelled], { stdio: 'ignore' }).status, 0, 'an unlabelled Created container was touched');
    } finally {
      spawnSync('docker', ['rm', '-f', '-v', id], { stdio: 'ignore' });
      spawnSync('docker', ['rm', '-f', '-v', unlabelled], { stdio: 'ignore' });
    }
  });

  test('every check left no container behind', () => {
    assert.equal(leftovers(TAG), '');
    assert.equal(leftovers(NO_START), '');
  });
});
