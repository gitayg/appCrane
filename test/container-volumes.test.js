import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, statSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import http from 'node:http';
import { createRequire, syncBuiltinESMExports } from 'module';

const execFileAsync = promisify(execFile);

// Arbitrary volume paths: WHICH directories inside a container hold state.
//
// AppCrane mounted exactly one: /data, from <app>/<env>/shared/data. That is a
// platform guarantee an image AppCrane BUILT keeps (DATA_DIR=/data) and a pulled
// image never agreed to. Everything else an image writes lives in its writable
// layer — and every redeploy runs `docker rm -f` (services/docker.js stopApp)
// and destroys it.
//
// Measured against the shipped catalogue on 2026-09-09 by reading each entry's
// image config straight from its registry: of the 63 entries whose config could
// be read, 25 declare a VOLUME and 22 declare at least one that is NOT /data —
// mattermost, paperless-ngx, bookstack (/config), odoo (/var/lib/odoo),
// openproject, snipe-it, appsmith (/appsmith-stacks) among them. A floor, not a
// count: an image that persists without declaring VOLUME is invisible to it.
//
// The claim this file has to settle is not "the -v flag is emitted". It is
// "state written inside the container is still there after the container has
// been destroyed and recreated", which only a real daemon can answer — so the
// live section writes a file, redeploys, and reads it back, WITH a negative
// control on an unmounted path so a pass cannot come from the writable layer
// having survived.
//
// Everything above the live section is measured off a recording `docker` shim.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-vol-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
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

// ---------------------------------------------------------------------------
// The recording `docker` shim (same as test/container-port.test.js)
// ---------------------------------------------------------------------------

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });

// CommonJS on purpose: the file is named `docker` with no extension, so Node
// parses it as CJS and an `import` here would be a syntax error at spawn time.
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync, readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.map(a => a + "\\n").join("") + "\\0");\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) {\n' +
  '  if (r.match.every(tok => argv.includes(tok))) {\n' +
  '    process.stdout.write(r.stdout || "");\n' +
  '    process.exit(r.code || 0);\n' +
  '  }\n' +
  '}\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const DIGEST = `sha256:${'b4'.repeat(32)}`;
writeFileSync(RULES, JSON.stringify([
  { match: ['image', 'inspect'], stdout: `bs@${DIGEST}\n` },
  { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
  { match: ['images', '--filter'], stdout: '' },
  // A daemon new enough for volume-subpath (Engine 26+), so declared volumes
  // take the --mount path. The fallback is pinned separately below.
  { match: ['version', '--format'], stdout: '1.55\n' },
  // The volume helper's modes (volumeHelper.js), for the one deploy below that
  // declares volumes. `docker cp ... -` answers with nothing: the image ships
  // nothing at those paths, so no extract runs.
  { match: ['appcrane-roothelper=true', 'prep'], stdout: 'empty /config\nempty /var/lib/odoo\n' },
  { match: ['appcrane-roothelper=true', 'chown'], stdout: 'chown-ok /config\nchown-ok /var/lib/odoo\n' },
  { match: ['cp', '-'], stdout: '' },
]));

function dockerCalls() {
  if (!existsSync(ARGV_LOG)) return [];
  return readFileSync(ARGV_LOG, 'utf8')
    .split('\0')
    .filter((rec) => rec.trim() !== '')
    .map((rec) => rec.split('\n').filter((l) => l !== ''));
}
function clearDockerCalls() {
  if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG);
}
const isHelperRun = (c) => c[0] === 'run' && c.includes('appcrane-roothelper=true');
function runArgs() {
  const runs = dockerCalls().filter((c) => c[0] === 'run' && !isHelperRun(c));
  assert.equal(runs.length, 1, `expected exactly one \`docker run\`, saw ${runs.length}`);
  return runs[0];
}
/** Every `-v` and `--mount` value in the argv, in order. */
function mountArgs(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) if (args[i] === '-v' || args[i] === '--mount') out.push(args[i + 1]);
  return out;
}
/** What a declared volume is mounted as: the app/env's volume bound to
 *  <shared>/volumes, with the daemon resolving the subpath (volumeHelper.js). */
const subpathMount = (slug, env, sub, dst) =>
  `type=volume,src=appcrane-vols-${slug}-${env},dst=${dst},volume-subpath=${sub},volume-nocopy=true`;

// GUARD for the v2.107.3 follow-up: while a deploy runs, record every
// mutating host fs call and every non-docker child process whose arguments
// name a path strictly BELOW `prefix` (<shared>/volumes). Builtin named
// exports are live bindings, so syncBuiltinESMExports() makes the already
// imported `mkdirSync` etc. in deployer.js and volumeSeeder.js the wrappers.
const nodeRequire = createRequire(import.meta.url);
function guardHostCalls(prefix) {
  const fs = nodeRequire('fs');
  const cp = nodeRequire('child_process');
  const under = (a) => typeof a === 'string' && a.startsWith(`${prefix}/`);
  const hits = [];
  const restore = [];
  const wrap = (mod, n, test) => {
    const orig = mod[n];
    mod[n] = function wrapped(...a) { if (test(a)) hits.push([n, ...a.filter((x) => typeof x === 'string' || Array.isArray(x)).flat()]); return orig.apply(this, a); };
    restore.push(() => { mod[n] = orig; });
  };
  for (const n of ['mkdirSync', 'chownSync', 'lchownSync', 'chmodSync', 'renameSync', 'rmSync', 'rmdirSync', 'unlinkSync',
    'writeFileSync', 'cpSync', 'copyFileSync', 'symlinkSync', 'mkdtempSync', 'openSync', 'utimesSync']) {
    wrap(fs, n, (a) => a.some(under));
  }
  for (const n of ['execFileSync', 'execFile', 'spawn', 'spawnSync']) {
    wrap(cp, n, (a) => a[0] !== 'docker' && Array.isArray(a[1]) && a[1].some(under));
  }
  syncBuiltinESMExports();
  return { hits, restore() { for (const r of restore) r(); syncBuiltinESMExports(); } };
}

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
// This file exercises a real daemon, not memory admission (test/memory-admission.test.js); a busy
// Docker host must not refuse its containers.
getDb().prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
const db = getDb();

const { startApp, stopApp } = await import('../server/services/docker.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const spec = await import('../server/services/containerRuntimeSpec.js');

const SHARED = '/srv/crane/data/apps/demo/production/shared';

// ===========================================================================
// 1. Resolution: which host directory backs which container path
// ===========================================================================

test('an app that declares nothing gets exactly the one mount it gets today', () => {
  const { mounts, skipped } = spec.resolveVolumeMounts({ sharedDir: SHARED, paths: [] });
  assert.deepEqual(mounts, [{ host: `${SHARED}/data`, container: '/data' }]);
  assert.deepEqual(skipped, []);
});

test('/data is always first, and no declared path can displace it', () => {
  // The platform guarantee. If a declared value could reorder or replace this
  // mount, every app that relies on DATA_DIR=/data would be one column away
  // from losing its data directory.
  const { mounts } = spec.resolveVolumeMounts({
    sharedDir: SHARED, paths: ['/config', '/var/lib/odoo'],
  });
  assert.deepEqual(mounts[0], { host: `${SHARED}/data`, container: '/data' });
  assert.deepEqual(mounts.slice(1), [
    { host: `${SHARED}/volumes/config`, container: '/config', base: SHARED },
    { host: `${SHARED}/volumes/var/lib/odoo`, container: '/var/lib/odoo', base: SHARED },
  ]);
});

test('the host layout mirrors the container layout, so two paths cannot collide', () => {
  // A flattened naming scheme ('/var/lib/odoo' -> 'var_lib_odoo') looks tidier
  // and lets '/var/lib/odoo' and '/var_lib_odoo' land on one directory, where
  // two apps' — or one app's two — states overwrite each other silently.
  const { mounts } = spec.resolveVolumeMounts({
    sharedDir: SHARED, paths: ['/var/lib/odoo', '/var_lib_odoo'],
  });
  const hosts = mounts.map((m) => m.host);
  assert.equal(new Set(hosts).size, hosts.length, `two mounts share a host directory: ${hosts}`);
});

test('a path already inside another mount is skipped, and says so', () => {
  const { mounts, skipped } = spec.resolveVolumeMounts({
    sharedDir: SHARED, paths: ['/data', '/data/db', '/config', '/config/cache'],
  });
  assert.deepEqual(mounts.map((m) => m.container), ['/data', '/config']);
  assert.deepEqual(skipped, [
    { path: '/data', coveredBy: '/data' },
    { path: '/data/db', coveredBy: '/data' },
    { path: '/config/cache', coveredBy: '/config' },
  ], 'docker would accept the nested bind and resolve it by mount order — a rule nobody reading ' +
     'the app configuration can see. Skipping is only acceptable if it is reported.');
});

test("'/config' and '/config/' are one mount, not two of the same directory", () => {
  const { mounts } = spec.resolveVolumeMounts({ sharedDir: SHARED, paths: ['/config', '/config/', '//config'] });
  assert.deepEqual(mounts.map((m) => m.container), ['/data', '/config']);
  // '/config/../config' normalises to the same thing and is still REFUSED, on
  // purpose: '..' is rejected before normalisation, so the rule stays "no '..'
  // anywhere" rather than "no '..' that happens to escape". A path that has to
  // be normalised to be judged safe is one normalisation bug away from not being.
  assert.throws(() => spec.validateVolumePaths(['/config/../config']), /'\.\.' segment/);
});

// ===========================================================================
// 2. Validation
// ===========================================================================

test('a colon in a path is refused — it is the -v field separator, not a character', async () => {
  // The sharp edge. '-v host:container:options' means a container path of
  // '/config:ro' does not produce a BROKEN mount, it produces a different valid
  // one (read-only), and a colon on the host side re-splits the argument and can
  // name a source AppCrane never chose. Refused where paths are stored...
  assert.throws(() => spec.validateVolumePaths(['/config:ro']), /field separator in a docker -v argument/);
  // ...and again where the argument is assembled, for a caller that built its
  // own list and never went through storage.
  await assert.rejects(() => startApp({
    slug: 'vol-colon', env: 'production', image: 'bs:1', hostPort: 4811, memoryMb: 512, cpus: 0.5,
    volumes: [{ host: '/tmp/x', container: '/config:ro' }],
  }), /field separator in a docker -v argument/);
});

test('relative paths, traversal and the container root are refused', () => {
  assert.throws(() => spec.validateVolumePaths(['config']), /must be absolute/);
  assert.throws(() => spec.validateVolumePaths(['/a/../../etc']), /'\.\.' segment/);
  assert.throws(() => spec.validateVolumePaths(['/']), /kernel mount point or the container root/);
  for (const p of ['/proc', '/sys', '/dev']) {
    assert.throws(() => spec.validateVolumePaths([p]), /kernel mount point/);
  }
  assert.throws(() => spec.validateVolumePaths('/config'), /not a single string/);
  assert.throws(() => spec.validateVolumePaths(['/a\u0000b']), /control character/);
  assert.throws(() => spec.validateVolumePaths(new Array(spec.MAX_VOLUME_PATHS + 1).fill('/x')), /at most/);
});

test('no declared path can put a mount outside the app\'s own shared tree', () => {
  // Belt and braces: '..' is already refused above, so this asserts the second
  // check — the one that still holds if the first is ever relaxed.
  for (const p of spec.validateVolumePaths(['/config', '/var/lib/odoo', '/appsmith-stacks'])) {
    const { mounts } = spec.resolveVolumeMounts({ sharedDir: SHARED, paths: [p] });
    for (const m of mounts) {
      assert.ok(m.host === `${SHARED}/data` || m.host.startsWith(`${SHARED}/volumes/`),
        `${p} resolved to ${m.host}, outside ${SHARED}`);
    }
  }
});

test('a malformed COLUMN degrades to "just /data" instead of failing the deploy', () => {
  for (const stored of ['not json', '"/config"', '{"a":1}', '["config"]', null, '', 7]) {
    assert.deepEqual(spec.parseVolumePaths(stored), [], `stored ${JSON.stringify(stored)}`);
  }
  assert.deepEqual(spec.parseVolumePaths('["/config","/config"]'), ['/config']);
});

// ===========================================================================
// 3. The argv, and the row -> argv path through a real deployApp
// ===========================================================================

test('startApp emits one -v per mount, in order', async () => {
  clearDockerCalls();
  const { mounts } = spec.resolveVolumeMounts({ sharedDir: SHARED, paths: ['/config'] });
  await startApp({
    slug: 'vol-argv', env: 'production', image: 'bs:1', hostPort: 4812,
    memoryMb: 512, cpus: 0.5, volumes: mounts,
  });
  assert.deepEqual(mountArgs(runArgs()), [
    `${SHARED}/data:/data`,
    subpathMount('vol-argv', 'production', 'config', '/config'),
  ]);
  // The volume is recreated bound to exactly <shared>/volumes before the run.
  const create = dockerCalls().find((c) => c[0] === 'volume' && c[1] === 'create');
  assert.ok(create.includes(`device=${SHARED}/volumes`) && create.includes('o=bind') && create.at(-1) === 'appcrane-vols-vol-argv-production');
  assert.ok(dockerCalls().findIndex((c) => c[0] === 'volume' && c[1] === 'rm') < dockerCalls().findIndex((c) => c[0] === 'volume' && c[1] === 'create'));
});

test('a daemon without volume-subpath falls back to the host-path bind', async () => {
  const { resetVolumeSubpathProbe } = await import('../server/services/docker.js');
  const rules = JSON.parse(readFileSync(RULES, 'utf8'));
  writeFileSync(RULES, JSON.stringify(rules.map((r) => (r.match[0] === 'version' ? { ...r, stdout: '1.44\n' } : r))));
  resetVolumeSubpathProbe();
  try {
    clearDockerCalls();
    const { mounts } = spec.resolveVolumeMounts({ sharedDir: SHARED, paths: ['/config'] });
    await startApp({ slug: 'vol-old', env: 'production', image: 'bs:1', hostPort: 4813, memoryMb: 512, cpus: 0.5, volumes: mounts });
    assert.deepEqual(mountArgs(runArgs()), [`${SHARED}/data:/data`, `${SHARED}/volumes/config:/config`]);
    assert.ok(!dockerCalls().some((c) => c[0] === 'volume'));
  } finally {
    writeFileSync(RULES, JSON.stringify(rules));
    resetVolumeSubpathProbe();
  }
});

test('a container path with a comma is quoted in the --mount record, not split by it', async () => {
  clearDockerCalls();
  const { mounts } = spec.resolveVolumeMounts({ sharedDir: SHARED, paths: ['/a,b'] });
  await startApp({ slug: 'vol-comma', env: 'production', image: 'bs:1', hostPort: 4814, memoryMb: 512, cpus: 0.5, volumes: mounts });
  assert.equal(mountArgs(runArgs())[1],
    'type=volume,src=appcrane-vols-vol-comma-production,"dst=/a,b","volume-subpath=a,b",volume-nocopy=true');
});

describe('a real deploy reads the column', () => {
  const HEALTH = '/health';
  let userId;
  let slot = null;
  let ports = null;
  const servers = [];

  const startHealthServer = (port) => new Promise((res) => {
    const s = http.createServer((req, out) => {
      out.writeHead(200, { 'content-type': 'application/json' });
      out.end(JSON.stringify({ status: 'ok', version: '1.0.0' }));
    });
    s.on('error', () => res(null));
    // Loopback explicitly: a hostless listen(0) binds [::] and can collide with
    // a Docker-published port, which reads as a phantom failure of this file.
    s.listen(port, '127.0.0.1', () => res(s));
  });

  before(async () => {
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
      "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','vol@x.io','platform_admin','unused',1,'human')",
    ).run().lastInsertRowid;
  });

  after(() => {
    for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); }
  });

  async function deployWith(slug, volumePaths) {
    db.prepare(
      'INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,health_path,volume_paths) ' +
      "VALUES (?,?,?,'image','bs:1',3000,?,?)",
    ).run(slug, slug, slot, HEALTH, volumePaths);
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
    const depId = db.prepare(
      "INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)",
    ).run(app.id, userId).lastInsertRowid;
    clearDockerCalls();
    await deployApp(depId, app, 'sandbox', ports, {});
    const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(depId);
    db.prepare('DELETE FROM apps WHERE id = ?').run(app.id);
    return { args: runArgs(), row, shared: join(process.env.DATA_DIR, 'apps', slug, 'sandbox', 'shared') };
  }

  test('volume_paths on the row become -v flags AND host directories on disk', async () => {
    const guard = guardHostCalls(join(process.env.DATA_DIR, 'apps', 'vol-row', 'sandbox', 'shared', 'volumes'));
    let out;
    try { out = await deployWith('vol-row', JSON.stringify(['/config', '/var/lib/odoo'])); } finally { guard.restore(); }
    const { args, row, shared } = out;
    assert.equal(row.status, 'live', row.log);
    // The host never walks a path below <shared>/volumes: not with fs, not
    // with a chown binary, and not as a docker -v source or a docker cp
    // destination (every docker argv the shim saw).
    assert.deepEqual(guard.hits, [], 'a host fs call or process touched a path inside the app-writable volumes tree');
    const dockerHostPaths = dockerCalls().flat().filter((a) => a.includes(`${shared}/volumes/`));
    assert.deepEqual(dockerHostPaths, [], 'docker was handed a host path inside the volumes tree');
    assert.deepEqual(mountArgs(args), [
      `${shared}/data:/data`,
      subpathMount('vol-row', 'sandbox', 'config', '/config'),
      subpathMount('vol-row', 'sandbox', 'var/lib/odoo', '/var/lib/odoo'),
    ]);
    // The directories have to EXIST before the container is created. /data is
    // AppCrane's own and is made on the host; the declared ones sit below a
    // tree the app can plant links in, so they are made by the helper, which
    // mounts ONLY <shared>/volumes and is handed the container paths.
    assert.ok(existsSync(`${shared}/data`) && statSync(`${shared}/data`).isDirectory());
    assert.ok(statSync(`${shared}/volumes`).isDirectory(), 'the volumes root is AppCrane\'s to create');
    const helpers = dockerCalls().filter(isHelperRun);
    assert.deepEqual(helpers.map((c) => c[c.indexOf('appcrane-volume-helper') + 1]), ['prep', 'chown']);
    for (const h of helpers) {
      assert.deepEqual(h.filter((a, i) => h[i - 1] === '-v'), [`${shared}/volumes:/.appcrane-volumes`]);
    }
    assert.deepEqual(helpers[0].slice(helpers[0].indexOf('appcrane-volume-helper') + 1), ['prep', '/config', '/var/lib/odoo']);
    assert.deepEqual(helpers[1].slice(helpers[1].indexOf('appcrane-volume-helper') + 1), ['chown', '1000:1000', '/config', '/var/lib/odoo']);
    const appRunAt = dockerCalls().findIndex((c) => c[0] === 'run' && !isHelperRun(c));
    assert.ok(helpers.every((h) => dockerCalls().indexOf(h) < appRunAt),
      'the helper must prepare the directories before the app container exists');
    assert.match(row.log, /Persistent mounts: \/data, \/config, \/var\/lib\/odoo/,
      'the deploy log must name the mounts — it is the only surface that tells an operator ' +
      'which paths are actually being kept');
  });

  test('a NULL column deploys exactly as it did before the column existed', async () => {
    const { args, row, shared } = await deployWith('vol-row-null', null);
    assert.equal(row.status, 'live', row.log);
    assert.deepEqual(mountArgs(args), [`${shared}/data:/data`],
      'one mount, the same literal that used to be inlined at the call site');
  });

  test('a corrupt column falls back to /data rather than failing the deploy', async () => {
    const { args, row, shared } = await deployWith('vol-row-junk', 'not json at all');
    assert.equal(row.status, 'live', row.log);
    assert.deepEqual(mountArgs(args), [`${shared}/data:/data`]);
  });
});

// ===========================================================================
// 4. The daemon: state survives the rm -f + recreate a redeploy performs
// ===========================================================================

describe('LIVE', { skip: liveSkip }, () => {
  const IMAGE = 'alpine:3.20';
  const SUFFIX = `vol${process.pid}`;
  const SLUG = `vol-persist-${SUFFIX}`;
  const NAME = `appcrane-${SLUG}-production`;
  const MARKER = `persisted-${SUFFIX}-${Date.now()}`;

  const dk = (args, timeout = 120000) =>
    execFileAsync(REAL_DOCKER, args, { timeout }).then((r) => r.stdout.trim());

  const freePort = () => new Promise((res, rej) => {
    const s = net.createServer();
    s.once('error', rej);
    // Loopback explicitly — see the note on the health server above.
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); });
  });

  const shared = join(process.env.DATA_DIR, 'apps', SLUG, 'production', 'shared');
  const { mounts } = spec.resolveVolumeMounts({ sharedDir: shared, paths: ['/config'] });

  // An image that is ALREADY local is not re-pulled. Docker Hub answers 429 to
  // an unauthenticated puller often enough that a mandatory pull turns this file
  // into a rate-limit detector; and a pull that fails with no local copy is an
  // environment fact, so it skips rather than fails.
  let imageProblem = null;
  before(async () => {
    // The shim comes off PATH: `docker` is the real binary from here on.
    process.env.PATH = REAL_PATH;
    try {
      await dk(['image', 'inspect', IMAGE], 30000);
    } catch (_) {
      try { await dk(['pull', IMAGE], 300000); }
      catch (e) { imageProblem = `could not obtain ${IMAGE}: ${String(e.message).split('\n')[0].slice(0, 120)}`; return; }
    }
    for (const m of mounts) mkdirSync(m.host, { recursive: true });
  });

  after(async () => {
    await dk(['rm', '-f', NAME], 30000).catch(() => {});
    await dk(['volume', 'rm', '-f', `appcrane-vols-${SLUG}-production`], 30000).catch(() => {});
  });

  /** What deployApp does on every deploy: the container is DESTROYED and a new
   *  one is created. stopApp() is `docker stop` + `docker rm -f`. */
  const launch = async () => startApp({
    slug: SLUG, env: 'production', image: IMAGE, hostPort: await freePort(),
    // alpine's CMD is /bin/sh, which exits immediately when detached — so this
    // test needs the command feature to hold the container open, and gets a
    // second, independent exercise of it for free.
    command: ['sleep', '600'],
    memoryMb: 256, cpus: 0.5, volumes: mounts,
  });

  test('a file written to a declared volume survives rm -f and recreate', async (t) => {
    if (imageProblem) return t.skip(imageProblem);
    await launch();
    // Two writes: one inside the declared mount, one in an ORDINARY container
    // directory. The second is the negative control — without it a pass could
    // come from the writable layer having survived, which would mean the test
    // proves nothing about the mount.
    await dk(['exec', NAME, 'sh', '-c', `mkdir -p /scratch && printf %s ${MARKER} > /config/marker && printf %s ${MARKER} > /scratch/marker`]);
    assert.equal(readFileSync(join(mounts[1].host, 'marker'), 'utf8'), MARKER,
      'the write must land on the HOST directory — that is what makes it survive');

    const idBefore = await dk(['inspect', NAME, '--format', '{{.Id}}']);
    await stopApp(SLUG, 'production');
    await assert.rejects(() => dk(['inspect', NAME]),
      'the container must actually be gone — if rm -f did not happen, this test proves nothing');
    await launch();
    const idAfter = await dk(['inspect', NAME, '--format', '{{.Id}}']);
    assert.notEqual(idAfter, idBefore, 'a different container, not a restart of the same one');

    assert.equal(await dk(['exec', NAME, 'cat', '/config/marker']), MARKER,
      'the declared volume must still hold what the previous container wrote');

    const scratch = await dk(['exec', NAME, 'sh', '-c', 'cat /scratch/marker 2>&1 || true']);
    assert.ok(!scratch.includes(MARKER),
      'CONTROL FAILED: the unmounted path also survived, so this test cannot tell a working ' +
      `mount from a container that was never destroyed. Got: ${JSON.stringify(scratch)}`);
  });

  test('the daemon binds the declared path to the app\'s own directory, read-write', async (t) => {
    if (imageProblem) return t.skip(imageProblem);
    const binds = JSON.parse(await dk(['inspect', NAME, '--format', '{{json .HostConfig.Binds}}']));
    // /data is still the one host-path bind. A declared path is NOT: it comes
    // through the app/env's volume bound to <shared>/volumes, with the daemon
    // resolving the subpath (volumeHelper.js), so a link planted in the tree
    // cannot redirect it.
    assert.deepEqual(binds, [`${mounts[0].host}:/data`]);
    const spec2 = JSON.parse(await dk(['inspect', NAME, '--format', '{{json .HostConfig.Mounts}}']))
      .find((m) => m.Target === '/config');
    assert.equal(spec2.Type, 'volume');
    assert.equal(spec2.Source, `appcrane-vols-${SLUG}-production`);
    assert.equal(spec2.VolumeOptions?.Subpath, 'config');
    const vol = JSON.parse(await dk(['volume', 'inspect', spec2.Source, '--format', '{{json .Options}}']));
    assert.deepEqual(vol, { device: join(shared, 'volumes'), o: 'bind', type: 'none' });
    const mnt = JSON.parse(await dk(['inspect', NAME, '--format', '{{json .Mounts}}']))
      .find((m) => m.Destination === '/config');
    assert.equal(mnt.RW, true, 'a read-only mount would let the app boot and fail on its first write');
  });
});
