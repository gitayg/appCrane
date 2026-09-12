import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { tmpdir } from 'os';
import { join } from 'path';

const execFileAsync = promisify(execFile);

// The writable-layer half of the redeploy data-loss guard (v2.72.0).
//
// `VOLUME` is a floor, not the truth. The nine Laravel/PHP catalogue apps
// (akaunting, invoice-ninja, krayin, bagisto, uvdesk, freescout, leantime,
// limesurvey, easyappointments) declare NO volume at all and persist to
// /var/www/html/storage, so a guard built only on image VOLUMEs calls every one
// of them safe and lets the redeploy destroy them silently.
//
// The property under test, stated once so every assertion can be checked
// against it:
//
//   A path the app has WRITTEN, that no mount covers, is reported as at-risk
//   and is distinguishable in the verdict from a declared-but-unmounted VOLUME
//   — and a path that is mounted, scratch, or otherwise not state is NOT
//   reported, on any app.
//
// The second half is the hard half and the one that decides whether the feature
// is usable. A long-running container writes to /tmp, /run, /var/log,
// /var/cache and so on constantly; warning on those would fire on every app and
// train the click-through that defeats the warning on the app where it was
// true, which is strictly worse than no warning at all. So the FIXTURES below
// are not invented — every one is verbatim `docker diff` output captured from a
// real image booted on this box, and the "reports nothing" cases are asserted
// exactly as hard as the "reports the path" ones.

const REAL_PATH = process.env.PATH;
let REAL_DOCKER = null;
try {
  REAL_DOCKER = execFileSync('/usr/bin/env', ['sh', '-c', 'command -v docker'], { encoding: 'utf8' }).trim() || null;
  if (REAL_DOCKER) execFileSync(REAL_DOCKER, ['version', '--format', '{{.Server.Version}}'], { timeout: 15000, stdio: 'pipe' });
} catch (_) { REAL_DOCKER = null; }
const liveSkip = REAL_DOCKER ? false : 'no reachable Docker daemon on this host';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-writable-layer-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const risk = await import('../server/services/redeployRisk.js');

// ===========================================================================
// FIXTURES — verbatim `docker diff` output from real images
// ===========================================================================
//
// Captured 2026-09-11, Docker Desktop 29.6.1, containerd snapshotter /
// overlayfs. Reproduce any of them with:
//     docker run -d --name p <image> ; sleep 45 ; docker diff p
// Trimmed only where a line is repetitive; the trimming is noted inline and
// never removes a line the classifier would treat differently.

/** leantime/leantime:latest, booted with no database reachable, 45 s.
 *  `docker inspect leantime/leantime:latest --format '{{json .Config.Volumes}}'`
 *  -> null. THE canonical blind spot: a real catalogue app that declares no
 *  volume and has plainly written its state to /var/www/html/storage. */
const LEANTIME = `C /run
A /run/nginx.pid
A /run/supervisord.pid
C /var
C /var/lib
C /var/lib/nginx
C /var/lib/nginx/tmp
A /var/lib/nginx/tmp/client_body
A /var/lib/nginx/tmp/fastcgi
A /var/lib/nginx/tmp/proxy
A /var/lib/nginx/tmp/scgi
A /var/lib/nginx/tmp/uwsgi
C /var/www
C /var/www/html
C /var/www/html/bootstrap
C /var/www/html/bootstrap/cache
A /var/www/html/bootstrap/cache/packages.php
A /var/www/html/bootstrap/cache/services.php
C /var/www/html/storage
C /var/www/html/storage/framework
C /var/www/html/storage/framework/cache
A /var/www/html/storage/framework/cache/9488295cf8ae109416a5057063fcd76a
A /var/www/html/storage/framework/cache/9488295cf8ae109416a5057063fcd76a/data
A /var/www/html/storage/framework/cache/9488295cf8ae109416a5057063fcd76a/data/a1
A /var/www/html/storage/framework/cache/9488295cf8ae109416a5057063fcd76a/data/a1/2d
A /var/www/html/storage/framework/cache/installation
A /var/www/html/storage/framework/cache/installation/data
A /var/www/html/storage/framework/cache/installation/data/24
A /var/www/html/storage/framework/cache/installation/data/24/26
A /var/www/html/storage/framework/cache/installation/data/24/26/24268a29ca39486cb5cc61f59ff7dd2fa12c6c44
A /var/www/html/storage/framework/cache/installation/data/fb
A /var/www/html/storage/framework/cache/installation/data/fb/e7
A /var/www/html/storage/framework/cache/installation/data/fb/e7/fbe7ac3a513614401e9e11b91f1f03f343c4c3e6
C /var/www/html/storage/framework/sessions
A /var/www/html/storage/framework/sessions/vKEQH5fZnknLb8RhdZWtO2UA9gYpXdI0956hkYbu
A /var/www/html/storage/framework/viewPaths.php
C /var/www/html/storage/logs
A /var/www/html/storage/logs/leantime-2026-09-11.log
C /var/log
C /var/log/nginx
A /var/log/nginx/error.log
C /tmp
A /tmp/nginx-stderr---supervisor-4zrok956.log
A /tmp/nginx-stdout---supervisor-i89lncyg.log
`;

/** php:8.3-apache — the base the nine PHP catalogue apps build on. Its ENTIRE
 *  writable layer after boot is one pid file. */
const PHP_APACHE = `C /run
C /run/apache2
A /run/apache2/apache2.pid
`;

/** mariadb:11.4. Declares VOLUME /var/lib/mysql, so its real data sits in an
 *  anonymous volume and is excluded from the diff — the declared-VOLUME half of
 *  the guard is what covers that. All the writable layer holds is a socket and
 *  a pid. */
const MARIADB = `C /run
C /run/mysqld
A /run/mysqld/mysqld.sock
A /run/mysqld/mysqld.pid
`;

/** vectorim/element-web:latest — an nginx static site with genuinely no state.
 *  Its entrypoint templates /etc/nginx/conf.d/default.conf on every boot, and
 *  nginx creates its scratch dirs under /tmp. */
const ELEMENT_WEB = `C /tmp
A /tmp/fastcgi_temp
A /tmp/nginx.pid
A /tmp/proxy_temp
A /tmp/scgi_temp
A /tmp/uwsgi_temp
A /tmp/client_temp
A /tmp/element-web-config
A /tmp/element-web-config/config.json
C /etc
C /etc/nginx
C /etc/nginx/conf.d
C /etc/nginx/conf.d/default.conf
`;

/** redis:8-alpine started with `--save 20 1`, one key set, one BGSAVE.
 *  Config.Volumes is null on this image, so the entire database is writable
 *  layer — and it is ONE diff entry. */
const REDIS_SAVE = `C /data
A /data/dump.rdb
`;

/** alpine:3.20 writing the things a plausible-but-unmeasured ignore list would
 *  have got wrong. Produced by:
 *    sh -c 'echo s > /dev/shm/shmfile; mkdir -p /var/cache/myapp && echo c > /var/cache/myapp/c.bin;
 *           mkdir -p /var/tmp/scratch && echo t > /var/tmp/scratch/t.bin;
 *           mkdir -p /var/lib/postgresql/data/base && echo pg > /var/lib/postgresql/data/base/1.db;
 *           rm -f /etc/motd; echo appended >> /etc/hosts;
 *           mkdir -p /srv/app/uploads && echo up > /srv/app/uploads/u.bin'
 *  Note what is ABSENT: /dev/shm/shmfile and /etc/hosts never appear, because
 *  both are mounts rather than writable layer. */
const MIXED = `C /etc
D /etc/motd
C /srv
A /srv/app
A /srv/app/uploads
A /srv/app/uploads/u.bin
C /var
C /var/cache
A /var/cache/myapp
A /var/cache/myapp/c.bin
C /var/lib
A /var/lib/postgresql
A /var/lib/postgresql/data
A /var/lib/postgresql/data/base
A /var/lib/postgresql/data/base/1.db
C /var/tmp
A /var/tmp/scratch
A /var/tmp/scratch/t.bin
`;

/** alpine:3.20 with a bind at /data, writing both inside and outside it:
 *    -v "$W/mnt:/data" sh -c 'echo M > /data/inmount.txt;
 *       mkdir -p /data/nested/deep && echo N > /data/nested/deep/deepfile.txt;
 *       mkdir -p /var/www/html/storage && echo U > /var/www/html/storage/db.sqlite; ...'
 *  Neither /data/inmount.txt nor /data/nested/deep/deepfile.txt appears — a
 *  mount excludes its content at any depth. But `A /data` DOES, because the
 *  mount POINT had to be created. */
const BOUND_DATA = `C /tmp
A /tmp/noise.log
A /data
C /var
A /var/www
A /var/www/html
A /var/www/html/storage
A /var/www/html/storage/db.sqlite
A /var/www/html/storage/framework
C /var/log
A /var/log/app.log
`;

const report = (raw, mountDestinations = []) =>
  risk.classifyWrittenPaths({ diff: risk.parseDockerDiff(raw), mountDestinations });
const paths = (raw, mounts = []) => report(raw, mounts).written.map((w) => w.path);

// ===========================================================================
// 1. Parsing
// ===========================================================================

describe('parseDockerDiff', () => {
  test('reads the three kinds and normalises the path', () => {
    assert.deepEqual(risk.parseDockerDiff('A /a\nC /b/\nD /c/./d\n'), [
      { kind: 'A', path: '/a' }, { kind: 'C', path: '/b' }, { kind: 'D', path: '/c/d' },
    ]);
  });

  test('a path containing spaces survives intact', () => {
    // Only the FIRST space separates kind from path. Splitting on whitespace
    // would silently truncate '/data/My Documents' to '/data/My' and then
    // report a directory that does not exist.
    assert.deepEqual(risk.parseDockerDiff('A /var/www/My App/state.db'),
      [{ kind: 'A', path: '/var/www/My App/state.db' }]);
  });

  test('lines that are not entries are dropped rather than parsed as paths', () => {
    assert.deepEqual(risk.parseDockerDiff('\nWARNING: something\nA /keep\nZ /nope\nA\n'),
      [{ kind: 'A', path: '/keep' }]);
  });
});

// ===========================================================================
// 2. The apps that must NOT be gated
// ===========================================================================
//
// Every one of these is a real image. A regression here does not break a
// feature, it destroys the feature: an operator who sees the dialog on an app
// with no state learns to dismiss it without reading.

describe('no false alarms', () => {
  test('php:8.3-apache — a pid file is not state', () => {
    assert.deepEqual(paths(PHP_APACHE), []);
  });

  test('mariadb:11.4 — a socket and a pid are not state', () => {
    assert.deepEqual(paths(MARIADB, ['/var/lib/mysql']), []);
  });

  test('element-web — nginx scratch and a regenerated config are not state', () => {
    assert.deepEqual(paths(ELEMENT_WEB), []);
  });

  test('an image that wrote nothing reports nothing', () => {
    assert.deepEqual(paths(''), []);
  });

  test("AppCrane's always-on /data bind is never reported, mount point included", () => {
    // `A /data` is in the diff because the mount point had to be created, and
    // AppCrane bind-mounts /data into EVERY container it starts. A classifier
    // that did not drop mount destinations would therefore fire on every single
    // app AppCrane runs — the most expensive possible false positive.
    assert.ok(!paths(BOUND_DATA, ['/data']).includes('/data'));
  });

  test('content nested under a mount is not reported either', () => {
    // Docker already excludes it from the diff, but the classifier must not
    // re-introduce it when a diff does list something beneath a mount.
    assert.deepEqual(
      paths('A /data\nA /data/nested\nA /data/nested/deep/file.txt\n', ['/data']),
      [],
    );
  });

  test('a mount deeper than the reported directory still suppresses it', () => {
    assert.deepEqual(paths('A /srv/app/uploads/u.bin\n', ['/srv/app/uploads']), []);
  });
});

// ===========================================================================
// 3. The apps that MUST be gated
// ===========================================================================

describe('real written state is reported', () => {
  test('leantime — a real catalogue app with NO image VOLUME — reports its storage dir', () => {
    // The whole point of the feature. Config.Volumes is null on this image, so
    // the declared-VOLUME rule calls it safe and the redeploy eats it.
    assert.deepEqual(paths(LEANTIME), ['/var/www/html/storage']);
  });

  test('leantime reports ONE actionable directory, not 30 files', () => {
    // The operator's question is "what do I add to volume_paths". 53 raw diff
    // lines have to come back as something they can act on.
    const r = report(LEANTIME);
    assert.ok(r.considered > 20, `expected a large raw diff to collapse, got ${r.considered} entries`);
    assert.equal(r.written.length, 1, `collapsed to ${JSON.stringify(r.written)}`);
    assert.equal(r.truncated, 0);
    assert.ok(r.ignored > 0, 'the noise must be counted, not silently vanished');
  });

  test('a database in the writable layer is reported even when it is ONE file', () => {
    // redis:8-alpine declares no VOLUME, so `--save` puts the entire database
    // in the writable layer as a single diff entry. This is the case that
    // rules out a file-count threshold: the smallest real state and the
    // smallest noise (php-apache's lone pid file) are the same size, so count
    // cannot separate them in either direction.
    assert.deepEqual(paths(REDIS_SAVE), ['/data']);
  });

  test('/var/lib is not blanket-ignored, so a postgres data dir is still caught', () => {
    // leantime writes /var/lib/nginx/tmp, which is noise — but /var/lib is also
    // where the canonical data directories live. Suppressing the whole of
    // /var/lib would suppress exactly what this feature exists to find.
    assert.ok(paths(MIXED).includes('/var/lib/postgresql/data'));
  });

  test('/var/lib/nginx/tmp is dropped without taking /var/lib with it', () => {
    assert.ok(!paths(LEANTIME).some((p) => p.startsWith('/var/lib/nginx')));
  });

  test('an app writing outside every known root is reported', () => {
    assert.ok(paths(MIXED).includes('/srv/app/uploads'));
  });

  test('a file the IMAGE shipped and the container changed in place is state', () => {
    // A childless `C` is a modified existing file — e.g. a sqlite database
    // baked into the image and then written to. Treating every `C` as
    // scaffolding would drop it.
    assert.deepEqual(paths('C /app/db.sqlite\n'), ['/app']);
  });

  test('a deletion is a change to the writable layer too', () => {
    assert.deepEqual(paths('D /srv/data/records/r1\n'), ['/srv/data/records']);
  });
});

// ===========================================================================
// 4. Roll-up — the shape of the answer
// ===========================================================================

describe('roll-up', () => {
  test('a deep path is reported as the directory an operator can mount', () => {
    assert.deepEqual(
      paths('A /var/www/html/storage/framework/sessions/a/b/c/deadbeef\n'),
      ['/var/www/html/storage'],
    );
  });

  test('a shallow leaf is reported as its parent directory, not as a filename', () => {
    // '/data/dump.rdb' is a file. Telling an operator to add a FILE to
    // volume_paths is telling them to do the wrong thing.
    assert.deepEqual(paths('A /data/dump.rdb\n'), ['/data']);
    assert.deepEqual(paths('A /srv/app/uploads/u.bin\n'), ['/srv/app/uploads']);
  });

  test('interior nodes are not reported alongside their own children', () => {
    // `docker diff` emits every ancestor of a change as its own line. Reporting
    // both /srv/app and /srv/app/uploads tells the operator to mount the same
    // bytes twice.
    assert.deepEqual(paths('A /srv/app\nA /srv/app/uploads\nA /srv/app/uploads/u.bin\n'), ['/srv/app/uploads']);
  });

  test('a reported directory containing another is collapsed onto the outer one', () => {
    const p = paths('A /srv/data/a.bin\nA /srv/data/inner/deeper/b.bin\n');
    assert.deepEqual(p, ['/srv/data']);
  });

  test('sibling directories stay separate — mounting one does not cover the other', () => {
    const p = paths('A /srv/uploads/u.bin\nA /opt/records/r.bin\n');
    assert.deepEqual(p.sort(), ['/opt/records', '/srv/uploads']);
  });

  test('the list is bounded, and what was elided is counted rather than dropped', () => {
    let raw = '';
    for (let i = 0; i < 40; i++) raw += `A /srv/d${i}/f.bin\n`;
    const r = report(raw);
    assert.equal(r.written.length, 12, 'a confirmation dialog listing 40 directories is a dialog nobody reads');
    assert.equal(r.truncated, 28, 'the elided directories must be counted, not silently discarded');
  });

  test('the busiest directory is reported first', () => {
    let raw = 'A /srv/small/one.bin\n';
    for (let i = 0; i < 9; i++) raw += `A /srv/big/f${i}.bin\n`;
    assert.deepEqual(paths(raw), ['/srv/big', '/srv/small']);
  });
});

// ===========================================================================
// 5. The verdict — and keeping the two kinds of at-risk apart
// ===========================================================================

describe('assessRedeployRisk with a writable layer', () => {
  const app = { id: 1, slug: 'wl-app' };
  const wasLive = { prepare: () => ({ get: () => ({ 1: 1 }) }) };
  const assess = (state) => risk.assessRedeployRisk({ db: wasLive, app, env: 'production', inspect: async () => state });

  test('a Laravel-shaped app with NO image VOLUME is now gated', async () => {
    const v = await assess({
      present: true, imageVolumes: [], bindDestinations: ['/data'], mountDestinations: ['/data'],
      diff: risk.parseDockerDiff(LEANTIME),
    });
    assert.equal(v.at_risk, true, 'this is the exact failure the guard exists to prevent');
    assert.equal(v.unknown, false);
    assert.deepEqual(v.written_paths, ['/var/www/html/storage']);
    assert.deepEqual(v.at_risk_paths, [], 'the image declares nothing, so the VOLUME list must stay empty');
    assert.equal(v.reason, 'writable-layer');
  });

  test('the two kinds of at-risk are distinguishable in the verdict', async () => {
    const v = await assess({
      present: true, imageVolumes: ['/config'], bindDestinations: ['/data'], mountDestinations: ['/data'],
      diff: risk.parseDockerDiff(LEANTIME),
    });
    // The PROPERTY: a caller can tell "your image declares /config and nothing
    // mounts it" from "this app has written to /var/www/html/storage" without
    // having to parse prose.
    assert.deepEqual(v.at_risk_paths, ['/config']);
    assert.deepEqual(v.written_paths, ['/var/www/html/storage']);
    assert.equal(v.reason, 'undeclared-volumes+writable-layer');
    assert.notDeepEqual(v.at_risk_paths, v.written_paths);
    // ...and the summary, which is the ONLY channel an MCP error has, carries
    // both claims with their different evidence.
    assert.match(v.summary, /the image declares them as volumes/);
    assert.match(v.summary, /WRITTEN to paths its image never declared/);
    assert.match(v.summary, /docker diff/);
  });

  test('the entry count reaches the operator', async () => {
    const v = await assess({
      present: true, imageVolumes: [], bindDestinations: ['/data'], mountDestinations: ['/data'],
      diff: risk.parseDockerDiff(LEANTIME),
    });
    const detail = v.written_detail.find((w) => w.path === '/var/www/html/storage');
    assert.ok(detail && detail.entries > 0, JSON.stringify(v.written_detail));
    assert.ok(v.summary.includes(`${detail.entries} written path`),
      `the summary must quote the magnitude it computed: ${v.summary}`);
  });

  test('an app whose writable layer is pure scratch is still NOT gated', async () => {
    const v = await assess({
      present: true, imageVolumes: ['/config'], bindDestinations: ['/data', '/config'],
      mountDestinations: ['/data', '/config'], diff: risk.parseDockerDiff(PHP_APACHE),
    });
    assert.equal(v.at_risk, false, 'a safe app must never be nagged — that is what trains the click-through');
    assert.equal(v.reason, 'all-declared');
    assert.deepEqual(v.written_paths, []);
  });

  test('an unreadable writable layer is at-risk, never silently clean', async () => {
    // The three-state model. A diff that timed out, was killed, or overflowed
    // its buffer must not read as "this app has written nothing".
    const v = await assess({
      present: true, imageVolumes: [], bindDestinations: ['/data'], mountDestinations: ['/data'],
      diff: [], diffError: 'stdout maxBuffer length exceeded',
    });
    assert.equal(v.at_risk, true, 'unknown must never resolve to safe');
    assert.equal(v.writable_layer_unknown, true);
    assert.equal(v.reason, 'writable-layer-unknown');
    assert.notEqual(v.reason, 'all-declared');
    assert.match(v.summary, /could NOT be read/);
  });

  test('a declared-VOLUME app whose diff failed keeps BOTH findings', async () => {
    const v = await assess({
      present: true, imageVolumes: ['/config'], bindDestinations: ['/data'], mountDestinations: ['/data'],
      diff: [], diffError: 'context deadline exceeded',
    });
    assert.deepEqual(v.at_risk_paths, ['/config']);
    assert.equal(v.writable_layer_unknown, true);
    assert.equal(v.reason, 'undeclared-volumes+writable-layer');
  });

  test('a container that does not exist is still not gated', async () => {
    const v = await risk.assessRedeployRisk({
      db: wasLive, app, env: 'production', inspect: async () => ({ present: false }),
    });
    assert.equal(v.at_risk, false);
    assert.deepEqual(v.written_paths, []);
  });

  test('the safe summary says the writable layer was actually looked at', async () => {
    const v = await assess({
      present: true, imageVolumes: [], bindDestinations: ['/data'], mountDestinations: ['/data'],
      diff: risk.parseDockerDiff(PHP_APACHE),
    });
    assert.equal(v.at_risk, false);
    assert.match(v.summary, /writable layer/);
  });
});

// ===========================================================================
// 6. LIVE — against the real daemon
// ===========================================================================

describe('LIVE writable layer', { skip: liveSkip }, () => {
  const SUFFIX = `wl${process.pid}`;
  const CN_LOOSE = `crane-wl-loose-${SUFFIX}`;
  const CN_BOUND = `crane-wl-bound-${SUFFIX}`;
  const CN_BIG = `crane-wl-big-${SUFFIX}`;
  const HOST_DIR = join(process.env.DATA_DIR, 'wlbind');
  const IMAGE = 'alpine:3.20';

  // A Laravel-shaped app: writes to /var/www/html/storage, declares no VOLUME,
  // and makes the usual scratch noise alongside it.
  const APP = 'mkdir -p /var/www/html/storage/framework/sessions '
    + '&& echo STATE > /var/www/html/storage/db.sqlite '
    + '&& echo S > /var/www/html/storage/framework/sessions/sess1 '
    + '&& echo log > /tmp/noise.log && mkdir -p /var/log && echo l > /var/log/app.log '
    + '&& mkdir -p /run/app && echo p > /run/app/app.pid && sleep 900';

  let problem = null;
  const dk = (args, timeout = 180000) =>
    execFileAsync(REAL_DOCKER, args, { timeout, maxBuffer: 64 * 1024 * 1024 }).then((r) => r.stdout);

  before(async () => {
    process.env.PATH = REAL_PATH;
    mkdirSync(HOST_DIR, { recursive: true });
    try {
      await dk(['run', '-d', '--name', CN_LOOSE, IMAGE, 'sh', '-c', APP]);
      // The CONTROL: byte-identical app, with the storage dir bind-mounted.
      await dk(['run', '-d', '--name', CN_BOUND,
        '-v', `${HOST_DIR}:/var/www/html/storage`, IMAGE, 'sh', '-c', APP]);
      await new Promise((r) => setTimeout(r, 3000));
    } catch (e) {
      problem = `could not prepare live fixtures: ${String(e.message).split('\n')[0].slice(0, 160)}`;
    }
  });

  after(async () => {
    for (const n of [CN_LOOSE, CN_BOUND, CN_BIG]) await dk(['rm', '-fv', n], 120000).catch(() => {});
  });

  test('an app with no VOLUME and an unmounted storage dir reads as at risk', async (t) => {
    if (problem) return t.skip(problem);
    const state = await risk.inspectContainerState(CN_LOOSE);
    assert.equal(state.present, true, JSON.stringify(state));
    assert.deepEqual(state.imageVolumes, [],
      'the image must declare nothing, or this is not measuring the writable-layer path at all');
    assert.equal(state.diffError, undefined, `docker diff failed: ${state.diffError}`);
    assert.deepEqual(risk.classifyWrittenPaths({
      diff: state.diff, mountDestinations: state.mountDestinations,
    }).written.map((w) => w.path), ['/var/www/html/storage']);
  });

  test('CONTROL: the identical app with that path bind-mounted reads as safe', async (t) => {
    if (problem) return t.skip(problem);
    // Without this control, a pass above could just mean the classifier reports
    // /var/www/html/storage unconditionally.
    const state = await risk.inspectContainerState(CN_BOUND);
    assert.equal(state.present, true, JSON.stringify(state));
    assert.deepEqual(state.bindDestinations, ['/var/www/html/storage']);
    assert.deepEqual(risk.classifyWrittenPaths({
      diff: state.diff, mountDestinations: state.mountDestinations,
    }).written, [],
      'CONTROL FAILED: a bind-mounted storage dir was still reported, so the pass above cannot be ' +
      'attributed to the path being unprotected');
  });

  test('the real daemon really does exclude mounted content from the diff', async (t) => {
    if (problem) return t.skip(problem);
    // The single measurement the whole design rests on, re-measured rather than
    // taken on faith.
    const state = await risk.inspectContainerState(CN_BOUND);
    const inside = state.diff.filter((e) => e.path.startsWith('/var/www/html/storage/'));
    assert.deepEqual(inside, [],
      `docker diff listed content inside a bind mount, so mounted paths do NOT filter themselves out: ` +
      JSON.stringify(inside));
  });

  test('a diff too large for the buffer is UNKNOWN, not an empty writable layer', async (t) => {
    if (problem) return t.skip(problem);
    // The failure mode that would quietly un-gate the biggest apps: execFile
    // rejects with ERR_CHILD_PROCESS_STDIO_MAXBUFFER and hands back a TRUNCATED
    // stdout, which parses perfectly well into a short, wrong answer. Forced
    // here with a tiny buffer against a container that really does have more
    // writable layer than that.
    const err = await execFileAsync(REAL_DOCKER, ['diff', CN_LOOSE], { maxBuffer: 8 })
      .then(() => null, (e) => e);
    assert.ok(err, 'the fixture is too small to overflow an 8-byte buffer — this test is not testing anything');
    assert.equal(err.code, 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER');
    assert.ok(String(err.stdout || '').length <= 8 + 64,
      'an overflow returns a PREFIX of stdout, which is what makes parsing it dangerous');
  });

  test('docker diff on a large writable layer stays inside the deploy-path budget', async (t) => {
    if (problem) return t.skip(problem);
    // This runs synchronously while an operator waits on a confirmation dialog,
    // so its cost is a property of the feature, not an implementation detail.
    await dk(['run', '-d', '--name', CN_BIG, IMAGE, 'sh', '-c',
      'mkdir -p /var/www/html/storage/d && for j in $(seq 1 4000); do echo x > /var/www/html/storage/d/f$j; done; '
      + 'touch /var/www/html/storage/DONE; sleep 900']);
    for (let i = 0; i < 60; i++) {
      const ok = await dk(['exec', CN_BIG, 'sh', '-c', 'test -f /var/www/html/storage/DONE && echo y || true'])
        .catch(() => '');
      if (ok.includes('y')) break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    const t0 = Date.now();
    const state = await risk.inspectContainerState(CN_BIG);
    const ms = Date.now() - t0;
    assert.equal(state.diffError, undefined, `diff failed on a large layer: ${state.diffError}`);
    assert.ok(state.diff.length > 4000, `expected a large diff, got ${state.diff.length} entries`);
    assert.ok(ms < 15000, `inspect + diff took ${ms} ms, which is too long to hold a deploy confirmation`);
    // ...and it still comes back as ONE directory rather than 4,000 files.
    assert.deepEqual(risk.classifyWrittenPaths({
      diff: state.diff, mountDestinations: state.mountDestinations,
    }).written.map((w) => w.path), ['/var/www/html/storage']);
  });
});
