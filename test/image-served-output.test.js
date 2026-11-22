import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawnSync } from 'child_process';
import { randomBytes } from 'crypto';

// served_secrets for a production-only build: the served output is copied out
// of the image the deploy just built (docker create + docker cp, never run) and
// scanned with the committed-output matcher. Real Docker: the images are FROM
// scratch, so nothing is pulled, and they are removed at the end.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-imgout-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug', 'error']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { scanImageServedOutput, imageOutputDirs } = await import('../server/services/imageServedOutput.js');
const { docker } = await import('../server/services/preflightCheck.js');
const rc = await import('../server/services/releaseCheck.js');
const { emptySupabase } = await import('../server/services/servedOutputScan.js');

const HAVE_DOCKER = spawnSync('docker', ['version', '--format', '{{.Server.Version}}']).status === 0;
const TAG = `appcrane-test-imgout-${randomBytes(4).toString('hex')}`;
const images = [];
const LEAK = 'sk_live_' + 'Q'.repeat(4) + 'abcdefghijklmnopqrstu';

function buildImage(name, files, dockerfile) {
  const ctx = mkdtempSync(join(ROOT, 'ctx-'));
  for (const [p, body] of Object.entries(files)) {
    mkdirSync(join(ctx, p, '..'), { recursive: true });
    if (body && body.symlink) symlinkSync(body.symlink, join(ctx, p)); else writeFileSync(join(ctx, p), body);
  }
  writeFileSync(join(ctx, 'Dockerfile'), dockerfile);
  const tag = `${TAG}-${name}`;
  execFileSync('docker', ['build', '-q', '-t', tag, ctx], { stdio: ['ignore', 'ignore', 'inherit'] });
  images.push(tag);
  return tag;
}
const servedTemps = () => readdirSync(tmpdir()).filter((n) => n.startsWith('appcrane-served-'));
const leftoverContainers = (tag) => execFileSync('docker', ['ps', '-a', '-q', '--filter', `ancestor=${tag}`], { encoding: 'utf8' }).trim();

let WITH_DIST, NGINX, EMPTY, BIG;
before(() => {
  if (!HAVE_DOCKER) return;
  WITH_DIST = buildImage('dist', {
    'dist/index.html': '<!doctype html><script src="/assets/app.js"></script>',
    'dist/assets/app.js': `const stripe = "${LEAK}";\n`,
    'dist/.env': 'API_TOKEN=abc\nOTHER=1\n',
    'dist/logo.png': Buffer.alloc(2048, 7),
    'dist/passwd.js': { symlink: '/etc/passwd' },
    'server.js': `const k = "${LEAK}";\n`,
  }, 'FROM scratch\nCOPY dist /app/dist\nCOPY server.js /app/server.js\n');
  NGINX = buildImage('nginx', { 'site/index.html': '<!doctype html><p>clean</p>' }, 'FROM scratch\nCOPY site /usr/share/nginx/html\n');
  EMPTY = buildImage('empty', { 'server.js': 'console.log(1)\n' }, 'FROM scratch\nCOPY server.js /app/server.js\n');
  BIG = buildImage('big', { 'dist/huge.js': Buffer.alloc(9 * 1024 * 1024, 0x61), 'dist/ok.js': 'ok\n' }, 'FROM scratch\nCOPY dist /app/dist\n');
});
after(() => {
  for (const t of images) spawnSync('docker', ['rmi', '-f', t]);
  rc._setReleaseCheckDepsForTests(null);
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

test('the output directories follow the generated Dockerfile layout, with fe.workdir/fe.dist first', () => {
  const dirs = imageOutputDirs({ fe: { workdir: 'client', dist: 'out-web' } });
  assert.equal(dirs[0], '/app/client/out-web');
  assert.ok(dirs.includes('/app/dist') && dirs.includes('/usr/share/nginx/html'));
  assert.deepEqual(imageOutputDirs({ fe: { workdir: '../etc', dist: '/x/../y' } }), imageOutputDirs(null), 'an unsafe manifest path is ignored');
});

test('a secret in /app/dist of a built image is found, the image is never started, and nothing is left behind', { skip: !HAVE_DOCKER && 'docker not available' }, async () => {
  const calls = [];
  const before = servedTemps();
  const r = await scanImageServedOutput({ image: WITH_DIST, runDocker: (args, o) => { calls.push(args); return docker(args, o); } });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.dirs, ['/app/dist']);
  assert.deepEqual(r.scan.findings.map((f) => [f.file, f.rule]).sort(), [['/app/dist/.env', 'served-env-file'], ['/app/dist/assets/app.js', 'stripe-live-secret']]);
  assert.ok(!r.scan.findings.some((f) => f.preview.includes(LEAK)), 'the value is redacted');
  assert.ok(!r.scan.scanned.some((s) => /passwd|logo|server\.js/.test(s.path)), 'no link, binary or non-output file was scanned');
  assert.deepEqual(calls[0].slice(0, 5), ['create', '--pull', 'never', '--network', 'none']);
  assert.ok(!calls.some((a) => ['start', 'run', 'exec'].includes(a[0])), 'the image was never run');
  assert.equal(calls.at(-1)[0], 'rm');
  assert.equal(leftoverContainers(WITH_DIST), '');
  assert.deepEqual(servedTemps(), before, 'the temp dir is removed');
});

test('an nginx-layout image is read from /usr/share/nginx/html', { skip: !HAVE_DOCKER && 'docker not available' }, async () => {
  const r = await scanImageServedOutput({ image: NGINX });
  assert.deepEqual(r.dirs, ['/usr/share/nginx/html']);
  assert.equal(r.scan.findings.length, 0);
  assert.deepEqual(r.scan.scanned.map((s) => s.path), ['/usr/share/nginx/html/index.html']);
});

test('an oversize text file is not read and marks the scan truncated', { skip: !HAVE_DOCKER && 'docker not available' }, async () => {
  const r = await scanImageServedOutput({ image: BIG });
  assert.equal(r.scan.truncated, true);
  assert.deepEqual(r.scan.scanned.map((s) => s.path), ['/app/dist/ok.js']);
});

test('an image that is not on the host is an error, never pulled', { skip: !HAVE_DOCKER && 'docker not available' }, async () => {
  const r = await scanImageServedOutput({ image: `${TAG}-absent:none` });
  assert.equal(r.ok, false);
  assert.match(r.error, /docker create exited/);
});

test('the deadline bounds the copy: directories after it are not read', async () => {
  const fake = async (args, o) => {
    if (args[0] === 'cp') { await new Promise((res) => setTimeout(res, 300)); return 1; }
    return 0;
  };
  const t0 = Date.now();
  const r = await scanImageServedOutput({ image: 'x', runDocker: fake, deadlineMs: 500 });
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(r.truncated, true);
});

// --- the release check ---------------------------------------------------

let slot = 400;
function mkApp(slug) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'managed')").run(slug, slug, slot++).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const tree = (files) => {
  const dir = mkdtempSync(join(ROOT, 'tree-'));
  for (const [p, b] of Object.entries(files)) { mkdirSync(join(dir, p, '..'), { recursive: true }); writeFileSync(join(dir, p), b); }
  return dir;
};
const served = async (app, ctx) => (await rc.runReleaseCheck({ db, app, trigger: 'deploy', ...ctx })).checks.find((c) => c.id === 'served_secrets');
const base = {
  scanTree: async () => ({ status: 'ok', findings_json: null }),
  probeUnauth: async () => ({ ok: true, error: null, openapi: null, requests: 1, truncated: false, discovered: {}, skipped: {}, reads: [], writes: [], write_candidates: [] }),
  crawlServed: async () => ({ ok: true, error: null, findings: [], scanned: [], truncated: false, html: true, supabase: emptySupabase() }),
};

test('release check: a production-only build with no committed dist fails served_secrets from its built image', { skip: !HAVE_DOCKER && 'docker not available' }, async () => {
  rc._setReleaseCheckDepsForTests(base);
  const app = mkApp('imgout-fail');
  const c = await served(app, { releaseDir: tree({ 'package.json': '{}' }), commit: 'c1', image: WITH_DIST });
  assert.equal(c.status, 'fail', JSON.stringify(c));
  assert.match(c.reasons[0], new RegExp(`^Built image ${TAG}-dist \\(/app/dist\\): 2 credential`));
  assert.ok(c.reasons.some((r) => r.startsWith('/app/dist/assets/app.js:1 (stripe-live-secret')));
});

test('release check: the built image is read ahead of a stale committed dist', { skip: !HAVE_DOCKER && 'docker not available' }, async () => {
  rc._setReleaseCheckDepsForTests(base);
  const app = mkApp('imgout-order');
  const c = await served(app, { releaseDir: tree({ 'dist/index.html': '<p>clean</p>' }), commit: 'c2', image: WITH_DIST });
  assert.equal(c.status, 'fail', JSON.stringify(c));
});

test('release check: an image with no output directory falls back, and says why', { skip: !HAVE_DOCKER && 'docker not available' }, async () => {
  rc._setReleaseCheckDepsForTests(base);
  const app = mkApp('imgout-none');
  const c = await served(app, { releaseDir: tree({ 'package.json': '{}' }), commit: 'c3', image: EMPTY });
  assert.equal(c.status, 'warn');
  assert.match(c.reasons[1], /the built image has none of the known output directories/);
  const committed = await served(app, { releaseDir: tree({ 'dist/a.js': `x = "${LEAK}"` }), commit: 'c4', image: EMPTY });
  assert.equal(committed.status, "fail", JSON.stringify(committed));
  assert.match(committed.reasons[0], /^Built output committed to the release/);
});

test('enforceReleaseCheckInDeploy hands the built image and manifest to the scan', async () => {
  let seen = null;
  rc._setReleaseCheckDepsForTests({ ...base, scanImageOutput: async (a) => { seen = a; return { ok: true, error: null, dirs: [], scan: null }; } });
  const app = mkApp('imgout-enforce');
  const dep = db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'deploying')").run(app.id).lastInsertRowid;
  const manifest = { fe: { workdir: 'web', dist: 'dist' } };
  await rc.enforceReleaseCheckInDeploy({ app, deployId: dep, releaseDir: tree({ 'package.json': '{}' }), commit: 'c5', image: 'appcrane-x:abc', manifest }).catch(() => {});
  assert.deepEqual(seen, { image: 'appcrane-x:abc', manifest });
});

test('a tree secret scan earlier in the run does not blind the served-output matcher', async () => {
  const { scanTreeForSecrets, secretMatches } = await import('../server/services/releaseSecretScan.js');
  const text = `x = "${LEAK}"`;
  scanTreeForSecrets(tree({ 'a.js': `${' '.repeat(40)}${text}` }));
  assert.equal(secretMatches(text).length, 1);
});
