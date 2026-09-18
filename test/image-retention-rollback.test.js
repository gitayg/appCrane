import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

// deploy -> deploy -> rollback, driven through the real deployer, counting
// `docker build`.
//
// The claim under test is the one appcrane_rollback has always made in its own
// description: rolling back to the previous release re-uses that release's
// cached per-commit image instead of rebuilding it. rollbackApp re-runs
// deployApp with the target deployment's commit_hash, and
// docker.js:buildImageIfNeeded skips the build ONLY while an image tagged
// `appcrane-<slug>-<env>:<commit>` is still on the host. Whether it is comes
// down to one number: deployApp prunes with keep = image_retention + 1 at the
// end of every successful deploy, so at image_retention = 0 the previous
// commit's image is deleted by the deploy that supersedes it and the promise
// could never hold. That was the shipped default until v2.78.0.
//
// So the assertion is a BUILD COUNT, and it is measured off a docker shim that
// keeps a real image store: `build` adds a tag, `image inspect` succeeds only
// for tags that are present, `images --filter label=slug=` lists them newest
// first and `rmi` removes one. The prune arithmetic and the cache check are the
// production ones; nothing about them is stubbed.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-imgret-rb-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

// ---------------------------------------------------------------------------
// A `docker` with an image store
// ---------------------------------------------------------------------------

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const STORE = join(process.env.DATA_DIR, 'docker-images.json');
const CALL_LOG = join(process.env.DATA_DIR, 'docker-calls.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(STORE, JSON.stringify({ seq: 0, images: [] }));

// CommonJS: the file is named `docker` with no extension, so Node parses it as
// CJS and an `import` here would be a syntax error at spawn time — surfacing as
// an unexplained docker failure rather than as a test error.
writeFileSync(
  join(SHIM_DIR, 'docker'),
  `#!/usr/bin/env node
const { readFileSync, writeFileSync, appendFileSync } = require('fs');
const STORE = ${JSON.stringify(STORE)};
const LOG = ${JSON.stringify(CALL_LOG)};
const argv = process.argv.slice(2);
appendFileSync(LOG, argv.map(a => a + '\\n').join('') + '\\0');
const read = () => JSON.parse(readFileSync(STORE, 'utf8'));
const write = (s) => writeFileSync(STORE, JSON.stringify(s));
const ok = (out = '') => { process.stdout.write(out); process.exit(0); };
const nope = (msg) => { process.stderr.write(msg + '\\n'); process.exit(1); };
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const labels = () => {
  const out = {};
  argv.forEach((a, i) => { if (a === '--label' && argv[i + 1] && argv[i + 1].includes('=')) {
    const [k, ...v] = argv[i + 1].split('='); out[k] = v.join('=');
  } });
  return out;
};

if (argv[0] === 'version') ok('29.0.0\\n');
if (argv[0] === 'network' && argv[1] === 'inspect') ok('false|172.20.0.0/16\\n');
if (argv[0] === 'image' && argv[1] === 'prune') ok('');
if (argv[0] === 'ps') ok('');

if (argv[0] === 'build') {
  const tag = flagValue('-t');
  const lab = labels();
  const s = read();
  s.seq += 1;
  // CreatedAt is what pruneOldBuiltImages sorts on, with a plain string
  // compare. Zero-padded and monotonic so newest really is newest.
  const created = '2026-01-01 00:00:' + String(s.seq).padStart(2, '0') + ' +0000 UTC';
  s.images = s.images.filter((im) => im.tag !== tag);
  s.images.push({ id: 'sha256:' + String(s.seq).padStart(4, '0').repeat(16), tag, slug: lab.slug, env: lab.env, created });
  write(s);
  ok('');
}

if (argv[0] === 'image' && argv[1] === 'inspect') {
  const ref = argv[2];
  const im = read().images.find((i) => i.tag === ref || i.id === ref);
  if (!im) nope('Error: No such image: ' + ref);
  ok(im.id + '\\n');
}

if (argv[0] === 'images') {
  const slug = (flagValue('--filter') || '').startsWith('label=slug=')
    ? flagValue('--filter').slice('label=slug='.length) : null;
  const envFilter = argv.filter((a, i) => argv[i - 1] === '--filter' && a.startsWith('label=env='))
    .map((a) => a.slice('label=env='.length))[0] || null;
  let rows = read().images;
  if (slug) rows = rows.filter((i) => i.slug === slug);
  if (envFilter) rows = rows.filter((i) => i.env === envFilter);
  ok(rows.map((i) => i.id + ' ' + i.created).join('\\n') + (rows.length ? '\\n' : ''));
}

if (argv[0] === 'rmi') {
  const ref = argv[argv.length - 1];
  const s = read();
  s.images = s.images.filter((i) => i.id !== ref && i.tag !== ref);
  write(s);
  ok('');
}

if (argv[0] === 'run') ok('c'.repeat(64) + '\\n');
if (argv[0] === 'inspect') ok('\\n');
ok('\\n');
`,
  { mode: 0o755 },
);
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const calls = () => (existsSync(CALL_LOG) ? readFileSync(CALL_LOG, 'utf8') : '')
  .split('\0').filter((r) => r.trim() !== '').map((r) => r.split('\n').filter((l) => l !== ''));
const countWhere = (fn) => calls().filter(fn).length;
const buildCount = () => countWhere((c) => c[0] === 'build');
const pruneListings = () => countWhere((c) => c[0] === 'images' && c.some((t) => t.startsWith('label=slug=')));

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { deployApp, rollbackApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

// ---------------------------------------------------------------------------
// A real health endpoint on the slot's backend ports
// ---------------------------------------------------------------------------

const servers = [];
function serve(port) {
  return new Promise((res) => {
    const s = http.createServer((_req, out) => {
      out.writeHead(200, { 'content-type': 'application/json' });
      out.end(JSON.stringify({ status: 'ok', version: '1.0.0' }));
    });
    s.on('error', () => res(null));
    s.listen(port, '127.0.0.1', () => res(s));
  });
}

// Searched for, not hardcoded: deployApp derives the host port from apps.slot,
// so a fixed slot fails with EADDRINUSE whenever anything else holds that port.
// One free slot PER APP, because apps.slot is unique and each app's health
// probe goes to its own port — an app on an unserved slot fails the deploy on a
// 30-second health timeout that has nothing to do with image retention.
const FREE = [];
for (let slot = 13100; slot < 13300 && FREE.length < 2; slot++) {
  const ports = getPortsForSlot(slot);
  const sand = await serve(ports.sand_be);
  if (!sand) continue;
  const prod = await serve(ports.prod_be);
  if (!prod) { sand.close(); continue; }
  FREE.push({ slot, ports });
  servers.push(sand, prod);
}
assert.equal(FREE.length, 2, 'could not find two slots whose sandbox and production ports are all free');

let userId;
before(() => {
  userId = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','r@example.com','platform_admin','unused',1,'human')"
  ).run().lastInsertRowid;
});

after(() => {
  for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); }
});

// ---------------------------------------------------------------------------
// Driving one app through deploy / deploy / rollback
// ---------------------------------------------------------------------------

let slotCursor = 0;
const portsFor = new Map();
function makeApp(slug, retention) {
  const { slot, ports } = FREE[slotCursor++];
  db.prepare(
    "INSERT INTO apps (name, slug, slot, source_type, image_retention) VALUES (?, ?, ?, 'upload', ?)"
  ).run(slug, slug, slot, retention);
  portsFor.set(slug, ports);
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}

/** A release tree on disk, the way an extracted upload bundle leaves one. */
function makeRelease(slug, env, tag, version) {
  const dir = join(process.env.DATA_DIR, 'apps', slug, env, 'releases', `r-${tag}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: slug, version, main: 'index.js' }));
  writeFileSync(join(dir, 'index.js'), `// ${tag}\n`);
  return dir;
}

const tagsFor = (slug) => JSON.parse(readFileSync(STORE, 'utf8')).images
  .filter((i) => i.slug === slug).map((i) => i.tag).sort();

/**
 * One deploy, waited out to a settled image store.
 *
 * deployApp calls pruneOldImages WITHOUT awaiting it, so when deployApp
 * resolves the prune has usually not run yet. `expectImages` is the number this
 * app should hold afterwards, and the wait is on THAT — a deterministic
 * condition — rather than on elapsed time: a fixed sleep passes on an idle
 * machine and fails on a loaded one, which is how this test failed once inside
 * the full suite while passing on its own.
 *
 * Reaching the count is not the end of it when the count is already right
 * before the prune runs (keep = 2 with two images). So after the count matches,
 * wait for the shim to go quiet and check again — an over-prune shows up there.
 */
async function deploy(app, env, commitHash, releaseDir, expectImages) {
  const id = db.prepare(
    "INSERT INTO deployments (app_id, env, status, deployed_by, commit_hash) VALUES (?, ?, 'pending', ?, ?)"
  ).run(app.id, env, userId, commitHash).lastInsertRowid;
  const before = pruneListings();
  await deployApp(id, app, env, portsFor.get(app.slug), { preExtractedDir: releaseDir, commitHash });
  const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(id);
  assert.equal(row.status, 'live', `deploy ${commitHash} did not go live:\n${row.log}`);

  await waitFor(() => pruneListings() > before, `prune did not run after deploying ${commitHash}`);
  await waitFor(() => tagsFor(app.slug).length === expectImages,
    `after deploying ${commitHash}, ${app.slug} should hold ${expectImages} image(s), ` +
    `holds ${tagsFor(app.slug).length}: ${tagsFor(app.slug).join(', ')}`);
  await settle();
  assert.equal(tagsFor(app.slug).length, expectImages,
    `the prune kept going past ${expectImages} image(s) for ${app.slug}`);
  return id;
}

async function waitFor(pred, msg, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  assert.fail(msg);
}

/** Wait for the shim to go quiet — half a second with no docker call at all. */
async function settle(quietMs = 500, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let last = -1;
  let quietSince = Date.now();
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 50));
    const n = calls().length;
    if (n !== last) { last = n; quietSince = Date.now(); continue; }
    if (Date.now() - quietSince >= quietMs) return;
  }
}

const COMMIT_A = 'a'.repeat(40);
const COMMIT_B = 'b'.repeat(40);

test('at the default (1) a rollback to the previous release re-uses its image — no rebuild', async () => {
  const app = makeApp('ret-reuse', 1);
  const env = 'sandbox';

  const r1 = makeRelease(app.slug, env, 'one', '1.0.0');
  await deploy(app, env, COMMIT_A, r1, 1);
  assert.equal(buildCount(), 1, 'the first deploy has nothing cached and must build');

  const r2 = makeRelease(app.slug, env, 'two', '1.0.1');
  await deploy(app, env, COMMIT_B, r2, 2);
  assert.equal(buildCount(), 2, 'a new commit must build');

  assert.deepEqual(tagsFor(app.slug), [
    `appcrane-${app.slug}-${env}:${COMMIT_A}`,
    `appcrane-${app.slug}-${env}:${COMMIT_B}`,
  ].sort(), 'the prune must keep TWO images at image_retention = 1 — the running one and the previous one');

  const fresh = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  await rollbackApp(fresh, env, null, userId);

  assert.equal(buildCount(), 2,
    'the rollback rebuilt. Its target image was still supposed to be on the host, so ' +
    'buildImageIfNeeded should have answered from `docker image inspect` and skipped the build — ' +
    'which is exactly what appcrane_rollback\'s description promises.');

  const live = db.prepare(
    "SELECT * FROM deployments WHERE app_id = ? AND env = ? AND status = 'live'"
  ).get(app.id, env);
  assert.equal(live.commit_hash, COMMIT_A, 'the rollback must land on the previous commit');
  assert.match(live.log, /Using cached image/,
    'the deploy log must say the image was re-used, not rebuilt');
});

test('at 0 the previous image is pruned and the same rollback rebuilds', async () => {
  const app = makeApp('ret-rebuild', 0);
  const env = 'sandbox';
  const base = buildCount();

  const r1 = makeRelease(app.slug, env, 'one', '1.0.0');
  await deploy(app, env, COMMIT_A, r1, 1);
  const r2 = makeRelease(app.slug, env, 'two', '1.0.1');
  await deploy(app, env, COMMIT_B, r2, 1);
  assert.equal(buildCount() - base, 2);

  assert.deepEqual(tagsFor(app.slug), [`appcrane-${app.slug}-${env}:${COMMIT_B}`],
    'image_retention = 0 must still mean "keep only the running image" — an operator who sets it ' +
    'is asking for the pre-v2.78.0 behaviour and must get it');

  const fresh = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  await rollbackApp(fresh, env, null, userId);

  assert.equal(buildCount() - base, 3,
    'with the target image pruned the rollback has to rebuild that commit — the cost of setting 0');
});
