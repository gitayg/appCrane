import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, copyFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawn } from 'child_process';
import { fileURLToPath, pathToFileURL } from 'url';
import { createServer } from 'net';
import Database from 'better-sqlite3';

// Safe self-update, end to end with real processes: a bare git repo as origin,
// a live clone standing in for /root/appCrane, a tiny fake AppCrane whose boot
// behaviour each release decides, and the real scripts/safe-boot.sh started the
// way systemd starts it. The update itself runs through the same service calls
// POST /api/self-update makes (server/services/selfUpdate.js), the snapshot
// through the real createPreUpdateSnapshot, and the fake server reconciles and
// audits with the real reconcilePendingUpdate / watchUpdateOutcome.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-safe-update-'));
process.env.GIT_CONFIG_GLOBAL = join(ROOT, 'gitconfig');
writeFileSync(process.env.GIT_CONFIG_GLOBAL, '[user]\n\tname = T\n\temail = t@t.t\n[init]\n\tdefaultBranch = main\n');
process.env.DATA_DIR = join(ROOT, 'template-data');
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SAFE_BOOT = fileURLToPath(new URL('../scripts/safe-boot.sh', import.meta.url));
const SERVICE_URL = pathToFileURL(fileURLToPath(new URL('../server/services/selfUpdate.js', import.meta.url))).href;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const { preflightUpdate, applyStagedRelease, buildPendingRecord, discardStaging, satisfiesEngine, rollbackAvailability, reconcilePendingUpdate } =
  await import('../server/services/selfUpdate.js');
const { createPreUpdateSnapshot } = await import('../server/services/updateSnapshot.js');
const { ensureSpaBuilt } = await import('../server/services/spaBuilder.js');

const children = new Set();
// safe-boot.sh runs in its own process group, so a failed assertion still takes
// down the node it spawned (otherwise that grandchild keeps the pipes, and this
// file, open).
after(() => { for (const c of children) { try { process.kill(-c.pid, 'SIGKILL'); } catch (_) {} } });

const git = (cwd, ...args) => execFileSync('git', args, { cwd, stdio: 'pipe' }).toString().trim();

const FAKE_SERVER = `
import http from 'node:http';
import { readFileSync, appendFileSync } from 'node:fs';
const here = new URL('..', import.meta.url).pathname;
const version = JSON.parse(readFileSync(here + 'package.json', 'utf8')).version;
const mode = readFileSync(here + 'server/mode.txt', 'utf8').trim();
if (mode === 'crash') { console.error('fake ' + version + ': crashing at boot'); process.exit(3); }
const su = await import(process.env.SELF_UPDATE_MODULE);
const file = process.env.DATA_DIR + '/self-update-pending.json';
const audit = (action, detail) => appendFileSync(process.env.DATA_DIR + '/audit.jsonl', JSON.stringify({ action, detail }) + '\\n');
const outcome = su.reconcilePendingUpdate({ file, version, underSafeBoot: process.env.APPCRANE_SAFE_BOOT === '1', audit });
if (outcome === 'verifying') su.watchUpdateOutcome({ file, audit, intervalMs: 200 });
http.createServer((req, res) => {
  if (req.url === '/api/info') {
    if (mode === 'hang') return;
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({ version, status: 'ready' }));
  }
  if (req.method === 'POST' && req.url === '/rollback') {
    const info = su.readPending(file);
    const check = su.rollbackAvailability(info, { version, headSha: null, underSafeBoot: process.env.APPCRANE_SAFE_BOOT === '1', previousDir: info?.previous_dir || '' });
    if (!check.ok) { res.statusCode = 409; return res.end(JSON.stringify(check)); }
    su.requestRollback(file, info, { by: 'admin@example.test', restoreDb: false });
    res.end(JSON.stringify(check));
    return setTimeout(() => process.exit(0), 100);
  }
  res.statusCode = 404; res.end();
}).listen(Number(process.env.PORT), '127.0.0.1');
`;

const POSTINSTALL = `
const fs = require('fs');
const v = require('../package.json').version;
fs.mkdirSync('node_modules/better-sqlite3', { recursive: true });
fs.writeFileSync('node_modules/better-sqlite3/index.js', 'module.exports = class { prepare() { return { get() { return 1; } }; } };');
fs.writeFileSync('node_modules/.marker', v);
`;

const SPA_BUILD = `
const fs = require('fs');
if (!fs.existsSync('src/jsx.d.ts')) { console.error('src/jsx.d.ts missing (tsc would fail on the custom element)'); process.exit(2); }
fs.mkdirSync('../docs/admin-app', { recursive: true });
fs.writeFileSync('../docs/admin-app/index.html', 'built ' + require('../package.json').version);
`;

// One release of the fake app, written into a working clone and committed.
function writeRelease(dir, { version, mode = 'ok', postinstall = 'node scripts/postinstall.cjs', build = 'node build.cjs', engines = '>=22', migrations = ['001-base.sql'], spaTouch = version }) {
  mkdirSync(join(dir, 'server', 'migrations'), { recursive: true });
  mkdirSync(join(dir, 'scripts'), { recursive: true });
  mkdirSync(join(dir, 'studio-web', 'src'), { recursive: true });
  mkdirSync(join(dir, 'docs', 'admin-app'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: 'fake-crane', version, private: true, type: 'module', engines: { node: engines }, scripts: { postinstall },
  }, null, 2));
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
    name: 'fake-crane', version, lockfileVersion: 3, requires: true,
    packages: { '': { name: 'fake-crane', version, hasInstallScript: true, engines: { node: engines } } },
  }, null, 2));
  writeFileSync(join(dir, '.gitignore'), 'node_modules/\n/.self-update/\nstudio-web/package-lock.json\ndocs/admin-app/.built-from\n');
  writeFileSync(join(dir, 'scripts', 'postinstall.cjs'), POSTINSTALL);
  copyFileSync(SAFE_BOOT, join(dir, 'scripts', 'safe-boot.sh'));
  writeFileSync(join(dir, 'server', 'index.js'), FAKE_SERVER);
  writeFileSync(join(dir, 'server', 'mode.txt'), mode);
  rmSync(join(dir, 'server', 'migrations'), { recursive: true, force: true });
  mkdirSync(join(dir, 'server', 'migrations'), { recursive: true });
  for (const m of migrations) writeFileSync(join(dir, 'server', 'migrations', m), '-- fake\n');
  writeFileSync(join(dir, 'studio-web', 'package.json'), JSON.stringify({ name: 'fake-studio', private: true, scripts: { 'build:admin': build } }));
  writeFileSync(join(dir, 'studio-web', 'build.cjs'), SPA_BUILD);
  writeFileSync(join(dir, 'studio-web', 'src', 'version.txt'), spaTouch);
  writeFileSync(join(dir, 'studio-web', 'src', 'jsx.d.ts'), 'declare namespace JSX {}\n');
  writeFileSync(join(dir, 'docs', 'admin-app', 'index.html'), `tracked ${version}`);
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', `v${version}`);
  git(dir, 'push', '-q', 'origin', 'HEAD:main');
  return git(dir, 'rev-parse', 'HEAD');
}

async function freePort() {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// A fresh origin, a live install at v1.0.0 (dependencies installed, SPA built,
// database fully migrated with the real schema) and a dev clone to push from.
async function setup(name) {
  const base = join(ROOT, name);
  const origin = join(base, 'origin.git');
  const dev = join(base, 'dev');
  const live = join(base, 'live');
  const data = join(base, 'data');
  mkdirSync(data, { recursive: true });
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', origin]);
  execFileSync('git', ['clone', '-q', origin, dev], { stdio: 'pipe' });
  const v1 = writeRelease(dev, { version: '1.0.0' });
  execFileSync('git', ['clone', '-q', origin, live], { stdio: 'pipe' });
  execFileSync('npm', ['ci', '--no-audit', '--no-fund'], { cwd: live, stdio: 'pipe' });
  const spa = ensureSpaBuilt(live, {});
  assert.equal(spa.rebuilt, true, `initial SPA build failed: ${spa.error}`);
  getDb().prepare('VACUUM INTO ?').run(join(data, 'deployhub.db'));
  const db = new Database(join(data, 'deployhub.db'));
  db.prepare("INSERT INTO _migrations (name) VALUES ('001-base.sql')").run();
  db.close();
  const port = await freePort();
  return { base, origin, dev, live, data, v1, port };
}

// The /api/self-update sequence, minus HTTP: fetch, resolve, preflight,
// snapshot, record, switch.
function runUpdate(env, { simulateMigration = false } = {}) {
  process.env.DATA_DIR = env.data;
  git(env.live, 'fetch', '-q', 'origin');
  const previousSha = git(env.live, 'rev-parse', 'HEAD');
  const targetSha = git(env.live, 'rev-parse', 'origin/main^{commit}');
  const db = new Database(join(env.data, 'deployhub.db'));
  try {
    const preflight = preflightUpdate({ cwd: env.live, sha: targetSha, db, nodeVersion: process.versions.node });
    if (!preflight.ok) { discardStaging(env.live); return { preflight }; }
    const snapshot = createPreUpdateSnapshot(env.live, {
      from: '1.0.0', to: preflight.targetVersion, sha: previousSha, pending: preflight.pendingMigrations,
    }, db);
    assert.equal(snapshot.ok, true, snapshot.error);
    const pending = buildPendingRecord({
      cwd: env.live, previousVersion: '1.0.0', previousSha, preflight, snapshot, pid: process.pid,
      healthUrl: `http://127.0.0.1:${env.port}/api/info`, dbPath: join(env.data, 'deployhub.db'),
    });
    writeFileSync(join(env.data, 'self-update-pending.json'), JSON.stringify(pending, null, 2));
    applyStagedRelease({ cwd: env.live, sha: targetSha, previousSha, spaRebuilt: preflight.spa.rebuilt });
    if (simulateMigration) {
      // What the new release's first boot does before it dies: apply its migrations.
      db.exec('CREATE TABLE fake_migrated (x INTEGER)');
      for (const m of preflight.pendingMigrations) db.prepare('INSERT INTO _migrations (name) VALUES (?)').run(m);
    }
    return { preflight, snapshot, previousSha, targetSha };
  } finally {
    db.close();
  }
}

function startSafeBoot(env, extra = {}) {
  const child = spawn('bash', [join(env.live, 'scripts', 'safe-boot.sh')], {
    cwd: env.live,
    env: {
      ...process.env,
      APPCRANE_DIR: env.live, DATA_DIR: env.data, PORT: String(env.port),
      SELF_UPDATE_MODULE: SERVICE_URL, APPCRANE_UPDATE_HEALTH_TIMEOUT: '6', APPCRANE_SKIP_NODE_UPGRADE: '1',
      ...extra,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  children.add(child);
  let output = '';
  child.stdout.on('data', (d) => { output += d; });
  child.stderr.on('data', (d) => { output += d; });
  child.output = () => output;
  child.exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
  return child;
}

async function waitFor(fn, ms, what, child) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 200));
  }
  assert.fail(`timed out waiting for ${what}\n--- safe-boot output ---\n${child?.output?.() ?? ''}`);
}

async function infoVersion(port) {
  try {
    const r = await fetch(`http://127.0.0.1:${port}/api/info`, { signal: AbortSignal.timeout(1000) });
    return r.ok ? (await r.json()).version : null;
  } catch (_) { return null; }
}

const pendingOf = (env) => JSON.parse(readFileSync(join(env.data, 'self-update-pending.json'), 'utf8'));
const auditOf = (env) => (existsSync(join(env.data, 'audit.jsonl'))
  ? readFileSync(join(env.data, 'audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : []);
const read = (...p) => readFileSync(join(...p), 'utf8');

async function stop(child) {
  child.kill('SIGTERM');
  await child.exited;
}

test('engine ranges: the subset package.json engines use', () => {
  assert.equal(satisfiesEngine('22.22.3', '>=22 <23').ok, true);
  assert.equal(satisfiesEngine('24.1.0', '>=22 <23').ok, false);
  assert.equal(satisfiesEngine('20.11.0', '>=22').ok, false);
  assert.equal(satisfiesEngine('22.1.0', '^20 || ^22').ok, true);
  assert.equal(satisfiesEngine('22.1.0', '22.x').ok, true);
});

test('an SPA rebuild removes stale emitted shadows but keeps committed declarations', async () => {
  const env = await setup('spa-dts');
  writeFileSync(join(env.live, 'studio-web', 'src', 'stale.js'), 'shadow');
  const spa = ensureSpaBuilt(env.live, { force: true });
  assert.equal(spa.rebuilt, true, spa.error);
  assert.ok(existsSync(join(env.live, 'studio-web', 'src', 'jsx.d.ts')), 'the committed jsx.d.ts was deleted');
  assert.equal(existsSync(join(env.live, 'studio-web', 'src', 'stale.js')), false, 'the untracked shadow survived');
});

test('preflight refuses a target whose install fails, and the live tree is untouched', async () => {
  const env = await setup('install-fails');
  writeRelease(env.dev, { version: '2.0.0', postinstall: 'exit 7' });
  const before = { head: git(env.live, 'rev-parse', 'HEAD'), status: git(env.live, 'status', '--porcelain'), marker: read(env.live, 'node_modules', '.marker'), spa: read(env.live, 'docs', 'admin-app', 'index.html') };

  const r = runUpdate(env);
  assert.equal(r.preflight.ok, false);
  assert.equal(r.preflight.step, 'install', r.preflight.error);

  assert.equal(git(env.live, 'rev-parse', 'HEAD'), before.head, 'the live HEAD moved');
  assert.equal(git(env.live, 'status', '--porcelain'), before.status, 'the live working tree changed');
  assert.equal(read(env.live, 'node_modules', '.marker'), before.marker, 'the live node_modules changed');
  assert.equal(read(env.live, 'docs', 'admin-app', 'index.html'), before.spa, 'the live SPA changed');
  assert.equal(existsSync(join(env.data, 'self-update-pending.json')), false, 'a refused update must not leave a pending record');
  assert.equal(existsSync(join(env.live, '.self-update', 'staging')), false, 'staging was not cleaned up');
});

test('preflight refuses a target whose admin SPA build fails, and one that needs another Node', async () => {
  const env = await setup('spa-fails');
  writeRelease(env.dev, { version: '2.0.0', build: 'exit 9' });
  const head = git(env.live, 'rev-parse', 'HEAD');
  const spa = runUpdate(env);
  assert.equal(spa.preflight.ok, false);
  assert.equal(spa.preflight.step, 'spa', spa.preflight.error);
  assert.equal(git(env.live, 'rev-parse', 'HEAD'), head);
  assert.equal(read(env.live, 'node_modules', '.marker'), '1.0.0');

  writeRelease(env.dev, { version: '2.0.1', engines: '>=99' });
  const engine = runUpdate(env);
  assert.equal(engine.preflight.ok, false);
  assert.equal(engine.preflight.step, 'engine');
  assert.match(engine.preflight.error, /requires Node >=99/);
  assert.equal(git(env.live, 'rev-parse', 'HEAD'), head);
});

test('a target that crashes at boot is rolled back: previous SHA, node_modules, SPA and the DB snapshot', async () => {
  const env = await setup('boot-crash');
  writeRelease(env.dev, { version: '2.0.0', mode: 'crash', migrations: ['001-base.sql', '002-new.sql'] });
  const r = runUpdate(env, { simulateMigration: true });
  assert.equal(r.preflight.ok, true, r.preflight.error);
  assert.deepEqual(r.preflight.pendingMigrations, ['002-new.sql'], 'pending migrations listed before the switch');
  assert.equal(git(env.live, 'rev-parse', 'HEAD'), r.targetSha, 'the update did not switch the tree');
  assert.equal(read(env.live, 'node_modules', '.marker'), '2.0.0', 'the staged node_modules were not moved in');
  assert.equal(read(env.live, 'docs', 'admin-app', 'index.html'), 'built 2.0.0', 'the staged SPA was not moved in');
  const migrated = new Database(join(env.data, 'deployhub.db'), { readonly: true });
  assert.ok(migrated.prepare("SELECT name FROM sqlite_master WHERE name = 'fake_migrated'").get(), 'precondition: the migration ran');
  migrated.close();

  const sb = startSafeBoot(env);
  await waitFor(async () => (await infoVersion(env.port)) === '1.0.0', 30000, 'v1.0.0 back up after rollback', sb);

  assert.equal(git(env.live, 'rev-parse', 'HEAD'), env.v1, 'not back on the previous SHA');
  assert.equal(read(env.live, 'node_modules', '.marker'), '1.0.0', 'previous node_modules not restored');
  assert.equal(read(env.live, 'docs', 'admin-app', 'index.html'), 'built 1.0.0', 'previous SPA not restored');
  const restored = new Database(join(env.data, 'deployhub.db'), { readonly: true });
  assert.equal(restored.prepare("SELECT name FROM sqlite_master WHERE name = 'fake_migrated'").get(), undefined, 'DB snapshot not restored');
  restored.close();
  assert.ok(existsSync(join(env.data, 'rolled-back-db', 'deployhub.db')), 'the failed release DB was not kept for a post-mortem');

  const p = pendingOf(env);
  assert.ok(p.rolled_back_at);
  assert.equal(p.db_restored, true);
  assert.equal(p.rollback_mode, 'gate');
  assert.match(p.rollback_reason, /exited with code 3 before passing the health check/);
  await waitFor(() => auditOf(env).find((a) => a.action === 'self-update-rolled-back'), 5000, 'rollback audit', sb);
  const a = auditOf(env).find((x) => x.action === 'self-update-rolled-back');
  assert.equal(a.detail.to, '2.0.0');
  assert.equal(a.detail.running, '1.0.0');
  assert.match(a.detail.reason, /exited with code 3/);
  assert.equal(pendingOf(env).outcome, 'rolled_back');
  await stop(sb);
});

test('a target that boots but never answers its health check is stopped and rolled back', async () => {
  const env = await setup('hang');
  writeRelease(env.dev, { version: '2.0.0', mode: 'hang' });
  const r = runUpdate(env);
  assert.equal(r.preflight.ok, true, r.preflight.error);
  assert.deepEqual(r.preflight.pendingMigrations, [], 'no new migrations');

  const sb = startSafeBoot(env);
  await waitFor(async () => (await infoVersion(env.port)) === '1.0.0', 45000, 'v1.0.0 back up after a failed health gate', sb);
  assert.equal(git(env.live, 'rev-parse', 'HEAD'), env.v1);
  const p = pendingOf(env);
  assert.match(p.rollback_reason, /did not answer .* within 6s/);
  assert.equal(p.db_restored, false, 'no migrations ran, so the database must be left alone');
  await stop(sb);
});

test('a healthy update completes, is audited, and an admin can then roll it back', async () => {
  const env = await setup('healthy');
  writeRelease(env.dev, { version: '2.0.0', migrations: ['001-base.sql', '002-new.sql'] });
  const r = runUpdate(env);
  assert.equal(r.preflight.ok, true, r.preflight.error);
  assert.equal(r.preflight.spa.rebuilt, true, 'studio-web changed, so the SPA must be built in staging');

  const sb = startSafeBoot(env);
  await waitFor(() => auditOf(env).find((a) => a.action === 'self-update-completed'), 30000, 'completion audit', sb);
  assert.equal(await infoVersion(env.port), '2.0.0');
  const done = auditOf(env).find((a) => a.action === 'self-update-completed');
  assert.equal(done.detail.health, 'passed');
  assert.equal(done.detail.to, '2.0.0');
  const p = pendingOf(env);
  assert.ok(p.health_ok_at);
  assert.equal(p.outcome, 'updated');
  assert.equal(git(env.live, 'rev-parse', 'HEAD'), r.targetSha);
  assert.equal(read(env.live, 'docs', 'admin-app', 'index.html'), 'built 2.0.0');
  assert.equal(auditOf(env).filter((a) => a.action === 'self-update-completed').length, 1, 'audited twice');

  const res = await fetch(`http://127.0.0.1:${env.port}/rollback`, { method: 'POST' });
  assert.equal(res.status, 200, await res.text());
  await waitFor(async () => (await infoVersion(env.port)) === '1.0.0', 30000, 'v1.0.0 after the requested rollback', sb);
  assert.equal(git(env.live, 'rev-parse', 'HEAD'), env.v1);
  assert.equal(read(env.live, 'node_modules', '.marker'), '1.0.0');
  const q = pendingOf(env);
  assert.equal(q.rollback_mode, 'requested');
  assert.equal(q.db_restored, false, 'a requested rollback restores the database only when asked');
  await waitFor(() => auditOf(env).find((a) => a.action === 'self-update-rolled-back'), 5000, 'requested-rollback audit', sb);
  assert.equal(auditOf(env).find((a) => a.action === 'self-update-rolled-back').detail.requested_by, 'admin@example.test');
  assert.equal(rollbackAvailability(pendingOf(env), { version: '1.0.0', underSafeBoot: true, previousDir: '' }).code, 'ALREADY_ROLLED_BACK');
  await stop(sb);
});

test('a legacy pending record (written by an older updater) is found and rolled back on a boot crash', async () => {
  const env = await setup('legacy');
  writeRelease(env.dev, { version: '2.0.0', mode: 'crash' });
  git(env.live, 'fetch', '-q', 'origin');
  git(env.live, 'reset', '-q', '--hard', 'origin/main');
  writeFileSync(join(env.data, 'self-update-pending.json'), JSON.stringify({
    previous_version: '1.0.0', previous_sha: env.v1, target_version: '2.0.0', started_at: new Date().toISOString(),
  }));
  const sb = startSafeBoot(env);
  await waitFor(async () => (await infoVersion(env.port)) === '1.0.0', 60000, 'v1.0.0 after a legacy rollback', sb);
  assert.equal(git(env.live, 'rev-parse', 'HEAD'), env.v1);
  assert.equal(pendingOf(env).rollback_mode, 'crash');
  await stop(sb);
});

test('without safe-boot.sh an update is recorded as completed with health unverified', () => {
  const dir = mkdtempSync(join(ROOT, 'reconcile-'));
  const file = join(dir, 'p.json');
  writeFileSync(file, JSON.stringify({ previous_version: '1.0.0', target_version: '2.0.0', health_url: 'http://x' }));
  const audits = [];
  assert.equal(reconcilePendingUpdate({ file, version: '2.0.0', underSafeBoot: false, audit: (a, d) => audits.push([a, d]) }), 'updated');
  assert.equal(audits[0][0], 'self-update-completed');
  assert.equal(audits[0][1].health, 'unverified');
  assert.equal(reconcilePendingUpdate({ file, version: '2.0.0', underSafeBoot: false, audit: (a, d) => audits.push([a, d]) }), null, 'reconciled twice');
});
