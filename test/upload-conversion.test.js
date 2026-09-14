import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, symlinkSync, chmodSync, readlinkSync, lstatSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Boot-time conversion of uploaded apps into Crane-hosted ones
// (services/uploadConversion.js). Every repository is read back with an
// independent, isolated git — never through the module under test.

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = mkdtempSync(join(tmpdir(), 'crane-uploadconv-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'info';
delete process.env.APPCRANE_UPLOAD_CONVERSION;

const logLines = [];
const origLog = console.log;
console.log = (...a) => { logLines.push(a.join(' ')); };

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt, decrypt, generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const uc = await import('../server/services/uploadConversion.js');
const lg = await import('../server/services/localGit.js');

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const g = (gitDir, args) => execFileSync('git', [`--git-dir=${gitDir}`, ...args], { env: CLEAN, stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 }).toString('utf8');

let slot = 7000;
const makeApp = (slug) => db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?,?,?,'upload')").run(slug, slug, ++slot).lastInsertRowid;
const appRow = (id) => db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
const outcome = (id) => db.prepare('SELECT * FROM upload_conversions WHERE app_id = ?').get(id);
const envVars = (id, env) => Object.fromEntries(db.prepare('SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ?').all(id, env).map((r) => [r.key, decrypt(r.value_encrypted)]));
const live = (id, env, dir, hash) => db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash, release_path) VALUES (?,?,'live',?,?)").run(id, env, hash, dir).lastInsertRowid;
const convert = (id, opts = {}) => uc.convertOneApp(db, appRow(id), { appTimeoutMs: 60000, ...opts });
const stagingLeft = () => existsSync(lg.reposRoot()) && readdirSync(lg.reposRoot()).filter((n) => n.startsWith('.converting-'));

function release(slug, env, name, files) {
  const dir = join(ROOT, 'apps', slug, env, 'releases', name);
  mkdirSync(dir, { recursive: true });
  for (const [p, v] of Object.entries(files)) {
    const abs = join(dir, p);
    mkdirSync(dirname(abs), { recursive: true });
    if (v && typeof v === 'object' && 'symlink' in v) symlinkSync(v.symlink, abs);
    else if (v && typeof v === 'object' && 'exec' in v) { writeFileSync(abs, v.exec); chmodSync(abs, 0o755); } else writeFileSync(abs, v);
  }
  return dir;
}

function treeOf(gitDir, commit) {
  return Object.fromEntries(g(gitDir, ['ls-tree', '-r', '-z', '--full-tree', commit]).split('\0').filter(Boolean).map((l) => {
    const [meta, path] = l.split('\t');
    const [mode, type, sha] = meta.split(' ');
    return [path, { mode, type, sha }];
  }));
}

const BASE = {
  'package.json': JSON.stringify({ name: 'x', version: '1.0.0', scripts: { start: 'node server.js' }, dependencies: { express: '4' } }),
  'package-lock.json': '{}',
  'server.js': 'console.log(1)\n',
};
const A64 = `sha256:${'a'.repeat(64)}`;
const B64 = `sha256:${'b'.repeat(64)}`;

// ---- Express harness for the routes ---------------------------------------
const ADMIN_KEY = generateApiKey('dhk_admin');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','admin@example.com','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY));
const USER_KEY = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('User','user@example.com','user',?,1,'human')").run(hashApiKey(USER_KEY));
const api = express();
api.use(express.json());
api.use('/api/apps', (await import('../server/routes/apps.js')).default);
api.use('/api/apps', (await import('../server/routes/deploy.js')).default);
api.use('/api/github-service', (await import('../server/routes/githubService.js')).default);
api.use((await import('../server/utils/errors.js')).errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE_URL = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  console.log = origLog;
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  server.closeAllConnections?.();
  server.unref();
  server.close();
  rmSync(ROOT, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------

const demo = {};

test('converts an uploaded app: exclusions, symlinks, two commits, per-env identity, env import', async () => {
  demo.id = makeApp('demo');
  demo.prodDir = release('demo', 'production', '1700000000000-upload', {
    ...BASE,
    'server.js': 'console.log("prod")\n',
    'bin/run.sh': { exec: '#!/bin/sh\necho run\n' },
    'config/app.json': '{"a":1}\n',
    'config-link.json': { symlink: 'config/app.json' },
    'config-alias': { symlink: 'config' },
    'escape': { symlink: '../../../../../../etc' },
    'data': { symlink: '/var/lib/somewhere' },
    '.env': 'DB_URL=postgres://VALUEMARK-db\nexport QUOTED="a=b#VALUEMARK-q"\nKEPT=VALUEMARK-kept\nSHARED=VALUEMARK-root\n# comment\n',
    '.env.production': 'SHARED=VALUEMARK-prod\n',
    '.env.example': 'EXAMPLE_ONLY=VALUEMARK-example\n',
    '.env.sample': 'SAMPLE_ONLY=VALUEMARK-sample\n',
    '.env.development': 'DEV_ONLY=VALUEMARK-dev\n',
    'lib/.env': 'NESTED=VALUEMARK-nested\n',
    'lib/index.js': 'module.exports = 1\n',
    'node_modules/express/index.js': 'x\n',
    'client/package.json': JSON.stringify({ scripts: { build: 'vite build' }, devDependencies: { vite: '5' } }),
    'client/package-lock.json': '{}',
    'client/src/main.js': 'x\n',
    'client/node_modules/vite/index.js': 'x\n',
    '.git/HEAD': 'ref: refs/heads/main\n',
    'docs/.git': 'gitdir: ../x\n',
    'docs/readme.md': '# docs\n',
    '"lead quote.txt': 'q\n',
  });
  execFileSync('mkfifo', [join(demo.prodDir, 'pipe')]);
  demo.sbDir = release('demo', 'sandbox', '1700000001000-upload', {
    ...BASE,
    'server.js': 'console.log("sandbox")\n',
    '.env': 'SHARED=VALUEMARK-sbroot\nKEPT=VALUEMARK-sbkept\n',
    '.env.sandbox': 'SANDBOX_ONLY=VALUEMARK-sb\n',
    '.env.production': 'SHARED=VALUEMARK-wrongenv\n',
  });
  demo.prodDep = live(demo.id, 'production', demo.prodDir, A64);
  demo.sbDep = live(demo.id, 'sandbox', demo.sbDir, B64);
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'KEPT', ?)").run(demo.id, encrypt('existing-value'));

  const r = await convert(demo.id);
  assert.equal(r.status, 'converted', JSON.stringify(r));

  const repo = lg.repoPath('demo');
  const log = g(repo, ['log', '--format=%H%x09%s', 'refs/heads/main']).trim().split('\n').map((l) => l.split('\t'));
  assert.equal(log.length, 2);
  const [[sbCommit, sbSubject], [prodCommit, prodSubject]] = log;
  assert.equal(prodSubject, `Imported from upload ${A64} (production)`);
  assert.equal(sbSubject, `Imported from upload ${B64} (sandbox)`);
  assert.equal(g(repo, ['rev-parse', `${sbCommit}^`]).trim(), prodCommit);
  assert.match(g(repo, ['log', '-1', '--format=%an <%ae>|%cn <%ce>', prodCommit]), /^AppCrane <noreply@appcrane\.invalid>\|AppCrane <noreply@appcrane\.invalid>/);
  Object.assign(demo, { repo, sbCommit, prodCommit });

  const prodTree = treeOf(repo, prodCommit);
  for (const p of Object.keys(prodTree)) {
    assert.doesNotMatch(p, /(^|\/)\.env/, `${p} must be excluded`);
    assert.doesNotMatch(p, /(^|\/)node_modules(\/|$)/, `${p} must be excluded`);
    assert.doesNotMatch(p, /(^|\/)\.git(\/|$)/, `${p} must be excluded`);
  }
  assert.deepEqual(Object.keys(prodTree).sort(), [
    '"lead quote.txt', 'bin/run.sh', 'client/package-lock.json', 'client/package.json', 'client/src/main.js', 'config-alias',
    'config-link.json', 'config/app.json', 'docs/readme.md', 'lib/index.js', 'package-lock.json', 'package.json', 'server.js',
  ]);
  assert.equal(prodTree['config-link.json'].mode, '120000');
  assert.equal(g(repo, ['cat-file', '-p', prodTree['config-link.json'].sha]), 'config/app.json');
  assert.equal(prodTree['config-alias'].mode, '120000');
  assert.equal(prodTree['config-alias'].type, 'blob');
  assert.equal(prodTree['bin/run.sh'].mode, '100755');
  assert.equal(prodTree['server.js'].mode, '100644');
  assert.equal(g(repo, ['cat-file', '-p', prodTree['server.js'].sha]), 'console.log("prod")\n');
  const sbTree = treeOf(repo, sbCommit);
  assert.deepEqual(Object.keys(sbTree).sort(), ['package-lock.json', 'package.json', 'server.js']);
  assert.equal(g(repo, ['cat-file', '-p', sbTree['server.js'].sha]), 'console.log("sandbox")\n');

  const app = appRow(demo.id);
  assert.equal(app.source_type, 'managed');
  assert.equal(app.repo_backend, 'local');
  assert.equal(app.branch, 'main');
  assert.equal(app.last_managed_push_sha, sbCommit);
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(demo.prodDep).commit_hash, prodCommit);
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(demo.sbDep).commit_hash, sbCommit);

  assert.deepEqual(envVars(demo.id, 'production'), { DB_URL: 'postgres://VALUEMARK-db', QUOTED: 'a=b#VALUEMARK-q', KEPT: 'existing-value', SHARED: 'VALUEMARK-prod' });
  assert.deepEqual(envVars(demo.id, 'sandbox'), { SHARED: 'VALUEMARK-sbroot', KEPT: 'VALUEMARK-sbkept', SANDBOX_ONLY: 'VALUEMARK-sb' });

  const o = outcome(demo.id);
  assert.equal(o.status, 'converted');
  assert.equal(o.tip, sbCommit);
  assert.deepEqual(JSON.parse(o.imported_keys_json), { production: ['DB_URL', 'QUOTED', 'SHARED'], sandbox: ['SHARED', 'KEPT', 'SANDBOX_ONLY'] });
  assert.deepEqual(JSON.parse(o.kept_existing_json), { production: ['KEPT'], sandbox: [] });
  const commits = JSON.parse(o.commits_json);
  assert.deepEqual(commits.production, { commit: prodCommit, release: '1700000000000-upload', source: 'live_deployment', identity: A64, deployment_id: Number(demo.prodDep), previous_commit_hash: A64 });
  assert.equal(commits.sandbox.commit, sbCommit);
  const excluded = JSON.parse(o.excluded_json).filter((x) => x.env === 'production').map((x) => `${x.path}:${x.reason}`).sort();
  assert.deepEqual(excluded, [
    '.env.development:env_file', '.env.example:env_file', '.env.production:env_file', '.env.sample:env_file', '.env:env_file',
    '.git:git_dir', 'client/node_modules:node_modules', 'data:symlink_outside_release', 'docs/.git:git_dir',
    'escape:symlink_outside_release', 'lib/.env:env_file', 'node_modules:node_modules',
  ]);
  assert.equal(o.excluded_count, 15);
  assert.deepEqual(JSON.parse(o.skipped_files_json), [{ env: 'production', path: 'pipe', reason: 'special_file' }]);
  const warnings = JSON.parse(o.warnings_json).map((w) => `${w.env}:${w.path}:${w.reason}`).sort();
  assert.deepEqual(warnings, ['production:.env.development:not_imported', 'production:lib/.env:nested_not_imported', 'sandbox:.env.production:not_imported']);
  assert.deepEqual(uc.getUploadConversionStatus(db).apps.find((a) => a.slug === 'demo').stored_env_files, {
    production: ['.env', '.env.development', '.env.example', '.env.production', '.env.sample', 'lib/.env'],
    sandbox: ['.env', '.env.production', '.env.sandbox'],
  });
});

test('no env value reaches logs, the outcome row, git objects, the database file or the status route', async () => {
  const everything = [
    logLines.join('\n'),
    JSON.stringify(db.prepare('SELECT * FROM upload_conversions').all()),
    g(demo.repo, ['cat-file', '--batch-all-objects', '--batch']),
  ];
  db.pragma('wal_checkpoint(TRUNCATE)');
  for (const f of readdirSync(ROOT).filter((n) => /\.db(-wal|-shm)?$/.test(n))) everything.push(readFileSync(join(ROOT, f), 'latin1'));
  const res = await fetch(`${BASE_URL}/api/github-service/upload-conversion`, { headers: { 'X-API-Key': ADMIN_KEY } });
  everything.push(await res.text());
  for (const [i, text] of everything.entries()) assert.ok(!text.includes('VALUEMARK'), `a value leaked into source #${i}`);
  assert.ok(logLines.some((l) => l.includes('[upload-conversion] demo: converted')), 'one line per app');
});

test('the deploy clone gets the committed tree; pinning production reaches the first commit with its symlink intact', () => {
  const dest = join(ROOT, 'clone-demo');
  lg.cloneForDeploySync('demo', dest, 'main');
  assert.equal(readFileSync(join(dest, 'server.js'), 'utf8'), 'console.log("sandbox")\n');
  assert.ok(!existsSync(join(dest, '.env')));
  lg.pinDeployCloneSync('demo', dest, demo.prodCommit, 'main');
  assert.equal(readFileSync(join(dest, 'server.js'), 'utf8'), 'console.log("prod")\n');
  assert.ok(lstatSync(join(dest, 'config-link.json')).isSymbolicLink());
  assert.equal(readlinkSync(join(dest, 'config-link.json')), 'config/app.json');
  assert.ok(!existsSync(join(dest, 'node_modules')) && !existsSync(join(dest, 'lib/.env')) && !existsSync(join(dest, 'data')));
});

test('status route: platform admin only, reports commits, key names, excluded paths', async () => {
  const denied = await fetch(`${BASE_URL}/api/github-service/upload-conversion`, { headers: { 'X-API-Key': USER_KEY } });
  assert.equal(denied.status, 403);
  const body = await (await fetch(`${BASE_URL}/api/github-service/upload-conversion`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  const row = body.apps.find((a) => a.slug === 'demo');
  assert.equal(row.status, 'converted');
  assert.equal(row.skip_reason, null);
  assert.equal(row.commits.production.commit, demo.prodCommit);
  assert.equal(row.commits.sandbox.commit, demo.sbCommit);
  assert.deepEqual(row.imported_keys.production, ['DB_URL', 'QUOTED', 'SHARED']);
  assert.deepEqual(row.kept_existing.production, ['KEPT']);
  assert.equal(row.excluded.count, 15);
  assert.ok(row.excluded.paths.some((p) => p.path === 'lib/.env'));
  assert.deepEqual(row.stored_env_files.production, ['.env', '.env.development', '.env.example', '.env.production', '.env.sample', 'lib/.env']);
  assert.equal(row.source_type, 'managed');
});

test('app list badge reads crane_hosted once the row flips', async () => {
  const body = await (await fetch(`${BASE_URL}/api/apps`, { headers: { 'X-API-Key': ADMIN_KEY } })).json();
  assert.equal(body.apps.find((a) => a.slug === 'demo').code_source, 'crane_hosted');
});

test('upload endpoints refuse a converted app (HTTP route 409, shared deploy service) and accept again after a revert', async () => {
  const form = new FormData();
  form.append('env', 'sandbox');
  form.append('file', new Blob([Buffer.from('PK')]), 'bundle.zip');
  const res = await fetch(`${BASE_URL}/api/apps/demo/deploy/upload`, { method: 'POST', headers: { 'X-API-Key': ADMIN_KEY }, body: form });
  const body = await res.json();
  assert.equal(res.status, 409, JSON.stringify(body));
  assert.equal(body.error.code, 'APP_IS_CRANE_HOSTED');
  assert.match(body.error.message, /appcrane_push_to_managed_app/);

  const tmp = join(ROOT, 'bundle.zip');
  writeFileSync(tmp, 'PK');
  const { deployArtifact } = await import('../server/services/artifactDeploy.js');
  await assert.rejects(
    deployArtifact({ app: appRow(demo.id), env: 'sandbox', filePath: tmp, filename: 'bundle.zip', userId: 1 }),
    (e) => e.code === 'APP_IS_CRANE_HOSTED' && e.status === 409,
  );
  assert.ok(!existsSync(tmp), 'the refused bundle is removed');
  assert.equal(uc.conversionRefusal(db, { ...appRow(demo.id), source_type: 'upload', repo_backend: null }), null, 'a reverted app is not refused');
});

test('second boot is idempotent: nothing to convert, repo and env vars unchanged', async () => {
  const before = { tip: g(demo.repo, ['rev-parse', 'refs/heads/main']), vars: db.prepare('SELECT COUNT(*) n FROM env_vars').get().n, attempts: outcome(demo.id).attempts };
  const r = await uc.convertUploadedApps({ db, appTimeoutMs: 60000 });
  assert.deepEqual(r.results.filter((x) => x.slug === 'demo'), []);
  assert.equal(g(demo.repo, ['rev-parse', 'refs/heads/main']), before.tip);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM env_vars').get().n, before.vars);
  assert.equal(outcome(demo.id).attempts, before.attempts);
});

test('identical releases in both envs: one commit, both envs point at it', async () => {
  const id = makeApp('same');
  const p = release('same', 'production', '1-upload', BASE);
  const s = release('same', 'sandbox', '2-upload', BASE);
  const pd = live(id, 'production', p, A64);
  const sd = live(id, 'sandbox', s, B64);
  assert.equal((await convert(id)).status, 'converted');
  const repo = lg.repoPath('same');
  assert.equal(g(repo, ['rev-list', '--count', 'refs/heads/main']).trim(), '1');
  const tip = g(repo, ['rev-parse', 'refs/heads/main']).trim();
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(pd).commit_hash, tip);
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(sd).commit_hash, tip);
});

test('only sandbox has a release (no deployment row): one commit from the newest upload release, tree identity', async () => {
  const id = makeApp('sbonly');
  release('sbonly', 'sandbox', '100-upload', { ...BASE, 'server.js': 'old\n' });
  release('sbonly', 'sandbox', '200-upload', { ...BASE, 'server.js': 'new\n' });
  assert.equal((await convert(id)).status, 'converted');
  const repo = lg.repoPath('sbonly');
  assert.equal(g(repo, ['rev-list', '--count', 'refs/heads/main']).trim(), '1');
  assert.match(g(repo, ['log', '-1', '--format=%s']), /^Imported from upload release 200-upload tree-sha256:[0-9a-f]{64} \(sandbox\)/);
  assert.equal(g(repo, ['show', 'refs/heads/main:server.js']), 'new\n');
  assert.equal(JSON.parse(outcome(id).commits_json).sandbox.deployment_id, null);
});

async function expectSkip(slug, files, reason, extra = {}) {
  const id = makeApp(slug);
  const dir = release(slug, 'production', '1-upload', files);
  live(id, 'production', dir, A64);
  const r = await convert(id, extra);
  assert.equal(r.status, 'skipped', JSON.stringify(r));
  assert.equal(r.error_code, reason);
  assert.equal(appRow(id).source_type, 'upload');
  assert.equal(appRow(id).repo_backend, null);
  assert.ok(!existsSync(lg.repoPath(slug)), 'no repo for a skipped app');
  assert.deepEqual(envVars(id, 'production'), {});
  assert.deepEqual(stagingLeft(), []);
  return { id, row: outcome(id) };
}

test('build-time keys no longer skip: the app converts and its .env files are stored, not committed', async () => {
  const id = makeApp('vite-root');
  live(id, 'production', release('vite-root', 'production', '1-upload', { ...BASE, '.env': 'VITE_API_URL=VALUEMARK-vite\nOTHER=VALUEMARK-o\n', 'client/.env': 'NEXT_PUBLIC_X=VALUEMARK-next\n' }), A64);
  const r = await convert(id);
  assert.equal(r.status, 'converted', JSON.stringify(r));
  assert.deepEqual(uc.getUploadConversionStatus(db).apps.find((a) => a.slug === 'vite-root').stored_env_files, { production: ['.env', 'client/.env'], sandbox: [] });
  assert.doesNotMatch(g(lg.repoPath('vite-root'), ['ls-tree', '-r', '--name-only', 'refs/heads/main']), /\.env/);
  assert.ok(!JSON.stringify(outcome(id)).includes('VALUEMARK'));
});

test('skip: app Dockerfile COPYs node_modules', async () => {
  await expectSkip('df-copy', { ...BASE, Dockerfile: 'FROM node:22\nCOPY node_modules ./node_modules\nCOPY . .\n', 'node_modules/a/i.js': '1' }, 'needs_bundled_node_modules');
});

test('skip: app Dockerfile installs nothing while node_modules is bundled', async () => {
  await expectSkip('df-noinstall', { ...BASE, Dockerfile: 'FROM node:22\nCOPY . .\nCMD ["node","server.js"]\n', 'node_modules/a/i.js': '1' }, 'needs_bundled_node_modules');
});

test('skip: node_modules with no package.json beside it', async () => {
  await expectSkip('nm-nomanifest', { 'index.js': '1', 'node_modules/a/i.js': '1' }, 'needs_bundled_node_modules');
});

test('skip: flat generated build whose devDependencies came from the bundled node_modules', async () => {
  await expectSkip('nm-devdeps', {
    'package.json': JSON.stringify({ scripts: { build: 'vite build', start: 'node s.js' }, devDependencies: { vite: '5' } }),
    's.js': '1', 'node_modules/vite/i.js': '1',
  }, 'needs_bundled_node_modules');
});

test('skip: nested node_modules outside every directory the generated Dockerfile installs in', async () => {
  await expectSkip('nm-outside', { ...BASE, 'tools/package.json': '{}', 'tools/node_modules/a/i.js': '1' }, 'needs_bundled_node_modules');
});

test('converts: app Dockerfile that installs, with node_modules bundled', async () => {
  const id = makeApp('df-install');
  live(id, 'production', release('df-install', 'production', '1-upload', { ...BASE, Dockerfile: 'FROM node:22\nCOPY . .\nRUN npm ci\n', 'node_modules/a/i.js': '1' }), A64);
  assert.equal((await convert(id)).status, 'converted');
});

test('converts from production alone when sandbox has a live deployment but no release on disk', async () => {
  // Measured on a real instance: production had five upload releases, sandbox's
  // recorded release was gone, and the whole app was skipped as releases_missing.
  const id = makeApp('prod-only');
  const prodDep = live(id, 'production', release('prod-only', 'production', '5-upload', { ...BASE, '.env': 'PROD_KEY=1\n' }), A64);
  const sbDep = live(id, 'sandbox', join(ROOT, 'apps', 'prod-only', 'sandbox', 'releases', '9-upload'), 'sha256:' + 'b'.repeat(64));
  const r = await convert(id);
  assert.equal(r.status, 'converted', JSON.stringify(r));
  const app = appRow(id);
  assert.equal(app.source_type, 'managed');
  assert.equal(app.repo_backend, 'local');
  const gitDir = lg.repoPath('prod-only');
  assert.equal(g(gitDir, ['rev-list', '--count', 'main']).trim(), '1', 'only production has a release, so one commit');
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(prodDep).commit_hash, g(gitDir, ['rev-parse', 'main']).trim());
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(sbDep).commit_hash, 'sha256:' + 'b'.repeat(64), 'sandbox ran no commit in this repo; its row is left as it was');
  const warnings = JSON.parse(outcome(id).warnings_json).map((w) => `${w.env}:${w.reason}`);
  assert.ok(warnings.includes('sandbox:no_release_on_disk_deploys_from_repo'), JSON.stringify(warnings));
  assert.deepEqual(envVars(id, 'sandbox'), {}, 'nothing is imported for the environment with no release');
});

test('skip: live deployment whose release is gone, and an app with no releases at all', async () => {
  const id = makeApp('gone');
  live(id, 'production', join(ROOT, 'apps', 'gone', 'production', 'releases', '9-upload'), A64);
  const r = await convert(id);
  assert.equal(r.error_code, 'releases_missing');
  const id2 = makeApp('never');
  assert.equal((await convert(id2)).error_code, 'releases_missing');
  assert.equal(appRow(id2).source_type, 'upload');
});

test('skip: nothing but excluded content', async () => {
  await expectSkip('only-excluded', { '.env': 'A=1\n', 'node_modules/x/i.js': '1', '.git/HEAD': 'x' }, 'empty_after_exclusions');
});

test('skip: size cap', async () => {
  const { row } = await expectSkip('big', { ...BASE, 'big.bin': Buffer.alloc(4096, 1) }, 'too_large', { maxBytes: 1024 });
  assert.equal(JSON.parse(row.detail_json).limit, 'bytes');
});

test('skip: malformed .env to import — line recorded, no value', async () => {
  const { row } = await expectSkip('badenv', { ...BASE, '.env': 'GOOD=1\nBAD="VALUEMARK-unterminated\n' }, 'env_parse_error');
  assert.deepEqual(JSON.parse(row.detail_json).errors, [{ env: 'production', path: '.env', line: 2, key: 'BAD', reason: 'unterminated quoted value' }]);
  assert.ok(!JSON.stringify(row).includes('VALUEMARK'));
});

test('DB flip is guarded by source_type=upload: a row that changed meanwhile is not flipped, no env import', async () => {
  const id = makeApp('guarded');
  const dep = live(id, 'production', release('guarded', 'production', '1-upload', { ...BASE, '.env': 'K=v\n' }), A64);
  const r = await convert(id, { afterInstall: () => { db.prepare("UPDATE apps SET source_type = 'image' WHERE id = ?").run(id); } });
  assert.equal(r.status, 'failed');
  assert.equal(r.error_code, 'FLIP_GUARD');
  assert.equal(appRow(id).source_type, 'image');
  assert.equal(appRow(id).repo_backend, null);
  assert.deepEqual(envVars(id, 'production'), {});
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(dep).commit_hash, A64);
});

test('never renames over an existing path: pre-existing repo dir is skipped, one appearing mid-run is left intact', async () => {
  const id = makeApp('occupied');
  live(id, 'production', release('occupied', 'production', '1-upload', BASE), A64);
  mkdirSync(lg.repoPath('occupied'), { recursive: true });
  writeFileSync(join(lg.repoPath('occupied'), 'sentinel'), 'mine');
  const r = await convert(id);
  assert.equal(r.error_code, 'local_repo_exists');
  assert.equal(readFileSync(join(lg.repoPath('occupied'), 'sentinel'), 'utf8'), 'mine');
  assert.equal(appRow(id).source_type, 'upload');

  const id2 = makeApp('racer');
  live(id2, 'production', release('racer', 'production', '1-upload', BASE), A64);
  const r2 = await convert(id2, { afterStage: () => { mkdirSync(lg.repoPath('racer'), { recursive: true }); } });
  assert.equal(r2.status, 'failed');
  assert.equal(r2.error_code, 'LOCAL_REPO_EXISTS');
  assert.deepEqual(readdirSync(lg.repoPath('racer')), [], 'the empty directory that appeared was not replaced');
  assert.equal(appRow(id2).source_type, 'upload');
  assert.deepEqual(stagingLeft(), []);
});

function crashAfterInstall(slug) {
  const script = `
    const { initDb, getDb } = await import(${JSON.stringify(join(REPO, 'server/db.js'))});
    initDb();
    const uc = await import(${JSON.stringify(join(REPO, 'server/services/uploadConversion.js'))});
    const db = getDb();
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(${JSON.stringify(slug)});
    await uc.convertOneApp(db, app, { appTimeoutMs: 60000, afterInstall: () => process.kill(process.pid, 'SIGKILL') });
    console.log('NOT KILLED');
  `;
  return spawnSync(process.execPath, ['--input-type=module', '-e', script], { env: { ...process.env }, encoding: 'utf8' });
}

test('crash between rename and DB flip: next boot verifies the installed repo and completes the flip', async () => {
  const id = makeApp('crashy');
  const dep = live(id, 'production', release('crashy', 'production', '1-upload', { ...BASE, '.env': 'CRASH_KEY=VALUEMARK-crash\n' }), A64);
  const c = crashAfterInstall('crashy');
  assert.equal(c.signal, 'SIGKILL', c.stdout + c.stderr);
  const mid = outcome(id);
  assert.equal(mid.status, 'installing');
  assert.equal(appRow(id).source_type, 'upload');
  assert.equal(g(lg.repoPath('crashy'), ['rev-parse', 'refs/heads/main']).trim(), mid.tip);

  const r = await uc.convertUploadedApps({ db, appTimeoutMs: 60000 });
  const mine = r.results.find((x) => x.slug === 'crashy');
  assert.equal(mine.status, 'converted', JSON.stringify(mine));
  assert.equal(mine.recovered, true);
  assert.equal(appRow(id).source_type, 'managed');
  assert.equal(appRow(id).last_managed_push_sha, mid.tip);
  assert.equal(db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(dep).commit_hash, mid.tip);
  assert.deepEqual(envVars(id, 'production'), { CRASH_KEY: 'VALUEMARK-crash' });
  assert.equal(JSON.parse(outcome(id).detail_json).recovered, true);
});

test('crash recovery refuses when the release changed or the repo was moved since', async () => {
  const id = makeApp('crashy2');
  const dir = release('crashy2', 'production', '1-upload', BASE);
  assert.equal(crashAfterInstall('crashy2').signal, 'SIGKILL');
  writeFileSync(join(dir, 'server.js'), 'changed\n');
  const r = await convert(id);
  assert.equal(r.error_code, 'RECOVERY_MISMATCH');
  assert.equal(appRow(id).source_type, 'upload');

  const id3 = makeApp('crashy3');
  release('crashy3', 'production', '1-upload', BASE);
  assert.equal(crashAfterInstall('crashy3').signal, 'SIGKILL');
  const repo = lg.repoPath('crashy3');
  const tip = g(repo, ['rev-parse', 'refs/heads/main']).trim();
  execFileSync('git', [`--git-dir=${repo}`, 'update-ref', 'refs/heads/other', tip], { env: CLEAN });
  const r3 = await convert(id3);
  assert.equal(r3.status, 'failed');
  assert.equal(r3.error_code, 'REPO_SHAPE');
  assert.equal(appRow(id3).source_type, 'upload');

  const id4 = makeApp('crashy4');
  release('crashy4', 'production', '1-upload', BASE);
  assert.equal(crashAfterInstall('crashy4').signal, 'SIGKILL');
  // fast-import unpacks a small import into loose objects; remove one blob so
  // refs and HEAD still look right and only fsck can tell.
  const repo4 = lg.repoPath('crashy4');
  const blob = g(repo4, ['rev-parse', 'refs/heads/main:server.js']).trim();
  const loose = join(repo4, 'objects', blob.slice(0, 2), blob.slice(2));
  assert.ok(existsSync(loose), 'expected a loose object to remove');
  rmSync(loose, { force: true });
  const r4 = await convert(id4);
  assert.equal(r4.status, 'failed');
  assert.equal(r4.error_code, 'FSCK_FAILED');
  assert.equal(appRow(id4).source_type, 'upload');
});

test('boot never crashes: a broken database handle and a throwing git layer both resolve', async () => {
  const broken = await uc.convertUploadedAppsAtBoot({ db: { prepare() { throw new Error('boom'); } } });
  assert.equal(broken.error, 'boom');

  const id = makeApp('gitboom');
  live(id, 'production', release('gitboom', 'production', '1-upload', BASE), A64);
  const r = await uc.convertUploadedApps({ db, appTimeoutMs: 60000, localGit: { ...lg, isolatedGitArgs: () => { throw new Error('git layer exploded'); } } });
  const mine = r.results.find((x) => x.slug === 'gitboom');
  assert.equal(mine.status, 'failed');
  assert.equal(appRow(id).source_type, 'upload');
  assert.ok(r.results.length > 1, 'the other candidates were still evaluated');
});

test('per-app timeout and total budget', async () => {
  const id = makeApp('slowpoke');
  live(id, 'production', release('slowpoke', 'production', '1-upload', BASE), A64);
  let gitStarts = 0;
  const countingGit = { ...lg, isolatedGitArgs: (...a) => { gitStarts++; return lg.isolatedGitArgs(...a); } };
  const t = await convert(id, { appTimeoutMs: 1, budgetDeadline: Date.now() - 1, localGit: countingGit });
  assert.equal(t.status, 'failed');
  assert.equal(t.error_code, 'TIMEOUT');
  assert.equal(gitStarts, 0, 'no git process is started once the deadline has passed');
  assert.deepEqual(stagingLeft(), []);
  const r = await uc.convertUploadedApps({ db, budgetMs: 0 });
  assert.equal(r.results.find((x) => x.slug === 'slowpoke').status, 'deferred');
  assert.equal(outcome(id).status, 'deferred');
  assert.equal(appRow(id).source_type, 'upload');
});

test('off switch: environment variable and setting', async () => {
  const id = makeApp('offapp');
  live(id, 'production', release('offapp', 'production', '1-upload', BASE), A64);
  process.env.APPCRANE_UPLOAD_CONVERSION = 'off';
  try {
    const r = await uc.convertUploadedApps({ db, appTimeoutMs: 60000 });
    assert.equal(r.disabled, 'APPCRANE_UPLOAD_CONVERSION=off');
    assert.deepEqual(r.results, []);
  } finally { delete process.env.APPCRANE_UPLOAD_CONVERSION; }
  db.prepare("INSERT INTO settings (key, value) VALUES ('upload_conversion_disabled', '1')").run();
  try {
    const r = await uc.convertUploadedApps({ db, appTimeoutMs: 60000 });
    assert.equal(r.disabled, 'settings.upload_conversion_disabled=1');
  } finally { db.prepare("DELETE FROM settings WHERE key = 'upload_conversion_disabled'").run(); }
  assert.equal(outcome(id), undefined);
  assert.equal(appRow(id).source_type, 'upload');
});
