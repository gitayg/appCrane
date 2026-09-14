import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Boot-time conversion of LEGACY upload apps (source_type='managed_legacy',
// renamed from 'upload' by migration 052) into Crane-hosted ones.

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = mkdtempSync(join(tmpdir(), 'crane-uploadconv-legacy-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
delete process.env.APPCRANE_UPLOAD_CONVERSION;

const origLog = console.log;
console.log = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { decrypt } = await import('../server/services/encryption.js');
const uc = await import('../server/services/uploadConversion.js');
const lg = await import('../server/services/localGit.js');

const CLEAN = {
  PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_AUTHOR_NAME: 'Test', GIT_AUTHOR_EMAIL: 'test@example.com', GIT_COMMITTER_NAME: 'Test', GIT_COMMITTER_EMAIL: 'test@example.com',
};
const g = (gitDir, args) => execFileSync('git', [`--git-dir=${gitDir}`, ...args], { env: CLEAN, stdio: ['pipe', 'pipe', 'pipe'] }).toString('utf8');

let slot = 8000;
const makeApp = (slug, type = 'managed_legacy', githubUrl = null) =>
  db.prepare('INSERT INTO apps (name, slug, slot, source_type, github_url) VALUES (?,?,?,?,?)').run(slug, slug, ++slot, type, githubUrl).lastInsertRowid;
const appRow = (id) => db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
const outcome = (id) => db.prepare('SELECT * FROM upload_conversions WHERE app_id = ?').get(id);
const detail = (id) => JSON.parse(outcome(id).detail_json);
const envVars = (id, env) => Object.fromEntries(db.prepare('SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ?').all(id, env).map((r) => [r.key, decrypt(r.value_encrypted)]));
const live = (id, env, dir, hash) => db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash, release_path) VALUES (?,?,'live',?,?)").run(id, env, hash, dir).lastInsertRowid;
const commitOf = (dep) => db.prepare('SELECT commit_hash FROM deployments WHERE id = ?').get(dep).commit_hash;
const convert = (id, opts = {}) => uc.convertOneApp(db, appRow(id), { appTimeoutMs: 60000, ...opts });
const statusOf = (slug) => uc.getUploadConversionStatus(db).apps.find((a) => a.slug === slug);

function release(slug, env, name, files) {
  const dir = join(ROOT, 'apps', slug, env, 'releases', name);
  mkdirSync(dir, { recursive: true });
  for (const [p, v] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), v);
  }
  return dir;
}

const BASE = {
  'package.json': JSON.stringify({ name: 'x', version: '1.0.0', scripts: { start: 'node server.js' }, dependencies: { express: '4' } }),
  'package-lock.json': '{}',
  'server.js': 'console.log(1)\n',
};

after(() => {
  console.log = origLog;
  rmSync(ROOT, { recursive: true, force: true });
});

test('a legacy upload app is a candidate and converts: pre-sha256 identity falls back to tree-sha256, original type recorded for revert', async () => {
  const id = makeApp('legacy');
  const prodDir = release('legacy', 'production', '1600000000000-upload', { ...BASE, 'server.js': 'prod\n', '.env': 'LEGACY_KEY=legacy-prod\n' });
  release('legacy', 'sandbox', '1600000001000-upload', { ...BASE, 'server.js': 'old sandbox\n' });
  release('legacy', 'sandbox', '1600000002000-upload', { ...BASE, 'server.js': 'sandbox\n' });
  const prodDep = live(id, 'production', prodDir, 'unknown');

  assert.ok(uc.candidateApps(db).some((a) => a.slug === 'legacy'), 'managed_legacy is selected');
  assert.deepEqual(uc.getUploadConversionStatus(db).pending.filter((s) => s === 'legacy'), ['legacy']);

  let whileRunning;
  const r = await convert(id, { afterStage: () => { whileRunning = [outcome(id).status, statusOf('legacy').original_source_type]; } });
  assert.equal(r.status, 'converted', JSON.stringify(r));
  assert.deepEqual(whileRunning, ['running', 'managed_legacy'], 'the running row already names the original type');

  const app = appRow(id);
  assert.equal(app.source_type, 'managed');
  assert.equal(app.repo_backend, 'local');
  const repo = lg.repoPath('legacy');
  const subjects = g(repo, ['log', '--format=%s', 'refs/heads/main']).trim().split('\n');
  assert.equal(subjects.length, 2);
  assert.match(subjects[1], /^Imported from upload release 1600000000000-upload tree-sha256:[0-9a-f]{64} \(production\)$/);
  assert.match(subjects[0], /^Imported from upload release 1600000002000-upload tree-sha256:[0-9a-f]{64} \(sandbox\)$/);
  assert.equal(g(repo, ['show', 'refs/heads/main:server.js']), 'sandbox\n');

  const commits = JSON.parse(outcome(id).commits_json);
  assert.match(commits.production.identity, /^tree-sha256:[0-9a-f]{64}$/);
  assert.equal(commits.production.previous_commit_hash, 'unknown');
  assert.equal(commitOf(prodDep), commits.production.commit);
  assert.equal(commits.sandbox.source, 'newest_upload_release');
  assert.deepEqual(envVars(id, 'production'), { LEGACY_KEY: 'legacy-prod' });

  assert.equal(detail(id).original_source_type, 'managed_legacy');
  const s = statusOf('legacy');
  assert.equal(s.original_source_type, 'managed_legacy');
  assert.deepEqual(s.revert, { source_type: 'managed_legacy', repo_backend: null });
  assert.equal(uc.candidateApps(db).some((a) => a.slug === 'legacy'), false, 'not a candidate once converted');

  const refusal = uc.conversionRefusal(db, appRow(id));
  assert.equal(refusal?.code, 'APP_IS_CRANE_HOSTED');
  assert.equal(uc.conversionRefusal(db, { ...appRow(id), source_type: 'managed_legacy', repo_backend: null }), null, 'a reverted legacy app is not refused');

  const again = await uc.convertUploadedApps({ db, appTimeoutMs: 60000 });
  assert.deepEqual(again.results.filter((x) => x.slug === 'legacy'), [], 'idempotent');
});

test('an upload app still records upload as its original type', async () => {
  const id = makeApp('plainupload', 'upload');
  live(id, 'production', release('plainupload', 'production', '1-upload', BASE), `sha256:${'a'.repeat(64)}`);
  assert.equal((await convert(id)).status, 'converted');
  assert.equal(detail(id).original_source_type, 'upload');
  assert.deepEqual(statusOf('plainupload').revert, { source_type: 'upload', repo_backend: null });
});

test('status of a row converted before the original type was recorded reads upload (the only type converted then)', () => {
  const id = makeApp('oldrow', 'managed');
  db.prepare("INSERT INTO upload_conversions (app_id, slug, status, detail_json) VALUES (?, 'oldrow', 'converted', ?)").run(id, JSON.stringify({ recovered: false }));
  const s = statusOf('oldrow');
  assert.equal(s.original_source_type, 'upload');
  assert.deepEqual(s.revert, { source_type: 'upload', repo_backend: null });
});

for (const [from, to] of [['managed_legacy', 'github'], ['managed_legacy', 'upload'], ['upload', 'managed_legacy']]) {
  test(`flip is guarded by the original type: ${from} changed to ${to} meanwhile is not flipped`, async () => {
    const slug = `guard-${from}-${to}`.replace(/_/g, '-');
    const id = makeApp(slug, from);
    const dep = live(id, 'production', release(slug, 'production', '1-upload', { ...BASE, '.env': 'K=v\n' }), 'unknown');
    const r = await convert(id, { afterInstall: () => { db.prepare('UPDATE apps SET source_type = ? WHERE id = ?').run(to, id); } });
    assert.equal(r.status, 'failed', JSON.stringify(r));
    assert.equal(r.error_code, 'FLIP_GUARD');
    assert.equal(appRow(id).source_type, to);
    assert.equal(appRow(id).repo_backend, null);
    assert.deepEqual(envVars(id, 'production'), {});
    assert.equal(commitOf(dep), 'unknown');
  });
}

test('a legacy app with a github_url is skipped, untouched; an upload app with one still converts', async () => {
  const id = makeApp('legacy-gh', 'managed_legacy', 'https://github.com/example/legacy-gh');
  const dep = live(id, 'production', release('legacy-gh', 'production', '1-upload', { ...BASE, '.env': 'K=v\n' }), 'unknown');
  const r = await convert(id);
  assert.equal(r.status, 'skipped', JSON.stringify(r));
  assert.equal(r.error_code, 'legacy_has_github_url');
  const app = appRow(id);
  assert.equal(app.source_type, 'managed_legacy');
  assert.equal(app.repo_backend, null);
  assert.equal(app.github_url, 'https://github.com/example/legacy-gh');
  assert.ok(!existsSync(lg.repoPath('legacy-gh')));
  assert.deepEqual(envVars(id, 'production'), {});
  assert.equal(commitOf(dep), 'unknown');
  assert.equal(statusOf('legacy-gh').skip_reason, 'legacy_has_github_url');

  const id2 = makeApp('upload-gh', 'upload', 'https://github.com/example/upload-gh');
  live(id2, 'production', release('upload-gh', 'production', '1-upload', BASE), 'unknown');
  assert.equal((await convert(id2)).status, 'converted');
});

test('a skipped legacy app records its type and stays legacy', async () => {
  const id = makeApp('legacy-empty');
  const r = await convert(id);
  assert.equal(r.error_code, 'releases_missing');
  assert.equal(appRow(id).source_type, 'managed_legacy');
  assert.equal(detail(id).original_source_type, 'managed_legacy');
  assert.equal(statusOf('legacy-empty').revert, null);
});

test('convertOneApp refuses an app that is neither upload nor legacy: nothing flipped, nothing recorded', async () => {
  const id = makeApp('gh-app', 'github', 'https://github.com/example/gh-app');
  release('gh-app', 'production', '1-upload', BASE);
  const r = await convert(id);
  assert.equal(r.status, 'skipped');
  assert.equal(r.error_code, 'not_an_upload_app');
  assert.equal(appRow(id).source_type, 'github');
  assert.equal(appRow(id).repo_backend, null);
  assert.equal(outcome(id), undefined);
  assert.ok(!existsSync(lg.repoPath('gh-app')));
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

test('legacy crash between rename and DB flip: next boot completes the flip under the legacy guard', async () => {
  const id = makeApp('legacy-crash');
  const dep = live(id, 'production', release('legacy-crash', 'production', '1-upload', { ...BASE, '.env': 'CRASH_KEY=crash\n' }), 'unknown');
  const c = crashAfterInstall('legacy-crash');
  assert.equal(c.signal, 'SIGKILL', c.stdout + c.stderr);
  const mid = outcome(id);
  assert.equal(mid.status, 'installing');
  assert.equal(JSON.parse(mid.detail_json).original_source_type, 'managed_legacy');
  assert.equal(appRow(id).source_type, 'managed_legacy');

  const r = await uc.convertUploadedApps({ db, appTimeoutMs: 60000 });
  const mine = r.results.find((x) => x.slug === 'legacy-crash');
  assert.equal(mine?.status, 'converted', JSON.stringify(r.results));
  assert.equal(mine.recovered, true);
  assert.equal(appRow(id).source_type, 'managed');
  assert.equal(appRow(id).last_managed_push_sha, mid.tip);
  assert.equal(commitOf(dep), mid.tip);
  assert.deepEqual(envVars(id, 'production'), { CRASH_KEY: 'crash' });
  assert.equal(detail(id).original_source_type, 'managed_legacy');
  assert.equal(detail(id).recovered, true);
});

test('a legacy app deferred by the budget records its type, not the upload fallback', async () => {
  const id = makeApp('legacy-deferred');
  live(id, 'production', release('legacy-deferred', 'production', '1-upload', BASE), 'unknown');
  const r = await uc.convertUploadedApps({ db, budgetMs: 0 });
  assert.equal(r.results.find((x) => x.slug === 'legacy-deferred').status, 'deferred');
  assert.equal(statusOf('legacy-deferred').original_source_type, 'managed_legacy');
  db.prepare('DELETE FROM upload_conversions WHERE app_id = ?').run(id);
  db.prepare("UPDATE apps SET source_type = 'github' WHERE id = ?").run(id);
});

test('off switch leaves legacy apps alone too', async () => {
  const id = makeApp('legacy-off');
  live(id, 'production', release('legacy-off', 'production', '1-upload', BASE), 'unknown');
  process.env.APPCRANE_UPLOAD_CONVERSION = 'off';
  try {
    const r = await uc.convertUploadedApps({ db, appTimeoutMs: 60000 });
    assert.deepEqual(r.results, []);
  } finally { delete process.env.APPCRANE_UPLOAD_CONVERSION; }
  assert.equal(outcome(id), undefined);
  assert.equal(appRow(id).source_type, 'managed_legacy');
});
