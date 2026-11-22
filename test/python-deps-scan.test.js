import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Python dependencies in the dependency scan and the release check:
// requirements.txt (exact == pins only; every other line is a warning, never a
// guess), uv.lock, and a pyproject.toml with no lockfile as "nothing to scan"
// with that reason. The fixtures under test/fixtures/python were produced by
// uv 0.13.8 (`uv lock`, `uv export --format requirements-txt`) and trimmed of
// wheel/sdist/hash lines only. Only the OSV network is stubbed.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-pydeps-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'python');

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug', 'error']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { parseManifest, MANIFESTS } = await import('../server/services/ecosystems.js');
const { scanApp, clearAdvisoryCache } = await import('../server/services/appScan.js');
const rc = await import('../server/services/releaseCheck.js');
const { emptySupabase } = await import('../server/services/servedOutputScan.js');

rc._setReleaseCheckDepsForTests({
  crawlServed: async () => ({ ok: true, error: null, findings: [], scanned: [{ path: '/' }], truncated: false, html: true, supabase: emptySupabase() }),
  probeUnauth: async () => ({ ok: true, error: null, openapi: null, requests: 1, truncated: false, discovered: {}, skipped: {}, reads: [], writes: [], write_candidates: [] }),
});

const realFetch = globalThis.fetch;
let queried = [];
function osvReplies(vulns) {
  queried = [];
  clearAdvisoryCache();
  globalThis.fetch = async (url, opts = {}) => {
    const u = String(url);
    if (u.includes('/v1/vulns/')) {
      const id = decodeURIComponent(u.slice(u.indexOf('/v1/vulns/') + 10));
      return { ok: true, status: 200, json: async () => ({ id, affected: [] }) };
    }
    const body = JSON.parse(opts.body);
    queried.push(...body.queries.map((q) => `${q.package.ecosystem}:${q.package.name}@${q.version}`));
    return {
      ok: true, status: 200,
      json: async () => ({ results: body.queries.map((q) => {
        const ids = vulns[`${q.package.name}@${q.version}`];
        return ids ? { vulns: ids.map((id) => ({ id, modified: '2026-09-08T15:15:05Z' })) } : {};
      }) }),
    };
  };
}
after(() => {
  globalThis.fetch = realFetch;
  rc._setReleaseCheckDepsForTests(null);
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

let slot = 300;
function mkApp(slug) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, 'managed')").run(slug, slug, slot++).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function liveRelease(slug, files, env = 'production') {
  const dir = join(ROOT, 'apps', slug, env, 'current');
  mkdirSync(dir, { recursive: true });
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}
function tree(files) {
  const dir = mkdtempSync(join(ROOT, 'tree-'));
  for (const [name, body] of Object.entries(files)) {
    if (body && body.copyFrom) copyFileSync(body.copyFrom, join(dir, name)); else writeFileSync(join(dir, name), body);
  }
  return dir;
}
const depCheck = async (app, releaseDir) => (await rc.runReleaseCheck({ db, app, releaseDir, trigger: 'deploy' })).checks.find((c) => c.id === 'dependencies');

// --- parsers -------------------------------------------------------------

test('uv.lock yields its registry packages and not the editable project itself', () => {
  const pkgs = parseManifest(join(FIX, 'uv.lock'));
  assert.equal(pkgs.length, 20);
  assert.ok(pkgs.every((p) => p.ecosystem === 'PyPI'));
  assert.ok(pkgs.some((p) => p.name === 'flask-cors' && p.version === '3.0.0'));
  assert.ok(!pkgs.some((p) => p.name === 'uvdemo'), 'the project ({ editable = "." }) is not a PyPI package');
});

test('a file called uv.lock with no top-level version line is an error, not an empty clean', () => {
  const dir = tree({ 'uv.lock': '[[package]]\nname = "x"\nversion = "1.0"\n' });
  assert.throws(() => parseManifest(join(dir, 'uv.lock')), /uv\.lock: .*not a uv\.lock/);
});

test('a uv-exported requirements.txt yields every == pin, through hash continuations and markers', () => {
  const pkgs = parseManifest(join(FIX, 'requirements.uv-export.txt'), MANIFESTS.find((m) => m.file === 'requirements.txt'));
  assert.equal(pkgs.length, 20);
  assert.deepEqual(pkgs.map((p) => `${p.name}@${p.version}`).sort(), parseManifest(join(FIX, 'uv.lock')).map((p) => `${p.name}@${p.version}`).sort());
});

test('requirements.txt: only exact pins are packages, under PEP 503 names; ranges and bare names are not guessed', () => {
  const dir = tree({ 'requirements.txt': 'Django>=4.2\nrequests\nPyYAML==5.3 # pinned\nflask[async] == 2.0.0 ; python_version > "3.8"\nbar===1.0\nbaz==1.*\nqux==1.0,<2\n--index-url https://pypi.example.test/simple\n-e .\n' });
  const pkgs = parseManifest(join(dir, 'requirements.txt'));
  assert.deepEqual(pkgs.map((p) => `${p.name}@${p.version}`), ['pyyaml@5.3', 'flask@2.0.0', 'bar@1.0']);
});

// --- release check -------------------------------------------------------

test('release check: a requirements.txt with pins is scanned, and its unpinned lines turn a pass into a warning', async () => {
  osvReplies({});
  const app = mkApp('py-mixed');
  const dir = tree({ 'requirements.txt': 'flask-cors==3.0.0\nDjango>=4.2\nrequests\n-r base.txt\ngit+https://git.example.test/x.git#egg=x\n' });
  const c = await depCheck(app, dir);
  assert.deepEqual(queried, ['PyPI:flask-cors@3.0.0']);
  assert.equal(c.status, 'warn', JSON.stringify(c));
  assert.ok(c.reasons.some((r) => /2 requirement\(s\) not pinned with == were not scanned \(Django>=4\.2, requests\)/.test(r)), JSON.stringify(c.reasons));
  assert.ok(c.reasons.some((r) => /1 -r\/-c include line\(s\) were not followed/.test(r)));
  assert.ok(c.reasons.some((r) => /1 VCS or URL requirement\(s\)/.test(r)));
});

test('release check: a fixable advisory on a pinned requirement fails the check', async () => {
  osvReplies({ 'flask-cors@3.0.0': ['GHSA-xc3p-ff3m-f46v'] });
  globalThis.fetch = ((inner) => async (url, opts) => {
    if (String(url).includes('/v1/vulns/')) {
      return { ok: true, status: 200, json: async () => ({ id: 'GHSA-xc3p-ff3m-f46v', affected: [{ package: { name: 'flask-cors', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.0.9' }] }] }] }) };
    }
    return inner(url, opts);
  })(globalThis.fetch);
  const app = mkApp('py-vuln');
  const c = await depCheck(app, tree({ 'requirements.txt': 'flask-cors==3.0.0\n' }));
  assert.equal(c.status, 'fail', JSON.stringify(c));
  assert.equal(c.fixable, 1);
});

test('release check: a requirements.txt that pins nothing is not scanned clean', async () => {
  osvReplies({});
  const app = mkApp('py-unpinned');
  const c = await depCheck(app, tree({ 'requirements.txt': 'django>=4.2\nrequests\n' }));
  assert.deepEqual(queried, [], 'nothing was asked about');
  assert.equal(c.status, 'warn', JSON.stringify(c));
  assert.match(c.reasons[0], /nothing to scan \(no package is pinned to an exact version/);
});

test('release check: a uv.lock is scanned', async () => {
  osvReplies({});
  const app = mkApp('py-uv');
  const c = await depCheck(app, tree({ 'uv.lock': { copyFrom: join(FIX, 'uv.lock') }, 'pyproject.toml': '[project]\nname = "uvdemo"\n' }));
  assert.equal(queried.length, 20);
  assert.equal(c.status, 'pass', JSON.stringify(c));
});

test('release check: a pyproject.toml with no lockfile is nothing to scan, and says why', async () => {
  osvReplies({});
  const app = mkApp('py-pyproject');
  const c = await depCheck(app, tree({ 'pyproject.toml': '[project]\nname = "x"\ndependencies = ["django>=4.2"]\n' }));
  assert.equal(c.status, 'pass', JSON.stringify(c));
  assert.match(c.reasons[0], /nothing to scan \(pyproject\.toml lists version ranges, not what is installed, and there is no uv\.lock, poetry\.lock, Pipfile\.lock or ==-pinned requirements\.txt/);
});

test('release check: a pyproject.toml next to a frontend lockfile warns that the Python half was not scanned', async () => {
  osvReplies({});
  const app = mkApp('py-half');
  const c = await depCheck(app, tree({
    'pyproject.toml': '[project]\nname = "x"\n',
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' }, 'node_modules/ms': { version: '2.1.3' } } }),
  }));
  assert.equal(c.status, 'warn', JSON.stringify(c));
  assert.ok(c.reasons.some((r) => /pyproject\.toml: .*Python dependencies were not scanned/.test(r)));
});

// --- deploy-time scan (app_vuln_scans) -----------------------------------

test('scanApp records unpinned requirements as notes, and the sandbox-row path of the release check warns on them', async () => {
  osvReplies({});
  const app = mkApp('py-scanapp');
  liveRelease(app.slug, { 'requirements.txt': 'flask==2.0.0\nrequests\n' }, 'sandbox');
  db.prepare("INSERT INTO deployments (app_id, env, status, commit_hash, started_at, finished_at) VALUES (?, 'sandbox', 'live', 'abc123', '2000-01-01 00:00:00', '2000-01-01 00:00:00')").run(app.id);
  const row = await scanApp(db, app, 'sandbox', 'deploy');
  assert.equal(row.status, 'ok');
  assert.equal(row.package_count, 1);
  assert.match(JSON.parse(row.notes)[0], /requirements\.txt: 1 requirement\(s\) not pinned with == were not scanned \(requests\)/);
  queried = [];
  const c = (await rc.runReleaseCheck({ db, app, trigger: 'promote' })).checks.find((x) => x.id === 'dependencies');
  assert.equal(queried.length, 0, 'the fresh sandbox row was used, not a new scan');
  assert.equal(c.status, 'warn', JSON.stringify(c));
  assert.ok(c.reasons.some((r) => /not pinned with ==/.test(r)));
});

test('scanApp: a pyproject-only release is skipped with the reason', async () => {
  osvReplies({});
  const app = mkApp('py-scanapp-pyproject');
  liveRelease(app.slug, { 'pyproject.toml': '[project]\nname = "x"\n' });
  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'skipped');
  assert.match(row.error, /^pyproject\.toml lists version ranges/);
  assert.equal(row.notes, null);
});

test('scanApp: a requirements.txt that pins nothing is skipped, not ok', async () => {
  osvReplies({});
  const app = mkApp('py-scanapp-none');
  liveRelease(app.slug, { 'requirements.txt': 'requests\n' });
  const row = await scanApp(db, app, 'production', 'deploy');
  assert.equal(row.status, 'skipped');
  assert.equal(queried.length, 0);
});
