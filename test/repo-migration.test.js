import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, statSync } from 'fs';
import { createHash } from 'crypto';
import http from 'http';
import { tmpdir } from 'os';
import { join } from 'path';

// Phase 3: moving GitHub-backed managed apps to <DATA_DIR>/repos at boot.
//
// Nothing here reaches GitHub. "GitHub" is a local bare repo served by
// `git http-backend` behind a tiny Node HTTP server that insists on the same
// Basic x-access-token header the service account sends, so the credential
// path is exercised for real. Everything is read back with an independent,
// isolated git — never through the module under test.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-repomig-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'info';
delete process.env.APPCRANE_REPO_MIGRATION;

const REAL_GIT = execFileSync('sh', ['-c', 'command -v git']).toString().trim();
const HTTP_BACKEND = join(execFileSync(REAL_GIT, ['--exec-path']).toString().trim(), 'git-http-backend');
const ORIG_PATH = process.env.PATH;

// argv of every top-level git the module runs. gitEnv() rebuilds the
// environment from scratch, so the log path is baked into the shim itself.
const SHIM = join(ROOT, 'bin');
const ARGV_LOG = join(ROOT, 'git-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'git'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> '${ARGV_LOG}'
exec '${REAL_GIT}' "$@"
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${ORIG_PATH}`;

const logLines = [];
const origLog = console.log;
console.log = (...a) => { logLines.push(a.join(' ')); };

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const rm = await import('../server/services/repoMigration.js');

const TOKEN = 'ghs_TESTTOKEN_' + 'q7Zk3'.repeat(6);
const TOKEN_B64 = Buffer.from(`x-access-token:${TOKEN}`).toString('base64');
const GH_ROOT = join(ROOT, 'github');
mkdirSync(GH_ROOT, { recursive: true });

const CLEAN = {
  PATH: ORIG_PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_AUTHOR_NAME: 'Test', GIT_AUTHOR_EMAIL: 'test@example.com',
  GIT_COMMITTER_NAME: 'Test', GIT_COMMITTER_EMAIL: 'test@example.com',
};
const g = (args, opts = {}) => execFileSync(REAL_GIT, args, { env: CLEAN, stdio: ['pipe', 'pipe', 'pipe'], ...opts }).toString('utf8').trim();
const refsOf = (gitDir, ...patterns) => {
  const out = g([`--git-dir=${gitDir}`, 'for-each-ref', '--format=%(objectname) %(refname)', ...patterns]);
  return Object.fromEntries(out.split('\n').filter(Boolean).map((l) => l.split(' ').reverse()));
};

// ---- fake GitHub -----------------------------------------------------------

const seenAuth = [];
const seenPaths = [];
const server = http.createServer((req, res) => {
  seenAuth.push(req.headers.authorization || null);
  seenPaths.push(req.url);
  if (req.headers.authorization !== `Basic ${TOKEN_B64}`) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="fake-github"' });
    return res.end();
  }
  const u = new URL(req.url, 'http://127.0.0.1');
  const child = spawn(HTTP_BACKEND, [], {
    env: {
      PATH: ORIG_PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_PROJECT_ROOT: GH_ROOT, GIT_HTTP_EXPORT_ALL: '1', PATH_INFO: decodeURIComponent(u.pathname),
      QUERY_STRING: u.search.slice(1), REQUEST_METHOD: req.method, REMOTE_ADDR: '127.0.0.1',
      CONTENT_TYPE: req.headers['content-type'] || '', HTTP_CONTENT_ENCODING: req.headers['content-encoding'] || '',
      HTTP_GIT_PROTOCOL: req.headers['git-protocol'] || '',
    },
  });
  req.pipe(child.stdin);
  let buf = Buffer.alloc(0);
  let started = false;
  child.stdout.on('data', (c) => {
    if (started) return res.write(c);
    buf = Buffer.concat([buf, c]);
    let i = buf.indexOf('\r\n\r\n'); let sep = 4;
    if (i < 0) { i = buf.indexOf('\n\n'); sep = 2; }
    if (i < 0) return;
    let status = 200;
    const headers = {};
    for (const line of buf.subarray(0, i).toString().split(/\r?\n/)) {
      const k = line.slice(0, line.indexOf(':')).trim();
      const v = line.slice(line.indexOf(':') + 1).trim();
      if (k.toLowerCase() === 'status') status = parseInt(v, 10); else if (k) headers[k] = v;
    }
    res.writeHead(status, headers);
    started = true;
    res.write(buf.subarray(i + sep));
  });
  child.stdout.on('end', () => res.end());
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;

// A server that accepts and never answers: the hang the timeout must bound.
const hangSockets = [];
const hang = http.createServer((req) => { hangSockets.push(req.socket); });
await new Promise((r) => hang.listen(0, '127.0.0.1', r));
const HANG_BASE = `http://127.0.0.1:${hang.address().port}`;

after(() => {
  console.log = origLog;
  for (const s of hangSockets) s.destroy();
  server.close();
  hang.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

function commit(work, file, content, msg) {
  writeFileSync(join(work, file), content);
  g(['-C', work, 'add', '--', file]);
  g(['-C', work, 'commit', '-q', '-m', msg]);
  return g(['-C', work, 'rev-parse', 'HEAD']);
}

/** GitHub-shaped AMC_<slug>: main + develop, an annotated and a lightweight tag, and a refs/pull ref. */
function makeGithubRepo(slug) {
  const bare = join(GH_ROOT, 'example-owner', `AMC_${slug}.git`);
  g(['init', '--bare', '--quiet', '--initial-branch=main', bare]);
  const work = mkdtempSync(join(ROOT, 'work-'));
  g(['init', '--quiet', '--initial-branch=main', work]);
  commit(work, 'README.md', `# AMC_${slug}\n`, 'Initial commit');
  commit(work, 'app.js', 'console.log(1)\n', 'app');
  g(['-C', work, 'tag', '-a', 'v1.0.0', '-m', 'release 1']);
  g(['-C', work, 'checkout', '-q', '-b', 'develop']);
  commit(work, 'dev.js', 'dev\n', 'develop work');
  g(['-C', work, 'tag', 'light-dev']);
  g(['-C', work, 'checkout', '-q', '-b', 'pr']);
  const prSha = commit(work, 'pr.js', 'pr\n', 'pull request head');
  g(['-C', work, 'push', '-q', bare, 'main', 'develop', 'refs/tags/v1.0.0', 'refs/tags/light-dev']);
  g(['-C', work, 'push', '-q', bare, `${prSha}:refs/pull/1/head`]);
  return { bare, work, prSha };
}

const remoteFor = (slug) => async () => ({ url: `${BASE}/example-owner/AMC_${slug}.git`, token: TOKEN });
const optsFor = (resolveRemote, extra = {}) => ({ db, resolveRemote, allowedSchemes: ['http'], appTimeoutMs: 60000, budgetMs: 120000, ...extra });

function addApp(slug, { backend = null, branch = 'main', source = 'managed' } = {}) {
  const slot = 5000 + db.prepare('SELECT COUNT(*) AS n FROM apps').get().n + Math.floor(Math.random() * 1000);
  return db.prepare('INSERT INTO apps (name, slug, slot, source_type, github_url, branch, repo_backend) VALUES (?,?,?,?,?,?,?)')
    .run(slug, slug, slot, source, `https://github.com/example-owner/AMC_${slug}`, branch, backend).lastInsertRowid;
}
const appRow = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
const migRow = (slug) => db.prepare('SELECT * FROM repo_migrations WHERE slug = ?').get(slug);
function resetApps() {
  db.prepare('DELETE FROM repo_migrations').run();
  db.prepare('DELETE FROM apps').run();
  rmSync(lg.reposRoot(), { recursive: true, force: true });
}

function filesUnder(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) out.push(...filesUnder(p)); else out.push(p);
  }
  return out;
}
const containsSecret = (buf) => buf.includes(TOKEN) || buf.includes(TOKEN_B64);

// ---------------------------------------------------------------------------

test('migrates a GitHub-shaped repo: every branch and tag, no refs/pull, remote-free, marker flipped', async () => {
  resetApps();
  const { bare, prSha } = makeGithubRepo('alpha');
  addApp('alpha');
  const githubRefs = refsOf(bare);
  assert.ok(githubRefs['refs/pull/1/head'], 'fixture must carry a refs/pull ref');

  const out = await rm.migrateManagedReposToLocal(optsFor(remoteFor('alpha')));
  assert.deepEqual(out.results.map((r) => [r.slug, r.status]), [['alpha', 'migrated']]);

  assert.equal(appRow('alpha').repo_backend, 'local');
  const local = lg.repoPath('alpha');
  const localRefs = refsOf(local);
  const expected = Object.fromEntries(Object.entries(githubRefs).filter(([r]) => !r.startsWith('refs/pull/')));
  assert.deepEqual(localRefs, expected, 'local refs must be exactly GitHub heads + tags');
  assert.equal(Object.keys(localRefs).length, 4);
  // Deleting a refs/pull ref after fetching it would still carry the pull
  // request's objects (unreachable, but on disk and in every backup bundle's
  // source repo). They must never have been fetched at all.
  assert.throws(() => g([`--git-dir=${local}`, 'cat-file', '-e', prSha]), 'the refs/pull commit object must not be in the local repo');
  assert.equal(g([`--git-dir=${local}`, 'symbolic-ref', 'HEAD']), 'refs/heads/main');
  assert.equal(g([`--git-dir=${local}`, 'cat-file', '-t', 'refs/tags/v1.0.0']), 'tag', 'annotated tag object kept');
  const cfg = readFileSync(join(local, 'config'), 'utf8');
  assert.doesNotMatch(cfg, /\[remote|extraheader|http|url\s*=/i);
  assert.equal(existsSync(join(local, 'FETCH_HEAD')), false);
  assert.equal(existsSync(lg.migrationStagingPath('alpha')), false, 'staging dir removed');
  g([`--git-dir=${local}`, 'fsck', '--full', '--no-progress']);

  const row = migRow('alpha');
  assert.equal(row.status, 'migrated');
  assert.deepEqual(JSON.parse(row.refs_json), expected);
  assert.ok(seenAuth.includes(`Basic ${TOKEN_B64}`), 'fake GitHub received the service-account header');
  assert.ok(!seenPaths.some((p) => p.includes('refs/pull')));

  // The app now works through the phase-1 API on its own.
  assert.equal(await lg.getBranchHeadSha('alpha', 'develop'), githubRefs['refs/heads/develop']);

  if (process.env.PHASE3_EVIDENCE) {
    writeFileSync(process.env.PHASE3_EVIDENCE, JSON.stringify({
      github_refs_including_pull: githubRefs, local_refs: localRefs,
      marker: appRow('alpha').repo_backend, migration_row: row,
      local_head: g([`--git-dir=${local}`, 'symbolic-ref', 'HEAD']), local_config: cfg,
      log: logLines.filter((l) => l.includes('repo-migration')),
    }, null, 2));
  }
});

test('the token is not in the repo files, argv, logs or the database', async () => {
  const leaks = [];
  for (const f of filesUnder(ROOT)) {
    if (f.startsWith(GH_ROOT) || f.includes(`${ROOT}/work-`)) continue;
    if (containsSecret(readFileSync(f))) leaks.push(f);
  }
  assert.deepEqual(leaks, [], 'no file under DATA_DIR (repos, sqlite db/wal, argv log) contains the token');
  const argv = readFileSync(ARGV_LOG, 'utf8');
  assert.match(argv, /fetch/, 'argv log captured the fetch');
  assert.ok(!containsSecret(Buffer.from(argv)));
  assert.ok(!logLines.some((l) => containsSecret(Buffer.from(l))));
  const rows = JSON.stringify(db.prepare('SELECT * FROM repo_migrations').all());
  assert.ok(!containsSecret(Buffer.from(rows)));
});

test('a rejected token fails that app, leaves it on GitHub, and the next app still migrates', async () => {
  resetApps();
  makeGithubRepo('bad-token');
  makeGithubRepo('good-after');
  addApp('bad-token');
  addApp('good-after');
  const resolve = async (app) => ({ url: `${BASE}/example-owner/AMC_${app.slug}.git`, token: app.slug === 'bad-token' ? 'ghs_wrong' : TOKEN });
  const out = await rm.migrateManagedReposToLocal(optsFor(resolve));
  assert.deepEqual(out.results.map((r) => [r.slug, r.status]), [['bad-token', 'failed'], ['good-after', 'migrated']]);
  assert.equal(appRow('bad-token').repo_backend, null);
  assert.equal(lg.localRepoExists('bad-token'), false);
  assert.equal(existsSync(lg.migrationStagingPath('bad-token')), false);
  assert.equal(migRow('bad-token').error_code, 'GIT_FAILED');
  assert.doesNotMatch(migRow('bad-token').error, /ghs_wrong/);
  assert.equal(appRow('good-after').repo_backend, 'local');
});

test('a push that lands on GitHub mid-migration fails the SHA compare and nothing switches', async () => {
  resetApps();
  const { bare, work } = makeGithubRepo('racing');
  addApp('racing');
  const out = await rm.migrateManagedReposToLocal(optsFor(remoteFor('racing'), {
    afterStage: async () => {
      g(['-C', work, 'checkout', '-q', 'develop']);
      commit(work, 'late.js', 'late\n', 'late push');
      g(['-C', work, 'push', '-q', bare, 'develop']);
    },
  }));
  assert.deepEqual(out.results.map((r) => [r.slug, r.status, r.error_code]), [['racing', 'failed', 'SHA_MISMATCH']]);
  assert.equal(appRow('racing').repo_backend, null);
  assert.equal(lg.localRepoExists('racing'), false);
  assert.equal(existsSync(lg.migrationStagingPath('racing')), false);
  const diffs = JSON.parse(migRow('racing').refs_json);
  assert.deepEqual(diffs.map((d) => d.ref), ['refs/heads/develop']);
  assert.equal(diffs[0].github, refsOf(bare)['refs/heads/develop']);
});

test('compareRefs requires the exact same ref set and SHAs', () => {
  const a = 'a'.repeat(40); const b = 'b'.repeat(40);
  assert.equal(rm.compareRefs({ 'refs/heads/main': a }, { 'refs/heads/main': a }).equal, true);
  assert.equal(rm.compareRefs({ 'refs/heads/main': a }, { 'refs/heads/main': b }).equal, false);
  assert.equal(rm.compareRefs({ 'refs/heads/main': a, 'refs/tags/v1': b }, { 'refs/heads/main': a }).equal, false);
  assert.equal(rm.compareRefs({ 'refs/heads/main': a }, { 'refs/heads/main': a, 'refs/heads/x': b }).equal, false);
  assert.equal(rm.compareRefs({}, {}).equal, false, 'an empty GitHub repo is never a match');
});

test('the migrated branch must exist on GitHub', async () => {
  resetApps();
  makeGithubRepo('nobranch');
  addApp('nobranch', { branch: 'release' });
  const out = await rm.migrateManagedReposToLocal(optsFor(remoteFor('nobranch')));
  assert.equal(out.results[0].status, 'failed');
  assert.equal(appRow('nobranch').repo_backend, null);
  assert.equal(lg.localRepoExists('nobranch'), false);
});

test('idempotent: local apps are not selected, an existing local repo is never overwritten, a half-staged dir is discarded, a rerun does nothing', async () => {
  resetApps();
  let calls = 0;
  const counting = (inner) => async (app) => { calls++; return inner(app); };

  // (a) already local: not a candidate, its repo untouched
  addApp('already-local', { backend: 'local' });
  await lg.createAppRepo('already-local');
  const beforeA = refsOf(lg.repoPath('already-local'));
  // (b) NULL marker but a repo already on disk
  makeGithubRepo('stray');
  addApp('stray');
  await lg.createAppRepo('stray');
  const strayHead = join(lg.repoPath('stray'), 'HEAD');
  const beforeB = { refs: refsOf(lg.repoPath('stray')), head: createHash('sha256').update(readFileSync(strayHead)).digest('hex') };
  // (c) a staging dir left by a crash, holding a branch GitHub does not have
  makeGithubRepo('halfdone');
  addApp('halfdone');
  const stage = lg.migrationStagingPath('halfdone');
  g(['init', '--bare', '--quiet', '--initial-branch=main', stage]);
  const junkWork = mkdtempSync(join(ROOT, 'work-'));
  g(['init', '--quiet', '--initial-branch=stale', junkWork]);
  commit(junkWork, 'junk', 'junk\n', 'junk');
  g(['-C', junkWork, 'push', '-q', stage, 'stale']);
  writeFileSync(join(stage, 'FETCH_HEAD'), 'junk\n');

  const resolver = counting(async (app) => ({ url: `${BASE}/example-owner/AMC_${app.slug}.git`, token: TOKEN }));
  const out = await rm.migrateManagedReposToLocal(optsFor(resolver));
  const bySlug = Object.fromEntries(out.results.map((r) => [r.slug, r]));
  assert.equal(bySlug['already-local'], undefined);
  assert.deepEqual(refsOf(lg.repoPath('already-local')), beforeA);
  assert.equal(bySlug.stray.status, 'skipped');
  assert.equal(bySlug.stray.error_code, 'LOCAL_REPO_EXISTS');
  assert.equal(appRow('stray').repo_backend, null);
  assert.deepEqual(refsOf(lg.repoPath('stray')), beforeB.refs);
  assert.equal(createHash('sha256').update(readFileSync(strayHead)).digest('hex'), beforeB.head);
  assert.equal(bySlug.halfdone.status, 'migrated');
  assert.equal(refsOf(lg.repoPath('halfdone'))['refs/heads/stale'], undefined, 'nothing from the half-staged dir survives');
  assert.equal(calls, 1, 'only halfdone reached the remote');

  calls = 0;
  const again = await rm.migrateManagedReposToLocal(optsFor(resolver));
  assert.deepEqual(again.results.map((r) => [r.slug, r.status]), [['stray', 'skipped']]);
  assert.equal(calls, 0);
  assert.equal(migRow('stray').attempts, 2);
});

test('finalizeStagedMirror strips remotes, hosting refs and FETCH_HEAD; inspect refuses what remains', async () => {
  resetApps();
  const { bare, prSha } = makeGithubRepo('shape');
  const stage = lg.migrationStagingPath('shape');
  mkdirSync(lg.reposRoot(), { recursive: true });
  // What a `git clone --mirror` would have left: origin with a URL, refs/pull.
  g(['clone', '--quiet', '--mirror', bare, stage]);
  g([`--git-dir=${stage}`, 'config', 'remote.upstream.url', 'https://example.com/x.git']);
  writeFileSync(join(stage, 'FETCH_HEAD'), `${prSha}\t\tbranch 'x' of https://example.com/x\n`);
  const deadline = Date.now() + 30000;
  const dirty = await lg.inspectMigratedRepoShape(stage, { branch: 'main', deadline });
  assert.ok(dirty.some((p) => /remote\.origin\.url/.test(p)), `inspect must flag the remote: ${dirty}`);
  assert.ok(dirty.some((p) => /refs\/pull\/1\/head/.test(p)));
  assert.ok(dirty.some((p) => /FETCH_HEAD/.test(p)));

  await lg.finalizeStagedMirror(stage, { branch: 'main', deadline });
  assert.deepEqual(await lg.inspectMigratedRepoShape(stage, { branch: 'main', deadline }), []);
  assert.doesNotMatch(readFileSync(join(stage, 'config'), 'utf8'), /remote/);
  assert.equal(refsOf(stage)['refs/pull/1/head'], undefined);

  const noHead = lg.migrationStagingPath('shape2');
  g(['init', '--bare', '--quiet', '--initial-branch=main', noHead]);
  assert.ok((await lg.inspectMigratedRepoShape(noHead, { branch: 'main', deadline })).some((p) => /does not resolve/.test(p)));
  rmSync(stage, { recursive: true, force: true });
  rmSync(noHead, { recursive: true, force: true });
});

test('a remote that never answers is killed at the deadline, and the token is not in any process argv', { timeout: 30000 }, async () => {
  resetApps();
  addApp('hangs');
  const started = Date.now();
  const running = rm.migrateManagedReposToLocal(optsFor(async () => ({ url: `${HANG_BASE}/example-owner/AMC_hangs.git`, token: TOKEN }), { appTimeoutMs: 2500 }));
  await new Promise((r) => setTimeout(r, 1200));
  const ps = execFileSync('ps', ['-A', '-ww', '-o', 'args='], { maxBuffer: 64 * 1024 * 1024 }).toString('utf8');
  const out = await running;
  const took = Date.now() - started;
  assert.ok(ps.includes(`${HANG_BASE}/example-owner/AMC_hangs.git`), 'the snapshot caught the live git process');
  assert.ok(!containsSecret(Buffer.from(ps)), 'token not visible in ps');
  assert.deepEqual(out.results.map((r) => [r.slug, r.status, r.error_code]), [['hangs', 'failed', 'TIMEOUT']]);
  assert.ok(took < 10000, `bounded: took ${took}ms`);
  // Killing only the top-level git leaves `git remote-http` reparented to init
  // and still waiting on the socket (measured). The whole group must be gone.
  await new Promise((r) => setTimeout(r, 500));
  const psAfter = execFileSync('ps', ['-A', '-ww', '-o', 'args='], { maxBuffer: 64 * 1024 * 1024 }).toString('utf8');
  assert.deepEqual(psAfter.split('\n').filter((l) => l.includes(`${HANG_BASE}/`)), [], 'no git process for the hung remote survives the deadline');
  assert.equal(appRow('hangs').repo_backend, null);
  assert.equal(existsSync(lg.migrationStagingPath('hangs')), false);
});

test('never throws: bad rows, throwing resolvers and a broken db are recorded or swallowed; budget defers', async () => {
  resetApps();
  makeGithubRepo('survivor');
  const badId = addApp('placeholder');
  db.prepare("UPDATE apps SET slug = 'Bad_Slug!' WHERE id = ?").run(badId);
  addApp('throws-string');
  addApp('survivor');
  const resolver = async (app) => {
    if (app.slug === 'throws-string') throw 'not even an Error'; // eslint-disable-line no-throw-literal
    return { url: `${BASE}/example-owner/AMC_${app.slug}.git`, token: TOKEN };
  };
  const out = await rm.migrateManagedReposToLocal(optsFor(resolver));
  assert.deepEqual(out.results.map((r) => [r.slug, r.status]), [['Bad_Slug!', 'failed'], ['throws-string', 'failed'], ['survivor', 'migrated']]);
  assert.equal(appRow('survivor').repo_backend, 'local');

  const broken = { prepare() { throw new Error('database is locked'); } };
  const r0 = await rm.migrateManagedReposToLocal({ db: broken });
  assert.match(r0.error, /database is locked/, 'migrateManagedReposToLocal itself never rejects');
  const r1 = await rm.migrateManagedReposAtBoot({ db: broken });
  assert.match(r1.error, /database is locked/);
  const r2 = await rm.migrateManagedReposAtBoot({ get db() { throw new Error('getter exploded'); } });
  assert.match(r2.error, /getter exploded/);

  resetApps();
  addApp('late-one');
  const d = await rm.migrateManagedReposToLocal(optsFor(async () => { throw new Error('must not be called'); }, { budgetMs: 0 }));
  assert.deepEqual(d.results.map((r) => [r.slug, r.status]), [['late-one', 'deferred']]);
  assert.equal(migRow('late-one').status, 'deferred');
  assert.equal(appRow('late-one').repo_backend, null);
});

test('escape hatch: env or setting turns it off; default is on', async () => {
  resetApps();
  addApp('hatch');
  let calls = 0;
  const resolver = async () => { calls++; throw new Error('stop here'); };
  process.env.APPCRANE_REPO_MIGRATION = 'off';
  try {
    const r = await rm.migrateManagedReposToLocal(optsFor(resolver));
    assert.match(r.disabled, /APPCRANE_REPO_MIGRATION/);
  } finally { delete process.env.APPCRANE_REPO_MIGRATION; }
  db.prepare("INSERT INTO settings (key, value) VALUES ('repo_migration_disabled', '1')").run();
  const r2 = await rm.migrateManagedReposToLocal(optsFor(resolver));
  assert.match(r2.disabled, /repo_migration_disabled/);
  assert.equal(calls, 0);
  db.prepare("DELETE FROM settings WHERE key = 'repo_migration_disabled'").run();
  const r3 = await rm.migrateManagedReposToLocal(optsFor(resolver));
  assert.equal(r3.disabled, null);
  assert.equal(calls, 1);
});

test('default remote: github.com URL + service token, header-only; refuses a missing token or foreign URL without any network', async () => {
  const { setServiceConfig } = await import('../server/services/githubService.js');
  const fetchCalls = [];
  const origFetch = global.fetch;
  global.fetch = async (u) => { fetchCalls.push(String(u)); throw new Error('no network in tests'); };
  try {
    setServiceConfig({ token: null });
    await assert.rejects(rm.defaultResolveRemote({ github_url: 'https://github.com/example-owner/AMC_x' }), { code: 'NO_SERVICE_TOKEN' });
    setServiceConfig({ token: TOKEN, owner: 'example-owner', enabled: true });
    assert.deepEqual(await rm.defaultResolveRemote({ github_url: 'https://github.com/example-owner/AMC_x' }),
      { url: 'https://github.com/example-owner/AMC_x.git', token: TOKEN });
    assert.equal((await rm.defaultResolveRemote({ github_url: 'https://github.com/example-owner/AMC_x.git' })).url, 'https://github.com/example-owner/AMC_x.git');
    await assert.rejects(rm.defaultResolveRemote({ github_url: 'https://example.com/example-owner/AMC_x' }), { code: 'NO_GITHUB_URL' });
    await assert.rejects(rm.defaultResolveRemote({ github_url: null }), { code: 'NO_GITHUB_URL' });
    await assert.rejects(lg.listRemoteHeadsAndTags({ url: `https://${TOKEN}@example.com/x.git`, deadline: Date.now() + 5000 }), { code: 'BAD_REMOTE' });
    await assert.rejects(lg.listRemoteHeadsAndTags({ url: 'file:///tmp/x.git', deadline: Date.now() + 5000 }), { code: 'BAD_REMOTE' });
    assert.deepEqual(fetchCalls, []);
  } finally {
    setServiceConfig({ token: null });
    global.fetch = origFetch;
  }
});

test('GET /api/github-service/repo-migration: platform admin only, read-only per-app outcome', async () => {
  resetApps();
  makeGithubRepo('routed');
  addApp('routed');
  await rm.migrateManagedReposToLocal(optsFor(remoteFor('routed')));
  const express = (await import('express')).default;
  const { hashApiKey } = await import('../server/services/encryption.js');
  const { errorHandler } = await import('../server/utils/errors.js');
  const routes = (await import('../server/routes/githubService.js')).default;
  db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('mig admin','mig-admin@example.com','platform_admin',1,?)").run(hashApiKey('dhk_user_mig_admin'));
  db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('mig user','mig-user@example.com','user',1,?)").run(hashApiKey('dhk_user_mig_user'));
  const app = express();
  app.use('/api/github-service', routes);
  app.use(errorHandler);
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const url = `http://127.0.0.1:${srv.address().port}/api/github-service/repo-migration`;
    const ok = await fetch(url, { headers: { 'x-api-key': 'dhk_user_mig_admin' } });
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.equal(body.disabled, null);
    assert.deepEqual(body.pending, []);
    assert.deepEqual(body.apps.map((a) => [a.slug, a.status, a.repo_backend]), [['routed', 'migrated', 'local']]);
    assert.equal((await fetch(url, { headers: { 'x-api-key': 'dhk_user_mig_user' } })).status, 403);
    assert.equal((await fetch(url)).status, 401);
    assert.equal((await fetch(url, { method: 'POST', headers: { 'x-api-key': 'dhk_user_mig_admin' } })).status, 404);
  } finally {
    srv.close();
  }
});

test('an error that carries the token is scrubbed before it is recorded or logged', async () => {
  resetApps();
  makeGithubRepo('leaky');
  addApp('leaky');
  const before = logLines.length;
  const out = await rm.migrateManagedReposToLocal(optsFor(remoteFor('leaky'), {
    afterStage: async () => { throw new Error(`upstream said Authorization: Basic ${TOKEN_B64} for ${TOKEN}`); },
  }));
  assert.equal(out.results[0].status, 'failed');
  const row = migRow('leaky');
  assert.match(row.error, /\[redacted\]/);
  assert.ok(!containsSecret(Buffer.from(JSON.stringify(row))), 'row holds no token');
  assert.ok(!containsSecret(Buffer.from(JSON.stringify(out))), 'returned result holds no token');
  assert.ok(!logLines.slice(before).some((l) => containsSecret(Buffer.from(l))), 'log holds no token');
  assert.equal(appRow('leaky').repo_backend, null);
});

test('installMigratedRepo never replaces an existing path, even an empty directory rename would swallow', () => {
  resetApps();
  const final = lg.repoPath('emptydir');
  mkdirSync(final, { recursive: true });
  const stage = lg.migrationStagingPath('emptydir');
  g(['init', '--bare', '--quiet', '--initial-branch=main', stage]);
  assert.throws(() => lg.installMigratedRepo('emptydir', stage), { code: 'LOCAL_REPO_EXISTS' });
  assert.deepEqual(readdirSync(final), [], 'existing directory untouched');
  assert.ok(existsSync(join(stage, 'HEAD')), 'staged repo not moved');
  rmSync(stage, { recursive: true, force: true });
});

test('the total budget caps a running app\'s deadline, not only whether the next app starts', { timeout: 30000 }, async () => {
  resetApps();
  addApp('hangs-budget');
  const started = Date.now();
  const out = await rm.migrateManagedReposToLocal(optsFor(async () => ({ url: `${HANG_BASE}/example-owner/AMC_hangs-budget.git`, token: TOKEN }), { appTimeoutMs: 600000, budgetMs: 2500 }));
  const took = Date.now() - started;
  assert.deepEqual(out.results.map((r) => [r.slug, r.status, r.error_code]), [['hangs-budget', 'failed', 'TIMEOUT']]);
  assert.ok(took < 10000, `budget bounded the app: took ${took}ms`);
});

test('a timed-out call settles even when a descendant escaped the process group and still holds the pipes', { timeout: 30000 }, async () => {
  // Group kill cannot reach a process that called setsid. If one keeps stdout
  // open, 'close' never fires; the call must settle on 'exit' regardless.
  const esc = join(ROOT, 'escape-bin');
  const pidFile = join(ROOT, 'escaped.pid');
  mkdirSync(esc, { recursive: true });
  writeFileSync(join(esc, 'git'), `#!/bin/sh
for a in "$@"; do case "$a" in *escape.invalid*)
  '${process.execPath}' -e 'const c=require("child_process").spawn("sleep",["60"],{detached:true,stdio:["ignore","inherit","inherit"]});require("fs").writeFileSync(${JSON.stringify(pidFile)},String(c.pid));c.unref();'
  exec sleep 60 ;;
esac; done
exec '${REAL_GIT}' "$@"
`, { mode: 0o755 });
  const savedPath = process.env.PATH;
  process.env.PATH = `${esc}:${ORIG_PATH}`;
  const started = Date.now();
  try {
    await assert.rejects(
      lg.listRemoteHeadsAndTags({ url: 'http://escape.invalid/x.git', token: TOKEN, deadline: Date.now() + 1500, allowedSchemes: ['http'] }),
      { code: 'GIT_TIMEOUT' },
    );
    assert.ok(Date.now() - started < 8000, `settled in ${Date.now() - started}ms`);
    assert.ok(existsSync(pidFile), 'the escaped descendant really was started');
  } finally {
    process.env.PATH = savedPath;
    try { process.kill(Number(readFileSync(pidFile, 'utf8')), 'SIGKILL'); } catch (_) { /* gone */ }
  }
});
