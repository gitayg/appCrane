import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Phase 1 of re-introducing Builder for Crane-hosted apps: /api/coder works for
// a managed app whose source lives in <DATA_DIR>/repos/<slug>.git
// (repo_backend='local', github_url NULL), and refuses to push one anywhere.
//
// Real git throughout, read back independently of the modules under test: the
// bare repo is seeded through localGit's own push path, and the workspace is
// inspected with `git -C` afterwards. `git` is a PATH shim that records argv
// and whether the child was given GIT_CONFIG_COUNT -- the only way a stored
// GitHub token reaches git -- so "no credential ran on the local path" is a
// measurement rather than an assumption. docker is a shim that plays the
// container. global.fetch is stubbed and counted: the Crane-hosted path must
// reach no network at all.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-coderlocal-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-coder-local';
process.env.GIT_TERMINAL_PROMPT = '0';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const REAL_FETCH = globalThis.fetch.bind(globalThis);
const REAL_GIT = execFileSync('which', ['git']).toString().trim();
const TOKEN = 'ghp_TOKENTHATMUSTNEVERTOUCHALOCALCLONE01';

// --- shims -------------------------------------------------------------------
const SHIM = join(ROOT, 'bin');
const GIT_LOG = join(ROOT, 'git-argv.log');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(GIT_LOG, '');
writeFileSync(DOCKER_LOG, '');
writeFileSync(join(SHIM, 'git'), `#!/bin/sh
{ printf 'CFG=%s\\037' "\${GIT_CONFIG_COUNT:-none}"; for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${GIT_LOG}"
exec "${REAL_GIT}" "$@"
`, { mode: 0o755 });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${DOCKER_LOG}"
case "$1" in
  image)   echo 3 ;;
  inspect) echo true ;;
  run)     echo 0123456789abcdef0123456789abcdef ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const lg = await import('../server/services/localGit.js');
const appContainer = await import('../server/services/builder/appContainer.js');
const { commitAndPush } = await import('../server/services/builder/gitOps.js');
const coderRoutes = (await import('../server/routes/coder.js')).default;

let fetchCalls = 0;
global.fetch = async (...args) => { fetchCalls++; return { ok: false, status: 404, json: async () => ({}), text: async () => '' }; };

after(async () => {
  try {
    const { stopHealthChecker } = await import('../server/services/healthChecker.js');
    stopHealthChecker();
  } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

// --- fixtures ----------------------------------------------------------------
const API_KEY = 'testkey-coder-local';
const uid = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin',?,1,'human')"
).run(hashApiKey(API_KEY)).lastInsertRowid;

let slot = 880;
function insertApp(cols) {
  const keys = Object.keys(cols);
  const id = db.prepare(
    `INSERT INTO apps (name,slot,${keys.join(',')}) VALUES (?,?,${keys.map(() => '?').join(',')})`
  ).run(cols.slug, slot++, ...keys.map((k) => cols[k])).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

// A Crane-hosted managed app: a real bare repo, github_url NULL. It carries a
// stored GitHub token on purpose -- the local path must ignore it entirely.
const LOCAL_SLUG = 'cranehosted';
const FILE_MARKER = 'CRANE_HOSTED_FILE_MARKER';
await lg.createAppRepo(LOCAL_SLUG, { description: 'phase 1 builder' });
await lg.pushFilesToManagedRepo(LOCAL_SLUG, [
  { path: 'package.json', content: '{"name":"cranehosted","version":"1.0.0"}\n' },
  { path: 'src/app.js', content: `export const marker = "${FILE_MARKER}";\n` },
], { message: 'seed' });
const localApp = insertApp({
  slug: LOCAL_SLUG, source_type: 'managed', repo_backend: 'local',
  github_url: null, branch: 'main', github_token_encrypted: encrypt(TOKEN),
});

// A GitHub-backed app, cloned the way it always was. Its "GitHub URL" is a bare
// repo on disk so the clone succeeds without a network; what is under test is
// that the argv shape and the origin are unchanged, not the transport.
const GH_BARE = join(ROOT, 'gh', 'widget.git');
mkdirSync(join(ROOT, 'gh'), { recursive: true });
execFileSync(REAL_GIT, ['init', '--bare', '-q', '-b', 'main', GH_BARE]);
{
  const work = mkdtempSync(join(ROOT, 'seed-'));
  const g = (...a) => execFileSync(REAL_GIT, ['-C', work, ...a], { stdio: 'pipe' });
  execFileSync(REAL_GIT, ['init', '-q', '-b', 'main', work]);
  g('config', 'user.email', 'seed@example.com');
  g('config', 'user.name', 'seed');
  writeFileSync(join(work, 'package.json'), '{"name":"widget","version":"1.0.0"}\n');
  g('add', '.');
  g('commit', '-qm', 'seed');
  g('push', '-q', GH_BARE, 'main');
}
const ghApp = insertApp({ slug: 'ghbacked', source_type: 'github', github_url: GH_BARE, branch: 'main' });

// A GitHub app with an https URL and a stored token, used only to prove the
// credential env is still built on the GitHub path. Its clone fails (nothing
// listens on port 1); the argv it produced is the evidence.
const ghTokenApp = insertApp({
  slug: 'ghtokened', source_type: 'github', github_url: 'https://127.0.0.1:1/acme/widget.git',
  branch: 'main', github_token_encrypted: encrypt(TOKEN),
});

// An app with neither source -- the case the old NO_GITHUB check existed for.
insertApp({ slug: 'nosource', source_type: 'github', github_url: null, branch: 'main' });

// --- http --------------------------------------------------------------------
const api = express();
api.use(express.json());
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = api.listen(0);
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => server.close());

const call = (method, path, body) => REAL_FETCH(`${BASE}${path}`, {
  method,
  headers: { 'X-API-Key': API_KEY, 'Content-Type': 'application/json' },
  ...(body ? { body: JSON.stringify(body) } : {}),
});

// --- helpers -----------------------------------------------------------------
const gitLines = () => readFileSync(GIT_LOG, 'utf8').split('\n').filter(Boolean)
  .map((l) => l.split('\x1f').slice(0, -1));
const clonesInto = (dir) => gitLines().filter((a) => a.includes('clone') && a.includes(dir));
const gitIn = (dir, ...a) => execFileSync(REAL_GIT, ['-C', dir, ...a], { stdio: 'pipe' }).toString().trim();
const bareRefs = (slug) => execFileSync(REAL_GIT, [`--git-dir=${lg.repoPath(slug)}`, 'for-each-ref', '--format=%(refname)'])
  .toString();

// =============================================================================

test('session start: a Crane-hosted app is no longer refused for having no github_url', async () => {
  assert.equal(localApp.github_url, null, 'fixture is wrong: a local app must have github_url NULL');
  const fetchBefore = fetchCalls;
  const r = await call('POST', `/api/coder/${LOCAL_SLUG}/session`);
  const body = await r.json();
  assert.equal(r.status, 201, `expected a session, got ${r.status} ${JSON.stringify(body)}`);
  assert.ok(body.session_id, 'no session id returned');
  // Nothing on this path may talk to GitHub.
  assert.equal(fetchCalls, fetchBefore, `Crane-hosted session start made ${fetchCalls - fetchBefore} network call(s)`);
});

test('workspace: cloned from <DATA_DIR>/repos/<slug>.git with the committed files', () => {
  const c = appContainer.getContainer(LOCAL_SLUG);
  assert.ok(c, 'no live container for the Crane-hosted app');
  const bare = lg.repoPath(LOCAL_SLUG);
  assert.equal(bare, join(ROOT, 'repos', `${LOCAL_SLUG}.git`));

  assert.ok(existsSync(join(c.workspaceDir, 'package.json')), 'package.json missing from the workspace');
  assert.ok(
    readFileSync(join(c.workspaceDir, 'src', 'app.js'), 'utf8').includes(FILE_MARKER),
    'the committed file content did not reach the workspace',
  );
  assert.equal(gitIn(c.workspaceDir, 'config', '--get', 'remote.origin.url'), bare);
  assert.equal(gitIn(c.workspaceDir, 'rev-parse', '--abbrev-ref', 'HEAD'), `builder/${LOCAL_SLUG}`);

  const clone = clonesInto(c.workspaceDir);
  assert.equal(clone.length, 1, `expected exactly one clone into the workspace, got ${clone.length}`);
  assert.ok(clone[0].includes(bare), `clone did not name the bare repo: ${clone[0].join(' ')}`);
  assert.ok(clone[0].includes('--no-local'), 'not the local-repo clone (localGit.cloneForDeploySync)');
});

test('workspace: no GitHub token, and no GitHub URL, anywhere on the local path', () => {
  const c = appContainer.getContainer(LOCAL_SLUG);
  const cfg = readFileSync(join(c.workspaceDir, '.git', 'config'), 'utf8');
  assert.ok(!cfg.includes(TOKEN), 'stored token reached the workspace .git/config');
  assert.ok(!/github\.com/i.test(cfg), `a GitHub remote URL is in the workspace .git/config:\n${cfg}`);

  const argv = readFileSync(GIT_LOG, 'utf8');
  assert.ok(!argv.includes(TOKEN), 'stored token reached git argv');
  // Every git call that touched this workspace ran WITHOUT a credential env.
  const touched = gitLines().filter((a) => a.some((x) => x.includes(c.workspaceDir)));
  assert.ok(touched.length > 0, 'no git calls recorded for the workspace — the shim is not in PATH');
  for (const a of touched) {
    assert.equal(a[0], 'CFG=none', `a credential env was built for the Crane-hosted path: ${a.join(' ')}`);
  }
});

test('ship: a Crane-hosted session refuses instead of pushing, and commits nothing', async () => {
  const c = appContainer.getContainer(LOCAL_SLUG);
  const session = db.prepare('SELECT * FROM coder_sessions WHERE app_slug = ? ORDER BY created_at DESC LIMIT 1').get(LOCAL_SLUG);
  assert.ok(session?.workspace_dir, 'session row has no workspace_dir');

  writeFileSync(join(c.workspaceDir, 'NEW.txt'), 'agent wrote this\n');
  const headBefore = gitIn(c.workspaceDir, 'rev-parse', 'HEAD');
  const refsBefore = bareRefs(LOCAL_SLUG);

  await assert.rejects(
    () => commitAndPush({ workspaceDir: c.workspaceDir, branchName: c.branchName, commitMsg: 'x', onLog: () => {} }),
    (err) => {
      assert.equal(err.code, 'LOCAL_REPO_NO_PUSH', `wrong error code: ${err.code} / ${err.message}`);
      assert.equal(err.status, 400);
      return true;
    },
  );

  assert.equal(gitIn(c.workspaceDir, 'rev-parse', 'HEAD'), headBefore, 'a refused ship still committed');
  assert.equal(bareRefs(LOCAL_SLUG), refsBefore, 'a refused ship still wrote a ref to the bare repo');
  assert.ok(!bareRefs(LOCAL_SLUG).includes(`builder/${LOCAL_SLUG}`), 'the builder branch reached the bare repo');
  // `git push -u origin <branch>` is the one command commitAndPush runs against
  // a remote. (A bare `push` match would also catch the `update-ref -m push`
  // localGit uses to seed the fixture.)
  const pushes = gitLines().filter((a) => a.includes('push') && a.includes('origin'));
  assert.equal(pushes.length, 0, `git push ran for a Crane-hosted app: ${JSON.stringify(pushes)}`);

  const res = await call('POST', `/api/coder/${LOCAL_SLUG}/session/${session.id}/ship`, { message: 'x' });
  const body = await res.json();
  assert.equal(res.status, 400, `ship should be refused, got ${res.status} ${JSON.stringify(body)}`);
  assert.equal(body.error.code, 'LOCAL_REPO_NO_PUSH');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(localApp.id).n, 0,
    'a refused ship still queued a deploy');
});

test('intro: the Crane-hosted bubble does not promise to ship branches to GitHub', () => {
  const session = db.prepare('SELECT id FROM coder_sessions WHERE app_slug = ? ORDER BY created_at DESC LIMIT 1').get(LOCAL_SLUG);
  const intro = db.prepare(
    "SELECT content FROM coder_session_messages WHERE session_id = ? AND role = 'assistant' ORDER BY id ASC LIMIT 1"
  ).get(session.id)?.content;
  assert.ok(intro, 'no intro message was written');
  assert.ok(!/ship branches back to GitHub/.test(intro), `the intro promises a GitHub push the ship path refuses:\n${intro}`);
  assert.ok(/Crane-hosted/.test(intro), 'the intro does not say the app is Crane-hosted');
});

test('releases: a Crane-hosted app gets an empty feed, not a 400', async () => {
  const r = await call('GET', `/api/coder/${LOCAL_SLUG}/releases`);
  const body = await r.json();
  assert.equal(r.status, 200, `releases refused for a Crane-hosted app: ${JSON.stringify(body)}`);
  assert.deepEqual(body.releases, []);

  const v = await call('GET', `/api/coder/${LOCAL_SLUG}/releases/view`);
  assert.equal(v.status, 200, 'the release viewer refused a Crane-hosted app');
  assert.ok((await v.text()).includes('<html'), 'the release viewer did not render a page');
});

test('an app with neither a GitHub repo nor a Crane-hosted one is still refused', async () => {
  const r = await call('POST', '/api/coder/nosource/session');
  const body = await r.json();
  assert.equal(r.status, 400);
  assert.equal(body.error.code, 'NO_REPO');

  const rel = await call('GET', '/api/coder/nosource/releases');
  assert.equal(rel.status, 400, 'the releases feed stopped refusing a source-less app');
});

test('GitHub-backed apps take the old clone path, unchanged', async () => {
  const c = await appContainer.getOrCreate(ghApp, () => {});
  try {
    assert.equal(gitIn(c.workspaceDir, 'config', '--get', 'remote.origin.url'), GH_BARE);
    assert.ok(existsSync(join(c.workspaceDir, 'package.json')));
    const clone = clonesInto(c.workspaceDir);
    assert.equal(clone.length, 1);
    // Exactly the argv the GitHub path has always produced.
    assert.deepEqual(clone[0].slice(1), ['clone', '--depth', '1', '--branch', 'main', GH_BARE, c.workspaceDir]);
    assert.equal(clone[0][0], 'CFG=none', 'a credential env appeared for a token-less GitHub app');
  } finally {
    appContainer.evict(ghApp.slug, 'test');
  }
});

test('GitHub-backed apps with a stored token still get the credential env', async () => {
  await assert.rejects(() => appContainer.getOrCreate(ghTokenApp, () => {}));
  const dir = join(ROOT, 'app-containers', ghTokenApp.slug, 'workspace');
  const clone = clonesInto(dir);
  assert.equal(clone.length, 1, `expected one clone attempt, got ${clone.length}`);
  assert.equal(clone[0][0], 'CFG=1', 'the GitHub token env stopped being built');
  assert.deepEqual(clone[0].slice(1),
    ['clone', '--depth', '1', '--branch', 'main', 'https://127.0.0.1:1/acme/widget.git', dir]);
  assert.ok(!readFileSync(GIT_LOG, 'utf8').includes(TOKEN), 'token in git argv');
});
