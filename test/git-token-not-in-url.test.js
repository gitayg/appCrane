import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync, spawn } from 'child_process';

// A stored GitHub token reaches git as an http.extraHeader in the child's
// environment -- never in the clone URL. A tokenized URL was in argv, in error
// text, and written by git into <workspace>/.git/config, which the AppStudio
// coding container and the builder container both mount.
//
// Real git against a real `git http-backend` on 127.0.0.1 that answers 401 to
// any request without an Authorization header, so a clone or push that works
// proves the header arrived. docker is a PATH shim that plays the containers
// and records the .git/config they would have been able to read.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-tokenurl-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = '9'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPSTUDIO_POLL_MS = '1000';
process.env.APPCRANE_GITHUB_ALLOW_HTTP_GIT = '1';
process.env.GIT_TERMINAL_PROMPT = '0';
process.env.GIT_ASKPASS = '/usr/bin/true';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const REAL_GIT = execFileSync('which', ['git']).toString().trim();
const TOKEN = 'ghp_STOREDPATFORTOKENURLTEST0123456789';
const B64 = Buffer.from(`x-access-token:${TOKEN}`).toString('base64');
const EXPECTED_AUTH = `Basic ${B64}`;

// --- bare repo behind an auth-requiring git server ---------------------------
const REPOS = join(ROOT, 'srv');
mkdirSync(join(REPOS, 'acme'), { recursive: true });
const BARE = join(REPOS, 'acme', 'widget.git');
execFileSync(REAL_GIT, ['init', '--bare', '-q', '-b', 'main', BARE]);
execFileSync(REAL_GIT, ['-C', BARE, 'config', 'http.receivepack', 'true']);
{
  const work = mkdtempSync(join(ROOT, 'seed-'));
  const g = (...a) => execFileSync(REAL_GIT, ['-C', work, ...a], { stdio: 'pipe' });
  execFileSync(REAL_GIT, ['init', '-q', '-b', 'main', work]);
  g('config', 'user.email', 'seed@example.com');
  g('config', 'user.name', 'seed');
  writeFileSync(join(work, 'package.json'), '{"name":"widget","version":"1.0.0"}\n');
  g('add', '.');
  g('commit', '-qm', 'seed');
  g('push', '-q', BARE, 'main');
}
// A fixed identity for commits made straight into the bare repo. Without it
// commit-tree takes the machine's own git identity, which a developer laptop has
// and a CI runner does not ("Author identity unknown" failed CI on v2.75.0).
const FIXTURE_IDENTITY = {
  GIT_AUTHOR_NAME: 'fixture', GIT_AUTHOR_EMAIL: 'fixture@example.com',
  GIT_COMMITTER_NAME: 'fixture', GIT_COMMITTER_EMAIL: 'fixture@example.com',
};
const bareGit = (...a) => execFileSync(REAL_GIT, ['-C', BARE, ...a], { stdio: 'pipe', env: { ...process.env, ...FIXTURE_IDENTITY } }).toString().trim();

const AUTH_LOG = join(ROOT, 'git-auth.jsonl');
writeFileSync(AUTH_LOG, '');
const gitServer = spawn(process.execPath, [fileURLToPath(new URL('./fixtures/git-http-auth-server.mjs', import.meta.url)), REPOS, AUTH_LOG], {
  stdio: ['ignore', 'pipe', 'inherit'],
});
const GIT_PORT = await new Promise((resolveP, reject) => {
  gitServer.once('error', reject);
  gitServer.stdout.once('data', (d) => resolveP(parseInt(String(d).trim(), 10)));
});
const REPO_URL = `http://127.0.0.1:${GIT_PORT}/acme/widget.git`;
const authSeen = () => readFileSync(AUTH_LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

// --- git + docker shims ------------------------------------------------------
const SHIM = join(ROOT, 'bin');
const CAPTURE = join(ROOT, 'capture');
const SNAP = join(ROOT, 'git-config-snapshots');
for (const d of [SHIM, CAPTURE, SNAP]) mkdirSync(d, { recursive: true });
const GIT_LOG = join(ROOT, 'git-argv.log');
// argv (unit-separated) plus whether the child got a GIT_CONFIG_COUNT; after
// each call the repo's .git/config is copied aside.
writeFileSync(join(SHIM, 'git'), `#!/bin/sh
{ printf 'CFG=%s\\037' "\${GIT_CONFIG_COUNT:-none}"; for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${GIT_LOG}"
"${REAL_GIT}" "$@"; rc=$?
dir=""
if [ "$1" = clone ]; then for a in "$@"; do dir="$a"; done; fi
if [ "$1" = -C ]; then dir="$2"; fi
if [ "$1" = -c ] && [ "$3" = -C ]; then dir="$4"; fi
if [ -n "$dir" ] && [ -f "$dir/.git/config" ]; then n=$(ls "${SNAP}" | wc -l | tr -d ' '); cp "$dir/.git/config" "${SNAP}/config.$n"; fi
exit $rc
`, { mode: 0o755 });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  ps|rm|stop|inspect) exit 0 ;;
  image) echo 5; exit 0 ;;
  build) exit 0 ;;
  run)
    kind=""; ws=""; prev=""
    for a in "$@"; do
      if [ "$prev" = --label ]; then case "$a" in appcrane.container.type=*) kind="\${a#appcrane.container.type=}" ;; esac; fi
      if [ "$prev" = -v ]; then case "$a" in *:/workspace|*:/workspace:ro) ws="\${a%%:/workspace*}" ;; esac; fi
      prev="$a"
    done
    [ -n "$ws" ] && cp "$ws/.git/config" "${CAPTURE}/$kind-container-gitconfig"
    if [ "$kind" = job ]; then
      echo "change $(date +%s%N)" >> "$ws/CHANGE.txt"
      echo '{"type":"result","usage":{"input_tokens":1,"output_tokens":1}}'
      exit 0
    fi
    if [ "$kind" = app ]; then echo 0123456789abcdef0123456789abcdef; exit 0; fi
    echo "no docker" >&2; exit 1 ;;
esac
echo "no docker" >&2; exit 1
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt } = await import('../server/services/encryption.js');
const { cloneForBuild } = await import('../server/services/appstudio/generator.js');
const { startWorker, stopWorker } = await import('../server/services/appstudio/worker.js');
const appContainer = await import('../server/services/builder/appContainer.js');

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });

after(() => {
  stopWorker();
  gitServer.kill('SIGTERM');
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

let slot = 950;
function mkApp(slug, { token = TOKEN } = {}) {
  const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,branch,github_token_encrypted) VALUES (?,?,?,'github',?,'main',?)")
    .run(slug, slug, slot++, REPO_URL, token ? encrypt(token) : null).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

const argvLines = () => (existsSync(GIT_LOG) ? readFileSync(GIT_LOG, 'utf8') : '').split('\n').filter(Boolean)
  .map((l) => l.split('\x1f').slice(0, -1));
const snapshots = () => readdirSync(SNAP).map((f) => readFileSync(join(SNAP, f), 'utf8')).join('\n');
function assertNoTokenAnywhere(where) {
  const argv = readFileSync(GIT_LOG, 'utf8');
  assert.ok(!argv.includes(TOKEN) && !argv.includes(B64), `${where}: token in git argv`);
  const snaps = snapshots();
  assert.ok(!snaps.includes(TOKEN) && !snaps.includes(B64), `${where}: token in a .git/config`);
}
const originOf = (dir) => execFileSync(REAL_GIT, ['-C', dir, 'config', '--get', 'remote.origin.url']).toString().trim();
function withCurlTrace(fn) {
  process.env.GIT_TRACE_CURL = '1';
  process.env.GIT_TRACE_REDACT = '0';
  try { return fn(); } finally { delete process.env.GIT_TRACE_CURL; delete process.env.GIT_TRACE_REDACT; }
}

async function waitFor(pred, ms, what) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = pred();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

// ---------------------------------------------------------------------------

test('cloneForBuild: private clone works only via the header; argv and .git/config are clean', () => {
  const app = mkApp('tu-build');
  writeFileSync(AUTH_LOG, '');
  const dir = cloneForBuild(7001, app, 'main');
  assert.ok(existsSync(join(dir, 'package.json')));
  assert.ok(authSeen().some((c) => c.auth === EXPECTED_AUTH), 'server never saw the header');
  assert.equal(originOf(dir), REPO_URL);
  assert.ok(!readFileSync(join(dir, '.git', 'config'), 'utf8').includes(TOKEN));
  const clone = argvLines().filter((a) => a[1] === 'clone' && a.includes(dir));
  assert.equal(clone.length, 1);
  assert.equal(clone[0][0], 'CFG=1');
  assert.ok(clone[0].includes(REPO_URL), `clone argv not the plain url: ${clone[0]}`);
  assertNoTokenAnywhere('cloneForBuild');
});

test('cloneForBuild: no stored token means no credential env (public repo path unchanged)', () => {
  const app = mkApp('tu-public', { token: null });
  assert.throws(() => cloneForBuild(7002, app, 'main'));
  const clone = argvLines().filter((a) => a[1] === 'clone' && a.some((x) => x.endsWith('build-7002')));
  assert.equal(clone.length, 1);
  assert.equal(clone[0][0], 'CFG=none');
});

test('cloneForBuild: error text is scrubbed even when git traces the header', () => {
  const app = mkApp('tu-build-err');
  let msg = '';
  withCurlTrace(() => {
    try { cloneForBuild(7003, app, 'no-such-branch'); } catch (err) { msg = err.message; }
  });
  assert.ok(msg.length > 0, 'expected the clone to fail');
  assert.ok(/Authorization|\[redacted\]/.test(msg), `trace did not reach the error text, test proves nothing: ${msg.slice(0, 300)}`);
  assert.ok(!msg.includes(TOKEN) && !msg.includes(B64), 'token escaped in error text');
});

test('AppStudio code phase: clone, container view, and push all without a tokenized URL', async () => {
  const app = mkApp('tu-studio');
  const plan = { summary: 'tweak', files_to_change: [] };
  const enh = db.prepare("INSERT INTO enhancement_requests (app_slug, message, status, ai_plan_json) VALUES (?, 'tweak', 'plan_approved', ?)")
    .run(app.slug, JSON.stringify(plan)).lastInsertRowid;
  // A second enhancement whose deterministic branch already exists on the
  // remote: cloneForCode must SEE it (authenticated ls-remote) and continue on it.
  const enh2 = db.prepare("INSERT INTO enhancement_requests (app_slug, message, status, ai_plan_json) VALUES (?, 'more', 'plan_approved', ?)")
    .run(app.slug, JSON.stringify(plan)).lastInsertRowid;
  const branch1 = `appstudio/${enh}-${app.slug}`;
  const branch2 = `appstudio/${enh2}-${app.slug}`;
  const priorCommit = bareGit('commit-tree', 'main^{tree}', '-p', 'main', '-m', 'prior coder run');
  bareGit('update-ref', `refs/heads/${branch2}`, priorCommit);

  writeFileSync(AUTH_LOG, '');
  const argvBefore = argvLines().length;
  const job1 = db.prepare("INSERT INTO enhancement_jobs (enhancement_id, phase) VALUES (?, 'code')").run(enh).lastInsertRowid;
  const job2 = db.prepare("INSERT INTO enhancement_jobs (enhancement_id, phase) VALUES (?, 'code')").run(enh2).lastInsertRowid;
  // Build jobs are the deployer's business, not this test's; cancel them as they appear.
  const cancelBuilds = setInterval(() => {
    db.prepare("UPDATE enhancement_jobs SET status = 'done' WHERE phase = 'build' AND status = 'queued'").run();
  }, 10);
  startWorker();
  try {
    for (const id of [job1, job2]) {
      await waitFor(() => {
        const j = db.prepare('SELECT status, error_message FROM enhancement_jobs WHERE id = ?').get(id);
        return j.status === 'done' || j.status === 'failed' ? j : null;
      }, 60000, `code job ${id}`);
    }
  } finally {
    stopWorker();
    clearInterval(cancelBuilds);
  }

  for (const [id, e, b] of [[job1, enh, branch1], [job2, enh2, branch2]]) {
    const j = db.prepare('SELECT status, error_message FROM enhancement_jobs WHERE id = ?').get(id);
    const r = db.prepare('SELECT status, branch_name FROM enhancement_requests WHERE id = ?').get(e);
    assert.equal(j.status, 'done', `job ${id}: ${j.error_message}`);
    assert.equal(r.branch_name, b, `enh ${e} not pushed (status=${r.status})`);
  }
  // Push reached the remote with the credential.
  assert.ok(bareGit('rev-parse', `refs/heads/${branch1}`));
  assert.ok(authSeen().some((c) => c.auth === EXPECTED_AUTH && /git-receive-pack/.test(c.url)), 'no authenticated push');
  // Continuation: the new commit sits on top of the prior run's commit.
  assert.equal(bareGit('rev-parse', `refs/heads/${branch2}^`), priorCommit, 'branch-exists detection lost: prior commit not the parent');

  const studio = argvLines().slice(argvBefore).filter((a) => a[1] === 'ls-remote' || a[1] === 'clone' || a.includes('push'));
  assert.ok(studio.length >= 6, `expected ls-remote+clone+push per job, got ${studio.length}`);
  for (const a of studio) assert.equal(a[0], 'CFG=1', `network git call without credential env: ${a.join(' ')}`);
  const container = readFileSync(join(CAPTURE, 'job-container-gitconfig'), 'utf8');
  assert.ok(container.includes(REPO_URL) && !container.includes(TOKEN) && !container.includes(B64), 'coding container could read the token');
  assertNoTokenAnywhere('AppStudio code phase');
});

// The builder container's GitHub clone branch was removed in v2.92.1: both
// routes that create a container require a Crane-hosted app (v2.83.0), so it
// was unreachable. What is left to prove is that a GitHub-backed app handed to
// the container code anyway is refused before git or the token is touched.
test('builder container: a GitHub-backed app is refused before any clone or token use', async () => {
  const app = mkApp('tu-builder');
  writeFileSync(AUTH_LOG, '');
  const before = argvLines().length;
  const err = await appContainer.getOrCreate(app, () => {}).then(() => null, (e) => e);
  try {
    assert.ok(err, 'a GitHub-backed app got a coder container');
    assert.match(err.message, /Crane-hosted apps only/);
    assert.equal(argvLines().slice(before).filter((a) => a[1] === 'clone').length, 0, 'a clone ran anyway');
    assert.equal(authSeen().length, 0, 'the token was sent to the git server');
    assertNoTokenAnywhere('builder refusal');
  } finally {
    appContainer.evict(app.slug, 'test');
  }
});

test('AppStudio clone failure: the job error recorded in the DB is scrubbed', async () => {
  const app = mkApp('tu-studio-err');
  db.prepare("UPDATE apps SET branch = 'no-such-branch' WHERE id = ?").run(app.id);
  const enh = db.prepare("INSERT INTO enhancement_requests (app_slug, message, status, ai_plan_json) VALUES (?, 'x', 'plan_approved', ?)")
    .run(app.slug, JSON.stringify({ summary: 'x' })).lastInsertRowid;
  const job = db.prepare("INSERT INTO enhancement_jobs (enhancement_id, phase) VALUES (?, 'code')").run(enh).lastInsertRowid;
  process.env.GIT_TRACE_CURL = '1';
  process.env.GIT_TRACE_REDACT = '0';
  startWorker();
  let j;
  try {
    j = await waitFor(() => {
      const r = db.prepare('SELECT status, error_message FROM enhancement_jobs WHERE id = ?').get(job);
      return r.status === 'done' || r.status === 'failed' ? r : null;
    }, 60000, 'failing code job');
  } finally {
    stopWorker();
    delete process.env.GIT_TRACE_CURL; delete process.env.GIT_TRACE_REDACT;
  }
  assert.equal(j.status, 'failed');
  assert.ok(/Authorization|\[redacted\]/.test(j.error_message), `trace did not reach the job error: ${String(j.error_message).slice(0, 300)}`);
  assert.ok(!j.error_message.includes(TOKEN) && !j.error_message.includes(B64), 'token stored in enhancement_jobs.error_message');
});
