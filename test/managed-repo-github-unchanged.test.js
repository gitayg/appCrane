import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Phase 2 of moving managed apps off GitHub: the property that protects every
// managed app already in production.
//
// A managed app whose apps.repo_backend is NULL — every row that existed before
// migration 090 — must take the GitHub path at EVERY touchpoint: agent push (all
// three tools), file read, create/repair, deploy clone, promote-pin, the
// supply-chain SHA check (with its retries), AskClaude and the credential probe.
//
// Stubbed at the boundary the code really calls, and nowhere else:
//   - GitHub REST: global.fetch (githubService.apiFetch and supplyChain both
//     call fetch directly). Response bodies use the shapes GitHub returns —
//     branch reads are { commit: { sha } }, not the refs shape.
//   - git and docker: PATH shims that record argv. The deployer runs
//     `execFileSync('git', …)` with the ambient PATH, so the shim sees exactly
//     the argv production would hand to GitHub, token and all, without a
//     network clone.
//
// Every app here ALSO has a real-looking <DATA_DIR>/repos/<slug>.git on disk.
// That is deliberate: the backend is decided by the column alone, and a stray
// directory must not be able to move a production app off GitHub.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-mrgh-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
const GIT_LOG = join(ROOT, 'git-argv.log');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
const ASK_CAPTURE = join(ROOT, 'ask-capture');
mkdirSync(SHIM, { recursive: true });
mkdirSync(ASK_CAPTURE, { recursive: true });
const REC = `{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "$LOGFILE"\n`;
writeFileSync(join(SHIM, 'git'), `#!/bin/sh
LOGFILE="$GIT_SHIM_LOG"
${REC}
[ -n "$GIT_SHIM_ENV_LOG" ] && printf '%s\\037%s\\037%s\\037\\n' "$1" "$GIT_CONFIG_KEY_0" "$GIT_CONFIG_VALUE_0" >> "$GIT_SHIM_ENV_LOG"
if [ "$1" = clone ]; then
  for a in "$@"; do last="$a"; case "$a" in https://*) url="$a" ;; esac; done
  # Real git's text for an unreachable remote, measured on git 2.50 and 2.39:
  # git itself strips the credential from the URL it prints. The token used to
  # reach the error anyway, through Node's "Command failed: git clone ... <url>"
  # line, because it was in argv; it now travels in the environment instead.
  if [ -n "$GIT_SHIM_CLONE_FAIL" ]; then
    anon=$(printf '%s' "$url" | sed 's#^https://[^@]*@#https://#')
    echo "fatal: unable to access '$anon/': Could not resolve host: github.com" >&2; exit 128
  fi
  mkdir -p "$last"; exit 0
fi
if [ -n "$GIT_SHIM_PIN_FAIL" ] && [ "$1" = -C ]; then
  # Measured text again: fetch prints the redacted remote URL, checkout names
  # only the commit.
  case "$3" in
    fetch) echo "fatal: unable to access 'https://github.com/svc-owner/AMC_gh-pinfail/': Could not resolve host: github.com" >&2; exit 128 ;;
    checkout) echo "fatal: reference is not a tree: $5" >&2; exit 128 ;;
  esac
fi
if [ "$1" = -C ]; then
  case "$3" in
    rev-parse) if [ "$4" = --short ]; then echo "$GIT_SHIM_SHA" | cut -c1-7; else echo "$GIT_SHIM_SHA"; fi ;;
    log) echo "shim commit" ;;
  esac
fi
exit 0
`, { mode: 0o755 });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
LOGFILE="$DOCKER_SHIM_LOG"
${REC}
if [ "$DOCKER_SHIM_MODE" != ask ]; then echo "no docker" >&2; exit 1; fi
case "$1" in
  run)
    prev=""
    for a in "$@"; do
      case "$a" in *:/studio:ro) if [ "$prev" = -v ]; then d="\${a%:/studio:ro}"; cp "$d/clone_url" "$ASK_CAPTURE/clone_url"; ls "$d" > "$ASK_CAPTURE/ls"; fi ;; esac
      prev="$a"
    done
    echo shimcontainer ;;
  inspect) echo running ;;
  image) echo 5 ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
const GIT_ENV_LOG = join(ROOT, 'git-env.log');
process.env.GIT_SHIM_ENV_LOG = GIT_ENV_LOG;
const basicFor = (t) => `Authorization: Basic ${Buffer.from(`x-access-token:${t}`).toString('base64')}`;
process.env.GIT_SHIM_LOG = GIT_LOG;
process.env.DOCKER_SHIM_LOG = DOCKER_LOG;
process.env.ASK_CAPTURE = ASK_CAPTURE;
const CLONE_SHA = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';
process.env.GIT_SHIM_SHA = CLONE_SHA;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { setServiceConfig } = await import('../server/services/githubService.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp, promoteApp } = await import('../server/services/deployer.js');
const { verifyCommitSha } = await import('../server/services/supplyChain.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { repoBackendOf, usesLocalRepo } = await import('../server/services/managedRepo.js');
const { PROBES } = await import('../server/services/credentialChecker.js');
const { runAskJob, stopSession } = await import('../server/services/askClaude.js');
const logger = (await import('../server/utils/logger.js')).default;

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const OWNER = 'svc-owner';
const TOKEN = 'ghp_SHIMTOKEN0123456789abcdefABCDEF';
const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('ghadmin','gh@x.test','platform_admin','h',1,'human')",
).run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'ghadmin' };
setServiceConfig({ owner: OWNER, token: TOKEN, visibility: 'private', enabled: true }, adminId);
db.prepare("INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled','1') ON CONFLICT(key) DO UPDATE SET value='1'").run();

let slot = 700;
/** A managed app exactly as production has them: github_url set, repo_backend never written. */
function legacyManagedApp(slug) {
  const id = db.prepare(
    "INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES (?, ?, ?, 'managed', ?, 'main')",
  ).run(slug, slug, slot++, `https://github.com/${OWNER}/AMC_${slug}`).lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(id, env);
    db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  }
  db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(id, adminId);
  // The stray directory. Shaped like a bare repo (HEAD, objects/, refs/) so
  // anything that probed the disk would take it for one.
  const stray = join(ROOT, 'repos', `${slug}.git`);
  mkdirSync(join(stray, 'objects'), { recursive: true });
  mkdirSync(join(stray, 'refs', 'heads'), { recursive: true });
  writeFileSync(join(stray, 'HEAD'), 'ref: refs/heads/main\n');
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const strayListing = (slug) => JSON.stringify(readdirSync(join(ROOT, 'repos', `${slug}.git`), { recursive: true }).sort());

// ---------------------------------------------------------------------------
// GitHub REST, at the fetch boundary
// ---------------------------------------------------------------------------
const calls = [];
let branchSha = CLONE_SHA;
const json = (status, body) => ({
  ok: status >= 200 && status < 300, status, statusText: String(status), headers: new Headers(),
  text: async () => JSON.stringify(body), json: async () => body,
});
global.fetch = async (url, init = {}) => {
  const u = String(url);
  const method = (init.method || 'GET').toUpperCase();
  const auth = init.headers?.Authorization || init.headers?.authorization || null;
  calls.push({ method, url: u, auth });
  const m = /^https:\/\/api\.github\.com(\/[^?]*)/.exec(u);
  if (!m) return json(599, { message: `unexpected fetch ${u}` });
  const p = m[1];
  let r;
  if (method === 'GET' && (r = /^\/repos\/svc-owner\/(AMC_[a-z0-9-]+)$/.exec(p))) {
    if (r[1] === 'AMC_gh-repair') return json(404, { message: 'Not Found' });
    return json(200, { full_name: `${OWNER}/${r[1]}`, default_branch: 'main', html_url: `https://github.com/${OWNER}/${r[1]}` });
  }
  if (method === 'GET' && /\/git\/ref\/heads\/main$/.test(p)) return json(200, { object: { sha: '1'.repeat(40) } });
  if (method === 'GET' && /\/git\/commits\/1{40}$/.test(p)) return json(200, { tree: { sha: '2'.repeat(40) } });
  if (method === 'POST' && /\/git\/blobs$/.test(p)) return json(201, { sha: '3'.repeat(40) });
  if (method === 'POST' && /\/git\/trees$/.test(p)) return json(201, { sha: '4'.repeat(40) });
  if (method === 'POST' && /\/git\/commits$/.test(p)) return json(201, { sha: '5'.repeat(40) });
  if (method === 'PATCH' && /\/git\/refs\/heads\/main$/.test(p)) return json(200, { object: { sha: '5'.repeat(40) } });
  if (method === 'GET' && /\/contents\/src\/app\.js$/.test(p)) {
    return json(200, { type: 'file', encoding: 'base64', content: Buffer.from('const a = 1;\n').toString('base64'), sha: '6'.repeat(40) });
  }
  if (method === 'GET' && p === `/users/${OWNER}`) return json(200, { login: OWNER, type: 'User' });
  if (method === 'POST' && p === '/user/repos') {
    const name = JSON.parse(init.body).name;
    return json(201, { full_name: `${OWNER}/${name}`, html_url: `https://github.com/${OWNER}/${name}`, clone_url: `https://github.com/${OWNER}/${name}.git`, ssh_url: 'x', default_branch: 'main', private: true, visibility: 'private' });
  }
  if (method === 'GET' && /\/branches\/main$/.test(p)) return json(200, { commit: { sha: branchSha } });
  if (method === 'GET' && p === '/rate_limit') return json(200, { resources: {} });
  return json(599, { message: `unrouted ${method} ${p}` });
};
const githubCallsFor = (slug) => calls.filter((c) => c.url.includes(`/AMC_${slug}`));

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}

const readLog = (file) => (existsSync(file) ? readFileSync(file, 'utf8') : '')
  .split('\n').filter(Boolean).map((l) => l.split('\x1f').slice(0, -1));

// ---------------------------------------------------------------------------

test('the marker, not the disk: NULL reads as GitHub even with a repo-shaped directory present', () => {
  const app = legacyManagedApp('gh-marker');
  assert.equal(app.repo_backend, null, 'migration 090 must leave a row that never set it NULL');
  assert.ok(existsSync(join(ROOT, 'repos', 'gh-marker.git', 'HEAD')));
  assert.equal(repoBackendOf(app), 'github');
  assert.equal(usesLocalRepo(app), false);
});

test('push (appcrane_push_to_managed_app) goes to GitHub with the service token, response unchanged', async () => {
  const app = legacyManagedApp('gh-push');
  const before = strayListing('gh-push');
  calls.length = 0;
  const res = await tool('appcrane_push_to_managed_app', { slug: 'gh-push', files: [{ path: 'a.txt', content: 'hi' }] });

  assert.deepEqual(res.commit, { sha: '5'.repeat(40), html_url: `https://github.com/${OWNER}/AMC_gh-push/commit/${'5'.repeat(40)}` });
  assert.equal(res.displaced, undefined);
  const gh = githubCallsFor('gh-push');
  assert.ok(gh.some((c) => c.method === 'PATCH' && /\/git\/refs\/heads\/main$/.test(c.url)), 'the branch ref was not moved on GitHub');
  assert.ok(gh.every((c) => c.auth === `Bearer ${TOKEN}`), 'every GitHub call must carry the service-account token');
  assert.equal(db.prepare('SELECT last_managed_push_sha FROM apps WHERE id = ?').get(app.id).last_managed_push_sha, '5'.repeat(40));
  assert.equal(strayListing('gh-push'), before, 'the stray directory was written to');
});

test('chunked push (appcrane_managed_assemble) goes to GitHub', async () => {
  legacyManagedApp('gh-chunk');
  calls.length = 0;
  await tool('appcrane_managed_push_chunk', { slug: 'gh-chunk', path: 'big.txt', session: 'gh-s1', part: 1, of: 1, content: 'part' });
  const res = await tool('appcrane_managed_assemble', { slug: 'gh-chunk', session: 'gh-s1', path: 'big.txt' });
  assert.equal(res.commit.html_url, `https://github.com/${OWNER}/AMC_gh-chunk/commit/${'5'.repeat(40)}`);
  assert.ok(githubCallsFor('gh-chunk').some((c) => c.method === 'POST' && /\/git\/commits$/.test(c.url)));
});

test('read + push (appcrane_managed_patch) reads the file from GitHub contents API', async () => {
  legacyManagedApp('gh-patch');
  calls.length = 0;
  const res = await tool('appcrane_managed_patch', {
    slug: 'gh-patch', path: 'src/app.js',
    unified_diff: '--- a/src/app.js\n+++ b/src/app.js\n@@ -1 +1 @@\n-const a = 1;\n+const a = 2;',
  });
  const gh = githubCallsFor('gh-patch');
  assert.ok(gh.some((c) => c.method === 'GET' && /\/contents\/src\/app\.js\?ref=main$/.test(c.url)), 'file was not read from GitHub');
  assert.ok(gh.some((c) => c.method === 'PATCH'));
  assert.equal(res.commit.html_url, `https://github.com/${OWNER}/AMC_gh-patch/commit/${'5'.repeat(40)}`);
});

test('repair of a GitHub-backed app re-provisions ON GITHUB, keeps the marker NULL, and names the repo', async () => {
  const app = legacyManagedApp('gh-repair');
  rmSync(join(ROOT, 'repos', 'gh-repair.git'), { recursive: true, force: true });
  calls.length = 0;
  const res = await tool('appcrane_create_managed_app', { name: 'x', slug: 'gh-repair' });

  assert.equal(res.repaired, true);
  // The latent bug: this read repaired.name, which createAppRepo never returns.
  assert.equal(res.repo.name, 'AMC_gh-repair');
  assert.equal(res.repo.html_url, `https://github.com/${OWNER}/AMC_gh-repair`);
  assert.ok(calls.some((c) => c.method === 'POST' && c.url === 'https://api.github.com/user/repos'), 'repo was not created on GitHub');
  assert.equal(existsSync(join(ROOT, 'repos', 'gh-repair.git')), false, 'a GitHub-backed repair must not create a local repo');
  const row = db.prepare('SELECT repo_backend, github_url FROM apps WHERE id = ?').get(app.id);
  assert.equal(row.repo_backend, null);
  assert.equal(row.github_url, `https://github.com/${OWNER}/AMC_gh-repair`);
});

test('deploy: shallow clone from GitHub with the token in git\'s environment, pin fetch, and the GitHub SHA check', async () => {
  const app = legacyManagedApp('gh-deploy');
  rmSync(GIT_LOG, { force: true });
  rmSync(GIT_ENV_LOG, { force: true });
  calls.length = 0;
  branchSha = CLONE_SHA;
  const target = CLONE_SHA;
  const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)")
    .run(app.id, adminId).lastInsertRowid;
  await deployApp(depId, app, 'sandbox', getPortsForSlot(app.slot), { targetCommit: target }).catch(() => {});
  const { log } = db.prepare('SELECT log FROM deployments WHERE id = ?').get(depId);

  const argv = readLog(GIT_LOG);
  const clone = argv.find((a) => a[0] === 'clone');
  assert.ok(clone, `no clone ran: ${log}`);
  const releaseDir = clone[clone.length - 1];
  assert.match(releaseDir, new RegExp(`/apps/gh-deploy/sandbox/releases/\\d+-git$`));
  // The URL carries no credential: in argv it was visible to `ps`, and git
  // wrote it into the release's .git/config, where it stayed on disk.
  assert.deepEqual(clone, ['clone', '--depth', '1', '--branch', 'main', `https://github.com/${OWNER}/AMC_gh-deploy`, releaseDir]);
  assert.equal(JSON.stringify(argv).includes(TOKEN), false, 'the service token reached git argv');
  const envs = readLog(GIT_ENV_LOG);
  for (const verb of ['clone', '-C']) {
    const e = envs.find((a) => a[0] === verb);
    assert.ok(e, `no environment recorded for git ${verb}`);
    assert.equal(e[1], 'http.https://github.com/.extraHeader', `git ${verb} was not given the credential for github.com`);
    assert.equal(e[2], basicFor(TOKEN), `git ${verb} did not get the service token`);
  }
  assert.deepEqual(argv.find((a) => a[0] === '-C' && a[2] === 'fetch'), ['-C', releaseDir, 'fetch', '--depth', '1', 'origin', target]);
  assert.deepEqual(argv.find((a) => a[0] === '-C' && a[2] === 'checkout'), ['-C', releaseDir, 'checkout', '--detach', target]);

  const branchReads = calls.filter((c) => c.url === `https://api.github.com/repos/${OWNER}/AMC_gh-deploy/branches/main`);
  assert.equal(branchReads.length, 1);
  assert.equal(branchReads[0].auth, `Bearer ${TOKEN}`);
  assert.match(log, new RegExp(`Cloning managed repo https://github.com/${OWNER}/AMC_gh-deploy \\(branch: main\\)`));
  assert.match(log, new RegExp(`Supply-chain verify: OK \\(HEAD ${CLONE_SHA.slice(0, 12)} matches GitHub ${OWNER}/AMC_gh-deploy@main\\)`));
  assert.doesNotMatch(log, /repository store|local managed repository|Same-host/);
  assert.equal(log.includes(TOKEN), false, 'the service token reached the deploy log');
});

/**
 * Run a deploy with every log method wrapped. The logger drops lines below
 * LOG_LEVEL before printing, and the deployer mirrors every deploy-log line to
 * log.info — so watching the console would miss exactly the lines at risk. The
 * wrapper records what was HANDED to the logger, whatever the level.
 */
async function deployCapturingLogs(app, opts) {
  const logged = [];
  const orig = { ...logger };
  for (const k of ['error', 'warn', 'info', 'debug']) {
    logger[k] = (msg, meta) => { logged.push(`${msg} ${meta ? JSON.stringify(meta) : ''}`); return orig[k](msg, meta); };
  }
  const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)")
    .run(app.id, adminId).lastInsertRowid;
  let thrown = null;
  try {
    await deployApp(depId, app, 'sandbox', getPortsForSlot(app.slot), opts);
  } catch (e) {
    thrown = e;
  } finally {
    Object.assign(logger, orig);
  }
  const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(depId);
  return { thrown, logged, row };
}

test('a failing GitHub clone never puts the service token in the error, the deploy log, or the logger', async () => {
  const app = legacyManagedApp('gh-clonefail');
  process.env.GIT_SHIM_CLONE_FAIL = '1';
  let r;
  try {
    r = await deployCapturingLogs(app, {});
  } finally {
    delete process.env.GIT_SHIM_CLONE_FAIL;
  }
  // CONTROL: the failing clone really did carry the service credential, so a
  // clean error below means it was kept out, not that it was never there.
  const clone = readLog(GIT_LOG).reverse().find((a) => a[0] === 'clone');
  assert.ok(clone, 'control: no clone ran');
  const cloneEnv = readLog(GIT_ENV_LOG).reverse().find((a) => a[0] === 'clone');
  assert.equal(cloneEnv?.[2], basicFor(TOKEN), 'control: the failing clone was not given the service token, so this test proves nothing');
  assert.equal(clone.some((a) => a.includes(TOKEN)), false, 'the service token reached git argv');

  assert.equal(r.row.status, 'failed');
  assert.match(r.row.log, /DEPLOY FAILED: [\s\S]*Could not resolve host: github\.com/, `the clone failure did not surface: ${r.row.log}`);
  assert.match(r.row.log, new RegExp(`unable to access 'https://github\\.com/${OWNER}/AMC_gh-clonefail/'`),
    'the scrubbed URL is not in the error, so the error text is not the one under test');
  const surfaces = { 'deploy log': r.row.log, thrown: r.thrown ? `${r.thrown.message}\n${r.thrown.stack}` : '', logger: r.logged.join('\n') };
  for (const [where, text] of Object.entries(surfaces)) {
    assert.equal(text.includes(TOKEN), false, `the service token leaked into the ${where}`);
  }
});

test('a failing GitHub pin (fetch + checkout) never puts the service token anywhere either', async () => {
  // Honest scope: with the error text git really prints, neither the pin argv
  // (`git -C <dir> fetch origin <sha>`) nor git's stderr contains the token, so
  // this passes with or without the deployer's replaceAll on the pin error. It
  // pins the current outcome; it cannot prove that scrub is needed.
  const app = legacyManagedApp('gh-pinfail');
  process.env.GIT_SHIM_PIN_FAIL = '1';
  let r;
  try {
    r = await deployCapturingLogs(app, { targetCommit: 'abc1234' });
  } finally {
    delete process.env.GIT_SHIM_PIN_FAIL;
  }
  assert.equal(r.row.status, 'failed');
  assert.match(r.row.log, /Failed to check out commit abc1234 for promotion/, r.row.log);
  const surfaces = { 'deploy log': r.row.log, thrown: r.thrown ? `${r.thrown.message}\n${r.thrown.stack}` : '', logger: r.logged.join('\n') };
  for (const [where, text] of Object.entries(surfaces)) {
    assert.equal(text.includes(TOKEN), false, `the service token leaked into the ${where}`);
  }
});

test('SHA check for a NULL managed app still retries a GitHub disagreement (3 reads) before failing', async () => {
  const app = legacyManagedApp('gh-retry');
  calls.length = 0;
  branchSha = 'f'.repeat(40);
  const dir = mkdtempSync(join(ROOT, 'wt-'));
  await assert.rejects(verifyCommitSha(app, dir, 'main', () => {}), /does not match GitHub's/);
  assert.equal(calls.filter((c) => /AMC_gh-retry\/branches\/main$/.test(c.url)).length, 3,
    'the eventual-consistency retries for GitHub were removed');
  branchSha = CLONE_SHA;
});

test('promote of a NULL managed app takes the fresh-rebuild path', async () => {
  const app = legacyManagedApp('gh-promote');
  db.prepare("INSERT INTO deployments (app_id, env, version, status, commit_hash, deployed_by) VALUES (?, 'sandbox', '1.0.0', 'live', 'c0ffee0', ?)")
    .run(app.id, adminId);
  const r = await promoteApp(app, adminId);
  assert.equal(r.mode, 'rebuild');
});

test('AskClaude clones a NULL managed app from github_url, exactly as before', async () => {
  const app = legacyManagedApp('gh-ask');
  process.env.DOCKER_SHIM_MODE = 'ask';
  const sessionId = 910001;
  try {
    await Promise.race([
      runAskJob({ sessionId, app, question: 'q', history: [], agentContext: '', contextDoc: null }).catch(() => {}),
      new Promise((r) => setTimeout(r, 20000)),
    ]);
  } finally {
    stopSession(sessionId);
    delete process.env.DOCKER_SHIM_MODE;
  }
  assert.equal(readFileSync(join(ASK_CAPTURE, 'clone_url'), 'utf8'), `https://github.com/${OWNER}/AMC_gh-ask`);
  assert.doesNotMatch(readFileSync(join(ASK_CAPTURE, 'ls'), 'utf8'), /repo\.bundle/);
  const run = readLog(DOCKER_LOG).find((a) => a[0] === 'run');
  assert.equal(run[run.length - 1],
    'CLONE_URL=$(cat /studio/clone_url) && git clone --depth 1 --branch "$BRANCH" "$CLONE_URL" /workspace && git -C /workspace remote remove origin && git -C /workspace config --local credential.helper "" && tail -f /dev/null');
});

test('credential probe still checks the service account while a NULL managed app exists', async () => {
  calls.length = 0;
  const probe = PROBES.find((p) => p.name === 'GitHub service account');
  const r = await probe.run();
  assert.deepEqual(r, { ok: true });
  assert.equal(calls.filter((c) => c.url === 'https://api.github.com/rate_limit').length, 1);
});
