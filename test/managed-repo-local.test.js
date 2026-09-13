import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Phase 2: a NEW managed app is created on this host (apps.repo_backend =
// 'local') and every touchpoint uses <DATA_DIR>/repos/<slug>.git.
//
// Real git throughout, read back independently of the module under test. The
// only shim is docker, which fails the build so a deploy stops after the parts
// under test (clone, pin, SHA check), or, for AskClaude, records the container
// it would have started. The GitHub side is a fetch stub that counts: a local
// app must never reach it.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-mrlocal-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
const ASK_CAPTURE = join(ROOT, 'ask-capture');
mkdirSync(SHIM, { recursive: true });
mkdirSync(ASK_CAPTURE, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "$DOCKER_SHIM_LOG"
if [ "$DOCKER_SHIM_MODE" != ask ]; then echo "no docker" >&2; exit 1; fi
case "$1" in
  run)
    prev=""
    for a in "$@"; do
      case "$a" in *:/studio:ro) if [ "$prev" = -v ]; then d="\${a%:/studio:ro}"; cp "$d/clone_url" "$ASK_CAPTURE/clone_url"; [ -f "$d/repo.bundle" ] && cp "$d/repo.bundle" "$ASK_CAPTURE/repo.bundle"; echo "$d" > "$ASK_CAPTURE/dir"; fi ;; esac
      prev="$a"
    done
    echo shimcontainer ;;
  inspect) echo running ;;
  image) echo 3 ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
process.env.DOCKER_SHIM_LOG = DOCKER_LOG;
process.env.ASK_CAPTURE = ASK_CAPTURE;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { setServiceConfig } = await import('../server/services/githubService.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp, promoteApp } = await import('../server/services/deployer.js');
const { verifyCommitSha } = await import('../server/services/supplyChain.js');
const { getPortsForSlot, getNextSlot } = await import('../server/services/portAllocator.js');
const { repoBackendOf, usesLocalRepo } = await import('../server/services/managedRepo.js');
const { PROBES } = await import('../server/services/credentialChecker.js');
const { runAskJob, stopSession } = await import('../server/services/askClaude.js');
const lg = await import('../server/services/localGit.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

// Independent reader: isolated git, never the module's helpers.
const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const git = (args, opts = {}) => execFileSync('git', args, { env: CLEAN_ENV, ...opts }).toString('utf8').trim();
const tipOf = (slug) => git([`--git-dir=${lg.repoPath(slug)}`, 'rev-parse', 'refs/heads/main']);

const fetchCalls = [];
global.fetch = async (url) => {
  fetchCalls.push(String(url));
  return { ok: true, status: 200, headers: new Headers(), text: async () => '{}', json: async () => ({}) };
};

const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('lcadmin','lc@x.test','platform_admin','h',1,'human')",
).run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'lcadmin' };
db.prepare("INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled','1') ON CONFLICT(key) DO UPDATE SET value='1'").run();
const setVerify = (on) => db.prepare("UPDATE settings SET value = ? WHERE key = 'supply_chain_verify_enabled'").run(on ? '1' : '0');

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}
const appRow = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);

async function deploy(app, opts = {}) {
  const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)")
    .run(app.id, adminId).lastInsertRowid;
  await deployApp(depId, app, 'sandbox', getPortsForSlot(app.slot), opts).catch(() => {});
  return db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(depId).log || '';
}
// The chown line names host paths on every deploy of every app (pre-existing);
// what must not leak is the repository store's path.
const leaksRoot = (log) => log.split('\n').some((l) => !/\] chown /.test(l) && l.includes(ROOT));
const clonedShort = (log) => /Cloned successfully\. Commit: ([0-9a-f]+)/.exec(log)?.[1];

// ---------------------------------------------------------------------------
// Schema + the decision
// ---------------------------------------------------------------------------

test('090: repo_backend is nullable with no default, so an insert that never names it is GitHub', () => {
  const col = db.prepare('PRAGMA table_info(apps)').all().find((c) => c.name === 'repo_backend');
  assert.ok(col, 'apps.repo_backend missing');
  assert.equal(col.notnull, 0);
  assert.equal(col.dflt_value, null);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('n','lc-null-row',?,'managed')").run(getNextSlot(db));
  assert.equal(appRow('lc-null-row').repo_backend, null);
});

test('090 on an upgraded box: every existing apps value survives the rebuild and repo_backend comes out NULL', async () => {
  // A fresh test DB has no rows when 090 runs, so it cannot catch a column the
  // rebuild forgets to copy. This builds the apps table exactly as 088 left it,
  // fills every column with a distinct value, and runs 090 over it.
  const Database = (await import('better-sqlite3')).default;
  const mig = (f) => readFileSync(new URL(`../server/migrations/${f}`, import.meta.url), 'utf8');
  const s088 = mig('088-container-command-volumes.sql');
  const create088 = /CREATE TABLE apps_new \([\s\S]*?\n\);/.exec(s088)[0].replace('apps_new', 'apps');
  const cols = [...create088.matchAll(/^ {2}([a-z_]+) +(?:INTEGER|TEXT)/gm)].map((m) => m[1]);
  assert.equal(cols.length, 38);
  const mem = new Database(':memory:');
  mem.exec('CREATE TABLE users (id INTEGER PRIMARY KEY);');
  mem.exec(create088);
  const row = Object.fromEntries(cols.map((c, i) => [c, c === 'source_type' ? 'managed' : c === 'id' ? 7 : `v${i}-${c}`]));
  row.slot = 42; row.public_access = 1; row.image_retention = 3; row.multitenant = 1; row.created_by = null;
  row.public_port = 51001; row.data_plane_port = 51002; row.sandbox_public_port = 51003; row.container_port = 8080;
  row.container_command = '["start-dev"]'; row.volume_paths = '["/config"]';
  mem.prepare(`INSERT INTO apps (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(cols.map((c) => row[c]));
  mem.exec(mig('090-apps-repo-backend.sql'));
  const after090 = mem.prepare('SELECT * FROM apps WHERE id = 7').get();
  for (const c of cols) assert.deepEqual(after090[c], row[c], `090 lost ${c}`);
  assert.equal(after090.repo_backend, null);
  assert.equal(Object.keys(after090).length, 39);
  mem.close();
});

test('repoBackendOf: NULL/absent is GitHub, local is local, anything else is refused rather than guessed', () => {
  assert.equal(repoBackendOf({ slug: 'a', repo_backend: null }), 'github');
  assert.equal(repoBackendOf({ slug: 'a' }), 'github');
  assert.equal(repoBackendOf({ slug: 'a', repo_backend: 'local' }), 'local');
  for (const bad of ['LOCAL', 'github', '', 'gitlab', 1]) {
    assert.throws(() => repoBackendOf({ slug: 'a', repo_backend: bad }), /does not recognise/, `accepted ${JSON.stringify(bad)}`);
  }
  assert.equal(usesLocalRepo({ source_type: 'github', repo_backend: 'local' }), false, 'only managed apps have a managed repo');
});

// ---------------------------------------------------------------------------
// Create / push / read through MCP
// ---------------------------------------------------------------------------

test('create: no GitHub service account needed; local repo, marker local, no web/clone URL handed out', async () => {
  const res = await tool('appcrane_create_managed_app', { name: 'Local One', slug: 'lc-one', description: 'phase two' });
  const row = appRow('lc-one');
  assert.equal(row.repo_backend, 'local');
  assert.equal(row.github_url, null);
  assert.equal(git([`--git-dir=${lg.repoPath('lc-one')}`, 'rev-parse', '--is-bare-repository']), 'true');
  assert.match(git([`--git-dir=${lg.repoPath('lc-one')}`, 'show', 'main:README.md']), /phase two/);

  const text = JSON.stringify(res);
  assert.equal(/html_url|clone_url|github_url/.test(text), false, `a null URL key reached the agent: ${text}`);
  assert.equal(text.includes(ROOT), false, 'the host DATA_DIR path reached the agent');
  assert.equal(res.app.repo_backend, 'local');
  assert.equal(res.repo.full_name, 'AMC_lc-one');
  assert.equal(fetchCalls.length, 0, 'a local create talked to GitHub');
});

test('credential probe: with only local managed apps the service account is not probed', async () => {
  db.prepare("DELETE FROM apps WHERE slug = 'lc-null-row'").run();
  setServiceConfig({ owner: 'o', token: 'ghp_x', visibility: 'private', enabled: true }, adminId);
  const probe = PROBES.find((p) => p.name === 'GitHub service account');
  fetchCalls.length = 0;
  try {
    assert.deepEqual(await probe.run(), { ok: true, skipped: true });
    assert.equal(fetchCalls.length, 0);

    // A GitHub-backed managed app appears: probing resumes.
    db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url) VALUES ('g','lc-probe-gh',?,'managed','https://github.com/o/AMC_lc-probe-gh')").run(getNextSlot(db));
    assert.deepEqual(await probe.run(), { ok: true });
    assert.equal(fetchCalls.filter((u) => u.endsWith('/rate_limit')).length, 1);
  } finally {
    // Cleanup that a failed assertion cannot skip: later tests assert zero
    // GitHub calls, and would all go red for this test's failure.
    db.prepare("DELETE FROM apps WHERE slug = 'lc-probe-gh'").run();
    setServiceConfig({ token: null }, adminId);
    fetchCalls.length = 0;
  }
});

test('push, chunked push and patch all commit to the local repo; commit is { sha } only', async () => {
  const push = await tool('appcrane_push_to_managed_app', {
    slug: 'lc-one', message: 'scaffold',
    files: [{ path: 'package.json', content: '{"name":"lc-one","version":"1.0.0"}' }, { path: 'src/app.js', content: 'const a = 1;\n' }],
  });
  assert.deepEqual(Object.keys(push.commit), ['sha']);
  assert.equal(push.commit.sha, tipOf('lc-one'));
  assert.equal(appRow('lc-one').last_managed_push_sha, push.commit.sha);

  await tool('appcrane_managed_push_chunk', { slug: 'lc-one', path: 'big.txt', session: 'lc-s1', part: 1, of: 2, content: 'hello ' });
  await tool('appcrane_managed_push_chunk', { slug: 'lc-one', path: 'big.txt', session: 'lc-s1', part: 2, of: 2, content: 'world' });
  const asm = await tool('appcrane_managed_assemble', { slug: 'lc-one', session: 'lc-s1', path: 'big.txt' });
  assert.equal(asm.commit.sha, tipOf('lc-one'));
  assert.equal(git([`--git-dir=${lg.repoPath('lc-one')}`, 'show', 'main:big.txt']), 'hello world');

  const patch = await tool('appcrane_managed_patch', {
    slug: 'lc-one', path: 'src/app.js',
    unified_diff: '--- a/src/app.js\n+++ b/src/app.js\n@@ -1 +1 @@\n-const a = 1;\n+const a = 2;',
  });
  assert.equal(patch.file.bytes_before, 13);
  assert.equal(patch.commit.sha, tipOf('lc-one'));
  assert.equal(git([`--git-dir=${lg.repoPath('lc-one')}`, 'show', 'main:src/app.js']), 'const a = 2;');
  assert.equal(JSON.stringify([push, asm, patch]).includes('html_url'), false);
  assert.equal(fetchCalls.length, 0);
});

test('repair of a local app re-creates the LOCAL repo, keeps the marker, and names the repo', async () => {
  await tool('appcrane_create_managed_app', { name: 'R', slug: 'lc-repair' });
  rmSync(lg.repoPath('lc-repair'), { recursive: true, force: true });
  const res = await tool('appcrane_create_managed_app', { name: 'R', slug: 'lc-repair' });
  assert.equal(res.repaired, true);
  assert.equal(res.repo.name, 'AMC_lc-repair');
  assert.equal(JSON.stringify(res).includes('html_url'), false);
  assert.ok(lg.localRepoExists('lc-repair'));
  assert.equal(appRow('lc-repair').repo_backend, 'local');
  await assert.rejects(tool('appcrane_create_managed_app', { name: 'R', slug: 'lc-repair' }), /nothing to repair/);
  assert.equal(fetchCalls.length, 0);
});

test('the marker decides: a NULL app whose slug has a real local repo on disk still pushes to GitHub', async () => {
  await lg.createAppRepo('lc-shadow');
  const before = tipOf('lc-shadow');
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url) VALUES ('s','lc-shadow',?,'managed','https://github.com/o/AMC_lc-shadow')").run(getNextSlot(db));
  await assert.rejects(
    tool('appcrane_push_to_managed_app', { slug: 'lc-shadow', files: [{ path: 'x', content: 'y' }] }),
    /github/i,
  );
  assert.equal(tipOf('lc-shadow'), before, 'the local repo was written for a GitHub-backed app');
});

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

test('deploy clones the local repo at the branch tip and verifies it against the local repo', async () => {
  const log = await deploy(appRow('lc-one'));
  const tip = tipOf('lc-one');
  assert.match(log, /Cloning managed repo AMC_lc-one from this host's repository store \(branch: main\)/);
  assert.ok(clonedShort(log) && tip.startsWith(clonedShort(log)), `deployed ${clonedShort(log)}, tip is ${tip}\n${log}`);
  assert.match(log, new RegExp(`Supply-chain verify: OK \\(HEAD ${tip.slice(0, 12)} matches the local managed repository AMC_lc-one@main\\)`));
  assert.match(log, /Same-host witness/);
  assert.equal(leaksRoot(log), false, 'host path in the deploy log');
  assert.equal(fetchCalls.length, 0, 'a local deploy talked to GitHub');
});

test('promote pin: a local deploy checks out the EXACT commit asked for, full or abbreviated', async () => {
  const app = appRow('lc-one');
  const older = tipOf('lc-one');
  await tool('appcrane_push_to_managed_app', { slug: 'lc-one', files: [{ path: 'later.txt', content: '1' }] });
  await tool('appcrane_push_to_managed_app', { slug: 'lc-one', files: [{ path: 'later.txt', content: '2' }] });
  assert.notEqual(tipOf('lc-one'), older);
  // Verification compares against the branch tip, which has moved on purpose
  // here (as it does on GitHub). It is covered separately; this is about the pin.
  setVerify(false);
  try {
    const full = await deploy(appRow('lc-one'), { targetCommit: older });
    assert.match(full, new RegExp(`Pinning to commit ${older}`));
    assert.ok(older.startsWith(clonedShort(full)), `full SHA: deployed ${clonedShort(full)}, asked for ${older}\n${full}`);

    const short = older.slice(0, 7);
    const abbrev = await deploy(appRow('lc-one'), { targetCommit: short });
    assert.ok(older.startsWith(clonedShort(abbrev)), `short SHA: deployed ${clonedShort(abbrev)}, asked for ${short}\n${abbrev}`);

    const missing = await deploy(app, { targetCommit: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' });
    assert.match(missing, /Failed to check out commit deadbeef/);
    assert.equal(leaksRoot(missing), false, missing);
  } finally {
    setVerify(true);
  }
});

test('deploy clone is shallow, copies no hooks, and host git config cannot run anything', async () => {
  const hookDir = join(ROOT, 'hostile-hooks');
  const marker = join(ROOT, 'hook-ran');
  mkdirSync(hookDir, { recursive: true });
  writeFileSync(join(hookDir, 'post-checkout'), `#!/bin/sh\necho "$0" >> "${marker}"\n`, { mode: 0o755 });
  const home = join(ROOT, 'hostile-home');
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, '.gitconfig'), `[core]\n\thooksPath = ${hookDir}\n`);
  // And a repo that carries its own hooksPath + hook, as a hand-restored one could.
  const repo = lg.repoPath('lc-one');
  git([`--git-dir=${repo}`, 'config', 'core.hooksPath', hookDir]);
  mkdirSync(join(repo, 'hooks'), { recursive: true });
  writeFileSync(join(repo, 'hooks', 'post-checkout'), readFileSync(join(hookDir, 'post-checkout')), { mode: 0o755 });

  // A second layer the command-line `-c core.hooksPath=/dev/null` does NOT
  // cover: a filter driver defined in host config runs on checkout for any path
  // .gitattributes routes to it, and .gitattributes is repo content an agent can
  // push. Only a scrubbed environment keeps the host's definition out.
  const filterMarker = join(ROOT, 'filter-ran');
  await tool('appcrane_push_to_managed_app', { slug: 'lc-one', files: [{ path: '.gitattributes', content: '*.txt filter=evil\n' }] });
  const saved = {};
  for (const k of ['HOME', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1']) saved[k] = process.env[k];
  Object.assign(process.env, {
    HOME: home, GIT_CONFIG_COUNT: '2',
    GIT_CONFIG_KEY_0: 'core.hooksPath', GIT_CONFIG_VALUE_0: hookDir,
    GIT_CONFIG_KEY_1: 'filter.evil.smudge', GIT_CONFIG_VALUE_1: `sh -c 'echo ran >> "${filterMarker}"; cat'`,
  });
  try {
    // CONTROL: with this environment an ordinary clone DOES run the hook, so a
    // clean result below is the isolation working, not a hook that cannot fire.
    execFileSync('git', ['clone', '-q', '--no-local', repo, join(ROOT, 'control-clone')], { stdio: 'pipe' });
    assert.ok(existsSync(marker), 'control: the hostile config did not run the hook, so this test proves nothing');
    assert.ok(existsSync(filterMarker), 'control: the host filter driver did not run, so this test proves nothing');
    rmSync(marker);
    rmSync(filterMarker);

    const log = await deploy(appRow('lc-one'));
    assert.match(log, /Cloned successfully/);
    assert.equal(existsSync(marker), false, `a hook ran during the local deploy clone: ${existsSync(marker) && readFileSync(marker, 'utf8')}`);
    assert.equal(existsSync(filterMarker), false, 'a host-defined filter driver ran during the local deploy clone');

    const dest = join(ROOT, 'unit-clone');
    lg.cloneForDeploySync('lc-one', dest, 'main');
    assert.equal(existsSync(marker), false, 'a hook ran during cloneForDeploySync');
    assert.equal(existsSync(filterMarker), false, 'a host-defined filter driver ran during cloneForDeploySync');
    assert.equal(git(['-C', dest, 'rev-list', '--count', 'HEAD']), '1', 'clone is not shallow (a plain-path clone ignores --depth)');
    assert.ok(existsSync(join(dest, '.git', 'shallow')));
    assert.deepEqual(existsSync(join(dest, '.git', 'hooks')) ? readdirSync(join(dest, '.git', 'hooks')) : [], []);
    assert.equal(git(['-C', dest, 'rev-parse', 'HEAD']), tipOf('lc-one'));
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    git([`--git-dir=${repo}`, 'config', '--unset', 'core.hooksPath']);
    rmSync(join(repo, 'hooks'), { recursive: true, force: true });
  }
});

test('a local clone failure names AMC_<slug>, never the repository store path', async () => {
  // Measured: a repo whose HEAD is unreadable makes git print
  //   fatal: repository '<absolute path>' does not exist
  // (a missing branch or a bad config line does not name the path, so they
  // could not tell whether the path is scrubbed).
  await tool('appcrane_create_managed_app', { name: 'Broken', slug: 'lc-broken' });
  writeFileSync(join(lg.repoPath('lc-broken'), 'HEAD'), 'garbage\n');
  const dest = join(ROOT, 'broken-clone');
  // CONTROL: the raw git error for this repo does contain the path.
  const raw = (() => {
    try { execFileSync('git', ['clone', '-q', '--no-local', lg.repoPath('lc-broken'), dest], { env: CLEAN_ENV, stdio: 'pipe' }); return ''; } catch (e) { return String(e.stderr); }
  })();
  assert.ok(raw.includes(lg.repoPath('lc-broken')), `control: raw git error does not name the path, so this proves nothing: ${raw}`);

  const log = await deploy(appRow('lc-broken'));
  assert.match(log, /DEPLOY FAILED: git clone failed: fatal: repository 'AMC_lc-broken' does not exist/, log);
  assert.equal(leaksRoot(log), false, log);
});

test('promote of a local app takes the fresh-rebuild path, pinned to the sandbox commit', async () => {
  const app = appRow('lc-one');
  const tip = tipOf('lc-one');
  db.prepare("INSERT INTO deployments (app_id, env, version, status, commit_hash, deployed_by) VALUES (?, 'sandbox', '1.0.0', 'live', ?, ?)")
    .run(app.id, tip.slice(0, 7), adminId);
  const r = await promoteApp(app, adminId);
  assert.equal(r.mode, 'rebuild', 'a local app fell through to the copy path (it has no github_url)');
  let row;
  for (let i = 0; i < 100; i++) {
    row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(r.deployment_id);
    if (row.status === 'failed' || row.status === 'live') break;
    await new Promise((res) => setTimeout(res, 100));
  }
  assert.match(row.log, new RegExp(`Pinning to commit ${tip.slice(0, 7)}`));
  assert.ok(tip.startsWith(clonedShort(row.log)));
});

// ---------------------------------------------------------------------------
// Supply-chain check
// ---------------------------------------------------------------------------

function workClone(slug) {
  const dest = mkdtempSync(join(ROOT, 'wc-'));
  rmSync(dest, { recursive: true });
  lg.cloneForDeploySync(slug, dest, 'main');
  return dest;
}

test('SHA check (local): match verifies with no GitHub call, even with a github.com URL on the row', async () => {
  const app = { ...appRow('lc-one'), github_url: 'https://github.com/o/AMC_lc-one' };
  const r = await verifyCommitSha(app, workClone('lc-one'), 'main', () => {});
  assert.equal(r.verified, true);
  assert.equal(r.witness, 'local');
  assert.equal(r.remoteSha, tipOf('lc-one'));
  assert.equal(fetchCalls.length, 0);
});

test('SHA check (local): a mismatch fails at once, with no retry delay', async () => {
  const dir = workClone('lc-one');
  await tool('appcrane_push_to_managed_app', { slug: 'lc-one', files: [{ path: 'moved.txt', content: 'x' }] });
  const app = { ...appRow('lc-one'), last_managed_push_sha: null };
  const t0 = Date.now();
  await assert.rejects(verifyCommitSha(app, dir, 'main', () => {}), /does not match the local managed repository AMC_lc-one@main/);
  const ms = Date.now() - t0;
  // GitHub's schedule is 0 / 1500 / 3000 ms. Anything near 1500 means the
  // retries came back for local.
  assert.ok(ms < 1000, `local mismatch took ${ms}ms — retried?`);
  assert.equal(fetchCalls.length, 0);
});

test('SHA check (local): an unreadable repo fails closed; the operator hatch reports NOT VERIFIED', async () => {
  const app = { ...appRow('lc-one'), slug: 'lc-gone', last_managed_push_sha: null };
  const dir = workClone('lc-one');
  await assert.rejects(verifyCommitSha(app, dir, 'main', () => {}), /Supply-chain verify FAILED: could not confirm/);
  process.env.APPCRANE_REQUIRE_VERIFY = '0';
  try {
    const lines = [];
    const r = await verifyCommitSha(app, dir, 'main', (l) => lines.push(l));
    assert.equal(r.verified, false);
    assert.equal(r.failOpen, true);
    assert.ok(lines.some((l) => /NOT VERIFIED/.test(l)));
  } finally {
    delete process.env.APPCRANE_REQUIRE_VERIFY;
  }
});

test('SHA check: an unknown marker on a managed app fails the check instead of routing anywhere', async () => {
  const app = { ...appRow('lc-one'), repo_backend: 'Local', github_url: 'https://github.com/o/r' };
  await assert.rejects(verifyCommitSha(app, workClone('lc-one'), 'main', () => {}), /does not recognise/);
  assert.equal(fetchCalls.length, 0);
});

