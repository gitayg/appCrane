import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * An eviction must not destroy a coder session's work or its conversation.
 *
 * Two independent guarantees are checked here, both against a REAL bare repo in
 * a temp DATA_DIR. Only Docker is faked — by a shim binary put first on PATH,
 * which records its argv. git is the host's real git throughout, and every
 * assertion about what landed is read back with an independent `git --git-dir`
 * against the bare repo, never through the module under test.
 *
 *   1. AUTO-COMMIT. Uncommitted work in the workspace is committed and pushed
 *      to `agent/<userId>/<sessionId>` in the managed repo before the wipe.
 *      That branch name is load-bearing: deployTrigger's branch_filter defaults
 *      to 'main', so a preserve commit on main would DEPLOY unreleased agent
 *      work to sandbox. The branch-filter test below proves it does not.
 *
 *   2. TRANSCRIPT PERSISTENCE. Claude Code writes its conversation transcripts
 *      to $HOME/.claude/projects/<cwd-slug>/<session-id>.jsonl — measured
 *      inside the real appcrane-studio image, see appContainer.js — so that
 *      directory is bind-mounted from the host and survives the eviction that
 *      removes the container.
 *
 * Eviction runs from a timer and from a sweeper, so it must NEVER throw. The
 * failure test deletes the bare repo out from under the push to prove it.
 */

const ROOT = mkdtempSync(join(tmpdir(), 'crane-evict-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

// ── the docker shim ────────────────────────────────────────────────────────
const BIN = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
mkdirSync(BIN, { recursive: true });
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(DOCKER_LOG)}
case "$1" in
  run)     echo c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ff ;;
  image)   echo 5 ;;
  inspect) echo true ;;
esac
exit 0
`);
chmodSync(join(BIN, 'docker'), 0o755);
process.env.PATH = `${BIN}:${process.env.PATH}`;

const dockerArgv = () => (existsSync(DOCKER_LOG) ? readFileSync(DOCKER_LOG, 'utf8').split('\n').filter(Boolean) : []);
const dockerRunArgs = () => dockerArgv().filter((l) => l.startsWith('run '));

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getNextSlot } = await import('../server/services/portAllocator.js');
const lg = await import('../server/services/localGit.js');
const { evaluatePush, pushConfigForApp } = await import('../server/services/deployTrigger.js');
const appContainer = await import('../server/services/builder/appContainer.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const bareGit = (dir, args) => execFileSync('git', [`--git-dir=${dir}`, ...args], { env: CLEAN }).toString('utf8').trim();
const refsIn = (dir) => bareGit(dir, ['for-each-ref', '--format=%(refname)']).split('\n').filter(Boolean).sort();
const treeOf = (dir, ref) => bareGit(dir, ['ls-tree', '-r', '--name-only', ref]).split('\n').filter(Boolean).sort();
const blobIn = (dir, ref, path) => bareGit(dir, ['show', `${ref}:${path}`]);

let nextUser = 0;
function userRow() {
  const n = ++nextUser;
  return db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,'platform_admin',?,1,'human')")
    .run(`u${n}`, `u${n}@example.com`, `hash-${n}`).lastInsertRowid;
}

/** A Crane-hosted (repo_backend='local') app with a real bare repo on disk. */
async function craneApp(slug) {
  await lg.createAppRepo(slug);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES (?,?,?, 'managed', 'local', 'main')")
    .run(slug, slug, getNextSlot(db));
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}

/** A GitHub-backed app whose "GitHub" remote is a bare repo path, so no network. */
function githubApp(slug) {
  const remote = join(ROOT, `${slug}-remote.git`);
  execFileSync('git', ['init', '--bare', '-b', 'main', '-q', remote], { env: CLEAN });
  const seed = join(ROOT, `${slug}-seed`);
  execFileSync('git', ['init', '-q', '-b', 'main', seed], { env: CLEAN });
  writeFileSync(join(seed, 'README.md'), '# seed\n');
  execFileSync('git', ['-C', seed, 'add', 'README.md'], { env: CLEAN });
  execFileSync('git', ['-C', seed, '-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '-m', 'init'], { env: CLEAN });
  execFileSync('git', ['-C', seed, 'push', '-q', remote, 'main'], { env: CLEAN });
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch, github_url) VALUES (?,?,?, 'github', NULL, 'main', ?)")
    .run(slug, slug, getNextSlot(db), remote);
  return { app: db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug), remote };
}

/** The coder_sessions row builderSession.js writes once the container is up. */
function session(app, container, userId) {
  const id = `sess-${app.slug}-${userId}`;
  db.prepare(`INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status, container_id, workspace_dir)
              VALUES (?,?,?,?, 'idle', ?, ?)`)
    .run(id, app.slug, userId, container.branchName, container.containerId, container.workspaceDir);
  return id;
}

// ---------------------------------------------------------------------------
// 1. Auto-commit on evict
// ---------------------------------------------------------------------------

test('uncommitted work survives an evict as a commit on agent/<user>/<session>', async () => {
  const app = await craneApp('ev-keep');
  const c = await appContainer.getOrCreate(app);
  const uid = userRow();
  const sid = session(app, c, uid);

  writeFileSync(join(c.workspaceDir, 'NEW.js'), 'export const added = 1;\n');
  writeFileSync(join(c.workspaceDir, 'README.md'), '# edited by the agent\n');

  assert.equal(appContainer.evict('ev-keep', 'idle'), true);

  const bare = lg.repoPath('ev-keep');
  const branch = `refs/heads/agent/${uid}/${sid}`;
  assert.ok(refsIn(bare).includes(branch), `no preserve branch; refs are ${refsIn(bare).join(', ')}`);
  // Exactly the agent's two files. `.appcrane/` is AppCrane's own scaffolding,
  // written into every workspace by github/snapshot.js — it is not the user's
  // work and must not ride along.
  assert.deepEqual(treeOf(bare, branch), ['NEW.js', 'README.md']);
  assert.equal(blobIn(bare, branch, 'NEW.js'), 'export const added = 1;');
  assert.equal(blobIn(bare, branch, 'README.md'), '# edited by the agent');
  // The safety net is not a release: main must be exactly where it was.
  assert.equal(treeOf(bare, 'refs/heads/main').includes('NEW.js'), false, 'the preserve commit landed on main');
  // …and the workspace is still wiped.
  assert.equal(existsSync(c.workspaceDir), false, 'the workspace survived the evict');
});

test('the preserve branch is never main, master or the app deploy branch', async () => {
  const app = await craneApp('ev-branchname');
  const b = appContainer.agentPreserveBranch(7, 'abc-123');
  assert.equal(b, 'agent/7/abc-123');
  for (const bad of ['main', 'master', 'refs/heads/main', '', 'a b', '../evil', 'x;rm -rf /']) {
    assert.throws(() => appContainer.assertPreserveBranchSafe(bad, app),
      /refus/i, `accepted preserve branch ${JSON.stringify(bad)}`);
  }
  assert.throws(() => appContainer.agentPreserveBranch(1, 'a b'), /refus/i);
  assert.throws(() => appContainer.agentPreserveBranch('../x', 'y'), /refus/i);
  // And a deploy branch that is NOT 'main' is refused too.
  db.prepare("UPDATE apps SET branch = 'agent/7/abc-123' WHERE slug = 'ev-branchname'").run();
  const moved = db.prepare('SELECT * FROM apps WHERE slug = ?').get('ev-branchname');
  assert.throws(() => appContainer.assertPreserveBranchSafe('agent/7/abc-123', moved), /refus/i);
});

test('the preserve branch does not trigger a deploy', async () => {
  const app = await craneApp('ev-nodeploy');
  // Deploy-on-push ON for sandbox, watching 'main' — exactly the default.
  db.prepare(`INSERT INTO webhook_configs (app_id, token, secret, auto_deploy_sandbox, auto_deploy_prod, branch_filter)
              VALUES (?, 'tok-ev-nodeploy', 'sec', 1, 0, 'main')`).run(app.id);

  const c = await appContainer.getOrCreate(app);
  const uid = userRow();
  const sid = session(app, c, uid);
  writeFileSync(join(c.workspaceDir, 'unreleased.js'), 'not ready\n');

  const before = db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(app.id).n;
  appContainer.evict('ev-nodeploy', 'idle');
  const after = db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(app.id).n;
  assert.equal(after, before, 'the preserve commit started a deploy');

  // The assertion above only says no deploy row appeared. What actually keeps
  // it that way is the branch NAME, so the branch the evict really used is
  // discovered from the repo — the ref that now carries the rescued file — and
  // run through deployTrigger's own gate. Point this at main and it goes green
  // for the wrong reason no longer: evaluatePush returns 'deploy'.
  const bare = lg.repoPath('ev-nodeploy');
  const carrying = refsIn(bare).filter((r) => treeOf(bare, r).includes('unreleased.js'));
  assert.deepEqual(carrying, [`refs/heads/agent/${uid}/${sid}`], `unexpected refs carrying the rescued file: ${carrying.join(', ')}`);
  const landedOn = carrying[0].replace('refs/heads/', '');

  const config = pushConfigForApp(app.id);
  assert.equal(evaluatePush(config, 'main').action, 'deploy', 'the app is not actually deploy-on-push');
  assert.equal(evaluatePush(config, landedOn).action, 'skipped_branch',
    `a push to ${landedOn} WOULD deploy ${app.slug}`);
});

test('a second evict of the same session does not overwrite the first rescue', async () => {
  const app = await craneApp('ev-twice');
  const bare = lg.repoPath('ev-twice');
  const uid = userRow();

  const c1 = await appContainer.getOrCreate(app);
  const sid = session(app, c1, uid);
  writeFileSync(join(c1.workspaceDir, 'round1.js'), 'first\n');
  appContainer.evict('ev-twice', 'idle');

  // The session is resumed: a FRESH clone of main, so the second workspace
  // knows nothing of the first rescue and its commit is not a descendant of it.
  const c2 = await appContainer.getOrCreate(app);
  db.prepare('UPDATE coder_sessions SET workspace_dir = ? WHERE id = ?').run(c2.workspaceDir, sid);
  writeFileSync(join(c2.workspaceDir, 'round2.js'), 'second\n');
  appContainer.evict('ev-twice', 'idle');

  const first = `refs/heads/agent/${uid}/${sid}`;
  const rescues = refsIn(bare).filter((r) => r.startsWith(`refs/heads/agent/${uid}/`));
  assert.equal(rescues.length, 2, `expected both rescues to survive, got ${rescues.join(', ') || 'none'}`);
  assert.deepEqual(treeOf(bare, first), ['README.md', 'round1.js'], 'the first rescue was overwritten');
  const second = rescues.find((r) => r !== first);
  assert.deepEqual(treeOf(bare, second), ['README.md', 'round2.js']);
});

test('an evict with no changes commits nothing', async () => {
  const app = await craneApp('ev-clean');
  const c = await appContainer.getOrCreate(app);
  const uid = userRow();
  session(app, c, uid);

  const bare = lg.repoPath('ev-clean');
  const refsBefore = refsIn(bare);
  const mainBefore = bareGit(bare, ['rev-parse', 'refs/heads/main']);

  appContainer.evict('ev-clean', 'idle');

  assert.deepEqual(refsIn(bare), refsBefore, 'an empty workspace still produced a commit');
  assert.equal(bareGit(bare, ['rev-parse', 'refs/heads/main']), mainBefore);
});

test('an evict whose auto-commit fails still evicts and does not throw', async () => {
  const app = await craneApp('ev-broken');
  const c = await appContainer.getOrCreate(app);
  const uid = userRow();
  session(app, c, uid);
  writeFileSync(join(c.workspaceDir, 'work.js'), 'work\n');

  // The push target disappears between the clone and the evict.
  rmSync(lg.repoPath('ev-broken'), { recursive: true, force: true });

  let threw = null;
  let ret;
  try { ret = appContainer.evict('ev-broken', 'idle'); } catch (e) { threw = e; }
  assert.equal(threw, null, `evict threw: ${threw?.message}`);
  assert.equal(ret, true);
  assert.equal(existsSync(c.workspaceDir), false, 'a failed auto-commit left the workspace behind');
  assert.equal(appContainer.getContainer('ev-broken'), null, 'the container was not dropped from the registry');
});

test('a GitHub-backed app gets no container, so an evict has nothing to push', async () => {
  // Since v2.92.1 the container code refuses a GitHub-backed app outright
  // (the routes already did, since v2.83.0). The property this test guarded,
  // that an evict never pushes to a GitHub remote, now holds because there is
  // no workspace to evict.
  const { app, remote } = githubApp('ev-github');
  const refsBefore = refsIn(remote);
  await assert.rejects(appContainer.getOrCreate(app), /Crane-hosted apps only/);
  assert.equal(appContainer.evict('ev-github', 'idle'), false, 'an evict found a container that should not exist');
  assert.deepEqual(refsIn(remote), refsBefore, 'something was pushed to the GitHub-backed app');
});

test('a .env* change is left out of the preserve commit, and the rest is still saved', async () => {
  const app = await craneApp('ev-env');
  const c = await appContainer.getOrCreate(app);
  const uid = userRow();
  const sid = session(app, c, uid);

  writeFileSync(join(c.workspaceDir, '.env'), 'SECRET=hunter2\n');
  mkdirSync(join(c.workspaceDir, 'web'), { recursive: true });
  writeFileSync(join(c.workspaceDir, 'web/.env.local'), 'SECRET=hunter2\n');
  writeFileSync(join(c.workspaceDir, 'src.js'), 'const ok = 1;\n');

  appContainer.evict('ev-env', 'idle');

  const bare = lg.repoPath('ev-env');
  const branch = `refs/heads/agent/${uid}/${sid}`;
  assert.ok(refsIn(bare).includes(branch), 'the non-.env work was not preserved');
  const tree = treeOf(bare, branch);
  assert.ok(tree.includes('src.js'), 'the ordinary file was dropped along with the .env files');
  assert.equal(tree.includes('.env'), false, '.env was committed to the managed repo');
  assert.equal(tree.includes('web/.env.local'), false, 'web/.env.local was committed to the managed repo');
});

// ---------------------------------------------------------------------------
// 2. Transcript persistence
// ---------------------------------------------------------------------------

test('the transcript directory is mounted into the container and survives an evict', async () => {
  const app = await craneApp('ev-transcript');
  const c = await appContainer.getOrCreate(app);
  const dir = appContainer.transcriptDirFor('ev-transcript');

  assert.equal(existsSync(dir), true, 'no host transcript directory was created');
  const run = dockerRunArgs().filter((l) => l.includes('appcrane-app-ev-transcript'));
  assert.equal(run.length, 1, `expected one docker run for this app, got ${run.length}`);
  assert.ok(
    run[0].includes(`-v ${dir}:${appContainer.CONTAINER_CLAUDE_PROJECTS_DIR}`),
    `transcript dir not bind-mounted. docker run was:\n${run[0]}`,
  );
  assert.equal(appContainer.CONTAINER_CLAUDE_PROJECTS_DIR, '/home/studio/.claude/projects');

  // What the CLI would have written while the container was up.
  const projectDir = join(dir, '-workspace');
  mkdirSync(projectDir, { recursive: true });
  const transcript = join(projectDir, '11111111-1111-1111-1111-111111111111.jsonl');
  writeFileSync(transcript, '{"type":"user","sessionId":"11111111-1111-1111-1111-111111111111"}\n');

  appContainer.evict('ev-transcript', 'idle');

  assert.equal(existsSync(c.workspaceDir), false, 'the workspace survived');
  assert.equal(existsSync(transcript), true, 'the evict destroyed the conversation transcript');
  assert.match(readFileSync(transcript, 'utf8'), /11111111-1111-1111-1111-111111111111/);
});

test('the transcript directory gets the workspace treatment, not looser', async () => {
  const app = await craneApp('ev-perms');
  await appContainer.getOrCreate(app);
  const { statSync } = await import('fs');
  const dir = appContainer.transcriptDirFor('ev-perms');
  const mode = statSync(dir).mode & 0o777;
  const wsMode = statSync(join(ROOT, 'app-containers', 'ev-perms', 'workspace')).mode & 0o777;
  assert.equal(mode, wsMode, `transcript dir ${mode.toString(8)} != workspace ${wsMode.toString(8)}`);
  // Contained by the same per-app parent as the workspace, under DATA_DIR.
  assert.equal(dir.startsWith(join(ROOT, 'app-containers', 'ev-perms') + '/'), true, dir);
  appContainer.evict('ev-perms', 'idle');
});

// ---------------------------------------------------------------------------
// 3. Transcript persistence across an AppCrane RESTART
// ---------------------------------------------------------------------------
//
// recoverOrphans() runs once on boot and clears the on-disk workspaces, because
// nothing is cached across a restart. It used to wipe the whole app-containers
// root, which took every app's `claude-projects` with it: the transcript
// survived a 30-minute idle eviction (section 2 above) and then died silently at
// the next `systemctl restart appcrane`, while coder_sessions.claude_session_id
// still pointed at it — so `claude -p --resume <id>` failed on an id the
// database swore existed.
//
// MUST BE LAST IN THIS FILE: recoverOrphans reaches across every app under the
// root, not just its own.

test('an AppCrane restart clears workspaces but keeps every app transcript', async () => {
  const a = await craneApp('ev-restart-a');
  const b = await craneApp('ev-restart-b');
  const ca = await appContainer.getOrCreate(a);
  const cb = await appContainer.getOrCreate(b);

  // What the CLI wrote into the bind-mounted transcript dir of each app.
  const transcripts = [ca, cb].map((c, i) => {
    const slug = i === 0 ? 'ev-restart-a' : 'ev-restart-b';
    const dir = join(appContainer.transcriptDirFor(slug), '-workspace');
    mkdirSync(dir, { recursive: true });
    const f = join(dir, `2222222${i}-2222-2222-2222-22222222222${i}.jsonl`);
    writeFileSync(f, `{"type":"user","sessionId":"transcript-${slug}"}\n`);
    return { slug, file: f, workspace: c.workspaceDir };
  });

  // A non-transcript sibling under the same per-app directory, to prove the
  // sweep still removes everything it is supposed to.
  const stray = join(ROOT, 'app-containers', 'ev-restart-a', 'stale-scratch');
  mkdirSync(stray, { recursive: true });
  writeFileSync(join(stray, 'junk.txt'), 'left over from the last process\n');

  for (const t of transcripts) assert.equal(existsSync(t.workspace), true, `${t.slug} has no workspace to clear`);

  appContainer.recoverOrphans();

  for (const t of transcripts) {
    assert.equal(existsSync(t.workspace), false, `${t.slug}: the workspace survived the restart sweep`);
    assert.equal(existsSync(t.file), true, `${t.slug}: the restart sweep destroyed the conversation transcript`);
    assert.match(readFileSync(t.file, 'utf8'), new RegExp(`transcript-${t.slug}`));
  }
  assert.equal(existsSync(stray), false, 'the restart sweep stopped clearing non-transcript state');
});
