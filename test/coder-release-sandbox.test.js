import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, unlinkSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Phase 4a: a Builder session on a Crane-hosted app RELEASES selected changes
// to sandbox THROUGH the managed repository.
//
// /ship (GitHub apps) pushes a branch and then deploys from the workspace, so
// what runs and what the repository holds can differ. For a Crane-hosted app
// there is no remote at all, so the release path reads the chosen files out of
// the workspace, commits them with managedRepo.pushFilesToManagedRepo, and lets
// deploy-on-push start the sandbox build. Nothing here writes a deployments row
// or calls deployApp, and the tests below check that by reading the columns the
// push path writes (the commit pin and message triggerAutoDeploys records, plus
// its webhook_deliveries row) rather than the bare row /ship writes.
//
// Real git and the real bare repo throughout: every claim about what landed is
// read back with an INDEPENDENT `git --git-dir=`, never through the module under
// test. docker is a shim that plays the Builder container and FAILS everything
// else — `docker version` included — so a triggered deploy dies at
// dockerAvailable() instead of building anything.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-coderrel-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-coder-release';
process.env.GIT_TERMINAL_PROMPT = '0';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const REAL_FETCH = globalThis.fetch.bind(globalThis);
const REAL_GIT = execFileSync('which', ['git']).toString().trim();

// --- shims -------------------------------------------------------------------
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  image)   echo 3; exit 0 ;;
  inspect) echo true; exit 0 ;;
  run)     echo 0123456789abcdef0123456789abcdef; exit 0 ;;
  rm)      exit 0 ;;
esac
echo "docker shim: refusing '$1'" >&2
exit 1
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const lg = await import('../server/services/localGit.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const appContainer = await import('../server/services/builder/appContainer.js');
const coderRoutes = (await import('../server/routes/coder.js')).default;

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

// --- independent git readers -------------------------------------------------
const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const bare = (slug, args) =>
  execFileSync(REAL_GIT, [`--git-dir=${lg.repoPath(slug)}`, ...args], { env: CLEAN });
const bareText = (slug, args) => bare(slug, args).toString('utf8').trim();
const tipOf = (slug) => bareText(slug, ['rev-parse', 'refs/heads/main']);
const treeOf = (slug, ref = 'refs/heads/main') =>
  bareText(slug, ['ls-tree', '-r', '--name-only', ref]).split('\n').filter(Boolean).sort();
const blobOf = (slug, path, ref = 'refs/heads/main') => bare(slug, ['show', `${ref}:${path}`]);

// --- fixtures ----------------------------------------------------------------
const ADMIN_KEY = 'coderrel-admin-key';
const MEMBER_KEY = 'coderrel-member-key';
const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('adm','adm@x.test','platform_admin',?,1,'human')",
).run(hashApiKey(ADMIN_KEY)).lastInsertRowid;
const memberId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('mem','mem@x.test','user',?,1,'human')",
).run(hashApiKey(MEMBER_KEY)).lastInsertRowid;

let slot = 910;
function insertApp(cols) {
  const keys = Object.keys(cols);
  const id = db.prepare(
    `INSERT INTO apps (name,slot,${keys.join(',')}) VALUES (?,?,${keys.map(() => '?').join(',')})`,
  ).run(cols.slug, slot++, ...keys.map((k) => cols[k])).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

const BIN = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe, 0x01, 0x00, 0x80]);

async function craneApp(slug, { autoDeploy = false } = {}) {
  await lg.createAppRepo(slug, { description: 'phase 4a' });
  await lg.pushFilesToManagedRepo(slug, [
    { path: 'src/keep.js', content: 'export const keep = 1;\n' },
    { path: 'src/gone.js', content: 'export const gone = 1;\n' },
    { path: 'assets/logo.png', content: BIN.toString('base64'), encoding: 'base64' },
  ], { message: 'seed' });
  const app = insertApp({ slug, source_type: 'managed', repo_backend: 'local', github_url: null, branch: 'main' });
  if (autoDeploy) {
    db.prepare(
      "INSERT INTO webhook_configs (app_id, token, secret, auto_deploy_sandbox, auto_deploy_prod, branch_filter) VALUES (?,?,?,1,0,'main')",
    ).run(app.id, `tok-${slug}`, `sec-${slug}`);
  }
  return app;
}

const CRANE = 'cranerel';
const DEPLOYING = 'cranedeploy';
const craneAppRow = await craneApp(CRANE);
const deployAppRow = await craneApp(DEPLOYING, { autoDeploy: true });

// The member can chat (app_users assignment) but holds no app-admin role.
db.prepare('INSERT INTO app_users (app_id, user_id) VALUES (?, ?)').run(craneAppRow.id, memberId);

// A GitHub-backed app whose "remote" is a bare repo on disk. It used to get a
// session and ship to that remote; the coder is Crane-hosted-only now, so what
// it gets is a refusal — and the bare repo below is what proves nothing was
// pushed to it anyway.
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
const ghAppRow = insertApp({ slug: 'ghrel', source_type: 'github', github_url: GH_BARE, branch: 'main' });

// --- http --------------------------------------------------------------------
const api = express();
api.use(express.json());
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = api.listen(0);
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => server.close());

const call = (method, path, body, key = ADMIN_KEY) => REAL_FETCH(`${BASE}${path}`, {
  method,
  headers: { 'X-API-Key': key, 'Content-Type': 'application/json' },
  ...(body ? { body: JSON.stringify(body) } : {}),
});
const json = async (r) => ({ status: r.status, body: await r.json() });

async function startSession(slug) {
  const r = await call('POST', `/api/coder/${slug}/session`);
  const body = await r.json();
  assert.equal(r.status, 201, `session start failed: ${r.status} ${JSON.stringify(body)}`);
  return db.prepare('SELECT * FROM coder_sessions WHERE app_slug = ? ORDER BY created_at DESC LIMIT 1').get(slug);
}

const sessions = {};
const workspaces = {};
// 'ghrel' is deliberately absent: the coder is Crane-hosted-only, so a
// GitHub-backed app cannot open a session at all. That refusal is what the
// last test in this file asserts.
for (const slug of [CRANE, DEPLOYING]) {
  sessions[slug] = await startSession(slug);
  workspaces[slug] = sessions[slug].workspace_dir;
  assert.ok(workspaces[slug], `no workspace_dir for ${slug}`);
}

const ws = (slug, ...p) => join(workspaces[slug], ...p);
const changes = async (slug) => (await (await call('GET', `/api/coder/${slug}/session/${sessions[slug].id}/changes`)).json()).files;
const release = (slug, body, key = ADMIN_KEY) =>
  call('POST', `/api/coder/${slug}/session/${sessions[slug].id}/release`, body, key);

// The agent's work: one modification, one new file, one deletion, one binary.
writeFileSync(ws(CRANE, 'src', 'keep.js'), 'export const keep = 2;\n');
writeFileSync(ws(CRANE, 'NEW.txt'), 'brand new file\n');
unlinkSync(ws(CRANE, 'src', 'gone.js'));
writeFileSync(ws(CRANE, 'assets', 'logo.png'), Buffer.concat([BIN, Buffer.from([0x00, 0xc3, 0x28])]));
symlinkSync('/etc/hosts', ws(CRANE, 'linked.conf'));

// =============================================================================

test('changes: modification, untracked add and deletion, with AppCrane scratch excluded', async () => {
  mkdirSync(ws(CRANE, '.appcrane'), { recursive: true });
  writeFileSync(ws(CRANE, '.appcrane', 'github-snapshot.md'), '# platform scratch\n');

  const files = await changes(CRANE);
  const byPath = Object.fromEntries(files.map((f) => [f.path, f]));

  assert.equal(byPath['src/keep.js']?.status, 'modified', JSON.stringify(files));
  assert.equal(byPath['NEW.txt']?.status, 'added', 'an untracked file is missing from the change set');
  assert.equal(byPath['src/gone.js']?.status, 'deleted', 'a deleted file is missing from the change set');
  assert.equal(byPath['assets/logo.png']?.status, 'modified');

  assert.match(byPath['src/keep.js'].diff, /-export const keep = 1;/);
  assert.match(byPath['src/keep.js'].diff, /\+export const keep = 2;/);
  assert.match(byPath['NEW.txt'].diff, /\+brand new file/, 'an untracked file got no diff');

  assert.ok(!files.some((f) => f.path.startsWith('.appcrane/')),
    `AppCrane's own workspace scratch is offered as a change: ${JSON.stringify(files.map((f) => f.path))}`);
  assert.ok(existsSync(ws(CRANE, '.appcrane', 'github-snapshot.md')), 'fixture is wrong: the scratch file is not there');
  assert.ok(!files.some((f) => f.path === 'linked.conf'), 'a symlink is offered as a releasable change');
});

test('release: only the selected subset reaches the managed repository', async () => {
  const before = tipOf(CRANE);
  const { status, body } = await json(await release(CRANE, { paths: ['NEW.txt'], message: 'add the new file' }));

  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual(body.released, ['NEW.txt']);
  assert.deepEqual(body.deleted, []);
  assert.equal(body.commit.sha, tipOf(CRANE), 'the reported commit is not the branch tip');
  assert.equal(bareText(CRANE, ['rev-parse', `${body.commit.sha}^`]), before, 'not one commit on the previous tip');

  assert.deepEqual(treeOf(CRANE), ['NEW.txt', 'README.md', 'assets/logo.png', 'src/gone.js', 'src/keep.js']);
  assert.equal(blobOf(CRANE, 'NEW.txt').toString('utf8'), 'brand new file\n');
  // The other three changes were NOT selected and must be untouched in the repo.
  assert.equal(blobOf(CRANE, 'src/keep.js').toString('utf8'), 'export const keep = 1;\n',
    'an unselected modification was released');
  assert.ok(Buffer.compare(blobOf(CRANE, 'assets/logo.png'), BIN) === 0, 'an unselected binary was released');
  assert.equal(bareText(CRANE, ['log', '-1', '--format=%B', body.commit.sha]), 'coder: add the new file');

  // Released paths stop being offered; everything else still is.
  const after = (await changes(CRANE)).map((f) => f.path);
  assert.ok(!after.includes('NEW.txt'), `a released path is still listed as changed: ${JSON.stringify(after)}`);
  assert.ok(after.includes('src/keep.js') && after.includes('src/gone.js'));
});

test('release: a selected deletion removes the path from the repository tree', async () => {
  const before = tipOf(CRANE);
  const { status, body } = await json(await release(CRANE, { paths: ['src/gone.js'], message: 'drop gone' }));

  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual(body.deleted, ['src/gone.js'], 'a deleted file was not released as a deletion');
  assert.deepEqual(body.released, [], 'a deletion was also written as a file');

  const tree = treeOf(CRANE);
  assert.ok(!tree.includes('src/gone.js'), `git ls-tree still lists the deleted path: ${JSON.stringify(tree)}`);
  assert.deepEqual(tree, ['NEW.txt', 'README.md', 'assets/logo.png', 'src/keep.js']);
  assert.equal(bareText(CRANE, ['rev-parse', `${body.commit.sha}^`]), before, 'a deletion is not one commit');
  // The parent still has it: a deletion is a new commit, not a rewrite.
  assert.ok(treeOf(CRANE, before).includes('src/gone.js'));
});

test('release: a binary change is committed byte for byte', async () => {
  const onDisk = readFileSync(ws(CRANE, 'assets', 'logo.png'));
  const { status, body } = await json(await release(CRANE, { paths: ['assets/logo.png'], message: 'new logo' }));
  assert.equal(status, 200, JSON.stringify(body));

  const committed = blobOf(CRANE, 'assets/logo.png');
  assert.equal(Buffer.compare(committed, onDisk), 0,
    `binary corrupted on release: ${committed.toString('hex')} != ${onDisk.toString('hex')}`);
  assert.ok(committed.includes(0xff) && committed.includes(0x00), 'the fixture stopped being binary');
});

test('release: a path outside the change set is refused and nothing is committed', async () => {
  const tip = tipOf(CRANE);
  for (const p of [['README.md'], ['src/keep.js', 'does/not/exist.js'], ['linked.conf'], ['.appcrane/github-snapshot.md']]) {
    const { status, body } = await json(await release(CRANE, { paths: p }));
    assert.equal(status, 400, `${JSON.stringify(p)} was accepted: ${JSON.stringify(body)}`);
    assert.equal(body.error.code, 'NOT_CHANGED', body.error.message);
    assert.match(body.error.message, /Nothing was released/);
  }
  const empty = await json(await release(CRANE, { paths: [] }));
  assert.equal(empty.status, 400);
  assert.equal(empty.body.error.code, 'VALIDATION');
  assert.equal(tipOf(CRANE), tip, 'a refused release still committed');
});

test('release: a chat-capable user who is not an app admin is refused', async () => {
  const tip = tipOf(CRANE);
  // The member can read the session — the bar for releasing is higher.
  const seen = await call('GET', `/api/coder/${CRANE}/session/${sessions[CRANE].id}/changes`, null, MEMBER_KEY);
  assert.equal(seen.status, 200, 'fixture is wrong: the member cannot reach this app at all');

  const { status, body } = await json(await release(CRANE, { paths: ['src/keep.js'] }, MEMBER_KEY));
  assert.equal(status, 403, `a non-app-admin released: ${JSON.stringify(body)}`);
  assert.equal(body.error.code, 'FORBIDDEN');
  assert.equal(tipOf(CRANE), tip, 'a refused release still committed');

  // Promoted to app-admin, the same call goes through: the gate is the role,
  // not "platform admin only".
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'admin')").run(craneAppRow.id, memberId);
  const ok = await json(await release(CRANE, { paths: ['src/keep.js'] }, MEMBER_KEY));
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(blobOf(CRANE, 'src/keep.js').toString('utf8'), 'export const keep = 2;\n');
});

test('release: a .env change surfaces the push guard, not a 500', async () => {
  writeFileSync(ws(CRANE, '.env'), 'SECRET=hunter2\n');
  const listed = (await changes(CRANE)).map((f) => f.path);
  assert.ok(listed.includes('.env'), 'fixture is wrong: .env is not in the change set');

  const tip = tipOf(CRANE);
  const { status, body } = await json(await release(CRANE, { paths: ['.env'] }));
  assert.equal(status, 422, `expected the guard's 422, got ${status}: ${JSON.stringify(body)}`);
  assert.equal(body.error.code, 'ENV_FILE_IN_PUSH');
  assert.match(body.error.message, /Nothing was committed/);
  assert.ok(!body.error.message.includes('hunter2'), 'the refusal echoed the secret');
  assert.equal(tipOf(CRANE), tip);
  assert.ok(!treeOf(CRANE).includes('.env'));
  unlinkSync(ws(CRANE, '.env'));
});

test('release: refused while the session is running', async () => {
  const tip = tipOf(CRANE);
  db.prepare("UPDATE coder_sessions SET status = 'active' WHERE id = ?").run(sessions[CRANE].id);
  try {
    writeFileSync(ws(CRANE, 'MIDRUN.txt'), 'x\n');
    const { status, body } = await json(await release(CRANE, { paths: ['MIDRUN.txt'] }));
    assert.equal(status, 400, `a running session released: ${JSON.stringify(body)}`);
    assert.equal(body.error.code, 'WRONG_STATUS');
    assert.equal(tipOf(CRANE), tip);
  } finally {
    db.prepare("UPDATE coder_sessions SET status = 'idle' WHERE id = ?").run(sessions[CRANE].id);
    unlinkSync(ws(CRANE, 'MIDRUN.txt'));
  }
});

test('release: a file over the per-file limit is refused, not read into memory', async () => {
  const { MAX_RELEASE_FILE_BYTES } = await import('../server/services/builder/gitOps.js');
  const tip = tipOf(CRANE);
  writeFileSync(ws(CRANE, 'huge.bin'), Buffer.alloc(MAX_RELEASE_FILE_BYTES + 1, 0));
  try {
    const { status, body } = await json(await release(CRANE, { paths: ['huge.bin'] }));
    assert.equal(status, 400, JSON.stringify(body));
    assert.equal(body.error.code, 'UNREADABLE_CHANGE');
    assert.match(body.error.message, /Nothing was released/);
    assert.equal(tipOf(CRANE), tip);
  } finally {
    unlinkSync(ws(CRANE, 'huge.bin'));
  }
});

test('release: the sandbox deploy comes from the push, not from a direct deployApp call', async () => {
  writeFileSync(ws(DEPLOYING, 'src', 'keep.js'), 'export const keep = 99;\n');
  const { status, body } = await json(await release(DEPLOYING, { paths: ['src/keep.js'], message: 'bump keep' }));
  assert.equal(status, 200, JSON.stringify(body));

  assert.equal(body.deploy?.action, 'deploy_triggered', `no deploy was triggered: ${JSON.stringify(body.deploy)}`);
  assert.equal(body.deploy.branch, 'main');
  assert.equal(body.deploy.commit, body.commit.sha.slice(0, 8));
  assert.equal(body.deploy.triggered.length, 1, JSON.stringify(body.deploy.triggered));
  assert.equal(body.deploy.triggered[0].env, 'sandbox');

  const rows = db.prepare('SELECT * FROM deployments WHERE app_id = ? ORDER BY id').all(deployAppRow.id);
  assert.equal(rows.length, 1, `expected exactly one deployment row, got ${rows.length}`);
  const row = rows[0];
  assert.equal(row.id, body.deploy.triggered[0].deployment_id);
  assert.equal(row.env, 'sandbox');
  // The commit pin and message triggerAutoDeploys writes. /ship's row carries
  // neither (it deploys a directory, not a commit), so these two columns are
  // what separates the push path from a direct deployApp call. `log` is not
  // checked: the async deployApp this triggers overwrites it with build output.
  assert.equal(row.commit_hash, body.commit.sha.slice(0, 8), 'the deploy is not pinned to the pushed commit');
  assert.equal(row.commit_message, 'coder: bump keep');

  // deploy-on-push records the push as a delivery; a workspace deploy does not.
  const delivery = db.prepare(
    "SELECT * FROM webhook_deliveries WHERE app_id = ? AND event = 'managed-push' ORDER BY id DESC LIMIT 1",
  ).get(deployAppRow.id);
  assert.equal(delivery?.action_taken, 'deploy_triggered');
  assert.equal(delivery.deploy_id, row.id);

  // The session is not marked shipped: a release is a selection, and the rest
  // of the change set must stay releasable.
  const s = db.prepare('SELECT status FROM coder_sessions WHERE id = ?').get(sessions[DEPLOYING].id);
  assert.equal(s.status, 'idle');
});

test('a GitHub-backed app gets no coder session at all, and its remote is untouched', async () => {
  const gh = 'ghrel';

  // The gate, before anything is built. NOT_CRANE_HOSTED rather than NO_REPO:
  // this app has source, it is simply not somewhere the coder works.
  const { status, body } = await json(await call('POST', `/api/coder/${gh}/session`));
  assert.equal(status, 400, `a GitHub-backed app was served a coder session: ${JSON.stringify(body)}`);
  assert.equal(body.error.code, 'NOT_CRANE_HOSTED', JSON.stringify(body.error));

  // Nothing downstream ran: no session row, no workspace, no deploy.
  assert.equal(db.prepare('SELECT COUNT(*) n FROM coder_sessions WHERE app_slug = ?').get(gh).n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM deployments WHERE app_id = ?').get(ghAppRow.id).n, 0);

  // …and the "GitHub remote" still has exactly the seed branch. The coder's own
  // ship route is gone (/api/coder no longer mounts one), so there is no longer
  // a path from this router to a `git push`.
  const refs = execFileSync(REAL_GIT, [`--git-dir=${GH_BARE}`, 'for-each-ref', '--format=%(refname)'], { env: CLEAN })
    .toString('utf8').split('\n').filter(Boolean);
  assert.deepEqual(refs, ['refs/heads/main'], `the coder pushed to a GitHub remote: ${refs.join(', ')}`);

  const ship = await call('POST', `/api/coder/${gh}/session/whatever/ship`, { message: 'gh ship' });
  assert.equal(ship.status, 404, `the GitHub ship route is still mounted on /api/coder (got ${ship.status})`);
});

after(() => {
  for (const slug of [CRANE, DEPLOYING]) {
    try { appContainer.evict(slug, 'test'); } catch (_) {}
  }
});
