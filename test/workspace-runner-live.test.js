import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * Against REAL Docker and the real appcrane-studio image: workspace git runs
 * in a container, and a .git/config swapped mid-flight can no longer make the
 * HOST run a command.
 *
 * The race, reproduced: a container mounting the workspace loops, putting a
 * clean config in place for an instant and then one whose
 * `filter.evil.clean` touches a path that exists ONLY on the host (plus a
 * marker inside the workspace), with `* filter=evil` in .gitattributes. Run
 * against v2.103.1's check-then-host-git, that loop got the host marker
 * created within 4–40 iterations in every one of six runs (see the v2.103.2
 * notes in README.md). Here AppCrane's change list, rescue git and exec git run
 * in that loop many times; the host marker must never appear. The in-workspace
 * marker is what proves the loop was live and the planted command really ran —
 * inside the sandbox, as the agent.
 *
 * Skipped without Docker or without the studio image (CI builds neither).
 */

let DOCKER = false;
try {
  execFileSync('docker', ['image', 'inspect', 'appcrane-studio:latest'], { stdio: 'pipe', timeout: 15000 });
  DOCKER = true;
} catch (_) {}
const skip = DOCKER ? false : 'docker or the appcrane-studio image is unavailable';

const ROOT = mkdtempSync(join(tmpdir(), 'crane-wslive-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const CONTAINERS = [];
after(async () => {
  for (const n of CONTAINERS) { try { execFileSync('docker', ['rm', '-f', n], { stdio: 'pipe' }); } catch (_) {} }
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const hostGit = (ws, ...a) => execFileSync('git', ['-C', ws, '-c', 'core.hooksPath=/dev/null', ...a], { env: CLEAN, stdio: 'pipe' }).toString('utf8').trim();

test('helper confinement, measured inside the helper', { skip }, async () => {
  const { runInWorkspace } = await import('../server/services/builder/workspaceRunner.js');
  const ws = join(ROOT, 'confine');
  mkdirSync(ws, { recursive: true });
  const out = runInWorkspace(ws, ['sh', '-c',
    'id -u; grep CapEff /proc/self/status; wc -l < /proc/net/route; touch /etc/x 2>/dev/null && echo rootfs-writable || echo rootfs-ro; ls /'], { input: null }).toString('utf8');
  const [uid, capEff, routes, rootfs] = out.split('\n');
  assert.equal(uid, '100', 'helper is not the studio uid');
  assert.match(capEff, /CapEff:\s+0+$/, 'helper kept a capability');
  // Header line only: no route anywhere (a default-network container has 3 lines).
  assert.equal(routes.trim(), '1', `helper has a network route: ${routes}`);
  assert.equal(rootfs, 'rootfs-ro');
});

test('a config swapped mid-flight never runs a command on the host', { skip, timeout: 300000 }, async () => {
  const { listWorkspaceChanges } = await import('../server/services/builder/gitOps.js');
  const { gitIn } = await import('../server/services/builder/appContainer.js');
  const { runWorkspaceGit, runInWorkspace, WORKSPACE_GIT_ARGS } = await import('../server/services/builder/workspaceRunner.js');

  const ws = join(ROOT, 'race');
  const hostOnly = join(ROOT, 'host-only');
  mkdirSync(ws, { recursive: true });
  mkdirSync(hostOnly, { recursive: true });
  const HOST_MARKER = join(hostOnly, 'host-marker');
  const INSIDE_MARKER = join(ws, '.git', 'inside-marker');
  execFileSync('git', ['init', '-q', '-b', 'main', ws], { env: CLEAN });
  hostGit(ws, 'config', 'user.email', 'builder@appcrane.local');
  hostGit(ws, 'config', 'user.name', 'AppCrane Builder');
  writeFileSync(join(ws, 'a.txt'), 'one\n');
  hostGit(ws, 'add', 'a.txt');
  hostGit(ws, 'commit', '-q', '-m', 'init');
  writeFileSync(join(ws, '.gitattributes'), '* filter=evil\n');
  const clean = readFileSync(join(ws, '.git', 'config'), 'utf8');
  writeFileSync(join(ws, '.git', 'clean.cfg'), clean);
  // Quoted: an unquoted `;` starts a comment in git config.
  writeFileSync(join(ws, '.git', 'evil.cfg'),
    `${clean}[filter "evil"]\n\tclean = "touch ${HOST_MARKER}; touch /workspace/.git/inside-marker; cat"\n`);
  execFileSync('chmod', ['-R', '777', ws]);

  const name = `appcrane-wslive-race-${process.pid}`;
  CONTAINERS.push(name);
  execFileSync('docker', ['run', '-d', '--rm', '--name', name, '-v', `${ws}:/workspace`, 'appcrane-studio:latest', 'sh', '-c',
    'cd /workspace/.git && while :; do cp clean.cfg c1; cp evil.cfg e1; mv c1 config; mv e1 config; sleep 0.01; done'], { stdio: 'pipe' });

  const calls = [
    () => listWorkspaceChanges(ws),                                                         // helper (no live record)
    () => gitIn(ws, ['add', '-A']),                                                         // helper (the rescue path)
    () => runWorkspaceGit(ws, ['diff', '--no-ext-diff', 'HEAD', '--', 'a.txt'], { container: name }), // exec into the agent's container
    // The allowlist skipped entirely: a race "won" on every call.
    () => runInWorkspace(ws, ['git', ...WORKSPACE_GIT_ARGS, 'add', '-A']),
    () => runInWorkspace(ws, ['git', ...WORKSPACE_GIT_ARGS, 'diff', '--no-ext-diff', 'HEAD', '--', 'a.txt'], { container: name }),
  ];
  let attempts = 0;
  for (let i = 0; i < 80; i++) {
    for (const c of calls) {
      // stat-dirty every time, so each status/diff/add must clean the file again
      writeFileSync(join(ws, 'a.txt'), `two ${i} ${Math.random()}\n`);
      try { c(); } catch (_) {}
      attempts++;
      assert.equal(existsSync(HOST_MARKER), false, `the planted filter ran ON THE HOST after ${attempts} workspace git call(s)`);
    }
  }
  assert.ok(existsSync(INSIDE_MARKER), 'the planted filter never ran at all, so this proves nothing about where it runs');
});

test('end to end: real coder container, change list by exec, eviction rescue via helper + bundle', { skip, timeout: 300000 }, async () => {
  const { initDb, getDb } = await import('../server/db.js');
  initDb();
  const db = getDb();
  const { getNextSlot } = await import('../server/services/portAllocator.js');
  const lg = await import('../server/services/localGit.js');
  const appContainer = await import('../server/services/builder/appContainer.js');
  const { listWorkspaceChanges, markReleasedInWorkspace } = await import('../server/services/builder/gitOps.js');

  const slug = `wslive-${process.pid}`;
  await lg.createAppRepo(slug);
  await lg.pushFilesToManagedRepo(slug, [{ path: 'README.md', content: '# hi\n' }], { message: 'seed' });
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES (?,?,?, 'managed', 'local', 'main')")
    .run(slug, slug, getNextSlot(db));
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('l','l@example.com','platform_admin','l-hash',1,'human')").run().lastInsertRowid;

  CONTAINERS.push(`appcrane-app-${slug}`);
  const c = await appContainer.getOrCreate(app, () => {});
  db.prepare(`INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status, container_id, workspace_dir)
              VALUES ('live-sess', ?, ?, ?, 'idle', ?, ?)`).run(slug, uid, c.branchName, c.containerId, c.workspaceDir);
  assert.equal(appContainer.liveContainerNameFor(c.workspaceDir), `appcrane-app-${slug}`);

  // The agent writes files as itself, inside its container.
  execFileSync('docker', ['exec', `appcrane-app-${slug}`, 'sh', '-c',
    'cd /workspace && echo released > rel.txt && echo kept > kept.txt && echo changed >> README.md'], { stdio: 'pipe' });
  const changes = listWorkspaceChanges(c.workspaceDir);
  assert.deepEqual(changes.map((x) => [x.path, x.status]), [['README.md', 'modified'], ['kept.txt', 'added'], ['rel.txt', 'added']]);
  assert.match(changes[0].diff, /\+changed/);
  assert.equal(markReleasedInWorkspace(c.workspaceDir, ['rel.txt'], 'release rel'), true);
  assert.deepEqual(listWorkspaceChanges(c.workspaceDir).map((x) => x.path), ['README.md', 'kept.txt']);

  appContainer.evict(slug, 'test');
  const bare = lg.repoPath(slug);
  const refs = execFileSync('git', [`--git-dir=${bare}`, 'for-each-ref', '--format=%(refname)'], { env: CLEAN }).toString('utf8');
  assert.match(refs, /refs\/heads\/agent\/\d+\/live-sess/);
  const tree = execFileSync('git', [`--git-dir=${bare}`, 'ls-tree', '-r', '--name-only', `agent/${uid}/live-sess`], { env: CLEAN }).toString('utf8').split('\n').filter(Boolean).sort();
  assert.deepEqual(tree, ['README.md', 'kept.txt', 'rel.txt']);
  const main = execFileSync('git', [`--git-dir=${bare}`, 'ls-tree', '-r', '--name-only', 'main'], { env: CLEAN }).toString('utf8').trim();
  assert.equal(main, 'README.md', 'the rescue moved main');
});
