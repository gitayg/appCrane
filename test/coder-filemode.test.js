import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * appContainer.cloneWorkspace runs `chmod -R 777` over a fresh workspace so the
 * container user can write in it. That sets the executable bit on every tracked
 * file, and git's default core.fileMode then calls the ENTIRE tree modified.
 * Measured on a real clone before any agent has touched it:
 *
 *     $ git status --porcelain=v1
 *      M README.md
 *      M src/a.js
 *     $ git -c core.fileMode=false status --porcelain=v1
 *     (clean)
 *
 * Uncorrected, that makes every reader of worktree state report the whole
 * repository: the change list a user picks from becomes every file in the repo,
 * and an eviction's rescue commit carries a mode flip for the whole tree.
 *
 * This file proves the correction two ways: at runtime, from the argv of every
 * git the remaining reader actually ran, and statically, so a git wrapper added
 * later to one of these four files cannot quietly read status with the default
 * fileMode again.
 *
 * The two ship cases that used to live here (the commit that lands in the
 * remote, and the scaffolding-only no-op) went with gitOps.commitAndPush in
 * v2.83.0 — it existed for POST /api/agents/:id/ship-sandbox, and /api/agents
 * is gone. Nothing in the repo pushes a builder workspace to GitHub now.
 */

const ROOT = mkdtempSync(join(tmpdir(), 'crane-filemode-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const REAL_GIT = execFileSync('which', ['git']).toString().trim();

// ── shims: docker plays the container, git records argv then execs real git ──
const BIN = join(ROOT, 'bin');
const GIT_LOG = join(ROOT, 'git-argv.log');
mkdirSync(BIN, { recursive: true });
writeFileSync(GIT_LOG, '');
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
case "$1" in
  run)     echo c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ff ;;
  image)   echo 3 ;;
  inspect) echo true ;;
esac
exit 0
`, { mode: 0o755 });
writeFileSync(join(BIN, 'git'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${GIT_LOG}"
exec "${REAL_GIT}" "$@"
`, { mode: 0o755 });
chmodSync(join(BIN, 'docker'), 0o755);
chmodSync(join(BIN, 'git'), 0o755);
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getNextSlot } = await import('../server/services/portAllocator.js');
const appContainer = await import('../server/services/builder/appContainer.js');
const { listWorkspaceChanges } = await import('../server/services/builder/gitOps.js');

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };

/**
 * A GitHub-backed app whose "GitHub" remote is a bare repo on disk. Seeded with
 * two tracked files that the agent will NOT touch — they are what a mode-only
 * diff would drag into the change list.
 */
const SLUG = 'fm-github';
const REMOTE = join(ROOT, `${SLUG}-remote.git`);
{
  execFileSync(REAL_GIT, ['init', '--bare', '-b', 'main', '-q', REMOTE], { env: CLEAN });
  const seed = join(ROOT, `${SLUG}-seed`);
  execFileSync(REAL_GIT, ['init', '-q', '-b', 'main', seed], { env: CLEAN });
  writeFileSync(join(seed, 'README.md'), '# untouched\n');
  mkdirSync(join(seed, 'src'), { recursive: true });
  writeFileSync(join(seed, 'src', 'a.js'), 'export const a = 1;\n');
  execFileSync(REAL_GIT, ['-C', seed, 'add', '.'], { env: CLEAN });
  execFileSync(REAL_GIT, ['-C', seed, '-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '-m', 'seed'], { env: CLEAN });
  execFileSync(REAL_GIT, ['-C', seed, 'push', '-q', REMOTE, 'main'], { env: CLEAN });
}
db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch, github_url) VALUES (?,?,?, 'github', NULL, 'main', ?)")
  .run(SLUG, SLUG, getNextSlot(db), REMOTE);
const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(SLUG);

const uid = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('fm','fm@example.com','platform_admin','fm-hash',1,'human')"
).run().lastInsertRowid;

// =============================================================================

test('the chmod -R 777 workspace really does look wholly modified to a default git', async () => {
  const c = await appContainer.getOrCreate(app, () => {});
  // The premise of the whole fix, measured rather than assumed: with git's
  // default fileMode this untouched clone is already "modified" everywhere.
  const dirty = execFileSync(REAL_GIT, ['-C', c.workspaceDir, 'status', '--porcelain=v1', '--untracked-files=no'], { env: CLEAN })
    .toString('utf8').split('\n').filter(Boolean);
  assert.ok(
    dirty.length >= 2,
    `the fileMode premise no longer holds on this host — an untouched workspace read clean: ${JSON.stringify(dirty)}`,
  );
  const clean = execFileSync(REAL_GIT, ['-C', c.workspaceDir, '-c', 'core.fileMode=false', 'status', '--porcelain=v1', '--untracked-files=no'], { env: CLEAN })
    .toString('utf8').trim();
  assert.equal(clean, '', `core.fileMode=false did not neutralise it: ${clean}`);
});

test('every git status/diff run against the workspace carried core.fileMode=false', async () => {
  const c = await appContainer.getOrCreate(app, () => {});
  db.prepare(`INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status, container_id, workspace_dir)
              VALUES ('fm-sess', ?, ?, ?, 'idle', ?, ?)`)
    .run(SLUG, uid, c.branchName, c.containerId, c.workspaceDir);

  // Drive the reader that is left. listWorkspaceChanges is what /api/coder's
  // GET .../changes answers from, and it is where getting fileMode wrong hurts
  // most: the user is handed that list and picks from it.
  writeFileSync(join(c.workspaceDir, 'NEW.txt'), 'the one file the agent wrote\n');
  const changed = listWorkspaceChanges(c.workspaceDir).map((x) => x.path).sort();
  assert.deepEqual(
    changed, ['NEW.txt'],
    `the change list carried files the agent never touched: ${changed.join(', ')}`,
  );

  const lines = readFileSync(GIT_LOG, 'utf8').split('\n').filter(Boolean)
    .map((l) => l.split('\x1f').slice(0, -1));
  const reads = lines.filter((a) =>
    a.some((x) => x === c.workspaceDir || x === `safe.directory=${c.workspaceDir}`) &&
    a.some((x) => x === 'status' || x === 'diff' || x === 'add'));
  assert.ok(reads.length > 0, 'no status/diff/add calls were recorded — the git shim is not on PATH');
  for (const a of reads) {
    assert.ok(
      a.includes('core.fileMode=false'),
      `a workspace status/diff ran with git's default fileMode: ${a.join(' ')}`,
    );
  }
  appContainer.evict(SLUG, 'test');
});

/**
 * The runtime check above only sees the paths this test exercises. This one is
 * static, so a git wrapper added to any of these four files later cannot read
 * status with the default fileMode without turning this red.
 */
test('no git helper in the coder/builder files can read status without core.fileMode=false', () => {
  const FILES = [
    'server/routes/coder.js',
    'server/services/builder/gitOps.js',
    'server/services/builder/appContainer.js',
    'server/services/builder/builderSession.js',
  ];
  const offenders = [];
  for (const rel of FILES) {
    const src = readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');
    // Every `execFileSync('git', [ ... ])` call site, argument array captured
    // up to the closing bracket of the array literal.
    const re = /execFileSync\(\s*'git'\s*,\s*\[([\s\S]*?)\]/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      const args = m[1];
      const isWrapper = args.includes('...args');           // forwards anything
      const readsState = /'(status|diff)'/.test(args);      // reads the worktree
      if (!isWrapper && !readsState) continue;              // clone/config/checkout: literal, no status
      if (args.includes('core.fileMode=false')) continue;
      offenders.push(`${rel}: execFileSync('git', [${args.trim().replace(/\s+/g, ' ').slice(0, 120)}…`);
    }
  }
  assert.deepEqual(offenders, [], `git invocation(s) that read worktree state with the default fileMode:\n${offenders.join('\n')}`);
});
