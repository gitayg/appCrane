import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Deleting files from a Crane-hosted (repo_backend='local') managed repo.
//
// Every assertion about what landed is read back with an INDEPENDENT git, never
// the module under test: the removal is done with `update-index --index-info`
// and a mode of 0 (git refuses `--force-remove` in a bare repo outright), and a
// mock of git would happily keep a wrong plumbing sequence green.
//
// The guards matter more than the happy path here. At the plumbing level,
// removing a path git does not have is a SILENT no-op, and removing every path
// produces a perfectly valid empty tree — so both have to be refused above git,
// or a typo reports success having changed nothing.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-mrdel-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getNextSlot } = await import('../server/services/portAllocator.js');
const managedRepo = await import('../server/services/managedRepo.js');
const lg = await import('../server/services/localGit.js');
const { callTool } = await import('../server/services/mcpTools.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const git = (slug, args) => execFileSync('git', [`--git-dir=${lg.repoPath(slug)}`, ...args], { env: CLEAN }).toString('utf8').trim();
const tipOf = (slug) => git(slug, ['rev-parse', 'refs/heads/main']);
const treeOf = (slug, ref = 'refs/heads/main') => git(slug, ['ls-tree', '-r', '--name-only', ref]).split('\n').filter(Boolean).sort();

const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('md','md@example.com','platform_admin','h',1,'human')").run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'md' };

// No webhook_configs row, so a committed push does not start a deploy.
async function localApp(slug) {
  await lg.createAppRepo(slug);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES (?, ?, ?, 'managed', 'local', 'main')").run(slug, slug, getNextSlot(db));
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}

/** Seed a repo with three files so a deletion has something to remove. */
async function seeded(slug) {
  const app = await localApp(slug);
  await lg.pushFilesToManagedRepo(slug, [
    { path: 'src/keep.js', content: 'keep\n' },
    { path: 'src/gone.js', content: 'gone\n' },
    { path: 'docs/old.md', content: '# old\n' },
  ], { message: 'seed' });
  return app;
}

async function rejection(fn) {
  try { await fn(); } catch (e) { return e; }
  assert.fail('expected a rejection, got success');
}

// ---------------------------------------------------------------------------
// The behaviour
// ---------------------------------------------------------------------------

test('a delete removes the path from the resulting tree, and only that path', async () => {
  await seeded('del-basic');
  const before = tipOf('del-basic');
  assert.deepEqual(treeOf('del-basic'), ['README.md', 'docs/old.md', 'src/gone.js', 'src/keep.js']);

  const res = await lg.pushFilesToManagedRepo('del-basic',
    [{ path: 'src/new.js', content: 'new\n' }],
    { deletions: ['src/gone.js'], message: 'feat: replace gone with new' });

  const after = tipOf('del-basic');
  assert.equal(res.commit.sha, after);
  assert.equal(git('del-basic', ['rev-parse', `${after}^`]), before, 'one commit on top of the previous tip');
  assert.equal(git('del-basic', ['rev-list', '--count', `${before}..${after}`]), '1', 'a write + a delete is ONE commit');
  assert.deepEqual(treeOf('del-basic'), ['README.md', 'docs/old.md', 'src/keep.js', 'src/new.js'],
    'git ls-tree still lists the deleted path, or lost an untouched one');
  assert.deepEqual(res.deleted, ['src/gone.js'], 'the response must echo what was removed');
  assert.deepEqual(res.files.map((f) => f.path), ['src/new.js'], 'the existing files field must be unchanged in shape');
  // The parent commit still has it: a delete is a new commit, not a rewrite.
  assert.ok(treeOf('del-basic', before).includes('src/gone.js'));
});

test('a pure-deletion push (files: []) commits and removes the path', async () => {
  await seeded('del-pure');
  const before = tipOf('del-pure');
  const res = await lg.pushFilesToManagedRepo('del-pure', [], { deletions: ['docs/old.md'], message: 'chore: drop old docs' });

  assert.equal(res.commit.sha, tipOf('del-pure'));
  assert.equal(git('del-pure', ['rev-parse', `${res.commit.sha}^`]), before);
  assert.deepEqual(treeOf('del-pure'), ['README.md', 'src/gone.js', 'src/keep.js']);
  assert.deepEqual(res.files, [], 'files must stay an array, empty');
  assert.deepEqual(res.deleted, ['docs/old.md']);
  assert.equal(git('del-pure', ['log', '-1', '--format=%B', res.commit.sha]), 'chore: drop old docs');
});

test('a push with neither files nor deletions is still refused', async () => {
  await seeded('del-neither');
  const tip = tipOf('del-neither');
  await assert.rejects(lg.pushFilesToManagedRepo('del-neither', [], {}), /files must be a non-empty array/);
  await assert.rejects(lg.pushFilesToManagedRepo('del-neither', [], { deletions: [] }), /files must be a non-empty array/);
  assert.equal(tipOf('del-neither'), tip, 'the branch moved for a push that had nothing in it');
});

// ---------------------------------------------------------------------------
// The guards
// ---------------------------------------------------------------------------

test('deleting a path that does not exist is refused by name, and nothing is committed', async () => {
  await seeded('del-missing');
  const tip = tipOf('del-missing');
  const e = await rejection(() => lg.pushFilesToManagedRepo('del-missing',
    [{ path: 'src/added.js', content: 'x\n' }],
    { deletions: ['src/keep.js', 'src/typo.js', 'nope/at/all.txt'] }));

  assert.equal(e.code, 'DELETE_PATH_NOT_FOUND', e.message);
  assert.equal(e.status, 404);
  assert.ok(e.message.includes('"src/typo.js"'), `offending path not named: ${e.message}`);
  assert.ok(e.message.includes('"nope/at/all.txt"'), `offending path not named: ${e.message}`);
  assert.equal(e.message.includes('"src/keep.js"'), false, 'a path that DOES exist was named as missing');
  assert.match(e.message, /Nothing was committed/);
  assert.equal(tipOf('del-missing'), tip, 'the branch moved despite the refusal');
  assert.deepEqual(treeOf('del-missing'), ['README.md', 'docs/old.md', 'src/gone.js', 'src/keep.js']);
});

test('deleting a directory prefix is refused — only exact blob paths are deletable', async () => {
  await seeded('del-dir');
  const e = await rejection(() => lg.pushFilesToManagedRepo('del-dir', [], { deletions: ['src'] }));
  assert.equal(e.code, 'DELETE_PATH_NOT_FOUND', e.message);
  assert.deepEqual(treeOf('del-dir'), ['README.md', 'docs/old.md', 'src/gone.js', 'src/keep.js']);
});

test('a push that would leave an empty tree is refused', async () => {
  await seeded('del-empty');
  const tip = tipOf('del-empty');
  const e = await rejection(() => lg.pushFilesToManagedRepo('del-empty', [],
    { deletions: ['README.md', 'src/keep.js', 'src/gone.js', 'docs/old.md'] }));

  assert.equal(e.code, 'EMPTY_TREE', e.message);
  assert.equal(e.status, 422);
  assert.match(e.message, /Nothing was committed/);
  assert.equal(tipOf('del-empty'), tip);
  assert.deepEqual(treeOf('del-empty'), ['README.md', 'docs/old.md', 'src/gone.js', 'src/keep.js']);

  // Deleting everything is fine as long as the push puts something back.
  const ok = await lg.pushFilesToManagedRepo('del-empty', [{ path: 'only.txt', content: 'hi\n' }],
    { deletions: ['README.md', 'src/keep.js', 'src/gone.js', 'docs/old.md'] });
  assert.deepEqual(treeOf('del-empty'), ['only.txt']);
  assert.equal(ok.deleted.length, 4);
});

test('a path in both files and deletions is refused, as are duplicates within either list', async () => {
  await seeded('del-both');
  const tip = tipOf('del-both');

  const e = await rejection(() => lg.pushFilesToManagedRepo('del-both',
    [{ path: 'src/keep.js', content: 'rewritten\n' }], { deletions: ['src/keep.js'] }));
  assert.match(e.message, /both files and deletions/);
  assert.ok(e.message.includes('"src/keep.js"'), e.message);

  await assert.rejects(lg.pushFilesToManagedRepo('del-both', [], { deletions: ['src/keep.js', 'src/keep.js'] }),
    /duplicate path\(s\) in deletions/);
  await assert.rejects(lg.pushFilesToManagedRepo('del-both',
    [{ path: 'a.txt', content: '1' }, { path: 'a.txt', content: '2' }], {}),
    /duplicate path\(s\) in files/);

  assert.equal(tipOf('del-both'), tip, 'one of the refusals still committed');
});

test('every deleted path goes through assertRepoFilePath', async () => {
  await seeded('del-path');
  const tip = tipOf('del-path');
  for (const bad of ['../outside.txt', '/etc/passwd', 'a/../b', '.git/config', 'x/.GIT/hooks', 'a//b', 'nul\0byte']) {
    await assert.rejects(lg.pushFilesToManagedRepo('del-path', [], { deletions: [bad] }),
      /invalid file path|path is required/, `accepted ${JSON.stringify(bad)}`);
  }
  await assert.rejects(lg.pushFilesToManagedRepo('del-path', [], { deletions: [42] }), /repo-relative path string/);
  await assert.rejects(lg.pushFilesToManagedRepo('del-path', [{ path: 'a', content: 'b' }], { deletions: 'src/keep.js' }),
    /deletions must be an array/);
  assert.equal(tipOf('del-path'), tip);
});

// ---------------------------------------------------------------------------
// managedRepo.js: the .env guard and the GitHub backend
// ---------------------------------------------------------------------------

test('a deleted .env* path is refused by the env-file guard, before the backend is touched', async () => {
  const app = await seeded('del-env');
  const tip = tipOf('del-env');
  for (const p of ['.env', 'web/.env.local', '.ENV']) {
    const e = await rejection(() => managedRepo.pushFilesToManagedRepo(app, [], { deletions: [p] }));
    assert.equal(e.code, 'ENV_FILE_IN_PUSH', `${p}: ${e.message}`);
    assert.equal(e.status, 422);
    assert.ok(e.message.includes(JSON.stringify(p)), e.message);
  }
  // The guard must see BOTH lists, not just files.
  const mixed = await rejection(() => managedRepo.pushFilesToManagedRepo(app,
    [{ path: 'src/ok.js', content: 'x\n' }], { deletions: ['config/.env.production'] }));
  assert.equal(mixed.code, 'ENV_FILE_IN_PUSH', mixed.message);
  assert.ok(mixed.message.includes('"config/.env.production"'), mixed.message);
  assert.equal(tipOf('del-env'), tip, 'a refused push still committed');
});

test('deletions are refused for a GitHub-backed managed app', async () => {
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES ('del-gh','del-gh',?, 'managed', NULL, 'main')").run(getNextSlot(db));
  const gh = db.prepare('SELECT * FROM apps WHERE slug = ?').get('del-gh');
  assert.equal(managedRepo.repoBackendOf(gh), 'github');
  const e = await rejection(() => managedRepo.pushFilesToManagedRepo(gh, [{ path: 'a.js', content: 'x' }], { deletions: ['b.js'] }));
  assert.match(e.message, /not supported for GitHub-backed managed apps/);
  assert.match(e.message, /Nothing was committed/);
});

// ---------------------------------------------------------------------------
// The MCP tool
// ---------------------------------------------------------------------------

test('appcrane_push_to_managed_app: deletions is advertised and works end to end', async () => {
  const { getToolCatalog } = await import('../server/services/mcpTools.js');
  const tool = getToolCatalog().find((t) => t.name === 'appcrane_push_to_managed_app');
  const schema = tool.inputSchema.properties;
  assert.equal(schema.deletions.type, 'array', 'the tool does not advertise deletions');
  assert.equal(schema.deletions.maxItems, 200);
  assert.equal(schema.files.minItems, 0, 'a pure-deletion push cannot be expressed while files requires minItems 1');

  await seeded('del-mcp');
  const r = await callTool(admin, 'appcrane_push_to_managed_app', {
    slug: 'del-mcp',
    files: [{ path: 'src/next.js', content: 'next\n' }],
    deletions: ['src/gone.js'],
    message: 'feat: swap',
  });
  const body = JSON.parse(r.content[0].text);
  assert.deepEqual(body.deleted, ['src/gone.js']);
  assert.deepEqual(treeOf('del-mcp'), ['README.md', 'docs/old.md', 'src/keep.js', 'src/next.js']);

  // Pure deletion over MCP.
  await callTool(admin, 'appcrane_push_to_managed_app', { slug: 'del-mcp', files: [], deletions: ['docs/old.md'] });
  assert.deepEqual(treeOf('del-mcp'), ['README.md', 'src/keep.js', 'src/next.js']);

  // And a bad path is refused with nothing committed.
  const tip = tipOf('del-mcp');
  await assert.rejects(callTool(admin, 'appcrane_push_to_managed_app', { slug: 'del-mcp', files: [], deletions: ['src/never.js'] }),
    /DELETE_PATH_NOT_FOUND|not in branch/);
  assert.equal(tipOf('del-mcp'), tip);
});
