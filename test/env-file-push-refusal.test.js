import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A Crane-hosted app's repository never takes a .env* file (envFilePushGuard.js).
// Real git, read back with an isolated git that is not the module under test.
// GitHub is a fetch stub: a GitHub-backed managed app must keep accepting the
// same push it accepted before.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-envpush-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'debug';

const logLines = [];
const origLog = console.log;
console.log = (...a) => { logLines.push(a.join(' ')); };

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { setServiceConfig } = await import('../server/services/githubService.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const managedRepo = await import('../server/services/managedRepo.js');
const lg = await import('../server/services/localGit.js');
const { isEnvFilePath } = await import('../server/services/envFilePushGuard.js');

after(async () => {
  console.log = origLog;
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const git = (slug, args) => execFileSync('git', [`--git-dir=${lg.repoPath(slug)}`, ...args], { env: CLEAN }).toString('utf8').trim();
const tipOf = (slug) => git(slug, ['rev-parse', 'refs/heads/main']);
const treeOf = (slug) => git(slug, ['ls-tree', '-r', '--name-only', 'refs/heads/main']).split('\n').filter(Boolean);
const blobExists = (slug, content) => {
  const sha = execFileSync('git', ['hash-object', '--stdin'], { env: CLEAN, input: content }).toString().trim();
  try { git(slug, ['cat-file', '-e', sha]); return true; } catch (_) { return false; }
};

const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('ep','ep@example.com','platform_admin','h',1,'human')").run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'ep' };

async function tool(name, args) {
  try {
    const r = await callTool(admin, name, args);
    return { ok: true, body: JSON.parse(r.content[0].text) };
  } catch (e) {
    return { ok: false, err: e };
  }
}
const appRow = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);

// No webhook_configs row, so a committed push does not start a deploy.
async function localApp(slug) {
  await lg.createAppRepo(slug);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES (?, ?, ?, 'managed', 'local', 'main')").run(slug, slug, getNextSlot(db));
  return appRow(slug);
}

const SECRET = 'SECRET_TOKEN=VALUEMARK-envpush-7c1d';
const auditText = () => db.prepare('SELECT action, detail FROM audit_log').all().map((r) => `${r.action} ${r.detail}`).join('\n');

function assertRefused(res, paths) {
  assert.equal(res.ok, false, `expected refusal, got ${JSON.stringify(res.body)}`);
  assert.equal(res.err.code, 'ENV_FILE_IN_PUSH', res.err.message);
  assert.equal(res.err.status, 422);
  assert.match(res.err.message, /^ENV_FILE_IN_PUSH: /);
  assert.match(res.err.message, /appcrane_set_secret/);
  assert.match(res.err.message, /Stored \.env files/);
  assert.match(res.err.message, /Nothing was committed/);
  for (const p of paths) assert.ok(res.err.message.includes(JSON.stringify(p)), `missing ${p} in: ${res.err.message}`);
  assert.equal(res.err.message.includes('VALUEMARK'), false, 'content echoed in the error');
}

// ---------------------------------------------------------------------------

test('the rule: basename starts with .env, any depth, any case', () => {
  for (const p of ['.env', '.ENV', '.Env.local', '.env.example', 'web/.env', 'a/b/.env.production', '.envrc']) assert.equal(isEnvFilePath(p), true, p);
  for (const p of ['env', 'src/env.js', 'docs/dot.env', '.env-dir/app.js', 'environment/.gitkeep', 'x.env', '']) assert.equal(isEnvFilePath(p), false, p);
});

test('appcrane_push_to_managed_app: a root .env is refused, nothing committed, content not in the error, log or audit', async () => {
  await localApp('ep-root');
  const tip = tipOf('ep-root');
  const logStart = logLines.length;
  const res = await tool('appcrane_push_to_managed_app', { slug: 'ep-root', files: [{ path: '.env', content: SECRET }] });
  assertRefused(res, ['.env']);
  assert.equal(tipOf('ep-root'), tip);
  assert.equal(blobExists('ep-root', SECRET), false, 'the refused blob was written into the object store');
  assert.equal(logLines.slice(logStart).join('\n').includes('VALUEMARK'), false, 'content in the log');
  assert.equal(auditText().includes('VALUEMARK'), false, 'content in the audit log');
  assert.match(auditText(), /mcp\.appcrane_push_to_managed_app .*redacted \.env content/);
});

test('nested, upper-case and example names are refused too', async () => {
  await localApp('ep-names');
  const tip = tipOf('ep-names');
  for (const p of ['web/.env.local', '.ENV', 'config/.Env', '.env.example']) {
    assertRefused(await tool('appcrane_push_to_managed_app', { slug: 'ep-names', files: [{ path: p, content: SECRET }] }), [p]);
  }
  assert.equal(tipOf('ep-names'), tip);
});

test('a push with one .env among ordinary files is refused WHOLE and names every offending path once', async () => {
  await localApp('ep-mixed');
  const tip = tipOf('ep-mixed');
  const res = await tool('appcrane_push_to_managed_app', {
    slug: 'ep-mixed',
    files: [
      { path: 'package.json', content: '{"name":"ep-mixed-marker"}' },
      { path: 'server/.env', content: SECRET },
      { path: 'src/app.js', content: 'console.log(1)\n' },
      { path: '.env.production', content: SECRET },
    ],
  });
  assertRefused(res, ['server/.env', '.env.production']);
  assert.equal(tipOf('ep-mixed'), tip, 'part of the push was committed');
  assert.deepEqual(treeOf('ep-mixed').filter((p) => p !== 'README.md'), []);
  assert.equal(blobExists('ep-mixed', '{"name":"ep-mixed-marker"}'), false, 'an ordinary file of the refused push was written');
});

test('ordinary files, including env-looking names that are not .env*, still commit', async () => {
  await localApp('ep-ok');
  const res = await tool('appcrane_push_to_managed_app', {
    slug: 'ep-ok', files: [{ path: 'src/env.js', content: 'x' }, { path: 'docs/dot.env', content: 'y' }, { path: 'environment/.gitkeep', content: '' }],
  });
  assert.equal(res.ok, true, res.err?.message);
  assert.equal(res.body.commit.sha, tipOf('ep-ok'));
  for (const p of ['src/env.js', 'docs/dot.env', 'environment/.gitkeep']) assert.ok(treeOf('ep-ok').includes(p), p);
});

test('appcrane_managed_push_chunk refuses at part 1, before storing anything', async () => {
  await localApp('ep-chunk');
  const res = await tool('appcrane_managed_push_chunk', { slug: 'ep-chunk', path: 'deep/.env', session: 'ep-c1', part: 1, of: 3, content: SECRET });
  assertRefused(res, ['deep/.env']);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM managed_push_chunks WHERE session = 'ep-c1'").get().n, 0);
  assert.equal(auditText().includes('VALUEMARK'), false, 'chunk content in the audit log');
});

test('appcrane_managed_assemble refuses a .env session staged before this rule (commit-step choke point)', async () => {
  await localApp('ep-asm');
  const tip = tipOf('ep-asm');
  db.prepare("INSERT INTO managed_push_chunks (session, user_id, slug, path, part, of_total, encoding, content, sha256) VALUES ('ep-a1', ?, 'ep-asm', '.env', 1, 1, 'utf-8', ?, 'x')").run(adminId, SECRET);
  const res = await tool('appcrane_managed_assemble', { slug: 'ep-asm', session: 'ep-a1', path: '.env' });
  assertRefused(res, ['.env']);
  assert.equal(tipOf('ep-asm'), tip);
  assert.equal(blobExists('ep-asm', SECRET), false);
});

test('appcrane_managed_patch refuses a .env path without reading the file already in the repo', async () => {
  await localApp('ep-patch');
  // A repo that already holds a .env (pushed before this rule): written with the
  // backend directly, below the facade.
  await lg.pushFilesToManagedRepo('ep-patch', [{ path: '.env', content: `${SECRET}\n` }], { branch: 'main' });
  const tip = tipOf('ep-patch');
  const res = await tool('appcrane_managed_patch', {
    slug: 'ep-patch', path: '.env', unified_diff: `--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-${SECRET}\n+SECRET_TOKEN=other`,
  });
  assertRefused(res, ['.env']);
  assert.equal(tipOf('ep-patch'), tip);
  // Refused as .env before the read: a path absent from the repo must not come
  // back as FILE_NOT_FOUND.
  assertRefused(await tool('appcrane_managed_patch', { slug: 'ep-patch', path: 'web/.env.local', unified_diff: '--- a\n+++ b\n@@ -1 +1 @@\n-a\n+b' }), ['web/.env.local']);
});

test('the facade itself refuses, whoever calls it', async () => {
  const app = await localApp('ep-facade');
  const tip = tipOf('ep-facade');
  await assert.rejects(managedRepo.pushFilesToManagedRepo(app, [{ path: 'a.txt', content: 'a' }, { path: 'x/.env.local', content: SECRET }]), (e) => {
    assert.equal(e.code, 'ENV_FILE_IN_PUSH');
    return true;
  });
  assert.equal(tipOf('ep-facade'), tip);
});

// ---------------------------------------------------------------------------
// GitHub-backed managed apps: unchanged
// ---------------------------------------------------------------------------

const ghCalls = [];
const json = (status, body) => ({ ok: status >= 200 && status < 300, status, statusText: String(status), headers: new Headers(), text: async () => JSON.stringify(body), json: async () => body });
global.fetch = async (url, init = {}) => {
  const u = String(url);
  const method = (init.method || 'GET').toUpperCase();
  ghCalls.push({ method, url: u, body: init.body });
  const p = /^https:\/\/api\.github\.com(\/[^?]*)/.exec(u)?.[1] || '';
  if (method === 'GET' && /^\/repos\/svc-owner\/AMC_[a-z0-9-]+$/.test(p)) return json(200, { default_branch: 'main', html_url: 'https://github.com/svc-owner/AMC_x' });
  if (method === 'GET' && /\/git\/ref\/heads\/main$/.test(p)) return json(200, { object: { sha: '1'.repeat(40) } });
  if (method === 'GET' && /\/git\/commits\/1{40}$/.test(p)) return json(200, { tree: { sha: '2'.repeat(40) } });
  if (method === 'POST' && /\/git\/blobs$/.test(p)) return json(201, { sha: '3'.repeat(40) });
  if (method === 'POST' && /\/git\/trees$/.test(p)) return json(201, { sha: '4'.repeat(40) });
  if (method === 'POST' && /\/git\/commits$/.test(p)) return json(201, { sha: '5'.repeat(40) });
  if (method === 'PATCH' && /\/git\/refs\/heads\/main$/.test(p)) return json(200, {});
  return json(599, { message: `unrouted ${method} ${p}` });
};

test('GitHub-backed managed app: a .env push still goes to GitHub exactly as before, and a .env chunk is still staged', async () => {
  setServiceConfig({ owner: 'svc-owner', token: 'ghp_test_not_real', visibility: 'private', enabled: true }, adminId);
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES ('g', 'ep-gh', ?, 'managed', 'https://github.com/svc-owner/AMC_ep-gh', 'main')").run(getNextSlot(db));
  assert.equal(appRow('ep-gh').repo_backend, null);
  const res = await tool('appcrane_push_to_managed_app', { slug: 'ep-gh', files: [{ path: '.env', content: 'A=1' }, { path: 'web/.env.local', content: 'B=2' }] });
  assert.equal(res.ok, true, res.err?.message);
  assert.equal(res.body.commit.sha, '5'.repeat(40));
  const tree = ghCalls.find((c) => c.method === 'POST' && c.url.endsWith('/git/trees'));
  assert.deepEqual(JSON.parse(tree.body).tree.map((t) => t.path), ['.env', 'web/.env.local']);

  const chunk = await tool('appcrane_managed_push_chunk', { slug: 'ep-gh', path: '.env', session: 'ep-g1', part: 1, of: 1, content: 'A=1' });
  assert.equal(chunk.ok, true, chunk.err?.message);
});
