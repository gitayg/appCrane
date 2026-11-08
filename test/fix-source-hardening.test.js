import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const ROOT = mkdtempSync(join(tmpdir(), 'crane-fix-harden-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
after(() => rmSync(ROOT, { recursive: true, force: true }));

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.test', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.test' } });

// ── uploadpack.hideRefs ─────────────────────────────────────────────────────

test('a parked agent tip under refs/dropped/agent is advertised to nobody, other dropped refs still are', async () => {
  const { uploadPackArgs } = await import('../server/services/gitHttp.js');
  const { repoPath } = await import('../server/services/localGit.js');
  const bare = repoPath('hidden-refs');
  mkdirSync(join(bare, '..'), { recursive: true });
  execFileSync('git', ['init', '--bare', '-b', 'main', bare]);
  const work = mkdtempSync(join(ROOT, 'w-'));
  git(work, 'init', '-b', 'main');
  writeFileSync(join(work, 'f'), 'x');
  git(work, 'add', 'f');
  git(work, 'commit', '-m', 'one');
  const sha = git(work, 'rev-parse', 'HEAD').trim();
  git(work, 'push', bare, 'main');
  for (const ref of ['refs/heads/agent/7/s1', 'refs/heads/agent/8/s1', 'refs/dropped/agent/7/s1/a', 'refs/dropped/main/a']) {
    git(bare, 'update-ref', ref, sha);
  }
  const advertised = (userId) => {
    const { args, env } = uploadPackArgs('hidden-refs', { userId, advertiseRefs: true });
    return execFileSync('git', args, { env, encoding: 'utf8', input: '' });
  };
  const other = advertised(8);
  assert.ok(!other.includes('refs/dropped/agent'), `another user sees the parked agent tip:\n${other}`);
  assert.ok(!other.includes('refs/heads/agent/7/'), other);
  assert.ok(other.includes('refs/heads/agent/8/s1'), other);
  assert.ok(other.includes('refs/dropped/main/a'), other);
  assert.ok(!advertised(7).includes('refs/dropped/agent'));
});

// ── safeExtract ─────────────────────────────────────────────────────────────

// Production tar is GNU, whose --no-overwrite-dir macOS's bsdtar refuses outright.
// This drops that one flag so the walk under test runs on either.
const realTar = execFileSync('sh', ['-c', 'command -v tar'], { encoding: 'utf8' }).trim();
const TAR_BIN = mkdtempSync(join(ROOT, 'tarbin-'));
writeFileSync(join(TAR_BIN, 'tar'), `#!/bin/bash\nargs=()\nfor a in "$@"; do [ "$a" = --no-overwrite-dir ] || args+=("$a"); done\nexec "${realTar}" "\${args[@]}"\n`);
chmodSync(join(TAR_BIN, 'tar'), 0o755);

function tarOf(build) {
  const src = mkdtempSync(join(ROOT, 'tar-src-'));
  build(src);
  const out = join(mkdtempSync(join(ROOT, 'tar-out-')), 'a.tar.gz');
  execFileSync('tar', ['-czf', out, '-C', src, '.']);
  return out;
}

test('a dangling link aimed outside the root is refused; one that stays inside is kept', async () => {
  const { safeExtractTarGz } = await import('../server/utils/safeExtract.js');
  const path = process.env.PATH;
  process.env.PATH = `${TAR_BIN}:${path}`;
  after(() => { process.env.PATH = path; });
  const external = tarOf((d) => symlinkSync('/nonexistent-crane/pwn', join(d, 'link')));
  assert.throws(() => safeExtractTarGz(external, mkdtempSync(join(ROOT, 'x-'))), /archive-slip/);

  const relative = tarOf((d) => { mkdirSync(join(d, 'a')); symlinkSync('../../../../nonexistent-crane/pwn', join(d, 'a', 'link')); });
  assert.throws(() => safeExtractTarGz(relative, mkdtempSync(join(ROOT, 'x-'))), /archive-slip/);

  const inside = tarOf((d) => { mkdirSync(join(d, 'a')); symlinkSync('../not-built-yet.js', join(d, 'a', 'link')); writeFileSync(join(d, 'f'), 'x'); });
  const dest = mkdtempSync(join(ROOT, 'x-'));
  safeExtractTarGz(inside, dest);
  assert.ok(existsSync(join(dest, 'f')));
});

// ── gitDeployClone ──────────────────────────────────────────────────────────

const opts = () => ({ timeout: 20000, stdio: 'pipe' });
const clone = async (over) => {
  const { cloneGitRelease } = await import('../server/services/gitDeployClone.js');
  const logs = [];
  await cloneGitRelease({ gitOpts: opts, scrubGit: (m) => m, appendLog: (l) => logs.push(l), ...over });
  return logs;
};
function origin() {
  const w = mkdtempSync(join(ROOT, 'origin-'));
  git(w, 'init', '-b', 'main');
  writeFileSync(join(w, 'f'), 'x');
  git(w, 'add', 'f');
  git(w, 'commit', '-m', 'one');
  return w;
}

test('a branch or commit that reads as an option never reaches git', async () => {
  const w = origin();
  const dir = () => join(mkdtempSync(join(ROOT, 'rel-')), 'r');
  const bin = mkdtempSync(join(ROOT, 'gitspy-'));
  const called = join(bin, 'called');
  writeFileSync(join(bin, 'git'), `#!/bin/bash\necho "$*" >> "${called}"\nexit 0\n`);
  chmodSync(join(bin, 'git'), 0o755);
  const before = process.env.PATH;
  process.env.PATH = `${bin}:${before}`;
  try {
    await assert.rejects(clone({ cloneUrl: 'file:///x', branch: '-x', releaseDir: dir() }), /refusing branch/);
    await assert.rejects(clone({ cloneUrl: 'file:///x', branch: 'main', releaseDir: dir(), targetCommit: '--upload-pack=x' }), /refusing commit/);
  } finally { process.env.PATH = before; }
  assert.equal(existsSync(called), false, 'git was invoked for a refused value');
  const ok = dir();
  await clone({ cloneUrl: `file://${w}`, branch: 'main', releaseDir: ok });
  assert.ok(existsSync(join(ok, 'f')));
});

test('real git accepts the pin with its end-of-options marker', async () => {
  const w = origin();
  writeFileSync(join(w, 'g'), 'y');
  git(w, 'add', 'g');
  git(w, 'commit', '-m', 'two');
  const tip = git(w, 'rev-parse', 'HEAD').trim();
  const first = git(w, 'rev-parse', 'HEAD~1').trim();
  const rel = join(mkdtempSync(join(ROOT, 'rel-')), 'r');
  // file:// shallow clone plus a fetch of a non-tip commit is the deepen fallback.
  await clone({ cloneUrl: `file://${w}`, branch: 'main', releaseDir: rel, targetCommit: first });
  assert.equal(git(rel, 'rev-parse', 'HEAD').trim(), first);
  assert.notEqual(first, tip);
});

test('a clone URL that reads as an option is an argument, not a flag', async () => {
  const bin = mkdtempSync(join(ROOT, 'gitshim-'));
  const argvFile = join(bin, 'argv');
  writeFileSync(join(bin, 'git'), `#!/bin/bash\nprintf '%s\\n' "$@" >> "${argvFile}"\nexit 0\n`);
  chmodSync(join(bin, 'git'), 0o755);
  const before = process.env.PATH;
  process.env.PATH = `${bin}:${before}`;
  try {
    await clone({ cloneUrl: '--upload-pack=x', branch: 'main', releaseDir: '/tmp/ignored-release', targetCommit: 'abc1234' });
  } finally { process.env.PATH = before; }
  const lines = readFileSync(argvFile, 'utf8').split('\n');
  assert.ok(lines.indexOf('--') > 0 && lines.indexOf('--') < lines.indexOf('--upload-pack=x'), lines.join(' '));
  const fetchAt = lines.indexOf('fetch');
  assert.ok(lines.indexOf('--', fetchAt) > fetchAt && lines.indexOf('--', fetchAt) < lines.indexOf('origin', fetchAt), lines.join(' '));
});

// ── branch regex on every write path ───────────────────────────────────────

test('REST and MCP refuse a branch with a leading dash and accept a normal one', async () => {
  const express = (await import('express')).default;
  const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
  const KEY = generateApiKey('dhk_admin');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@t.test','platform_admin',?,1,'human')").run(hashApiKey(KEY)).lastInsertRowid;
  const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const appsRoutes = (await import('../server/routes/apps.js')).default;
  const { errorHandler } = await import('../server/utils/errors.js');
  const { callTool } = await import('../server/services/mcpTools.js');
  const api = express();
  api.use(express.json());
  api.use('/api/apps', appsRoutes);
  api.use(errorHandler);
  const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
  const BASE = `http://127.0.0.1:${server.address().port}`;
  const req = (method, path, body) => fetch(`${BASE}${path}`, { method, headers: { 'Content-Type': 'application/json', 'X-API-Key': KEY }, body: JSON.stringify(body) }).then((r) => r.status);
  const URL_ = 'https://github.com/example-owner/own-repo';
  try {
    assert.equal(await req('POST', '/api/apps', { name: 'b', slug: 'branch-post', source_type: 'github', github_url: URL_, branch: '-x' }), 400);
    assert.equal(await req('POST', '/api/apps', { name: 'b', slug: 'branch-post', source_type: 'github', github_url: URL_, branch: 'feature/a-b' }), 201);
    assert.equal(await req('PUT', '/api/apps/branch-post', { branch: '--orphan' }), 400);
    assert.equal(await req('PUT', '/api/apps/branch-post', { branch: 'dev' }), 200);
    await assert.rejects(callTool(admin, 'appcrane_create_app', { name: 'b', slug: 'branch-mcp', github_url: URL_, branch: '-x' }), /branch/);
    await callTool(admin, 'appcrane_create_app', { name: 'b', slug: 'branch-mcp', github_url: URL_, branch: 'dev' });
    await assert.rejects(callTool(admin, 'appcrane_update_app', { slug: 'branch-mcp', branch: '-x' }), /branch/);
    await assert.rejects(callTool(admin, 'appcrane_create_managed_app', { name: 'b', slug: 'branch-managed', branch: '-x' }), /branch/);
  } finally {
    const { stopHealthChecker } = await import('../server/services/healthChecker.js');
    stopHealthChecker();
    server.closeAllConnections?.();
    server.unref();
    server.close();
  }
});

// ── committed symlinks: dockerfileGen ───────────────────────────────────────

test('dockerfileGen does not read package.json through a committed link', async () => {
  const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');
  const outside = join(ROOT, 'outside-package.json');
  writeFileSync(outside, JSON.stringify({ name: 'x', main: 'LEAKED-MAIN.js', scripts: { build: 'LEAKED-BUILD' } }));

  const rel = mkdtempSync(join(ROOT, 'rel-pkg-'));
  symlinkSync(outside, join(rel, 'package.json'));
  ensureDockerfile({ releaseDir: rel, manifest: {}, appBasePath: '/x/', craneUrl: '', craneInternalUrl: '', slug: 'link-app' });
  const df = readFileSync(join(rel, 'Dockerfile'), 'utf8');
  assert.ok(!df.includes('LEAKED'), df);

  // The frontend detection walks client/, frontend/, ... with the same read.
  const rel2 = mkdtempSync(join(ROOT, 'rel-fe-'));
  writeFileSync(join(rel2, 'package.json'), JSON.stringify({ name: 'x', scripts: { start: 'node s.js' } }));
  mkdirSync(join(rel2, 'client'));
  const feOutside = join(ROOT, 'outside-fe.json');
  writeFileSync(feOutside, JSON.stringify({ scripts: { build: 'x' }, dependencies: { vite: '1' } }));
  symlinkSync(feOutside, join(rel2, 'client', 'package.json'));
  ensureDockerfile({ releaseDir: rel2, manifest: {}, appBasePath: '/x/', craneUrl: '', craneInternalUrl: '', slug: 'link-app' });
  assert.ok(!readFileSync(join(rel2, 'Dockerfile'), 'utf8').includes('client'), 'a linked package.json picked the frontend workdir');

  // A directory that is a link out of the tree counts as well.
  const rel3 = mkdtempSync(join(ROOT, 'rel-dir-'));
  const outsideDir = mkdtempSync(join(ROOT, 'outside-dir-'));
  writeFileSync(join(outsideDir, 'package.json'), JSON.stringify({ main: 'LEAKED-WORKDIR.js' }));
  symlinkSync(outsideDir, join(rel3, 'server'));
  writeFileSync(join(rel3, 'package.json'), '{"name":"x"}');
  ensureDockerfile({ releaseDir: rel3, manifest: { be: { workdir: 'server' } }, appBasePath: '/x/', craneUrl: '', craneInternalUrl: '', slug: 'link-app' });
  assert.ok(!readFileSync(join(rel3, 'Dockerfile'), 'utf8').includes('LEAKED'));
});

test('dockerfileGen still reads an ordinary package.json', async () => {
  const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');
  const rel = mkdtempSync(join(ROOT, 'rel-ok-'));
  writeFileSync(join(rel, 'package.json'), JSON.stringify({ name: 'x', main: 'real-main.js' }));
  ensureDockerfile({ releaseDir: rel, manifest: {}, appBasePath: '/x/', craneUrl: '', craneInternalUrl: '', slug: 'plain-app' });
  assert.ok(readFileSync(join(rel, 'Dockerfile'), 'utf8').includes('real-main.js'));
});

// ── committed symlinks: a real deployApp, the way an owner's push reaches it ─

test('a deploy of a repo that commits a linked manifest fails, and logs nothing of the target', async () => {
  const bin = join(ROOT, 'deploybin');
  mkdirSync(bin);
  const secret = join(ROOT, 'host-secret.env');
  writeFileSync(secret, 'ANTHROPIC_KEY=do-not-leak\n');
  const outsidePkg = join(ROOT, 'host-package.json');
  writeFileSync(outsidePkg, JSON.stringify({ name: 'LEAKED-NAME', version: '9.9.9-leaked' }));
  writeFileSync(join(bin, 'docker'), `#!/usr/bin/env node
const argv = process.argv.slice(2);
let code = 0, out = '0123456789abcdef\\n';
// The build fails on purpose: both claims are settled before it, and a deploy
// that got further would sit in the health probe.
if (argv[0] === 'build') { code = 1; out = ''; }
else if (argv[0] === 'version') out = '29.0.0\\n';
else if (argv[0] === 'image' && argv[1] === 'inspect') { code = 1; out = ''; }
else if (argv[0] === 'inspect') { code = 1; out = ''; }
else if (argv[0] === 'network' && argv[1] === 'inspect') out = 'false|172.20.0.0/16\\n';
else if (argv[0] === 'images' || argv[0] === 'ps') out = '';
process.stdout.write(out);
process.exit(code);
`, { mode: 0o755 });
  writeFileSync(join(bin, 'git'), `#!/usr/bin/env node
const { mkdirSync, writeFileSync, symlinkSync } = require('fs');
const { join } = require('path');
const argv = process.argv.slice(2);
const SHA = '${'ab'.repeat(20)}';
if (argv[0] === 'clone') {
  const dir = argv[argv.length - 1];
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'server.js'), 'x');
  if (process.env.CRANE_TEST_LINK === 'manifest') {
    symlinkSync(${JSON.stringify(secret)}, join(dir, 'deployhub.json'));
  } else {
    writeFileSync(join(dir, 'deployhub.json'), JSON.stringify({ version: '1.0.0', port: 3000 }));
    symlinkSync(${JSON.stringify(outsidePkg)}, join(dir, 'package.json'));
  }
  process.exit(0);
}
if (argv[0] === '-C') {
  if (argv[2] === 'rev-parse') { process.stdout.write((argv[3] === '--short' ? SHA.slice(0, 7) : SHA) + '\\n'); process.exit(0); }
  if (argv[2] === 'log') { process.stdout.write('fixture commit\\n'); process.exit(0); }
}
process.exit(0);
`, { mode: 0o755 });
  chmodSync(join(bin, 'git'), 0o755);
  db.prepare("INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled','0') ON CONFLICT(key) DO UPDATE SET value='0'").run();
  const userId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','dep@t.test','platform_admin','unused-dep',1,'human')").run().lastInsertRowid;
  db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,branch,container_port,health_path) VALUES ('l','link-deploy',4000,'github','https://github.com/example-owner/example-repo','main',3000,'/health')").run();
  const { deployApp } = await import('../server/services/deployer.js');
  const { getPortsForSlot } = await import('../server/services/portAllocator.js');
  const before = process.env.PATH;
  process.env.PATH = `${bin}:${before}`;
  const deploy = async (link) => {
    process.env.CRANE_TEST_LINK = link;
    const app = db.prepare("SELECT * FROM apps WHERE slug = 'link-deploy'").get();
    const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)").run(app.id, userId).lastInsertRowid;
    await deployApp(depId, app, 'sandbox', getPortsForSlot(4000), {}).catch(() => {});
    return db.prepare('SELECT * FROM deployments WHERE id = ?').get(depId);
  };
  try {
    const manifest = await deploy('manifest');
    assert.equal(manifest.status, 'failed');
    assert.match(manifest.log, /deployhub\.json is a symbolic link/, manifest.log);
    assert.ok(!/ANTHROPIC|Unexpected token/.test(manifest.log), manifest.log);

    const pkg = await deploy('package');
    assert.ok(!/LEAKED|9\.9\.9-leaked/.test(pkg.log), pkg.log);
    assert.match(pkg.log, /package\.json is a symbolic link/, pkg.log);
  } finally {
    process.env.PATH = before;
    delete process.env.CRANE_TEST_LINK;
    const { stopHealthChecker } = await import('../server/services/healthChecker.js');
    stopHealthChecker();
  }
});
