import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { gzipSync } from 'zlib';
import http from 'http';
import express from 'express';

// git clone/fetch over HTTPS for Crane-hosted apps (routes/gitHttp.js).
// Real git on both ends: the server runs upload-pack against a bare repo made by
// localGit, the client is the git CLI over HTTP on an ephemeral port. Git runs
// asynchronously because the server lives in this same process.

const run = promisify(execFile);
const ROOT = mkdtempSync(join(tmpdir(), 'crane-githttp-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const { createGitHttpRouter } = await import('../server/routes/gitHttp.js');
const { GIT_HTTP_LIMITS, activeUploadPacks } = await import('../server/services/gitHttp.js');

let slot = 0;
function mkApp(slug, backend) {
  return db.prepare(`INSERT INTO apps (name, slug, slot, source_type, repo_backend) VALUES (?, ?, ?, 'managed', ?)`)
    .run(slug, slug, ++slot, backend).lastInsertRowid;
}
let seq = 0;
function mkUser({ role = 'user', active = 1 } = {}) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const uid = db.prepare('INSERT INTO users (name, email, role, active, api_key_hash) VALUES (?, ?, ?, ?, ?)')
    .run(`gh${n}`, `gh${n}@t.test`, role, active, hashApiKey(key)).lastInsertRowid;
  return { uid, key };
}
const seat = (appId, uid, tier) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(appId, uid, tier);

const APP = mkApp('gh-a', 'local');
const OTHER_APP = mkApp('gh-b', 'local');
const GH_APP = mkApp('gh-github', 'github');

const MEMBER = mkUser();
const PEER = mkUser();
const OUTSIDER = mkUser();
const DEACTIVATED = mkUser({ active: 0 });
const VIEWER_NONE = mkUser();
const PLATFORM_ADMIN = mkUser({ role: 'platform_admin' });
seat(APP, MEMBER.uid, 'user');
seat(APP, PEER.uid, 'owner');
seat(APP, DEACTIVATED.uid, 'user');
seat(APP, VIEWER_NONE.uid, 'none');
seat(OTHER_APP, OUTSIDER.uid, 'owner');
seat(GH_APP, MEMBER.uid, 'owner');

const MCP_KEY = generateApiKey('dhk_mcp');
db.prepare('INSERT INTO user_mcp_keys (user_id, key_hash, label) VALUES (?, ?, ?)').run(MEMBER.uid, hashApiKey(MCP_KEY), 'git test');
const crewAgent = db.prepare("INSERT INTO crew_agents (name, owner_user_id, kind) VALUES ('git-test-agent', ?, 'mcp')").run(MEMBER.uid).lastInsertRowid;
const CREW_TOKEN = `dhk_crew_${'x'.repeat(43)}`;
db.prepare('INSERT INTO crew_agent_tokens (agent_id, token_hash, hint) VALUES (?, ?, ?)').run(crewAgent, hashApiKey(CREW_TOKEN), 'xxxxxx');

await lg.createAppRepo('gh-a');
await lg.pushFilesToManagedRepo('gh-a', [{ path: 'src/hello.txt', content: 'hello from crane\n' }], { branch: 'main', message: 'add hello' });
await lg.createAppRepo('gh-b');
// The GitHub-backed app gets a bare repo on disk too, so its 404 is the backend
// rule and not a missing directory.
await lg.createAppRepo('gh-github');

const REPO = lg.repoPath('gh-a');
const bareGit = (...args) => execFileSync('git', ['--git-dir', REPO, ...args], {
  env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.invalid' },
}).toString().trim();
function agentBranch(ref, msg) {
  const main = bareGit('rev-parse', 'refs/heads/main');
  const tree = bareGit('rev-parse', 'refs/heads/main^{tree}');
  const sha = bareGit('commit-tree', tree, '-p', main, '-m', msg);
  bareGit('update-ref', ref, sha);
  return sha;
}
const OWN_AGENT = agentBranch(`refs/heads/agent/${MEMBER.uid}/s1`, 'member rescue');
const PEER_AGENT = agentBranch(`refs/heads/agent/${PEER.uid}/s2`, 'peer rescue');
const PREFIX_AGENT = agentBranch(`refs/heads/agent/${MEMBER.uid}0/s3`, 'prefix-neighbour rescue');

function startServer(router) {
  const api = express();
  api.use('/git', router);
  api.use(express.json());
  api.use((req, res) => res.status(418).json({ fellThrough: true }));
  return new Promise((resolve) => {
    const s = api.listen(0, '127.0.0.1', () => resolve(s));
  });
}

let server; let base;
before(async () => {
  server = await startServer(createGitHttpRouter({ limits: { ...GIT_HTTP_LIMITS, timeoutMs: 4000 } }));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server?.close(); });

const HOME = mkdtempSync(join(tmpdir(), 'crane-githttp-home-'));
const clientEnv = {
  PATH: process.env.PATH, HOME, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.invalid',
};
const urlFor = (slug, key) => `http://${key ? `anyone:${key}@` : ''}${base.slice('http://'.length)}/git/${slug}.git`;
async function git(args, cwd) {
  try {
    const r = await run('git', ['-c', 'credential.helper=', ...args], { cwd, env: clientEnv });
    return { code: 0, out: r.stdout + r.stderr };
  } catch (e) {
    return { code: e.code, out: String(e.stdout || '') + String(e.stderr || '') };
  }
}
let dirSeq = 0;
const freshDir = () => join(HOME, `w${++dirSeq}`);
const basic = (key) => `Basic ${Buffer.from(`u:${key}`).toString('base64')}`;
const auditRows = () => db.prepare("SELECT * FROM audit_log WHERE action = 'git-fetch' ORDER BY id").all();

test('a member clones the repo and gets the right files and commit; a later fetch sees a new push', async () => {
  const dir = freshDir();
  const r = await git(['clone', urlFor('gh-a', MEMBER.key), dir]);
  assert.equal(r.code, 0, r.out);
  assert.equal(readFileSync(join(dir, 'src/hello.txt'), 'utf8'), 'hello from crane\n');
  const head = (await run('git', ['rev-parse', 'HEAD'], { cwd: dir, env: clientEnv })).stdout.trim();
  assert.equal(head, await lg.getBranchHeadSha('gh-a', 'main'));

  await lg.pushFilesToManagedRepo('gh-a', [{ path: 'src/second.txt', content: 'two\n' }], { branch: 'main', message: 'second' });
  const f = await git(['fetch', 'origin'], dir);
  assert.equal(f.code, 0, f.out);
  const remoteMain = (await run('git', ['rev-parse', 'origin/main'], { cwd: dir, env: clientEnv })).stdout.trim();
  assert.equal(remoteMain, await lg.getBranchHeadSha('gh-a', 'main'));
});

test('agent branches: the caller sees their own, never another user\'s, and cannot fetch one by id', async () => {
  const mine = await git(['ls-remote', urlFor('gh-a', MEMBER.key)]);
  assert.equal(mine.code, 0, mine.out);
  assert.match(mine.out, new RegExp(`${OWN_AGENT}\\s+refs/heads/agent/${MEMBER.uid}/s1`));
  assert.ok(!mine.out.includes(PEER_AGENT), `peer agent branch leaked:\n${mine.out}`);
  assert.ok(!mine.out.includes(PREFIX_AGENT), `agent/${MEMBER.uid}0 leaked through a prefix match:\n${mine.out}`);
  assert.match(mine.out, /refs\/heads\/main/);

  const peer = await git(['ls-remote', urlFor('gh-a', PEER.key)]);
  assert.match(peer.out, new RegExp(`refs/heads/agent/${PEER.uid}/s2`));
  assert.ok(!peer.out.includes(OWN_AGENT), `member agent branch leaked to peer:\n${peer.out}`);

  for (const version of ['0', '2']) {
    const dir = freshDir();
    await git(['init', '-q', dir]);
    const r = await git(['-c', `protocol.version=${version}`, 'fetch', urlFor('gh-a', MEMBER.key), PEER_AGENT], dir);
    assert.notEqual(r.code, 0, `protocol.version=${version}: fetching another user's agent commit by id succeeded\n${r.out}`);
    const has = await git(['cat-file', '-e', PEER_AGENT], dir);
    assert.notEqual(has.code, 0, `protocol.version=${version}: peer's agent commit reached the client`);
  }
});

test('no credentials → 401 with a Basic challenge; a wrong key → 401', async () => {
  const none = await fetch(`${base}/git/gh-a.git/info/refs?service=git-upload-pack`);
  assert.equal(none.status, 401);
  assert.match(none.headers.get('www-authenticate') || '', /^Basic realm="AppCrane"/);
  const wrong = await fetch(`${base}/git/gh-a.git/info/refs?service=git-upload-pack`, { headers: { Authorization: basic(generateApiKey('dhk_user')) } });
  assert.equal(wrong.status, 401);
  assert.match(wrong.headers.get('www-authenticate') || '', /^Basic realm="AppCrane"/);
  const c = await git(['clone', urlFor('gh-a', 'dhk_user_wrong'), freshDir()]);
  assert.notEqual(c.code, 0);
});

test('no access, a "none" seat, an unknown slug and a GitHub-backed app are the same 404', async () => {
  const probe = async (slug, key) => {
    const r = await fetch(`${base}/git/${slug}.git/info/refs?service=git-upload-pack`, { headers: { Authorization: basic(key) } });
    return { status: r.status, body: await r.text(), type: r.headers.get('content-type') };
  };
  const outsider = await probe('gh-a', OUTSIDER.key);
  assert.equal(outsider.status, 404);
  assert.deepEqual(await probe('gh-a', VIEWER_NONE.key), outsider);
  assert.deepEqual(await probe('no-such-app', MEMBER.key), outsider);
  assert.deepEqual(await probe('gh-github', MEMBER.key), outsider);
  const c = await git(['clone', urlFor('gh-a', OUTSIDER.key), freshDir()]);
  assert.notEqual(c.code, 0);
  const admin = await git(['ls-remote', urlFor('gh-a', PLATFORM_ADMIN.key)]);
  assert.equal(admin.code, 0, `a platform admin is allowed on every app: ${admin.out}`);
});

test('git push is refused with a pointer to the supported path, and the repo is unchanged', async () => {
  const dir = freshDir();
  assert.equal((await git(['clone', urlFor('gh-a', MEMBER.key), dir])).code, 0);
  writeFileSync(join(dir, 'pushed.txt'), 'nope\n');
  await git(['add', 'pushed.txt'], dir);
  await git(['commit', '-qm', 'try push'], dir);
  const before = await lg.getBranchHeadSha('gh-a', 'main');
  const refsBefore = bareGit('for-each-ref');
  const p = await git(['push', 'origin', 'HEAD:main'], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /does not accept git push/);
  const p2 = await git(['push', 'origin', 'HEAD:refs/heads/sneaky'], dir);
  assert.notEqual(p2.code, 0, p2.out);
  assert.equal(await lg.getBranchHeadSha('gh-a', 'main'), before);
  assert.equal(bareGit('for-each-ref'), refsBefore);

  const post = await fetch(`${base}/git/gh-a.git/git-receive-pack`, {
    method: 'POST', headers: { Authorization: basic(MEMBER.key), 'Content-Type': 'application/x-git-receive-pack-request' }, body: '0000',
  });
  assert.equal(post.status, 403);
  const other = await fetch(`${base}/git/gh-a.git/info/refs?service=git-upload-archive`, { headers: { Authorization: basic(MEMBER.key) } });
  assert.equal(other.status, 403);
});

test('a deactivated user, a personal MCP key and a Crew agent token are refused', async () => {
  for (const [who, key, status] of [['deactivated', DEACTIVATED.key, 403], ['mcp key', MCP_KEY, 403], ['crew token', CREW_TOKEN, 401]]) {
    const r = await fetch(`${base}/git/gh-a.git/info/refs?service=git-upload-pack`, { headers: { Authorization: basic(key) } });
    assert.equal(r.status, status, `${who}: ${r.status} ${await r.text()}`);
    const c = await git(['clone', urlFor('gh-a', key), freshDir()]);
    assert.notEqual(c.code, 0, `${who} cloned`);
  }
});

test('a gzip-encoded upload-pack request is decoded and answered', async () => {
  const main = await lg.getBranchHeadSha('gh-a', 'main');
  const want = `want ${main} ofs-delta\n`;
  const body = `${(want.length + 4).toString(16).padStart(4, '0')}${want}00000009done\n`;
  const r = await fetch(`${base}/git/gh-a.git/git-upload-pack`, {
    method: 'POST',
    headers: { Authorization: basic(MEMBER.key), 'Content-Type': 'application/x-git-upload-pack-request', 'Content-Encoding': 'gzip' },
    body: gzipSync(Buffer.from(body)),
  });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('content-type'), 'application/x-git-upload-pack-result');
  assert.equal(r.headers.get('cache-control'), 'no-cache');
  const out = Buffer.from(await r.arrayBuffer());
  assert.equal(out.subarray(0, 8).toString(), '0008NAK\n');
  assert.ok(out.includes(Buffer.from('PACK')), 'no pack in the response');

  const adv = await fetch(`${base}/git/gh-a.git/info/refs?service=git-upload-pack`, { headers: { Authorization: basic(MEMBER.key) } });
  assert.equal(adv.headers.get('content-type'), 'application/x-git-upload-pack-advertisement');
  assert.ok((await adv.text()).startsWith('001e# service=git-upload-pack\n0000'));
});

function partialUploadPack(port) {
  const req = http.request({
    host: '127.0.0.1', port, method: 'POST', path: '/git/gh-a.git/git-upload-pack',
    headers: { Authorization: basic(MEMBER.key), 'Content-Type': 'application/x-git-upload-pack-request', 'Transfer-Encoding': 'chunked' },
  });
  req.on('error', () => {});
  req.write('0032want ');
  return req;
}
async function until(fn, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (fn()) return true; await new Promise((r) => setTimeout(r, 20)); }
  return fn();
}

test('the upload-pack child is killed when the client disconnects', async () => {
  assert.equal(activeUploadPacks(), 0);
  const req = partialUploadPack(server.address().port);
  assert.ok(await until(() => activeUploadPacks() === 1), 'upload-pack never started');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(activeUploadPacks(), 1, 'upload-pack ended on its own before the disconnect');
  req.destroy();
  assert.ok(await until(() => activeUploadPacks() === 0, 3000), 'upload-pack still running after the client went away');
});

test('the upload-pack child is killed at the timeout', async () => {
  const s = await startServer(createGitHttpRouter({ limits: { ...GIT_HTTP_LIMITS, timeoutMs: 300 } }));
  try {
    const req = partialUploadPack(s.address().port);
    const closed = new Promise((r) => req.on('close', r));
    assert.ok(await until(() => activeUploadPacks() === 1), 'upload-pack never started');
    assert.ok(await until(() => activeUploadPacks() === 0, 3000), 'upload-pack outlived the timeout');
    await closed;
  } finally { s.close(); }
});

test('an oversized request body is refused with 413', async () => {
  // A want, then have-lines for an object the repo lacks (a common one is ACKed
  // at once) with no terminating flush: upload-pack keeps reading, so the size
  // cap, not git, is what ends the request.
  const main = await lg.getBranchHeadSha('gh-a', 'main');
  const head = `0032want ${main}\n0000`;
  const have = `0032have ${'1'.repeat(40)}\n`;
  const body = head + have.repeat(Math.ceil(GIT_HTTP_LIMITS.maxBodyBytes / have.length) + 1);
  const r = await fetch(`${base}/git/gh-a.git/git-upload-pack`, {
    method: 'POST',
    headers: { Authorization: basic(MEMBER.key), 'Content-Type': 'application/x-git-upload-pack-request', 'Content-Encoding': 'gzip' },
    body: gzipSync(Buffer.from(body)),
  });
  assert.equal(r.status, 413);
  assert.ok(await until(() => activeUploadPacks() === 0));
});

test('path tricks and dumb-HTTP paths are 404', async () => {
  const raw = (path) => new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port: server.address().port, path, headers: { Authorization: basic(MEMBER.key) } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
  });
  for (const p of [
    '/git/gh-a/info/refs?service=git-upload-pack',
    '/git/gh-a.git.git/info/refs?service=git-upload-pack',
    '/git/GH-A.git/info/refs?service=git-upload-pack',
    '/git/gh-a.GIT/info/refs?service=git-upload-pack',
    '/git/..%2Fgh-a.git/info/refs?service=git-upload-pack',
    '/git/%2e%2e/gh-a.git/info/refs?service=git-upload-pack',
    '/git/x/../gh-a.git/info/refs?service=git-upload-pack',
    '/git/gh-b.git/../gh-a.git/info/refs?service=git-upload-pack',
    '/git/gh-a.git%2Finfo%2Frefs?service=git-upload-pack',
    '/git/-gh-a.git/info/refs?service=git-upload-pack',
    '/git/.git/info/refs?service=git-upload-pack',
    '/git/gh-a.git/HEAD',
    '/git/gh-a.git/objects/info/packs',
    '/git/gh-a.git/config',
    '/git/',
  ]) {
    assert.equal(await raw(p), 404, p);
  }
});

test('repo config the server did not write cannot run a pack-objects hook', async () => {
  const marker = join(ROOT, 'hook-ran');
  const hook = join(ROOT, 'hook.sh');
  writeFileSync(hook, `#!/bin/sh\ntouch "${marker}"\nexec "$@"\n`);
  chmodSync(hook, 0o755);
  bareGit('config', 'uploadpack.packObjectsHook', hook);
  try {
    const r = await git(['clone', urlFor('gh-a', MEMBER.key), freshDir()]);
    assert.equal(r.code, 0, r.out);
    assert.equal(existsSync(marker), false, 'repo-config packObjectsHook ran');
  } finally { bareGit('config', '--unset', 'uploadpack.packObjectsHook'); }
});

test('each clone/fetch is audited once, with who and which app, never the key', async () => {
  const n = auditRows().length;
  const r = await git(['clone', urlFor('gh-a', MEMBER.key), freshDir()]);
  assert.equal(r.code, 0, r.out);
  const rows = auditRows().slice(n);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].user_id, MEMBER.uid);
  assert.equal(rows[0].app_id, APP);
  assert.ok(!rows[0].detail.includes(MEMBER.key));
  for (const row of auditRows()) assert.ok(!row.detail.includes('dhk_'), 'a key reached the audit log');
});

test('repeated failed keys from one address are throttled', async () => {
  const s = await startServer(createGitHttpRouter());
  try {
    const url = `http://127.0.0.1:${s.address().port}/git/gh-a.git/info/refs?service=git-upload-pack`;
    const statuses = [];
    for (let i = 0; i < 31; i++) statuses.push((await fetch(url, { headers: { Authorization: basic(`dhk_user_bad${i}`) } })).status);
    assert.deepEqual(statuses.slice(0, 30), Array(30).fill(401));
    assert.equal(statuses[30], 429);
    assert.equal((await fetch(url, { headers: { Authorization: basic(MEMBER.key) } })).status, 429);
  } finally { s.close(); }
});

test('server/index.js mounts /git before the JSON body parser', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'index.js'), 'utf8');
  const mount = src.indexOf("app.use('/git', gitHttpRoutes)");
  const json = src.indexOf('app.use(express.json(');
  assert.ok(mount > 0 && json > 0 && mount < json);
});
