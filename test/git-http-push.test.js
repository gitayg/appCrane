import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import { mkdtempSync, writeFileSync, existsSync, chmodSync, mkdirSync, readdirSync } from 'fs';
import { randomBytes } from 'crypto';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// git push over HTTPS for Crane-hosted apps (routes/gitHttp.js POST
// git-receive-pack). Real git on both ends, as in git-http.test.js.

const run = promisify(execFile);
const ROOT = mkdtempSync(join(tmpdir(), 'crane-gitpush-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const { createGitHttpRouter } = await import('../server/routes/gitHttp.js');
const { GIT_HTTP_LIMITS, activeReceivePacks } = await import('../server/services/gitHttp.js');

let slot = 0;
const mkApp = (slug, backend = 'local') => db.prepare(`INSERT INTO apps (name, slug, slot, source_type, repo_backend) VALUES (?, ?, ?, 'managed', ?)`)
  .run(slug, slug, ++slot, backend).lastInsertRowid;
let seq = 0;
function mkUser({ role = 'user' } = {}) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const uid = db.prepare('INSERT INTO users (name, email, role, active, api_key_hash) VALUES (?, ?, ?, 1, ?)')
    .run(`gp${n}`, `gp${n}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { uid, key };
}
const seat = (appId, uid, tier) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(appId, uid, tier);

const APP = mkApp('gp-a');
const OTHER = mkApp('gp-b');
const GH = mkApp('gp-github', 'github');
const OWNER = mkUser();
const ADMIN = mkUser();
const MEMBER = mkUser();
const OUTSIDER = mkUser();
const PLATFORM_ADMIN = mkUser({ role: 'platform_admin' });
const VIEWER = mkUser();
seat(APP, OWNER.uid, 'owner');
seat(APP, ADMIN.uid, 'admin');
seat(APP, MEMBER.uid, 'user');
seat(APP, VIEWER.uid, 'owner');
seat(OTHER, OUTSIDER.uid, 'owner');
seat(GH, OWNER.uid, 'owner');
db.prepare(`INSERT INTO view_as_sessions (credential_hash, user_id, target_role, app_id, expires_at)
  VALUES (?, ?, 'admin', ?, datetime('now', '+60 minutes'))`).run(hashApiKey(VIEWER.key), VIEWER.uid, APP);

await lg.createAppRepo('gp-a');
await lg.pushFilesToManagedRepo('gp-a', [{ path: 'app.txt', content: 'one\n' }], { branch: 'main', message: 'one' });
await lg.createAppRepo('gp-b');
await lg.createAppRepo('gp-github');

const REPO = lg.repoPath('gp-a');
const bareGit = (...args) => execFileSync('git', ['--git-dir', REPO, ...args], {
  env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.invalid' },
}).toString().trim();
const tip = (ref) => { try { return bareGit('rev-parse', '--verify', '-q', ref); } catch (_) { return null; } };

const LIMITS = { ...GIT_HTTP_LIMITS, timeoutMs: 20_000, maxPushBytes: 2 * 1024 * 1024 };
let server; let base;
before(async () => {
  const api = express();
  api.use('/git', createGitHttpRouter({ limits: LIMITS }));
  server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
  base = `127.0.0.1:${server.address().port}`;
});
after(() => { server?.close(); });

const HOME = mkdtempSync(join(tmpdir(), 'crane-gitpush-home-'));
const clientEnv = {
  PATH: process.env.PATH, HOME, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.invalid',
};
const urlFor = (slug, key) => `http://anyone:${key}@${base}/git/${slug}.git`;
async function git(args, cwd) {
  try {
    const r = await run('git', ['-c', 'credential.helper=', ...args], { cwd, env: clientEnv, maxBuffer: 64 * 1024 * 1024 });
    return { code: 0, out: r.stdout + r.stderr };
  } catch (e) {
    return { code: e.code, out: String(e.stdout || '') + String(e.stderr || '') };
  }
}
let dirSeq = 0;
async function cloneAs(key, slug = 'gp-a') {
  const dir = join(HOME, `w${++dirSeq}`);
  const r = await git(['clone', urlFor(slug, key), dir]);
  assert.equal(r.code, 0, r.out);
  return dir;
}
async function commit(dir, name, content = `${name}\n`) {
  writeFileSync(join(dir, name), content);
  await git(['add', name], dir);
  const r = await git(['commit', '-qm', name], dir);
  assert.equal(r.code, 0, r.out);
  return (await git(['rev-parse', 'HEAD'], dir)).out.trim();
}
const pushRows = () => db.prepare("SELECT * FROM audit_log WHERE action IN ('git-push', 'git-push-refused') ORDER BY id").all()
  .map((r) => ({ ...r, detail: JSON.parse(r.detail) }));
function lastPushRow(since) {
  const rows = pushRows().slice(since);
  assert.equal(rows.length, 1, `expected one push audit row, got ${JSON.stringify(rows)}`);
  return rows[0];
}

test('an owner fast-forward push moves the branch and is audited with the refs it moved', async () => {
  const dir = await cloneAs(OWNER.key);
  const before = tip('refs/heads/main');
  const sha = await commit(dir, 'ff.txt');
  const n = pushRows().length;
  const p = await git(['push', 'origin', 'HEAD:main'], dir);
  assert.equal(p.code, 0, p.out);
  assert.equal(tip('refs/heads/main'), sha);
  const row = lastPushRow(n);
  assert.equal(row.action, 'git-push');
  assert.equal(row.user_id, OWNER.uid);
  assert.equal(row.app_id, APP);
  assert.equal(row.detail.transport, 'smart-http');
  assert.equal(row.detail.ip, '127.0.0.1');
  assert.deepEqual(row.detail.refs, [{ ref: 'refs/heads/main', old: before.slice(0, 12), new: sha.slice(0, 12), updated: true }]);
  assert.ok(!JSON.stringify(row).includes(OWNER.key), 'the key reached the audit log');
});

test('an app admin and a platform admin may push; a new branch and a new tag are accepted', async () => {
  for (const who of [ADMIN, PLATFORM_ADMIN]) {
    const dir = await cloneAs(who.key);
    const sha = await commit(dir, `by-${who.uid}.txt`);
    const p = await git(['push', 'origin', 'HEAD:main', `HEAD:refs/heads/feature-${who.uid}`], dir);
    assert.equal(p.code, 0, p.out);
    assert.equal(tip('refs/heads/main'), sha);
    assert.equal(tip(`refs/heads/feature-${who.uid}`), sha);
  }
  const dir = await cloneAs(OWNER.key);
  const t = await git(['tag', 'v1'], dir);
  assert.equal(t.code, 0, t.out);
  const p = await git(['push', 'origin', 'v1'], dir);
  assert.equal(p.code, 0, p.out);
  assert.equal(tip('refs/tags/v1'), tip('refs/heads/main'));
});

test('a force push is refused, git shows why, the ref is unchanged and the refusal is audited', async () => {
  const dir = await cloneAs(OWNER.key);
  await commit(dir, 'rewrite-base.txt');
  assert.equal((await git(['push', 'origin', 'HEAD:main'], dir)).code, 0);
  const before = tip('refs/heads/main');
  const reset = await git(['reset', '--hard', 'HEAD~1'], dir);
  assert.equal(reset.code, 0, reset.out);
  const rewritten = await commit(dir, 'rewritten.txt');
  const n = pushRows().length;
  const p = await git(['push', '--force', 'origin', 'HEAD:main'], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /\[remote rejected\] HEAD -> main \(non-fast-forward: AppCrane refuses force pushes/);
  assert.equal(tip('refs/heads/main'), before);
  const row = lastPushRow(n);
  assert.equal(row.action, 'git-push-refused');
  assert.deepEqual(row.detail.refs, [{ ref: 'refs/heads/main', old: before.slice(0, 12), new: rewritten.slice(0, 12), updated: false, reason: 'non-fast-forward: AppCrane refuses force pushes and history rewrites' }]);

  const rewind = await git(['push', '--force', 'origin', `${before}~1:main`], dir);
  assert.notEqual(rewind.code, 0, rewind.out);
  assert.equal(tip('refs/heads/main'), before, 'rewinding main to an older commit it already has');
});

test('a fast-forward pushed alongside a refused update does not land either', async () => {
  const dir = await cloneAs(OWNER.key);
  const main = tip('refs/heads/main');
  await commit(dir, 'side.txt');
  const p = await git(['push', 'origin', 'HEAD:main', ':refs/heads/feature-' + ADMIN.uid], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.equal(tip('refs/heads/main'), main);
  assert.match(p.out, /another ref in this push was refused/);
});

test('deleting a branch or a tag is refused and the ref survives', async () => {
  const dir = await cloneAs(OWNER.key);
  const feature = `refs/heads/feature-${ADMIN.uid}`;
  const had = tip(feature);
  assert.ok(had);
  const n = pushRows().length;
  const p = await git(['push', 'origin', `:${feature}`], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /AppCrane does not allow deleting a ref/);
  assert.equal(tip(feature), had);
  assert.equal(lastPushRow(n).detail.refs[0].reason, 'AppCrane does not allow deleting a ref');
  const t = await git(['push', 'origin', ':refs/tags/v1'], dir);
  assert.notEqual(t.code, 0, t.out);
  assert.ok(tip('refs/tags/v1'));
});

test('moving an existing tag is refused, even forced', async () => {
  const dir = await cloneAs(OWNER.key);
  const was = tip('refs/tags/v1');
  await commit(dir, 'tagmove.txt');
  assert.equal((await git(['push', 'origin', 'HEAD:main'], dir)).code, 0);
  await git(['tag', '-f', 'v1'], dir);
  const p = await git(['push', '--force', 'origin', 'refs/tags/v1'], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /AppCrane does not allow moving or replacing an existing tag/);
  assert.equal(tip('refs/tags/v1'), was);
});

test('refs outside branches and tags, and another user\'s agent branch, are refused', async () => {
  const dir = await cloneAs(OWNER.key);
  const sha = await commit(dir, 'odd.txt');
  for (const ref of ['refs/notes/x', 'refs/dropped/main/1-x', `refs/heads/agent/${MEMBER.uid}/s1`]) {
    const p = await git(['push', 'origin', `HEAD:${ref}`], dir);
    assert.notEqual(p.code, 0, `${ref}: ${p.out}`);
    assert.equal(tip(ref), null, ref);
  }
  const own = await git(['push', 'origin', `HEAD:refs/heads/agent/${OWNER.uid}/mine`], dir);
  assert.equal(own.code, 0, own.out);
  assert.equal(tip(`refs/heads/agent/${OWNER.uid}/mine`), sha);
});

test('a member who can clone but not push gets 403 and nothing changes; the refusal is audited', async () => {
  const dir = await cloneAs(MEMBER.key);
  await commit(dir, 'member.txt');
  const refs = bareGit('for-each-ref');
  const n = pushRows().length;
  const p = await git(['push', 'origin', 'HEAD:main'], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /requires admin or owner role/);
  assert.match(p.out, /403/);
  assert.equal(bareGit('for-each-ref'), refs);
  const row = lastPushRow(n);
  assert.equal(row.action, 'git-push-refused');
  assert.equal(row.user_id, MEMBER.uid);
  assert.equal(row.detail.reason, 'forbidden');

  const post = await fetch(`http://${base}/git/gp-a.git/git-receive-pack`, {
    method: 'POST',
    headers: { Authorization: `Basic ${Buffer.from(`u:${MEMBER.key}`).toString('base64')}`, 'Content-Type': 'application/x-git-receive-pack-request' },
    body: '0000',
  });
  assert.equal(post.status, 403);
  assert.equal(bareGit('for-each-ref'), refs);
});

test('a credential viewing as another role cannot push, even previewing an admin seat', async () => {
  const dir = await cloneAs(OWNER.key);
  await commit(dir, 'viewer.txt');
  const before = tip('refs/heads/main');
  const p = await git(['push', urlFor('gp-a', VIEWER.key), 'HEAD:main'], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /viewing as admin/);
  assert.equal(tip('refs/heads/main'), before);
});

test('not yours, unknown and GitHub-backed are the same 404 for push as for clone', async () => {
  const probe = async (slug, key) => {
    const r = await fetch(`http://${base}/git/${slug}.git/info/refs?service=git-receive-pack`, { headers: { Authorization: `Basic ${Buffer.from(`u:${key}`).toString('base64')}` } });
    return { status: r.status, body: await r.text() };
  };
  const outsider = await probe('gp-a', OUTSIDER.key);
  assert.equal(outsider.status, 404);
  assert.deepEqual(await probe('no-such-app', OWNER.key), outsider);
  assert.deepEqual(await probe('gp-github', OWNER.key), outsider);
  const dir = await cloneAs(OWNER.key);
  await commit(dir, 'outsider.txt');
  const before = tip('refs/heads/main');
  const p = await git(['push', urlFor('gp-a', OUTSIDER.key), 'HEAD:main'], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /404|not found/i);
  assert.equal(tip('refs/heads/main'), before);
});

test('a push over the size cap is refused with a message git prints, the ref is unchanged, and it is audited', async () => {
  const dir = await cloneAs(OWNER.key);
  const before = tip('refs/heads/main');
  await commit(dir, 'big.bin', randomBytes(LIMITS.maxPushBytes + 512 * 1024).toString('base64'));
  const n = pushRows().length;
  const p = await git(['push', 'origin', 'HEAD:main'], dir);
  assert.notEqual(p.code, 0, p.out);
  assert.match(p.out, /\[remote rejected\] HEAD -> main \(the pack is larger than AppCrane's 2 MiB push limit\)/);
  assert.equal(tip('refs/heads/main'), before);
  const row = lastPushRow(n);
  assert.equal(row.action, 'git-push-refused');
  assert.equal(row.detail.reason, 'too large');
  assert.ok(row.detail.bytes > LIMITS.maxPushBytes);
  const end = Date.now() + 3000;
  while (activeReceivePacks() !== 0 && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
  assert.equal(activeReceivePacks(), 0);

  const declared = await fetch(`http://${base}/git/gp-a.git/git-receive-pack`, {
    method: 'POST',
    headers: { Authorization: `Basic ${Buffer.from(`u:${OWNER.key}`).toString('base64')}`, 'Content-Type': 'application/x-git-receive-pack-request' },
    body: Buffer.alloc(LIMITS.maxPushBytes + 1),
  });
  assert.equal(declared.status, 413);
  assert.match(await declared.text(), /larger than AppCrane's 2 MiB push limit/);
  assert.equal(tip('refs/heads/main'), before);
});

test('hooks planted in the bare repo, and a core.hooksPath in its config, never run', async () => {
  const marker = join(ROOT, 'hook-ran');
  const hookDir = join(ROOT, 'evil-hooks');
  mkdirSync(join(REPO, 'hooks'), { recursive: true });
  mkdirSync(hookDir, { recursive: true });
  for (const d of [join(REPO, 'hooks'), hookDir]) {
    for (const h of ['pre-receive', 'update', 'post-receive', 'post-update', 'reference-transaction', 'proc-receive', 'push-to-checkout']) {
      writeFileSync(join(d, h), `#!/bin/sh\necho "${h} $0" >> "${marker}"\ncat >/dev/null\nexit 0\n`);
      chmodSync(join(d, h), 0o755);
    }
  }
  bareGit('config', 'core.hooksPath', hookDir);
  try {
    const dir = await cloneAs(OWNER.key);
    const sha = await commit(dir, 'hooked.txt');
    const p = await git(['push', 'origin', 'HEAD:main'], dir);
    assert.equal(p.code, 0, p.out);
    assert.equal(tip('refs/heads/main'), sha);
    assert.equal(existsSync(marker), false, 'a server-side hook ran');
  } finally { bareGit('config', '--unset', 'core.hooksPath'); }
});

test('git\'s own layer, run with the server\'s pinned config and AppCrane\'s checks bypassed, still refuses a force push and a deletion even when repo config allows them', async () => {
  const { receivePackArgs } = await import('../server/services/gitHttp.js');
  const { args, env } = receivePackArgs('gp-a', { userId: OWNER.uid, advertiseRefs: false });
  const pinned = args.slice(0, args.indexOf('receive-pack'));
  const q = (v) => `'${String(v).replace(/'/g, `'\\''`)}'`;
  const wrapper = join(ROOT, 'pinned-receive-pack.sh');
  writeFileSync(wrapper, `#!/bin/sh\n${Object.entries(env).map(([k, v]) => `export ${k}=${q(v)}`).join('\n')}\nexec git ${pinned.map(q).join(' ')} receive-pack "$@"\n`);
  chmodSync(wrapper, 0o755);
  bareGit('config', 'receive.denyNonFastForwards', 'false');
  bareGit('config', 'receive.denyDeletes', 'false');
  try {
    const dir = await cloneAs(OWNER.key);
    const main = tip('refs/heads/main');
    const feature = `refs/heads/feature-${ADMIN.uid}`;
    const had = tip(feature);
    await git(['reset', '--hard', 'HEAD~1'], dir);
    await commit(dir, 'git-layer.txt');
    const force = await git(['push', '--force', `--receive-pack=${wrapper}`, REPO, 'HEAD:main'], dir);
    assert.notEqual(force.code, 0, force.out);
    assert.match(force.out, /non-fast-forward/);
    assert.equal(tip('refs/heads/main'), main);
    const del = await git(['push', `--receive-pack=${wrapper}`, REPO, `:${feature}`], dir);
    assert.notEqual(del.code, 0, del.out);
    assert.match(del.out, /deletion prohibited/);
    assert.equal(tip(feature), had);
  } finally {
    bareGit('config', '--unset', 'receive.denyNonFastForwards');
    bareGit('config', '--unset', 'receive.denyDeletes');
  }
});

test('the push spool is removed and nothing is left in the repo or temp dir', async () => {
  const spools = () => readdirSync(tmpdir()).filter((n) => n.startsWith('appcrane-receive-'));
  const before = spools().length;
  const dir = await cloneAs(OWNER.key);
  await commit(dir, 'spool.txt');
  assert.equal((await git(['push', 'origin', 'HEAD:main'], dir)).code, 0);
  assert.ok(spools().length <= before, 'a receive spool was left behind');
  bareGit('fsck', '--no-progress', '--strict');
});

const recorded = (appId) => db.prepare('SELECT last_managed_push_sha AS s FROM apps WHERE id = ?').get(appId).s;
const deployments = (appId) => db.prepare('SELECT COUNT(*) AS n FROM deployments WHERE app_id = ?').get(appId).n;
async function verifyDeploy(slug, appId, branch) {
  const { verifyCommitSha } = await import('../server/services/supplyChain.js');
  const rel = join(HOME, `release-${++dirSeq}`);
  lg.cloneForDeploySync(slug, rel, branch);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  const logs = [];
  return verifyCommitSha(app, rel, branch, (l) => logs.push(l)).then(() => ({ ok: true, logs }), (e) => ({ ok: false, error: e.message }));
}

test('a push that moves the deploy branch is recorded like an AppCrane push, so the next deploy\'s supply-chain verify passes; nothing is deployed', async () => {
  db.prepare('UPDATE apps SET last_managed_push_sha = ? WHERE id = ?').run(tip('refs/heads/main'), APP);
  const dir = await cloneAs(OWNER.key);
  const sha = await commit(dir, 'deployable.txt');
  const n = pushRows().length;
  const p = await git(['push', 'origin', 'HEAD:main'], dir);
  assert.equal(p.code, 0, p.out);
  assert.equal(recorded(APP), sha);
  assert.equal(lastPushRow(n).detail.recorded_push_sha, sha.slice(0, 12));
  const v = await verifyDeploy('gp-a', APP, 'main');
  assert.equal(v.ok, true, v.error);
  assert.equal(deployments(APP), 0, 'a git push started a deploy');
});

test('a push to another branch, a refused push and a forbidden push leave the recorded commit alone', async () => {
  const dir = await cloneAs(OWNER.key);
  await commit(dir, 'base-for-record.txt');
  assert.equal((await git(['push', 'origin', 'HEAD:main'], dir)).code, 0);
  const rec = recorded(APP);
  assert.equal(rec, tip('refs/heads/main'));

  await commit(dir, 'side-branch.txt');
  const side = await git(['push', 'origin', 'HEAD:refs/heads/side-record'], dir);
  assert.equal(side.code, 0, side.out);
  assert.equal(recorded(APP), rec, 'a non-deploy branch push moved the record');

  await git(['reset', '--hard', 'HEAD~2'], dir);
  await commit(dir, 'forced-record.txt');
  const forced = await git(['push', '--force', 'origin', 'HEAD:main'], dir);
  assert.notEqual(forced.code, 0, forced.out);
  assert.equal(recorded(APP), rec, 'a refused push moved the record');

  const mdir = await cloneAs(MEMBER.key);
  await commit(mdir, 'member-record.txt');
  assert.notEqual((await git(['push', 'origin', 'HEAD:main'], mdir)).code, 0);
  assert.equal(recorded(APP), rec, 'a forbidden push moved the record');
  assert.equal((await verifyDeploy('gp-a', APP, 'main')).ok, true);
});

test('the deploy branch is the app\'s own branch, not main', async () => {
  const id = mkApp('gp-c');
  db.prepare("UPDATE apps SET branch = 'prod' WHERE id = ?").run(id);
  seat(id, OWNER.uid, 'owner');
  await lg.createAppRepo('gp-c');
  await lg.pushFilesToManagedRepo('gp-c', [{ path: 'x.txt', content: 'x\n' }], { branch: 'main', message: 'x' });
  const dir = await cloneAs(OWNER.key, 'gp-c');
  const sha = await commit(dir, 'prod.txt');
  assert.equal((await git(['push', 'origin', 'HEAD:main'], dir)).code, 0);
  assert.equal(recorded(id), null, 'a push to main recorded an app that deploys prod');
  assert.equal((await git(['push', 'origin', 'HEAD:refs/heads/prod'], dir)).code, 0);
  assert.equal(recorded(id), sha);
  const v = await verifyDeploy('gp-c', id, 'prod');
  assert.equal(v.ok, true, v.error);
});
