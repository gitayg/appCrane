import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawn } from 'child_process';
import http from 'node:http';
import express from 'express';

// Export of a Crane-hosted app's repo to GitHub, with real git on both sides:
// the app's bare repo under DATA_DIR/repos, and a bare "GitHub" repo served
// over smart HTTP by `git http-backend` behind a local server that demands
// the token the credential seam hands out. Helpers copied from
// github-sync-status.test.js (not exported there).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-github-export-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'debug';

const TOKEN = 'ghs_ExportSecretToken1234567890abcd';
const TOKEN_B64 = Buffer.from(`x-access-token:${TOKEN}`).toString('base64');
const SVC_TOKEN = 'ghp_ServiceAccountTokenMustNotBeUsed000';
const SVC_B64 = Buffer.from(`x-access-token:${SVC_TOKEN}`).toString('base64');

const logged = [];
const origLog = console.log;
console.log = (...a) => { logged.push(a.join(' ')); };

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const sync = await import('../server/services/githubSyncStatus.js');
const ex = await import('../server/services/githubExport.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { getServiceTokenInternal } = await import('../server/services/githubService.js');

const GH_ROOT = join(ROOT, 'github');
mkdirSync(GH_ROOT, { recursive: true });
const CLEAN = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C',
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.com', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.com' };
const git = (dir, ...args) => execFileSync('git', [`--git-dir=${dir}`, ...args], { env: CLEAN }).toString().trim();
const tip = (dir, ref) => { try { return git(dir, 'rev-parse', '--verify', '--quiet', ref); } catch (_) { return null; } };

function commitOn(dir, branch, msg) {
  const parent = tip(dir, `refs/heads/${branch}`);
  const blob = execFileSync('git', [`--git-dir=${dir}`, 'hash-object', '-w', '--stdin'], { env: CLEAN, input: msg }).toString().trim();
  const tree = execFileSync('git', [`--git-dir=${dir}`, 'mktree'], { env: CLEAN, input: `100644 blob ${blob}\tf.txt\n` }).toString().trim();
  const c = git(dir, 'commit-tree', tree, ...(parent ? ['-p', parent] : []), '-m', msg);
  git(dir, 'update-ref', `refs/heads/${branch}`, c);
  return c;
}

function pushTo(from, to, branch) {
  execFileSync('git', [`--git-dir=${from}`, 'push', '--quiet', '--force', to, `refs/heads/${branch}:refs/heads/${branch}`], { env: CLEAN });
}

let mode = 'ok';
const seenAuth = [];
let ghServer;
let GH_BASE;
function startGithub() {
  return new Promise((res) => {
    ghServer = http.createServer((req, resp) => {
      seenAuth.push(req.headers.authorization || null);
      if (req.headers.authorization !== `Basic ${TOKEN_B64}`) {
        resp.writeHead(401, { 'WWW-Authenticate': 'Basic realm="GitHub"' });
        return resp.end();
      }
      const u = new URL(req.url, 'http://x');
      const path = decodeURIComponent(u.pathname);
      const child = spawn('git', ['http-backend'], {
        env: {
          ...CLEAN, GIT_PROJECT_ROOT: GH_ROOT, GIT_HTTP_EXPORT_ALL: '1', REQUEST_METHOD: req.method,
          PATH_INFO: path, QUERY_STRING: u.search.slice(1), REMOTE_USER: 'gh',
          CONTENT_TYPE: req.headers['content-type'] || '', HTTP_CONTENT_ENCODING: req.headers['content-encoding'] || '',
          GIT_PROTOCOL: req.headers['git-protocol'] || '', REMOTE_ADDR: '127.0.0.1',
        },
      });
      req.pipe(child.stdin);
      const chunks = [];
      child.stdout.on('data', (c) => chunks.push(c));
      child.on('close', () => {
        // 'lie': after a push lands, something else moves the branch, so
        // GitHub then reports a tip other than the one AppCrane pushed.
        if (mode === 'lie' && path.endsWith('/git-receive-pack')) {
          const dir = join(GH_ROOT, path.split('/')[1]);
          commitOn(dir, 'main', 'moved-behind-our-back');
        }
        const buf = Buffer.concat(chunks);
        const sep = buf.indexOf('\r\n\r\n');
        const head = buf.subarray(0, sep).toString();
        const headers = {};
        let status = 200;
        for (const l of head.split('\r\n')) {
          const i = l.indexOf(':');
          const k = l.slice(0, i).trim();
          const v = l.slice(i + 1).trim();
          if (k.toLowerCase() === 'status') status = Number(v.split(' ')[0]);
          else headers[k] = v;
        }
        resp.writeHead(status, headers);
        resp.end(buf.subarray(sep + 4));
      });
    });
    ghServer.listen(0, '127.0.0.1', () => { GH_BASE = `http://127.0.0.1:${ghServer.address().port}`; res(); });
  });
}

const spawned = [];
function recordingSpawn(cmd, args, opts) {
  spawned.push({ args: [...args], env: { ...opts.env } });
  return spawn(cmd, args, opts);
}

let slot = 900;
async function makeApp(slug, { github = true, branch = 'main' } = {}) {
  await lg.createAppRepo(slug);
  const ghDir = join(GH_ROOT, `${slug}.git`);
  execFileSync('git', ['init', '--bare', '--quiet', '-b', branch, ghDir], { env: CLEAN });
  pushTo(lg.repoPath(slug), ghDir, branch);
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch,github_url) VALUES (?,?,?,'managed','local',?,?)")
    .run(slug, slug, slot++, branch, github ? `https://github.com/acme/${slug}` : null).lastInsertRowid);
  return { app: db.prepare('SELECT * FROM apps WHERE id = ?').get(id), crane: lg.repoPath(slug), gh: ghDir };
}

let clock = 10_000_000;
function useResolver(resolveRemote, extra = {}) {
  clock += 60_000;
  const common = { spawn: recordingSpawn, allowedSchemes: ['http'], now: () => clock };
  sync._setGithubSyncDepsForTests({ ...common, resolveRemote });
  ex._setGithubExportDepsForTests({ ...common, resolveRemote, ...extra });
}
const useRemote = (url, extra) => useResolver(async () => ({ url, token: TOKEN, credential: 'installation' }), extra);
const auditRows = (appId) => db.prepare("SELECT * FROM audit_log WHERE app_id = ? AND action = 'github-export' ORDER BY id").all(appId)
  .map((r) => ({ ...r, detail: JSON.parse(r.detail) }));

before(startGithub);
after(() => {
  console.log = origLog;
  ghServer?.closeAllConnections?.();
  ghServer?.close();
  sync._setGithubSyncDepsForTests(null);
  ex._setGithubExportDepsForTests(null);
});

test('fast-forward: AppCrane is 2 commits ahead; the export pushes them and verifies GitHub\'s tip equals AppCrane\'s', async () => {
  const { app, crane, gh } = await makeApp('ff-app');
  const old = tip(gh, 'refs/heads/main');
  commitOn(crane, 'main', 'c1');
  const local = commitOn(crane, 'main', 'c2');
  git(crane, 'tag', '-a', 'v1.0.0', '-m', 'release', local);
  useRemote(`${GH_BASE}/ff-app.git`);
  const r = await ex.exportToGithub(app, { userId: null });
  assert.deepEqual([r.ok, r.state, r.verified, r.reason_code], [true, 'pushed', true, null], JSON.stringify(r));
  assert.equal(r.local_sha, local);
  assert.equal(r.github_sha_after, local);
  assert.equal(tip(gh, 'refs/heads/main'), local, 'GitHub really has the new tip');
  assert.equal(tip(gh, 'refs/tags/v1.0.0'), tip(crane, 'refs/tags/v1.0.0'), 'the annotated tag was pushed');
  const branchRow = r.refs.find((x) => x.ref === 'refs/heads/main');
  assert.deepEqual([branchRow.old_sha, branchRow.new_sha, branchRow.remote_sha, branchRow.status], [old, local, local, 'updated']);
  assert.equal(r.refs.find((x) => x.ref === 'refs/tags/v1.0.0').status, 'created');

  const status = await sync.getGithubSyncStatus(app);
  assert.equal(status.state, 'same', 'the ahead/behind status is re-measured after an export, not served stale from cache');

  const again = await ex.exportToGithub(app);
  assert.deepEqual([again.ok, again.state, again.verified], [true, 'up_to_date', true], JSON.stringify(again));
});

test('GitHub ahead: refused before pushing, and nothing on GitHub changes', async () => {
  const { app, crane, gh } = await makeApp('behind-app');
  commitOn(crane, 'main', 'crane-only');
  git(crane, 'tag', 'v-crane', tip(crane, 'refs/heads/main'));
  const ghTip = commitOn(gh, 'main', 'gh-only');
  const ghRefsBefore = git(gh, 'for-each-ref');
  useRemote(`${GH_BASE}/behind-app.git`);
  spawned.length = 0;
  const r = await ex.exportToGithub(app);
  assert.deepEqual([r.ok, r.state, r.reason_code, r.verified], [false, 'refused', 'github_ahead', false], JSON.stringify(r));
  assert.match(r.reason, /never force-pushes/);
  assert.equal(tip(gh, 'refs/heads/main'), ghTip);
  assert.equal(git(gh, 'for-each-ref'), ghRefsBefore, 'no ref on GitHub moved, the tag was not pushed either');
  assert.ok(!spawned.some((s) => s.args.includes('push')), 'git push never ran');
});

test('GitHub ahead after a stale check: the push itself is fast-forward only and atomic, so nothing lands', async () => {
  const { app, crane, gh } = await makeApp('race-app');
  commitOn(crane, 'main', 'crane-only');
  git(crane, 'tag', 'v-race', tip(crane, 'refs/heads/main'));
  const ghTip = commitOn(gh, 'main', 'gh-only');
  useRemote(`${GH_BASE}/race-app.git`, {
    syncStatus: async () => ({ state: 'ahead', ahead: 1, behind: 0, github_sha: null }),
  });
  const r = await ex.exportToGithub(app);
  assert.deepEqual([r.ok, r.state, r.reason_code], [false, 'refused', 'github_ahead'], JSON.stringify(r));
  assert.equal(tip(gh, 'refs/heads/main'), ghTip, 'GitHub branch untouched');
  assert.equal(tip(gh, 'refs/tags/v-race'), null, 'atomic: the tag did not land either');
});

test('tag conflict: GitHub already has the tag at another commit; nothing is pushed', async () => {
  const { app, crane, gh } = await makeApp('tag-app');
  const base = tip(gh, 'refs/heads/main');
  commitOn(crane, 'main', 'c1');
  git(crane, 'tag', 'v2', tip(crane, 'refs/heads/main'));
  git(gh, 'tag', 'v2', base);
  useRemote(`${GH_BASE}/tag-app.git`);
  const r = await ex.exportToGithub(app);
  assert.deepEqual([r.ok, r.state, r.reason_code], [false, 'refused', 'tag_conflict'], JSON.stringify(r));
  assert.equal(tip(gh, 'refs/heads/main'), base, 'branch not moved: the push was atomic');
  assert.equal(tip(gh, 'refs/tags/v2'), base);
});

test('verify mismatch: GitHub reports a different tip after the push, and the export is a failure', async () => {
  const { app, crane } = await makeApp('lie-app');
  const local = commitOn(crane, 'main', 'c1');
  useRemote(`${GH_BASE}/lie-app.git`);
  mode = 'lie';
  let r;
  try { r = await ex.exportToGithub(app); } finally { mode = 'ok'; }
  assert.deepEqual([r.ok, r.state, r.reason_code, r.verified], [false, 'failed', 'verify_mismatch', false], JSON.stringify(r));
  assert.notEqual(r.github_sha_after, local);
  assert.ok(r.github_sha_after);
  assert.equal(r.refs.find((x) => x.ref === 'refs/heads/main').remote_sha, r.github_sha_after);
});

function setServiceToken() {
  db.prepare("INSERT INTO settings (key, value) VALUES ('github_service_token_enc', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(encrypt(SVC_TOKEN));
  assert.equal(getServiceTokenInternal(), SVC_TOKEN, 'precondition: the service token is configured and readable');
}

test('local app: the service-account token is never used; with no own credential the export is refused', async () => {
  setServiceToken();
  const { app, crane, gh } = await makeApp('svc-app');
  commitOn(crane, 'main', 'c1');
  const ghBefore = tip(gh, 'refs/heads/main');
  const realMoved = async (a) => ({ ...(await sync.defaultResolveRemote(a)), url: `${GH_BASE}/svc-app.git` });
  useResolver(realMoved);
  seenAuth.length = 0;
  spawned.length = 0;
  const r = await ex.exportToGithub(app);
  assert.deepEqual([r.ok, r.state, r.reason_code, r.credential], [false, 'refused', 'no_credential', 'none'], JSON.stringify(r));
  assert.equal(tip(gh, 'refs/heads/main'), ghBefore);
  assert.ok(!seenAuth.includes(`Basic ${SVC_B64}`));
  for (const s of spawned) assert.ok(!JSON.stringify(s).includes(SVC_B64) && !JSON.stringify(s).includes(SVC_TOKEN));

  db.prepare('UPDATE apps SET github_token_encrypted = ? WHERE id = ?').run(encrypt(TOKEN), app.id);
  const withPat = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  seenAuth.length = 0;
  const r2 = await ex.exportToGithub(withPat);
  assert.deepEqual([r2.ok, r2.credential, r2.verified], [true, 'pat', true], JSON.stringify(r2));
  assert.ok(seenAuth.includes(`Basic ${TOKEN_B64}`), 'the app\'s own PAT was used');
  assert.ok(!seenAuth.includes(`Basic ${SVC_B64}`), 'the service token never reached GitHub');
});

test('the token reaches GitHub only as a header: never in a URL, argv, log line or result', async () => {
  const { app, crane } = await makeApp('tok-app');
  commitOn(crane, 'main', 'x');
  seenAuth.length = 0;
  spawned.length = 0;
  logged.length = 0;
  useRemote(`${GH_BASE}/tok-app.git`);
  const r = await ex.exportToGithub(app);
  assert.equal(r.ok, true, JSON.stringify(r));
  const pushes = spawned.filter((s) => s.args.includes('push'));
  assert.equal(pushes.length, 1);
  assert.ok(!pushes[0].args.some((a) => a.startsWith('+') || a === '--force' || a === '-f'), `force in argv: ${pushes[0].args.join(' ')}`);
  for (const s of spawned) {
    const argv = s.args.join(' ');
    assert.ok(!argv.includes(TOKEN) && !argv.includes(TOKEN_B64), `token in argv: ${argv}`);
    for (const a of s.args) if (/^https?:/.test(a)) assert.equal(new URL(a).username + new URL(a).password, '');
    assert.ok(s.args.includes('core.hooksPath=/dev/null'), 'hooks disabled');
  }
  for (const s of spawned.filter((x) => x.args.includes('push') || x.args.includes('ls-remote'))) {
    assert.equal(s.env.GIT_CONFIG_VALUE_0, `Authorization: Basic ${TOKEN_B64}`);
  }
  const { app: bad } = await makeApp('tok-bad-app');
  commitOn(lg.repoPath('tok-bad-app'), 'main', 'x');
  useResolver(async () => ({ url: `${GH_BASE}/tok-bad-app.git`, token: 'ghs_WrongTokenForLogCheck', credential: 'pat' }),
    { syncStatus: async () => ({ state: 'ahead', ahead: 1, behind: 0, github_sha: null }) });
  const failedR = await ex.exportToGithub(bad);
  assert.equal(failedR.reason_code, 'auth_failed', JSON.stringify(failedR));
  const all = logged.join('\n');
  assert.ok(!all.includes(TOKEN) && !all.includes(TOKEN_B64) && !all.includes('ghs_WrongTokenForLogCheck'), 'token in a log line');
  assert.ok(!JSON.stringify(r).includes(TOKEN) && !JSON.stringify(failedR).includes('ghs_WrongTokenForLogCheck'));
  assert.ok(!JSON.stringify(auditRows(bad.id)).includes('ghs_WrongTokenForLogCheck'));
});

test('audit: one github-export row per export, with who, refs, old/new SHAs and verified', async () => {
  const uid = Number(db.prepare("INSERT INTO users (name,email,role,active,kind) VALUES ('Aud','aud@t.test','user',1,'human')").run().lastInsertRowid);
  const { app, crane, gh } = await makeApp('audit-app');
  const old = tip(gh, 'refs/heads/main');
  const local = commitOn(crane, 'main', 'c1');
  useRemote(`${GH_BASE}/audit-app.git`);
  await ex.exportToGithub(app, { userId: uid });
  commitOn(gh, 'main', 'gh-only');
  await ex.exportToGithub(app, { userId: uid });
  const rows = auditRows(app.id);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].user_id, uid);
  assert.equal(rows[0].actor_kind, 'human');
  assert.deepEqual([rows[0].detail.ok, rows[0].detail.verified, rows[0].detail.state], [true, true, 'pushed']);
  assert.deepEqual(rows[0].detail.refs.find((x) => x.ref === 'refs/heads/main'),
    { ref: 'refs/heads/main', old_sha: old, new_sha: local, remote_sha: local, status: 'updated' });
  assert.deepEqual([rows[1].detail.ok, rows[1].detail.verified, rows[1].detail.reason_code], [false, false, 'github_ahead']);
});

test('route: owners and platform admins may export; app admin and user get 403; a non-member gets 403 as release-check does; not Crane-hosted / no github_url is 404', async () => {
  const { app, crane } = await makeApp('route-app');
  commitOn(crane, 'main', 'c1');
  const { app: noGh } = await makeApp('route-nogh-app', { github: false });
  const connected = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url) VALUES ('rc','route-connected',?,'github','https://github.com/acme/route-connected')").run(slot++).lastInsertRowid);
  useRemote(`${GH_BASE}/route-app.git`);
  const mk = (name, role = 'user') => {
    const key = generateApiKey('dhk_x');
    const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')").run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid);
    return { id, key };
  };
  const owner = mk('rowner');
  const admin = mk('radmin');
  const user = mk('ruser');
  const outsider = mk('rout');
  const pa = mk('rpa', 'platform_admin');
  const seat = (appId, uid, r) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(appId, uid, r);
  seat(app.id, owner.id, 'owner');
  seat(app.id, admin.id, 'admin');
  seat(app.id, user.id, 'user');
  seat(noGh.id, owner.id, 'owner');
  seat(connected, owner.id, 'owner');

  const api = express();
  api.use(express.json());
  api.use('/api', (await import('../server/routes/githubExport.js')).default);
  api.use('/api', (await import('../server/routes/releaseCheck.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  const BASE = `http://127.0.0.1:${server.address().port}`;
  try {
    const call = async (method, path, key) => {
      const r = await fetch(`${BASE}${path}`, { method, headers: { 'Content-Type': 'application/json', ...(key ? { 'X-API-Key': key } : {}) }, body: method === 'POST' ? '{}' : undefined });
      return { status: r.status, body: await r.json() };
    };
    const post = (slug, key) => call('POST', `/api/apps/${slug}/github-export`, key);
    assert.equal((await post('route-app', null)).status, 401);
    const out = await post('route-app', outsider.key);
    assert.equal(out.status, 403);
    assert.deepEqual(out, await call('GET', '/api/apps/route-app/release-check', outsider.key), 'same refusal as the neighbour');
    assert.equal((await post('route-app', admin.key)).status, 403);
    assert.equal((await post('route-app', user.key)).status, 403);
    assert.equal(auditRows(app.id).length, 0, 'refused callers never reached the export');
    assert.equal((await post('no-such-app', owner.key)).status, 404);
    assert.equal((await post('route-nogh-app', owner.key)).status, 404);
    assert.equal((await post('route-connected', owner.key)).status, 404);
    const ok = await post('route-app', owner.key);
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.deepEqual([ok.body.state, ok.body.verified], ['pushed', true]);
    const paR = await post('route-app', pa.key);
    assert.equal(paR.status, 200, JSON.stringify(paR.body));
    assert.equal(paR.body.state, 'up_to_date');
    commitOn(join(GH_ROOT, 'route-app.git'), 'main', 'gh-only');
    const refused = await post('route-app', owner.key);
    assert.equal(refused.status, 409);
    assert.equal(refused.body.error.code, 'GITHUB_AHEAD');
    assert.equal(refused.body.error.state, 'refused');
    assert.equal(auditRows(app.id).length, 3);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});
