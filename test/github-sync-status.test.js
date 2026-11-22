import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync, spawn } from 'child_process';
import http from 'node:http';
import express from 'express';

// GitHub-vs-AppCrane comparison for a Crane-hosted app, with real git on both
// sides: the app's bare repo under DATA_DIR/repos, and a bare "GitHub" repo
// served over smart HTTP by `git http-backend` behind a local server that
// demands the token the credential seam hands out.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-github-sync-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'debug';

const TOKEN = 'ghs_SyncCheckSecretToken1234567890';
const TOKEN_B64 = Buffer.from(`x-access-token:${TOKEN}`).toString('base64');

const logged = [];
const origLog = console.log;
console.log = (...a) => { logged.push(a.join(' ')); };

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const sync = await import('../server/services/githubSyncStatus.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');

const GH_ROOT = join(ROOT, 'github');
mkdirSync(GH_ROOT, { recursive: true });
const CLEAN = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C',
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.com', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.com' };
const git = (dir, ...args) => execFileSync('git', [`--git-dir=${dir}`, ...args], { env: CLEAN }).toString().trim();

function commitOn(dir, branch, msg) {
  let parent = null;
  try { parent = git(dir, 'rev-parse', '--verify', '--quiet', `refs/heads/${branch}`); } catch (_) { /* root */ }
  const blob = execFileSync('git', [`--git-dir=${dir}`, 'hash-object', '-w', '--stdin'], { env: CLEAN, input: msg }).toString().trim();
  const tree = execFileSync('git', [`--git-dir=${dir}`, 'mktree'], { env: CLEAN, input: `100644 blob ${blob}\tf.txt\n` }).toString().trim();
  const c = git(dir, 'commit-tree', tree, ...(parent ? ['-p', parent] : []), '-m', msg);
  git(dir, 'update-ref', `refs/heads/${branch}`, c);
  return c;
}

// Copy objects + set a ref from one bare repo to another (a dual push, done by hand).
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
      if (mode === 'saml') {
        resp.writeHead(403, { 'Content-Type': 'text/plain' });
        return resp.end('Resource protected by organization SAML enforcement. You must grant your Personal Access token access to this organization.');
      }
      if (req.headers.authorization !== `Basic ${TOKEN_B64}`) {
        resp.writeHead(401, { 'WWW-Authenticate': 'Basic realm="GitHub"' });
        return resp.end();
      }
      const u = new URL(req.url, 'http://x');
      const child = spawn('git', ['http-backend'], {
        env: {
          ...CLEAN, GIT_PROJECT_ROOT: GH_ROOT, GIT_HTTP_EXPORT_ALL: '1', REQUEST_METHOD: req.method,
          PATH_INFO: decodeURIComponent(u.pathname), QUERY_STRING: u.search.slice(1),
          CONTENT_TYPE: req.headers['content-type'] || '', HTTP_CONTENT_ENCODING: req.headers['content-encoding'] || '',
          GIT_PROTOCOL: req.headers['git-protocol'] || '', REMOTE_ADDR: '127.0.0.1',
        },
      });
      req.pipe(child.stdin);
      const chunks = [];
      child.stdout.on('data', (c) => chunks.push(c));
      child.on('close', () => {
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

function useRemote(url) {
  sync._setGithubSyncDepsForTests({
    spawn: recordingSpawn,
    allowedSchemes: ['http'],
    resolveRemote: async () => ({ url, token: TOKEN, credential: 'installation' }),
  });
}

const snapshot = (dir) => ({
  refs: git(dir, 'for-each-ref', '--format=%(objectname) %(refname)'),
  config: readFileSync(join(dir, 'config'), 'utf8'),
  fetchHead: existsSync(join(dir, 'FETCH_HEAD')),
  packs: readdirSync(join(dir, 'objects')).sort().join(','),
});

before(startGithub);
after(() => {
  console.log = origLog;
  ghServer?.closeAllConnections?.();
  ghServer?.close();
  sync._setGithubSyncDepsForTests(null);
});

test('same: both tips are the same commit', async () => {
  const { app } = await makeApp('same-app');
  useRemote(`${GH_BASE}/same-app.git`);
  const r = await sync.getGithubSyncStatus(app);
  assert.equal(r.state, 'same', JSON.stringify(r));
  assert.equal(r.ahead, 0);
  assert.equal(r.behind, 0);
  assert.equal(r.crane_sha, r.github_sha);
  assert.match(r.checked_at, /^\d{4}-\d\d-\d\dT/);
  assert.equal(r.branch, 'main');
});

test('ahead: AppCrane has 2 commits GitHub does not, and the app repo is left untouched', async () => {
  const { app, crane } = await makeApp('ahead-app');
  commitOn(crane, 'main', 'c1');
  const tip = commitOn(crane, 'main', 'c2');
  const before = snapshot(crane);
  useRemote(`${GH_BASE}/ahead-app.git`);
  const r = await sync.getGithubSyncStatus(app);
  assert.deepEqual([r.state, r.ahead, r.behind], ['ahead', 2, 0], JSON.stringify(r));
  assert.equal(r.crane_sha, tip);
  assert.deepEqual(snapshot(crane), before);
});

test('behind: GitHub has 3 commits AppCrane does not; fetch does not alter the app repo', async () => {
  const { app, crane, gh } = await makeApp('behind-app');
  commitOn(gh, 'main', 'g1');
  commitOn(gh, 'main', 'g2');
  const ghTip = commitOn(gh, 'main', 'g3');
  const before = snapshot(crane);
  useRemote(`${GH_BASE}/behind-app.git`);
  const r = await sync.getGithubSyncStatus(app);
  assert.deepEqual([r.state, r.ahead, r.behind], ['behind', 0, 3], JSON.stringify(r));
  assert.equal(r.github_sha, ghTip);
  assert.deepEqual(snapshot(crane), before, 'refs, config, FETCH_HEAD and object store unchanged');
  assert.ok(!git(crane, 'for-each-ref').includes('appcrane-github'));
  assert.throws(() => git(crane, 'cat-file', '-e', `${ghTip}^{commit}`), 'GitHub-only objects did not land in the app repo');
  assert.ok(!readdirSync(tmpdir()).some((n) => n.startsWith('appcrane-github-sync-') && existsSync(join(tmpdir(), n, 'objects', 'info', 'alternates'))
    && readFileSync(join(tmpdir(), n, 'objects', 'info', 'alternates'), 'utf8').includes(crane)), 'scratch repo removed');
});

test('diverged: each side has commits the other lacks', async () => {
  const { app, crane, gh } = await makeApp('div-app');
  commitOn(crane, 'main', 'crane-only');
  commitOn(gh, 'main', 'gh-only-1');
  commitOn(gh, 'main', 'gh-only-2');
  useRemote(`${GH_BASE}/div-app.git`);
  const r = await sync.getGithubSyncStatus(app);
  assert.deepEqual([r.state, r.ahead, r.behind], ['diverged', 1, 2], JSON.stringify(r));
});

test('unknown: unreachable GitHub is reported with a reason, never as in sync', async () => {
  const { app } = await makeApp('down-app');
  const dead = http.createServer();
  await new Promise((res) => dead.listen(0, '127.0.0.1', res));
  const port = dead.address().port;
  await new Promise((res) => dead.close(res));
  useRemote(`http://127.0.0.1:${port}/down-app.git`);
  const r = await sync.getGithubSyncStatus(app);
  assert.equal(r.state, 'unknown');
  assert.equal(r.reason_code, 'network');
  assert.match(r.reason, /could not reach GitHub/);
  assert.equal(r.ahead, null);
  assert.equal(r.github_sha, null);
});

test('unknown: SAML-enforced 403 and a refused credential each say so', async () => {
  const { app } = await makeApp('saml-app');
  useRemote(`${GH_BASE}/saml-app.git`);
  mode = 'saml';
  try {
    const r = await sync.getGithubSyncStatus(app);
    assert.equal(r.state, 'unknown');
    assert.equal(r.reason_code, 'saml_required', JSON.stringify(r));
  } finally { mode = 'ok'; }
  sync._setGithubSyncDepsForTests({
    spawn: recordingSpawn, allowedSchemes: ['http'],
    resolveRemote: async () => ({ url: `${GH_BASE}/saml-app.git`, token: 'wrong-token', credential: 'pat' }),
  });
  const r2 = await sync.getGithubSyncStatus(app);
  assert.deepEqual([r2.state, r2.reason_code], ['unknown', 'auth_failed'], JSON.stringify(r2));
  assert.match(r2.reason, /Make the repository public, or attach a GitHub App installation or a token/);
  sync._setGithubSyncDepsForTests({
    spawn: recordingSpawn, allowedSchemes: ['http'],
    resolveRemote: async () => ({ url: `${GH_BASE}/saml-app.git`, token: null, credential: 'none' }),
  });
  const r3 = await sync.getGithubSyncStatus(app);
  assert.deepEqual([r3.state, r3.reason_code], ['unknown', 'no_credential'], JSON.stringify(r3));
  assert.match(r3.reason, /Make the repository public, or attach a GitHub App installation or a token/);
  assert.doesNotMatch(r3.reason, /service account/);
});

test('unknown: no github_url, and a GitHub repo without the branch', async () => {
  const { app } = await makeApp('nogh-app', { github: false });
  useRemote(`${GH_BASE}/nogh-app.git`);
  const r = await sync.getGithubSyncStatus(app);
  assert.deepEqual([r.state, r.reason_code], ['unknown', 'no_github_url']);
  const { app: app2, gh } = await makeApp('nobranch-app');
  git(gh, 'update-ref', '-d', 'refs/heads/main');
  useRemote(`${GH_BASE}/nobranch-app.git`);
  const r2 = await sync.getGithubSyncStatus(app2);
  assert.deepEqual([r2.state, r2.reason_code], ['unknown', 'github_branch_missing'], JSON.stringify(r2));
});

test('the token reaches GitHub only as a header: never in a URL, argv or log line', async () => {
  const { app, crane } = await makeApp('tok-app');
  commitOn(crane, 'main', 'x');
  seenAuth.length = 0;
  spawned.length = 0;
  useRemote(`${GH_BASE}/tok-app.git`);
  const r = await sync.getGithubSyncStatus(app);
  assert.equal(r.state, 'ahead', JSON.stringify(r));
  assert.ok(seenAuth.includes(`Basic ${TOKEN_B64}`), 'GitHub received the credential');
  assert.ok(spawned.length >= 3);
  for (const s of spawned) {
    const argv = s.args.join(' ');
    assert.ok(!argv.includes(TOKEN) && !argv.includes(TOKEN_B64), `token in argv: ${argv}`);
    for (const a of s.args) if (/^https?:/.test(a)) assert.equal(new URL(a).username + new URL(a).password, '');
    assert.ok(s.args.includes('core.hooksPath=/dev/null'), 'hooks disabled');
  }
  const remoteCalls = spawned.filter((s) => s.args.includes('ls-remote') || s.args.includes('fetch'));
  assert.equal(remoteCalls.length, 2);
  for (const s of remoteCalls) assert.equal(s.env.GIT_CONFIG_VALUE_0, `Authorization: Basic ${TOKEN_B64}`);
  mode = 'saml';
  try { await sync.getGithubSyncStatus(app, { refresh: true }); } finally { mode = 'ok'; }
  const all = logged.join('\n');
  assert.ok(all.includes('[github-sync]'), 'a failure was logged');
  assert.ok(!all.includes(TOKEN) && !all.includes(TOKEN_B64), 'token in a log line');
  assert.ok(!JSON.stringify(r).includes(TOKEN));
});

test('cache: a second read within the TTL does not run git; refresh inside MIN_REFRESH_MS is still cached', async () => {
  const { app } = await makeApp('cache-app');
  let t = 1_000_000;
  sync._setGithubSyncDepsForTests({
    spawn: recordingSpawn, allowedSchemes: ['http'], now: () => t,
    resolveRemote: async () => ({ url: `${GH_BASE}/cache-app.git`, token: TOKEN, credential: 'installation' }),
  });
  spawned.length = 0;
  const a = await sync.getGithubSyncStatus(app);
  const n = spawned.length;
  assert.equal(a.cached, false);
  const b = await sync.getGithubSyncStatus(app, { refresh: true });
  assert.equal(b.cached, true);
  assert.equal(spawned.length, n);
  t += sync.MIN_REFRESH_MS + 1;
  const c = await sync.getGithubSyncStatus(app, { refresh: true });
  assert.equal(c.cached, false);
  assert.ok(spawned.length > n);
});

test('route: per-app authz refuses an unassigned user exactly as release-check does; an assigned user gets the status', async () => {
  const { app } = await makeApp('route-app');
  let t = 5_000_000;
  sync._setGithubSyncDepsForTests({
    spawn: recordingSpawn, allowedSchemes: ['http'], now: () => t,
    resolveRemote: async () => ({ url: `${GH_BASE}/route-app.git`, token: TOKEN, credential: 'installation' }),
  });
  const OUT_KEY = generateApiKey('dhk_out');
  const IN_KEY = generateApiKey('dhk_in');
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Out','out@t.test','user',?,1,'human')").run(hashApiKey(OUT_KEY));
  const inId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('In','in@t.test','user',?,1,'human')").run(hashApiKey(IN_KEY)).lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(app.id, inId);

  const api = express();
  api.use('/api', (await import('../server/routes/githubSyncStatus.js')).default);
  api.use('/api', (await import('../server/routes/releaseCheck.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  const BASE = `http://127.0.0.1:${server.address().port}`;
  try {
    const get = async (path, key) => {
      const r = await fetch(`${BASE}${path}`, { headers: key ? { 'X-API-Key': key } : {} });
      return { status: r.status, body: await r.json() };
    };
    const refused = await get('/api/apps/route-app/github-sync', OUT_KEY);
    const neighbour = await get('/api/apps/route-app/release-check', OUT_KEY);
    assert.equal(refused.status, 403);
    assert.deepEqual(refused, neighbour);
    assert.equal((await get('/api/apps/route-app/github-sync', null)).status, 401);
    assert.equal((await get('/api/apps/no-such-app/github-sync', IN_KEY)).status, 404);
    const ok = await get('/api/apps/route-app/github-sync', IN_KEY);
    assert.equal(ok.status, 200);
    assert.equal(ok.body.state, 'same', JSON.stringify(ok.body));
    t += sync.MIN_REFRESH_MS + 1;
    assert.equal((await get('/api/apps/route-app/github-sync', IN_KEY)).body.cached, true, 'no refresh: cached');
    assert.equal((await get('/api/apps/route-app/github-sync?refresh=1', IN_KEY)).body.cached, false, '?refresh=1 re-measures');
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

// The owner of a Crane-hosted app may set its github_url (routes/apps.js PUT).
// The platform service-account token reads every repo that account can, so it
// must never be the credential the comparison uses: an owner could otherwise
// point github_url at any of those repos and read back whether it exists and
// its branch tip.
const SVC_TOKEN = 'ghp_ServiceAccountTokenMustNotBeUsed000';
const SVC_B64 = Buffer.from(`x-access-token:${SVC_TOKEN}`).toString('base64');
function setServiceToken() {
  db.prepare("INSERT INTO settings (key, value) VALUES ('github_service_token_enc', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(encrypt(SVC_TOKEN));
  assert.equal(getServiceTokenInternal(), SVC_TOKEN, 'precondition: the service token is configured and readable');
}
const { getServiceTokenInternal } = await import('../server/services/githubService.js');

test('local app: the platform service-account token is never the credential, even when it is configured', async () => {
  setServiceToken();
  const { app } = await makeApp('svc-none-app');
  const remote = await sync.defaultResolveRemote(app);
  assert.deepEqual(remote, { url: 'https://github.com/acme/svc-none-app.git', token: null, credential: 'none' });

  db.prepare('UPDATE apps SET github_token_encrypted = ? WHERE id = ?').run(encrypt(TOKEN), app.id);
  const own = await sync.defaultResolveRemote(db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id));
  assert.deepEqual(own, { url: 'https://github.com/acme/svc-none-app.git', token: TOKEN, credential: 'pat' }, 'the app\'s own PAT is used');
});

test('local app: on the wire, GitHub never sees the service token, and a private repo reads as no_credential', async () => {
  setServiceToken();
  const { app } = await makeApp('svc-wire-app');
  sync._setGithubSyncDepsForTests({
    spawn: recordingSpawn, allowedSchemes: ['http'],
    // The real resolver, with only the host moved to the local fake GitHub.
    resolveRemote: async (a) => ({ ...(await sync.defaultResolveRemote(a)), url: `${GH_BASE}/svc-wire-app.git` }),
  });
  seenAuth.length = 0;
  spawned.length = 0;
  const r = await sync.getGithubSyncStatus(app);
  assert.deepEqual([r.state, r.reason_code, r.credential], ['unknown', 'no_credential', 'none'], JSON.stringify(r));
  assert.ok(seenAuth.length > 0, 'GitHub was asked');
  assert.ok(!seenAuth.includes(`Basic ${SVC_B64}`), `the service token reached GitHub: ${JSON.stringify(seenAuth)}`);
  for (const s of spawned) assert.ok(!JSON.stringify(s).includes(SVC_B64) && !JSON.stringify(s).includes(SVC_TOKEN), 'service token in a git child');
});
