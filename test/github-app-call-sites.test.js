import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync, spawn } from 'child_process';
import { mock } from 'node:test';
import crypto from 'crypto';
import http from 'http';

// Where a GitHub App installation token actually gets used, end to end.
//
// Two real servers on 127.0.0.1 and no network beyond them:
//   - api.github.com is an HTTP server serving the App endpoints (the App's key
//     is generated for this run), reached through APPCRANE_GITHUB_API_BASE;
//   - github.com itself is a real `git http-backend` that DEMANDS an
//     Authorization header, so a clone that works proves the credential
//     arrived, and one that is missing the header fails the way it would in
//     production.
//
// The claims under test:
//   - the deployer clones with the installation token, and the token is in NO
//     argv, NO file on disk (including .git/config) and NO log line;
//   - the supply-chain SHA check and the PR poller and /updates all present the
//     installation token instead of the PAT;
//   - "Register on GitHub" refuses instead of reaching for the PAT, because the
//     App is read-only.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-ghapp-sites-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = '9'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_GITHUB_ALLOW_HTTP_GIT = '1';
// No interactive credential prompts anywhere in this file: a git that cannot
// authenticate must FAIL, not sit waiting for a username that will never come.
process.env.GIT_TERMINAL_PROMPT = '0';
process.env.GIT_ASKPASS = '/usr/bin/true';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const REAL_GIT = execFileSync('which', ['git']).toString().trim();

const { privateKey: PEM } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const APP_ID = 777001;
const INSTALLATION_ID = 6120;
const INSTALLATION_TOKEN = 'ghs_LIVEINSTALLATIONTOKEN_abcdef123456';
const PAT = 'ghp_THEPATBEINGRETIRED0123456789abcd';

// --- a git server that requires the credential -------------------------------
const REPOS = join(ROOT, 'srv');
mkdirSync(join(REPOS, 'acme'), { recursive: true });
const BARE = join(REPOS, 'acme', 'widget.git');
execFileSync(REAL_GIT, ['init', '--bare', '-q', '-b', 'main', BARE]);
{
  const work = mkdtempSync(join(ROOT, 'seed-'));
  const g = (...a) => execFileSync(REAL_GIT, ['-C', work, ...a], { stdio: 'pipe' });
  execFileSync(REAL_GIT, ['init', '-q', '-b', 'main', work]);
  g('config', 'user.email', 'seed@example.com');
  g('config', 'user.name', 'seed');
  writeFileSync(join(work, 'index.js'), 'console.log(1)\n');
  g('add', '.');
  g('commit', '-qm', 'seed');
  g('push', '-q', BARE, 'main');
}
const HEAD_SHA = execFileSync(REAL_GIT, ['-C', BARE, 'rev-parse', 'HEAD']).toString().trim();

// Out of process on purpose: git is driven with execFileSync, which blocks
// this process's event loop, so a server living here could never answer.
const AUTH_LOG = join(ROOT, 'git-auth.jsonl');
writeFileSync(AUTH_LOG, '');
const gitServer = spawn(process.execPath, [fileURLToPath(new URL('./fixtures/git-http-auth-server.mjs', import.meta.url)), REPOS, AUTH_LOG], {
  stdio: ['ignore', 'pipe', 'inherit'],
});
const GIT_PORT = await new Promise((resolveP, reject) => {
  gitServer.once('error', reject);
  gitServer.stdout.once('data', (d) => resolveP(parseInt(String(d).trim(), 10)));
});
const GIT_ORIGIN = `http://127.0.0.1:${GIT_PORT}`;
const gitAuthSeen = {
  clear: () => writeFileSync(AUTH_LOG, ''),
  list: () => readFileSync(AUTH_LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)),
};

// --- api.github.com ----------------------------------------------------------
const api = { calls: [], tokenFails: false };
const apiServer = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    api.calls.push({ method: req.method, path: req.url, auth: req.headers.authorization || null, body: chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null });
    const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (req.method === 'POST' && /access_tokens$/.test(req.url)) {
      if (api.tokenFails) return send(403, { message: 'installation suspended' });
      return send(201, { token: INSTALLATION_TOKEN, expires_at: new Date(Date.now() + 3600_000).toISOString() });
    }
    if (req.method === 'GET' && /\/installation$/.test(req.url)) return send(200, { id: INSTALLATION_ID, account: { login: 'acme' } });
    return send(404, { message: `unrouted ${req.method} ${req.url}` });
  });
});
await new Promise((r) => apiServer.listen(0, '127.0.0.1', r));
process.env.APPCRANE_GITHUB_API_BASE = `http://127.0.0.1:${apiServer.address().port}`;

// --- git + docker shims: argv is recorded, git itself is the real thing -------
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
const GIT_LOG = join(ROOT, 'git-argv.log');
const SNAP = join(ROOT, 'git-config-snapshots');
mkdirSync(SNAP, { recursive: true });
// A failed deploy removes its release directory, so "is the token on disk" is
// checked while it still exists: after every git call, the repo's .git/config
// is copied aside.
writeFileSync(join(SHIM, 'git'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${GIT_LOG}"
"${REAL_GIT}" "$@"; rc=$?
dir=""
if [ "$1" = clone ]; then for a in "$@"; do dir="$a"; done; fi
if [ "$1" = -C ]; then dir="$2"; fi
if [ -n "$dir" ] && [ -f "$dir/.git/config" ]; then n=$(ls "${SNAP}" | wc -l | tr -d ' '); cp "$dir/.git/config" "${SNAP}/config.$n"; fi
exit $rc
`, { mode: 0o755 });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2; exit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt, hashApiKey } = await import('../server/services/encryption.js');
const ghApp = await import('../server/services/githubApp.js');
const ghCred = await import('../server/services/githubCredential.js');
const { installationGitEnv } = await import('../server/services/githubGitAuth.js');
const { deployApp } = await import('../server/services/deployer.js');
const { verifyCommitSha } = await import('../server/services/supplyChain.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const poller = await import('../server/services/githubPoller.js');
const webhooksRoutes = (await import('../server/routes/webhooks.js')).default;
const express = (await import('express')).default;
const logger = (await import('../server/utils/logger.js')).default;

ghApp.saveAppConfig({
  id: APP_ID, slug: 'appcrane-sites', name: 'AppCrane', owner: { login: 'acme' },
  html_url: 'https://github.com/apps/appcrane-sites', client_id: 'Iv1.x',
  client_secret: 'cs', webhook_secret: 'ws', pem: PEM,
});

after(() => {
  gitServer.kill('SIGTERM');
  apiServer.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin',?,1,'human')")
  .run(hashApiKey('dhk_sites')).lastInsertRowid;
let slot = 940;
function mkApp(slug, url) {
  const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,branch,github_token_encrypted) VALUES (?,?,?,'github',?,'main',?)")
    .run(slug, slug, slot++, url, encrypt(PAT)).lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(id, env);
    db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  }
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(id, uid);
  db.prepare("INSERT INTO webhook_configs (app_id, token, secret) VALUES (?, ?, 'sec')").run(id, `wh-${slug}`);
  db.prepare('INSERT INTO app_github_installations (app_id, slug, installation_id, repo_full_name) VALUES (?,?,?,?)')
    .run(id, slug, INSTALLATION_ID, `acme/${slug}`);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const readArgv = () => (existsSync(GIT_LOG) ? readFileSync(GIT_LOG, 'utf8') : '')
  .split('\n').filter(Boolean).map((l) => l.split('\x1f').slice(0, -1));

/** Every regular file under dir, as one string. Used to prove absence. */
function allBytes(dir) {
  let out = '';
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out += allBytes(p);
    else if (st.isFile() && st.size < 2_000_000) out += readFileSync(p).toString('latin1');
  }
  return out;
}

// ---------------------------------------------------------------------------

test('a real clone with the installation token: the server sees it, argv and disk do not', () => {
  gitAuthSeen.clear();
  rmSync(GIT_LOG, { force: true });
  const dest = join(ROOT, 'direct-clone');
  const url = `${GIT_ORIGIN}/acme/widget.git`;
  const env = installationGitEnv(url, INSTALLATION_TOKEN);
  execFileSync('git', ['clone', '--depth', '1', '--branch', 'main', url, dest], { env, stdio: 'pipe', timeout: 60000 });

  assert.equal(readFileSync(join(dest, 'index.js'), 'utf8'), 'console.log(1)\n');
  const expected = `Basic ${Buffer.from(`x-access-token:${INSTALLATION_TOKEN}`).toString('base64')}`;
  assert.ok(gitAuthSeen.list().some((c) => c.auth === expected), `git server never saw the token: ${JSON.stringify(gitAuthSeen.list())}`);

  const argv = JSON.stringify(readArgv());
  assert.equal(argv.includes(INSTALLATION_TOKEN), false, 'the token reached git argv');
  const config = readFileSync(join(dest, '.git', 'config'), 'utf8');
  assert.equal(config.includes(INSTALLATION_TOKEN), false, 'the token was written into .git/config');
  assert.match(config, new RegExp(`url = ${GIT_ORIGIN.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/acme/widget\\.git`));
  const onDisk = allBytes(dest);
  assert.equal(onDisk.includes(INSTALLATION_TOKEN), false, 'the token is somewhere in the clone');
  assert.equal(onDisk.includes(Buffer.from(`x-access-token:${INSTALLATION_TOKEN}`).toString('base64')), false);
});

test('a clone with NO credential is refused by that same server — the previous test proves auth, not a lax server', () => {
  const dest = join(ROOT, 'unauth-clone');
  assert.throws(
    () => execFileSync('git', ['-c', 'credential.helper=', 'clone', '--depth', '1', `${GIT_ORIGIN}/acme/widget.git`, dest],
      { stdio: 'pipe', timeout: 60000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/usr/bin/true' } }),
    /401|Authentication|could not read Username/i,
  );
});

test('the deployer clones an App-backed app with an installation token, and leaks it nowhere', async () => {
  const prevWeb = process.env.APPCRANE_GITHUB_WEB_BASE;
  process.env.APPCRANE_GITHUB_WEB_BASE = GIT_ORIGIN;
  ghApp.clearTokenCache();
  rmSync(GIT_LOG, { force: true });
  gitAuthSeen.clear();
  api.calls.length = 0;

  const app = mkApp('widget', `${GIT_ORIGIN}/acme/widget.git`);
  const logged = [];
  const orig = { ...logger };
  for (const k of ['error', 'warn', 'info', 'debug']) logger[k] = (m, meta) => { logged.push(`${m} ${meta ? JSON.stringify(meta) : ''}`); };
  const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)")
    .run(app.id, uid).lastInsertRowid;
  try {
    await deployApp(depId, app, 'sandbox', getPortsForSlot(app.slot), { targetCommit: HEAD_SHA }).catch(() => {});
  } finally {
    Object.assign(logger, orig);
    process.env.APPCRANE_GITHUB_WEB_BASE = prevWeb;
    if (prevWeb === undefined) delete process.env.APPCRANE_GITHUB_WEB_BASE;
  }
  const { log } = db.prepare('SELECT log FROM deployments WHERE id = ?').get(depId);

  // The token was issued for this one repository only.
  const tokenCalls = api.calls.filter((c) => /access_tokens$/.test(c.path));
  assert.equal(tokenCalls.length, 1, JSON.stringify(api.calls));
  assert.equal(tokenCalls[0].path, `/app/installations/${INSTALLATION_ID}/access_tokens`);
  assert.deepEqual(tokenCalls[0].body, { repositories: ['widget'] }, 'the token was not narrowed to this one repository');

  // The clone really happened, over HTTP, authenticated.
  const argv = readArgv();
  const clone = argv.find((a) => a[0] === 'clone');
  assert.ok(clone, `no clone ran: ${log}`);
  assert.deepEqual(clone.slice(0, 5), ['clone', '--depth', '1', '--branch', 'main']);
  assert.equal(clone[5], `${GIT_ORIGIN}/acme/widget.git`, 'the URL carried a credential');
  assert.ok(gitAuthSeen.list().some((c) => c.auth === `Basic ${Buffer.from(`x-access-token:${INSTALLATION_TOKEN}`).toString('base64')}`));
  assert.match(log, /GitHub App \(installation token/);
  assert.match(log, new RegExp(`Cloned successfully. Commit: ${HEAD_SHA.slice(0, 7)}`));

  // …and the token is in none of the places a PAT would have been.
  assert.equal(JSON.stringify(argv).includes(INSTALLATION_TOKEN), false, 'the token reached git argv');
  assert.equal(log.includes(INSTALLATION_TOKEN), false, 'the token reached the deploy log');
  assert.equal(logged.join('\n').includes(INSTALLATION_TOKEN), false, 'the token reached the logger');
  const snaps = readdirSync(SNAP).filter((f) => f.startsWith('config.'));
  assert.ok(snaps.length >= 3, `expected .git/config snapshots from clone, pin and verify, got ${snaps.length}`);
  for (const f of snaps) {
    const text = readFileSync(join(SNAP, f), 'utf8');
    assert.equal(text.includes(INSTALLATION_TOKEN), false, `the token was written into the release .git/config (${f})`);
    assert.equal(text.includes(Buffer.from(`x-access-token:${INSTALLATION_TOKEN}`).toString('base64')), false, `the encoded token is in .git/config (${f})`);
  }
  assert.equal(allBytes(join(ROOT, 'apps')).includes(INSTALLATION_TOKEN), false, 'the token is on disk under DATA_DIR');
  assert.equal(readFileSync(join(ROOT, 'deployhub.db')).includes(Buffer.from(INSTALLATION_TOKEN)), false, 'the token reached the database');
  assert.equal(log.includes(PAT), false);
});

test('the supply-chain SHA check presents the installation token, not the app PAT', async () => {
  ghApp.clearTokenCache();
  const app = mkApp('sha-check', 'https://github.com/acme/sha-check');
  const work = mkdtempSync(join(ROOT, 'sha-'));
  execFileSync(REAL_GIT, ['clone', '-q', BARE, work]);
  const localSha = execFileSync(REAL_GIT, ['-C', work, 'rev-parse', 'HEAD']).toString().trim();

  const seen = [];
  const realFetch = global.fetch;
  global.fetch = async (url, init = {}) => {
    const u = String(url);
    if (!u.startsWith('https://api.github.com')) return realFetch(url, init);
    seen.push({ url: u, auth: init.headers?.Authorization || null });
    return { ok: true, status: 200, headers: new Headers(), json: async () => ({ commit: { sha: localSha } }), text: async () => '' };
  };
  const lines = [];
  try {
    const r = await verifyCommitSha(app, work, 'main', (l) => lines.push(l));
    assert.equal(r.verified, true);
  } finally {
    global.fetch = realFetch;
  }
  assert.equal(seen.length, 1);
  assert.equal(seen[0].auth, `Bearer ${INSTALLATION_TOKEN}`);
  assert.equal(seen[0].auth.includes(PAT), false);
});

test('the PR poller uses the installation token, and skips the app entirely when it cannot be issued', async () => {
  ghApp.clearTokenCache();
  const app = mkApp('poller-app', 'https://github.com/acme/poller-app');
  db.prepare("INSERT INTO enhancement_requests (id, app_slug, message, status) VALUES (11, 'poller-app', 'x', 'new')").run();

  const seen = [];
  const realFetch = global.fetch;
  global.fetch = async (url, init = {}) => {
    const u = String(url);
    if (!u.startsWith('https://api.github.com')) return realFetch(url, init);
    seen.push({ url: u, auth: init.headers?.Authorization || null });
    return {
      ok: true, status: 200, headers: new Headers(), text: async () => '[]',
      json: async () => [{ number: 3, body: 'Closes appcrane#11', html_url: 'https://github.com/acme/poller-app/pull/3', state: 'open', merged_at: null, head: { ref: 'b' } }],
    };
  };
  // startGithubPoller() is idempotent per module instance (a second call is a
  // no-op), so each tick loads a FRESH copy of the poller module. Reusing one
  // instance made the second tick silently not run — and "no PAT call" was then
  // true for the wrong reason (falsification caught it).
  let instance = 0;
  const runTick = async () => {
    seen.length = 0;
    const fresh = instance++ === 0 ? poller : await import(`../server/services/githubPoller.js?tick=${instance}`);
    mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
    fresh.startGithubPoller();
    mock.timers.tick(30000);
    mock.timers.reset();
    await new Promise((r) => setTimeout(r, 250));
  };
  try {
    await runTick();
    const mine = seen.filter((c) => c.url.includes('/acme/poller-app/pulls'));
    assert.equal(mine.length, 1, JSON.stringify(seen));
    assert.equal(mine[0].auth, `Bearer ${INSTALLATION_TOKEN}`);
    assert.equal(db.prepare('SELECT pr_url FROM enhancement_requests WHERE id = 11').get().pr_url, 'https://github.com/acme/poller-app/pull/3');

    // Token issuance broken: the app is skipped, NOT retried with its PAT.
    // A PAT-only control app in the same tick proves the tick really ran.
    const ctlId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,branch,github_token_encrypted) VALUES ('ctl','poller-control',?,'github','https://github.com/acme/poller-control','main',?)")
      .run(slot++, encrypt(PAT)).lastInsertRowid;
    ghApp.clearTokenCache();
    api.tokenFails = true;
    await runTick();
    const control = seen.filter((c) => c.url.includes('/acme/poller-control/pulls'));
    assert.equal(control.length, 1, `the second tick did not run: ${JSON.stringify(seen)}`);
    assert.equal(control[0].auth, `token ${PAT}`, 'an app with no installation must still use its PAT');
    const after = seen.filter((c) => c.url.includes('/acme/poller-app/pulls'));
    assert.equal(after.length, 0, `the poller fell back: ${JSON.stringify(after)}`);
    db.prepare('DELETE FROM apps WHERE id = ?').run(ctlId);
  } finally {
    api.tokenFails = false;
    global.fetch = realFetch;
  }
});

test('/updates uses the installation token, and Register-on-GitHub refuses instead of using the PAT', async () => {
  ghApp.clearTokenCache();
  const app = mkApp('routes-app', 'https://github.com/acme/routes-app');
  const ex = express();
  ex.use(express.json());
  ex.use('/api/apps', webhooksRoutes);
  ex.use((e, _req, res, _next) => res.status(e.statusCode || e.status || 500).json({ error: { code: e.code, message: e.message } }));
  const srv = http.createServer(ex);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;

  const seen = [];
  const realFetch = global.fetch;
  global.fetch = async (url, init = {}) => {
    const u = String(url);
    if (!u.startsWith('https://api.github.com')) return realFetch(url, init);
    seen.push({ url: u, auth: init.headers?.Authorization || null, method: (init.method || 'GET').toUpperCase() });
    return { ok: true, status: 200, headers: new Headers(), text: async () => '{}', json: async () => ({ sha: HEAD_SHA, commit: { message: 'm', committer: { date: '2026-01-01T00:00:00Z' } } }) };
  };
  try {
    const u = await realFetch(`${base}/api/apps/routes-app/updates`, { headers: { 'X-API-Key': 'dhk_sites' } });
    assert.equal(u.status, 200);
    const commitCall = seen.find((c) => c.url.includes('/commits/main'));
    assert.equal(commitCall.auth, `Bearer ${INSTALLATION_TOKEN}`);

    seen.length = 0;
    const reg = await realFetch(`${base}/api/apps/routes-app/webhook/register-github`, { method: 'POST', headers: { 'X-API-Key': 'dhk_sites' } });
    const body = await reg.json();
    assert.equal(reg.status, 400);
    assert.match(body.error, /read-only/);
    assert.equal(seen.length, 0, 'a webhook was created with some credential anyway');
  } finally {
    global.fetch = realFetch;
    srv.close();
  }
});

test('the token is never sent over plain http to a real host', () => {
  const prev = process.env.APPCRANE_GITHUB_ALLOW_HTTP_GIT;
  delete process.env.APPCRANE_GITHUB_ALLOW_HTTP_GIT;
  try {
    assert.throws(() => installationGitEnv('http://git.example.com/acme/widget.git', INSTALLATION_TOKEN), /Refusing to send a GitHub token over 'http'/);
    const env = installationGitEnv('https://github.com/acme/widget.git', INSTALLATION_TOKEN, { GIT_CONFIG_COUNT: '2' });
    assert.equal(env.GIT_CONFIG_COUNT, '3');
    assert.equal(env.GIT_CONFIG_KEY_2, 'http.https://github.com/.extraHeader');
  } finally {
    process.env.APPCRANE_GITHUB_ALLOW_HTTP_GIT = prev;
  }
});
