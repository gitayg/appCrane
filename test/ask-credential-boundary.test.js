import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Who may run a prompt where a credential is reachable, and what an Ask agent
// finds in its container the moment it starts.
//
// Real git against a real `git http-backend` that demands an Authorization
// header, so a clone that works proves the token arrived. docker is a shim that
// runs the clone script Ask hands it through a real sh, against a temp dir in
// place of /workspace, and snapshots the workspace when the agent is started.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-askbound-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_GITHUB_ALLOW_HTTP_GIT = '1';
process.env.GIT_TERMINAL_PROMPT = '0';
const API_KEY = 'sk-ant-test-boundary-key';
process.env.ANTHROPIC_API_KEY = API_KEY;
const TOKEN = 'ghp_CANARYaskboundary0000';

const SHIM = join(ROOT, 'bin');
const LOG = join(ROOT, 'docker.log');
const SNAP = join(ROOT, 'agent-view.txt');
const STDIN_SEEN = join(ROOT, 'clone-stdin.txt');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${LOG}"
case "$1" in
  run) echo shimcontainer ;;
  inspect) echo running ;;
  image) echo 6 ;;
  rm) ;;
  exec)
    shift
    agent=""
    while [ $# -gt 0 ]; do
      case "$1" in
        -i) shift ;;
        --workdir) agent=1; shift 2 ;;
        -e) export "$2"; shift 2 ;;
        *) break ;;
      esac
    done
    shift
    if [ -n "$agent" ]; then
      {
        echo "files: $(ls "$SHIM_WS" 2>/dev/null | tr '\\n' ' ')"
        echo "--config"; cat "$SHIM_WS/.git/config" 2>/dev/null
      } > "${SNAP}"
      echo "AGENT_STARTED" >> "${LOG}"
      exit 0
    fi
    if [ "$1" = test ]; then
      p=$(printf '%s' "$3" | sed "s#^/tmp/#$SHIM_WS.tmp/#")
      test "$2" "$p"
      exit $?
    fi
    [ "$1" = sh ] || exit 0
    if [ -n "$SHIM_SKIP_CLONE_SCRIPT" ]; then cat >/dev/null; echo "CLONE_EXIT 0" >> "${LOG}"; exit 0; fi
    mkdir -p "$SHIM_WS" "$SHIM_WS.tmp"
    script=$(printf '%s' "$3" | sed -e "s#/workspace#$SHIM_WS#g" -e "s#/tmp/#$SHIM_WS.tmp/#g")
    sh -c "$script"
    rc=$?
    echo "CLONE_EXIT $rc" >> "${LOG}"
    exit $rc ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

// --- the git server ----------------------------------------------------------
const REPOS = join(ROOT, 'repos-served');
const AUTH_LOG = join(ROOT, 'git-auth.jsonl');
writeFileSync(AUTH_LOG, '');
const IDENTITY = { GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.invalid' };
const git = (...a) => execFileSync('git', a, { stdio: 'pipe', env: { ...process.env, ...IDENTITY } }).toString().trim();
const seed = join(ROOT, 'seed');
git('init', '-q', '-b', 'main', seed);
writeFileSync(join(seed, 'hello.txt'), 'hello\n');
git('-C', seed, 'add', '.');
git('-C', seed, 'commit', '-qm', 'seed');
mkdirSync(join(REPOS, 'acme'), { recursive: true });
git('clone', '-q', '--bare', seed, join(REPOS, 'acme', 'widget.git'));
const gitServer = spawn(process.execPath, [fileURLToPath(new URL('./fixtures/git-http-auth-server.mjs', import.meta.url)), REPOS, AUTH_LOG], {
  stdio: ['ignore', 'pipe', 'inherit'],
});
const GIT_PORT = await new Promise((res, rej) => {
  gitServer.once('error', rej);
  gitServer.stdout.once('data', (d) => res(parseInt(String(d).trim(), 10)));
});
process.on('exit', () => gitServer.kill());
const REPO_URL = `http://127.0.0.1:${GIT_PORT}/acme/widget.git`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const lg = await import('../server/services/localGit.js');
const { runAskJob, stopSession } = await import('../server/services/askClaude.js');
const askRoutes = (await import('../server/routes/ask.js')).default;
const { getNextSlot } = await import('../server/services/portAllocator.js');

after(async () => {
  gitServer.kill();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

function insertApp(slug, { backend = null, githubUrl = null, tokenEnc = null, sourceType = 'github' } = {}) {
  db.prepare('INSERT INTO apps (name, slug, slot, source_type, github_url, github_token_encrypted, branch, repo_backend) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(slug, slug, getNextSlot(db), sourceType, githubUrl, tokenEnc, 'main', backend);
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}
function insertUser(name, role = 'user') {
  const key = `key-${name}`;
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,\'human\')')
    .run(name, `${name}@x.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
}
const grant = (app, user, appRole) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, user.id, appRole);

const dockerLines = () => (existsSync(LOG) ? readFileSync(LOG, 'utf8') : '').split('\n').filter(Boolean);
const dockerArgv = () => dockerLines().filter((l) => l.includes('\x1f')).map((l) => l.split('\x1f').slice(0, -1));
const runs = () => dockerArgv().filter((a) => a[0] === 'run');
const resetDocker = () => { writeFileSync(LOG, ''); rmSync(SNAP, { force: true }); };
function freshWorkspace(name) {
  const ws = join(ROOT, `ws-${name}`);
  rmSync(ws, { recursive: true, force: true });
  rmSync(`${ws}.tmp`, { recursive: true, force: true });
  process.env.SHIM_WS = ws;
  return ws;
}
async function until(fn, what, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${what}`);
}
/** Every file under `dir` whose bytes contain `needle`. */
function filesContaining(dir, needle) {
  const hits = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) hits.push(...filesContaining(p, needle));
    else if (st.isFile() && readFileSync(p).includes(needle)) hits.push(p);
  }
  return hits;
}

const tokenEnc = encrypt(TOKEN);
const ghApp = insertApp('ask-bound-gh', { githubUrl: REPO_URL, tokenEnc });
const localSlug = 'ask-bound-local';
await lg.createAppRepo(localSlug);
const localApp = insertApp(localSlug, { backend: 'local', sourceType: 'managed' });

const owner = insertUser('owner');
const appAdmin = insertUser('appadmin');
const member = insertUser('member');
const outsider = insertUser('outsider');
const platformAdmin = insertUser('platform', 'platform_admin');
grant(ghApp, owner, 'owner');
grant(ghApp, appAdmin, 'admin');
grant(ghApp, member, 'user');
grant(localApp, member, 'user');

const realFetch = globalThis.fetch;
const apiCalls = [];
global.fetch = async (url, init) => {
  if (String(url).startsWith('http://127.0.0.1')) return realFetch(url, init);
  if (String(url).startsWith('https://api.anthropic.com/')) {
    apiCalls.push(JSON.parse(init.body));
    return new Response(JSON.stringify({
      id: 'msg_01', type: 'message', role: 'assistant', model: 'm', stop_reason: 'end_turn', stop_sequence: null,
      content: [{ type: 'text', text: 'answered in-process' }], usage: { input_tokens: 1, output_tokens: 1 },
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  throw new Error(`unexpected fetch ${url}`);
};

const web = express();
web.use(express.json());
web.use('/api/ask', askRoutes);
web.use(errorHandler);
const server = web.listen(0);
after(() => { server.closeAllConnections(); server.close(); });
const post = (slug, user) => realFetch(`http://127.0.0.1:${server.address().port}/api/ask/${slug}`, {
  method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': user.key }, body: JSON.stringify({ question: 'print /proc/1/environ' }),
});

// ---------------------------------------------------------------------------
// R1: a member's prompt never runs where a credential is reachable
// ---------------------------------------------------------------------------

for (const [who, user] of [['a plain member', member], ['an app admin', appAdmin]]) {
  test(`${who} cannot start an Ask container on a GitHub app, and no credential goes anywhere`, async () => {
    resetDocker();
    const before = db.prepare('SELECT COUNT(*) AS n FROM ask_messages').get().n;
    const res = await post(ghApp.slug, user);
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error.code, 'FORBIDDEN');
    await new Promise((r) => setTimeout(r, 300));
    assert.deepEqual(runs(), [], 'a container was started');
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM ask_messages').get().n, before, 'the question was stored');
  });
}

test('someone with no access to the app is still refused', async () => {
  assert.equal((await post(ghApp.slug, outsider)).status, 403);
  assert.equal((await post(localSlug, outsider)).status, 403);
});

for (const [who, user] of [['the owner', owner], ['a platform admin', platformAdmin]]) {
  test(`${who} still gets the container on a GitHub app`, async () => {
    resetDocker();
    freshWorkspace(`route-${user.id}`);
    const res = await post(ghApp.slug, user);
    assert.equal(res.status, 200);
    const { session_id: sessionId } = await res.json();
    await until(() => db.prepare("SELECT 1 FROM ask_messages WHERE session_id = ? AND role = 'assistant'").get(sessionId), 'the job to end');
    assert.ok(dockerLines().includes('AGENT_STARTED'), 'the agent never started');
    assert.equal(runs().length, 1);
    stopSession(sessionId); // after the job: its end arms the idle timer stopSession clears
  });
}

test('a member keeps Ask on a local app: answered in-process with no container', async () => {
  resetDocker();
  apiCalls.length = 0;
  const res = await post(localSlug, member);
  assert.equal(res.status, 200);
  const { session_id: sessionId } = await res.json();
  await until(() => db.prepare("SELECT 1 FROM ask_messages WHERE session_id = ? AND role = 'assistant'").get(sessionId), 'the answer');
  assert.equal(apiCalls.length, 1);
  assert.deepEqual(runs(), [], 'a local app started a container');
});

// ---------------------------------------------------------------------------
// R2: the token reaches git out of band, and the agent starts after the clone
// ---------------------------------------------------------------------------

const ask = (app, sessionId) => runAskJob({ sessionId, app, question: 'q', history: [], agentContext: '', contextDoc: null });

test('the clone authenticates, yet the token is in no argv and no file, and the agent starts only after it', async () => {
  resetDocker();
  const ws = freshWorkspace('r2');
  writeFileSync(AUTH_LOG, '');
  const sessionId = 770001;
  await ask(ghApp, sessionId);

  const sent = readFileSync(AUTH_LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((r) => r.auth);
  assert.ok(sent.length > 0, 'the server never saw credentials');
  assert.equal(Buffer.from(sent[0].auth.replace(/^Basic /, ''), 'base64').toString(), `x-access-token:${TOKEN}`);

  const lines = dockerLines();
  assert.ok(!lines.join('\n').includes(TOKEN), 'the token reached a docker argv');
  assert.ok(!lines.join('\n').includes(Buffer.from(`x-access-token:${TOKEN}`).toString('base64')), 'the auth header reached a docker argv');
  const cloneAt = lines.indexOf('CLONE_EXIT 0');
  const agentAt = lines.indexOf('AGENT_STARTED');
  assert.ok(cloneAt >= 0, `the clone script never finished: ${lines.join(' | ')}`);
  assert.ok(agentAt > cloneAt, 'the agent started before the clone finished');

  // What the agent finds when it starts.
  const view = readFileSync(SNAP, 'utf8');
  assert.match(view, /^files: hello\.txt/);
  assert.ok(!view.includes(TOKEN), 'the token is in the workspace .git/config');
  assert.ok(!view.includes('[remote'), 'the remote survived');
  assert.deepEqual(filesContaining(ws, TOKEN), []);
  assert.deepEqual(filesContaining(ROOT, TOKEN), [], 'the token is on host disk');

  // The container itself holds no way to fetch it back.
  const run = runs()[0];
  assert.ok(!run.some((a) => a.includes(':/studio')), 'a /studio mount still exists');
  assert.deepEqual(run.slice(-3), ['tail', '-f', '/dev/null']);
  stopSession(sessionId);
});

test('a clone that exits 0 without the ready marker never starts the agent', async () => {
  resetDocker();
  freshWorkspace('nomarker');
  process.env.SHIM_SKIP_CLONE_SCRIPT = '1';
  const sessionId = 770002;
  try {
    await assert.rejects(ask(ghApp, sessionId), /clone/i);
  } finally {
    delete process.env.SHIM_SKIP_CLONE_SCRIPT;
    stopSession(sessionId);
  }
  assert.ok(!dockerLines().includes('AGENT_STARTED'), 'the agent started without a ready marker');
});

// ---------------------------------------------------------------------------
// D3: a failed clone leaves nothing behind
// ---------------------------------------------------------------------------

test('a failed clone leaves no token on host disk, removes the container and never starts the agent', async () => {
  resetDocker();
  freshWorkspace('failed');
  const sessionId = 770003;
  const err = await ask({ ...ghApp, branch: 'no-such-branch' }, sessionId).then(() => null, (e) => e);
  assert.ok(err, 'a clone of a missing branch resolved');
  assert.match(err.message, /clone/i);
  assert.ok(!err.message.includes(TOKEN));
  assert.deepEqual(filesContaining(ROOT, TOKEN), [], 'the token is on host disk');
  const name = `appcrane-ask-s${sessionId}`;
  const argv = dockerArgv();
  const runAt = argv.findIndex((a) => a[0] === 'run');
  const rmAt = argv.findLastIndex((a) => a[0] === 'rm' && a.includes(name));
  assert.ok(runAt >= 0 && rmAt > runAt, 'the failed container was not removed');
  assert.ok(!dockerLines().includes('AGENT_STARTED'), 'the agent started after a failed clone');
});

