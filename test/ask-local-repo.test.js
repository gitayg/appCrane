import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Ask Claude for a local-backed managed app (repo_backend = 'local') answers
// from <DATA_DIR>/repos/<slug>.git with a direct Messages API call and
// read-only git tools — no container.
//
// Real git for the repository and the tools. The Claude API is stubbed at the
// boundary production calls (global fetch), returning real Response objects
// whose bodies have the shape the Messages API returns. The stub reads the
// tool_result blocks production sends back, so an answer that contains a value
// from the repo proves the tool output reached the model. docker is a shim
// that records its argv: a local app must never reach it.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-asklocal-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
const API_KEY = 'sk-ant-test-0000-must-never-be-logged';
process.env.ANTHROPIC_API_KEY = API_KEY;
delete process.env.APPSTUDIO_CODER_MODEL;

const SHIM = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
const ASK_CAPTURE = join(ROOT, 'ask-capture');
mkdirSync(SHIM, { recursive: true });
mkdirSync(ASK_CAPTURE, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "$DOCKER_SHIM_LOG"
if [ "$DOCKER_SHIM_MODE" != ask ]; then echo "no docker" >&2; exit 1; fi
case "$1" in
  run)
    prev=""
    for a in "$@"; do
      case "$a" in *:/studio:ro) if [ "$prev" = -v ]; then d="\${a%:/studio:ro}"; cp "$d/clone_url" "$ASK_CAPTURE/clone_url"; fi ;; esac
      prev="$a"
    done
    echo shimcontainer ;;
  inspect) echo running ;;
  image) echo 5 ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;
process.env.DOCKER_SHIM_LOG = DOCKER_LOG;
process.env.ASK_CAPTURE = ASK_CAPTURE;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const { runAskJob, stopSession } = await import('../server/services/askClaude.js');
const { runLocalAskJob, LIMITS } = await import('../server/services/askLocalRepo.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const askRoutes = (await import('../server/routes/ask.js')).default;
const { getNextSlot } = await import('../server/services/portAllocator.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

// ---------------------------------------------------------------------------
// The repository: built with plain isolated git, never the module under test.
// ---------------------------------------------------------------------------

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C',
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t.invalid' };
const git = (args) => execFileSync('git', args, { env: CLEAN_ENV, stdio: 'pipe' }).toString('utf8').trim();

const SLUG = 'ask-local';
const OUTSIDE = join(ROOT, 'outside-secret.txt');
writeFileSync(OUTSIDE, 'OUTSIDE-SECRET-7731\n');
const BIG_LINE = 'match-everything filler line that pads the file out to many megabytes of text 0123456789\n';
const BIG_LINES = Math.ceil((3 * 1024 * 1024) / BIG_LINE.length);

await lg.createAppRepo(SLUG, { autoInit: false });
const work = join(ROOT, 'work');
git(['init', '-q', '-b', 'main', work]);
mkdirSync(join(work, 'server'), { recursive: true });
mkdirSync(join(work, 'bin'), { recursive: true });
writeFileSync(join(work, 'README.md'), '# ask-local\n');
writeFileSync(join(work, 'server', 'config.js'), 'export const MAGIC_PORT = 48213; // ask-local-marker\n');
writeFileSync(join(work, 'server', 'big.txt'), BIG_LINE.repeat(BIG_LINES));
writeFileSync(join(work, 'bin', 'blob.bin'), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 1, 2, 3]));
symlinkSync(OUTSIDE, join(work, 'link-out'));
git(['-C', work, 'add', '-A']);
git(['-C', work, 'commit', '-q', '-m', 'fixture']);
git(['-C', work, 'push', '-q', lg.repoPath(SLUG), 'main:refs/heads/main']);
const TIP = git([`--git-dir=${lg.repoPath(SLUG)}`, 'rev-parse', 'refs/heads/main']);

function insertApp(slug, { backend, githubUrl, sourceType = 'managed' }) {
  db.prepare('INSERT INTO apps (name, slug, slot, source_type, github_url, branch, repo_backend) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(slug, slug, getNextSlot(db), sourceType, githubUrl, 'main', backend);
  return db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
}
const localApp = insertApp(SLUG, { backend: 'local', githubUrl: null });
const ghApp = insertApp('ask-gh', { backend: null, githubUrl: 'https://github.com/o/AMC_ask-gh' });
insertApp('ask-norepo', { backend: null, githubUrl: null, sourceType: 'github' });

// ---------------------------------------------------------------------------
// The Messages API stub
// ---------------------------------------------------------------------------

const realFetch = globalThis.fetch;
const calls = [];
let reply = null; // (body, index, init) => message object | Response | Promise thereof
global.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  calls.push({ url: String(url), headers: init.headers, body });
  const out = await reply(body, calls.length - 1, init);
  if (out instanceof Response) return out;
  return new Response(JSON.stringify(out), { status: 200, headers: { 'content-type': 'application/json' } });
};

let seq = 0;
const nextId = (p) => `${p}${String(++seq).padStart(24, '0')}`;
const message = (content, stopReason, usage = { input_tokens: 1500, output_tokens: 90 }) => ({
  id: nextId('msg_01'),
  type: 'message',
  role: 'assistant',
  model: 'claude-sonnet-4-6',
  content,
  stop_reason: stopReason,
  stop_sequence: null,
  usage: { cache_creation_input_tokens: 0, cache_read_input_tokens: 0, service_tier: 'standard', ...usage },
});
const toolUse = (name, input) => ({ type: 'tool_use', id: nextId('toolu_01'), name, input });
const text = (t) => ({ type: 'text', text: t });
/** tool_result blocks in the last user message of a request. */
const toolResults = (body) => {
  const last = body.messages[body.messages.length - 1];
  return Array.isArray(last.content) ? last.content.filter((b) => b.type === 'tool_result') : [];
};
const dockerRuns = () => (existsSync(DOCKER_LOG) ? readFileSync(DOCKER_LOG, 'utf8') : '')
  .split('\n').filter(Boolean).map((l) => l.split('\x1f').slice(0, -1)).filter((a) => a[0] === 'run');

function ask(app, extra = {}) {
  const logs = [];
  let tokens = 0;
  const p = runAskJob({
    sessionId: 990000 + (++seq), app, question: 'Which port does the server listen on?', history: [],
    agentContext: '', contextDoc: null, onLog: (l) => logs.push(l), onTokens: (n) => { tokens = n; }, ...extra,
  });
  return { p, logs, tokens: () => tokens };
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

test('a local app is answered from its repository through the tools, with no container', async (t) => {
  calls.length = 0;
  const runsBefore = dockerRuns().length;
  reply = (body, i) => {
    if (i === 0) return message([text("I'll look at the layout."), toolUse('list_files', {})], 'tool_use');
    if (i === 1) {
      assert.match(toolResults(body)[0].content, /^server\/config\.js \(53 bytes\)$/m);
      return message([toolUse('search_code', { pattern: 'MAGIC_PORT' })], 'tool_use');
    }
    if (i === 2) return message([toolUse('read_file', { path: 'server/config.js' })], 'tool_use');
    const port = /MAGIC_PORT = (\d+)/.exec(toolResults(body)[0].content)?.[1];
    return message([text(`The server listens on port ${port}.`)], 'end_turn');
  };
  const { p, logs, tokens } = ask(localApp);
  const answer = await p;

  assert.equal(answer, 'The server listens on port 48213.');
  assert.equal(calls.length, 4);
  assert.equal(dockerRuns().length, runsBefore, 'a container was started for a local app');

  const [first] = calls;
  assert.equal(first.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(first.headers['x-api-key'], API_KEY);
  assert.equal(first.headers['anthropic-version'], '2023-06-01');
  assert.equal(first.body.model, 'claude-sonnet-4-6', 'ASK_MODEL default changed');
  assert.deepEqual(first.body.tools.map((x) => x.name), ['list_files', 'read_file', 'search_code']);
  assert.equal(first.body.tool_choice, undefined);
  assert.match(first.body.system, new RegExp(`commit ${TIP.slice(0, 12)}`));
  assert.match(first.body.messages[0].content, /# Question\nWhich port does the server listen on\?$/);

  assert.equal(toolResults(calls[2].body)[0].content, 'server/config.js:1:export const MAGIC_PORT = 48213; // ask-local-marker');
  assert.equal(toolResults(calls[3].body)[0].content, '1\texport const MAGIC_PORT = 48213; // ask-local-marker\n2\t');
  for (const c of calls.slice(1)) assert.equal(toolResults(c.body).some((r) => r.is_error), false);
  // Every assistant turn is sent back verbatim, tool_use blocks included.
  assert.equal(calls[3].body.messages.filter((m) => m.role === 'assistant').length, 3);

  assert.deepEqual(logs, [
    `[ask] Reading the local repository (main @ ${TIP.slice(0, 7)})`,
    '[ask] Asking Claude...',
    '[ask:tool] list_files',
    '[ask:tool] search_code',
    '[ask:tool] read_file server/config.js',
  ]);
  assert.equal(tokens(), 4 * (1500 + 90));
  assert.equal(logs.some((l) => l.includes(API_KEY)), false);

  t.diagnostic(`answer: ${answer}`);
  for (const [i, c] of calls.entries()) {
    const uses = i + 1 < calls.length
      ? toolResults(calls[i + 1].body).map((r) => r.content.split('\n')[0]).join(' | ') : '';
    t.diagnostic(`call ${i + 1}: tool_results in -> ${toolResults(c.body).length}; next tool output head: ${uses}`);
  }
});

test('history and operator context reach the model in the same prompt shape as the container path', async () => {
  calls.length = 0;
  reply = () => message([text('ok')], 'end_turn');
  await runAskJob({
    sessionId: 990500, app: localApp, question: 'and now?', agentContext: 'OPS-NOTE', contextDoc: 'ARCH-DOC',
    history: [{ role: 'user', content: 'first q' }, { role: 'assistant', content: 'first a' }],
  });
  assert.equal(calls[0].body.messages[0].content,
    '# Codebase context\nARCH-DOC\n\n# Operator notes\nOPS-NOTE\n\n# Previous conversation\nUser: first q\n\nAssistant: first a\n\n---\n\n# Question\nand now?');
});

// ---------------------------------------------------------------------------
// Read-only, inside the repo
// ---------------------------------------------------------------------------

test('tool arguments cannot read outside the tree: traversal, absolute, .git, NUL, symlinks, git-dir files', async () => {
  calls.length = 0;
  const pwned = join(ROOT, 'pwned');
  const attempts = [
    toolUse('read_file', { path: '../outside-secret.txt' }),
    toolUse('read_file', { path: '../../../../../etc/passwd' }),
    toolUse('read_file', { path: '/etc/passwd' }),
    toolUse('read_file', { path: OUTSIDE }),
    toolUse('read_file', { path: 'server/../../outside-secret.txt' }),
    toolUse('read_file', { path: '.git/config' }),
    toolUse('read_file', { path: 'a b' }),
    toolUse('read_file', { path: 'link-out' }),
    toolUse('read_file', { path: 'config' }),
    toolUse('read_file', { path: 'HEAD' }),
    toolUse('list_files', { path: '..' }),
    toolUse('list_files', { path: '/' }),
    toolUse('search_code', { pattern: 'x', path: '../' }),
    toolUse('read_file', { path: 42 }),
  ];
  reply = (body, i) => (i === 0
    ? message(attempts, 'tool_use')
    : message([text('refused')], 'end_turn'));
  assert.equal(await ask(localApp).p, 'refused');

  const results = toolResults(calls[1].body);
  assert.equal(results.length, attempts.length, 'every tool_use needs a tool_result');
  for (const [i, r] of results.entries()) {
    assert.equal(r.tool_use_id, attempts[i].id);
    assert.equal(r.is_error, true, `attempt ${i} (${JSON.stringify(attempts[i].input)}) was not refused: ${r.content}`);
    assert.doesNotMatch(r.content, /OUTSIDE-SECRET|root:|\[core\]|refs\/heads/);
  }
  assert.match(results[7].content, /symbolic link; links are not followed/);
  assert.equal(existsSync(pwned), false);
});

test('a search pattern is never parsed as a git option, and the symlink target is not searched', async () => {
  calls.length = 0;
  const pwned = join(ROOT, 'pwned-grep');
  reply = (body, i) => (i === 0
    ? message([
      toolUse('search_code', { pattern: `--open-files-in-pager=touch ${pwned}` }),
      toolUse('search_code', { pattern: '-Otouch' }),
      toolUse('search_code', { pattern: 'OUTSIDE-SECRET' }),
    ], 'tool_use')
    : message([text('done')], 'end_turn'));
  await ask(localApp).p;
  const results = toolResults(calls[1].body);
  assert.deepEqual(results.map((r) => r.content), ['No matches.', 'No matches.', 'No matches.']);
  assert.equal(existsSync(pwned), false);
  assert.equal(existsSync(join(ROOT, 'work', 'pwned-grep')), false);
});

test('gitReadCapped refuses any subcommand that is not a read', () => {
  for (const sub of ['update-ref', 'push', 'config', 'gc', 'hash-object', 'fetch', 'worktree']) {
    assert.throws(() => lg.gitReadCapped(SLUG, [sub, 'x'], { maxBytes: 10 }), /not a read-only subcommand/);
  }
});

test('a binary file is described, not dumped', async () => {
  calls.length = 0;
  reply = (body, i) => (i === 0
    ? message([toolUse('read_file', { path: 'bin/blob.bin' })], 'tool_use')
    : message([text('bin')], 'end_turn'));
  await ask(localApp).p;
  assert.equal(toolResults(calls[1].body)[0].content, "'bin/blob.bin' is a binary file (10 bytes); not shown.");
});

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

test('a 3 MiB file and a grep matching every line each come back under the per-call cap', async () => {
  calls.length = 0;
  reply = (body, i) => (i === 0
    ? message([toolUse('read_file', { path: 'server/big.txt' }), toolUse('search_code', { pattern: 'match-everything' })], 'tool_use')
    : message([text('big')], 'end_turn'));
  await ask(localApp).p;
  const [read, grep] = toolResults(calls[1].body);
  assert.ok(Buffer.byteLength(read.content) <= LIMITS.maxToolResultBytes, `read_file returned ${Buffer.byteLength(read.content)} bytes`);
  assert.ok(Buffer.byteLength(read.content) > LIMITS.maxToolResultBytes / 2, 'read_file returned suspiciously little');
  assert.match(read.content, /\[output truncated at line \d+; call read_file again with start_line=\d+\]$/);
  assert.ok(Buffer.byteLength(grep.content) <= LIMITS.maxToolResultBytes, `search_code returned ${Buffer.byteLength(grep.content)} bytes`);
  assert.match(grep.content, /\[results truncated after \d+ matches; use a more specific pattern or path\]$/);
});

test('gitReadCapped holds at most maxBytes of a blob and kills git past it', async () => {
  const sha = git([`--git-dir=${lg.repoPath(SLUG)}`, 'rev-parse', `${TIP}:server/big.txt`]);
  const r = await lg.gitReadCapped(SLUG, ['cat-file', 'blob', sha], { maxBytes: 65536 });
  assert.equal(r.truncated, true);
  assert.equal(r.stdout.length, 65536);
  const small = await lg.gitReadCapped(SLUG, ['cat-file', 'blob', sha], { maxBytes: 8 * 1024 * 1024 });
  assert.equal(small.truncated, false);
  assert.equal(small.stdout.length, BIG_LINE.length * BIG_LINES);
});

test('the tool-call loop stops at maxIterations and makes Claude answer without tools', async () => {
  calls.length = 0;
  reply = (body) => (body.tool_choice?.type === 'none'
    ? message([text('answered at the cap')], 'end_turn')
    : message([toolUse('list_files', { path: 'server' })], 'tool_use'));
  assert.equal(await ask(localApp).p, 'answered at the cap');
  assert.equal(calls.length, LIMITS.maxIterations + 1);
  assert.equal(calls.filter((c) => c.body.tool_choice).length, 1);
  const lastUser = calls.at(-1).body.messages.at(-1).content;
  assert.match(lastUser.at(-1).text, /Tool limit reached/);
});

test('a model that ignores tool_choice none at the cap is an error, not an endless loop', async () => {
  calls.length = 0;
  reply = () => message([toolUse('list_files', {})], 'tool_use');
  await assert.rejects(ask(localApp).p, /kept calling tools after the tool limit/);
  assert.equal(calls.length, LIMITS.maxIterations + 1);
});

test('the total reading budget ends the loop long before the iteration cap', async () => {
  calls.length = 0;
  let line = 1;
  reply = (body) => {
    if (body.tool_choice?.type === 'none') return message([text('budget')], 'end_turn');
    const prev = toolResults(body)[0]?.content;
    const m = prev && /start_line=(\d+)\]$/.exec(prev);
    if (m) line = Number(m[1]);
    return message([toolUse('read_file', { path: 'server/big.txt', start_line: line })], 'tool_use');
  };
  assert.equal(await ask(localApp).p, 'budget');
  assert.ok(calls.length < LIMITS.maxIterations, `took ${calls.length} calls`);
  let delivered = 0;
  for (const c of calls) for (const r of toolResults(c.body)) if (!r.is_error) delivered += Buffer.byteLength(r.content);
  assert.ok(delivered <= LIMITS.maxTotalToolBytes, `delivered ${delivered} bytes of tool output`);
  assert.ok(delivered > LIMITS.maxTotalToolBytes - LIMITS.maxToolResultBytes, `delivered only ${delivered} bytes`);
  const last = toolResults(calls.at(-1).body)[0];
  assert.equal(last.is_error, true);
  assert.match(last.content, /reading budget for this question is used up/);
});

test('wall time: a Claude call that does not return is abandoned at the deadline', async () => {
  calls.length = 0;
  reply = (body, i, init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(init.signal.reason));
  });
  const started = Date.now();
  await assert.rejects(
    runLocalAskJob({ app: localApp, question: 'q', history: [], model: 'claude-sonnet-4-6', limits: { ...LIMITS, timeoutMs: 400 } }),
    /Ask Claude timed out/,
  );
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

// ---------------------------------------------------------------------------
// Credentials, errors, and the GitHub path
// ---------------------------------------------------------------------------

test('without ANTHROPIC_API_KEY a local app fails NOT_CONFIGURED and calls nothing', async () => {
  calls.length = 0;
  const runsBefore = dockerRuns().length;
  delete process.env.ANTHROPIC_API_KEY;
  try {
    await assert.rejects(ask(localApp).p, (e) => e.code === 'NOT_CONFIGURED' && e.status === 503);
  } finally {
    process.env.ANTHROPIC_API_KEY = API_KEY;
  }
  assert.equal(calls.length, 0);
  assert.equal(dockerRuns().length, runsBefore);
});

test('an API error surfaces its status and type, never the key', async () => {
  calls.length = 0;
  reply = () => new Response(JSON.stringify({ type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' }, request_id: 'req_011' }),
    { status: 401, headers: { 'content-type': 'application/json' } });
  await assert.rejects(ask(localApp).p, (e) => {
    assert.equal(e.message, 'Claude API error 401 (authentication_error): invalid x-api-key');
    return true;
  });
  assert.equal(calls.length, 1, 'a 401 was retried');
});

test('a refusal is reported as an error rather than an empty answer', async () => {
  reply = () => ({ ...message([], 'refusal'), stop_details: { type: 'refusal', category: null, explanation: null } });
  await assert.rejects(ask(localApp).p, /declined to answer/);
});

test('a NULL-marker managed app still starts the ask container and never calls the API directly', async () => {
  calls.length = 0;
  const runsBefore = dockerRuns().length;
  process.env.DOCKER_SHIM_MODE = 'ask';
  const sessionId = 991001;
  try {
    await Promise.race([
      runAskJob({ sessionId, app: ghApp, question: 'q', history: [], agentContext: '', contextDoc: null }).catch(() => {}),
      new Promise((r) => setTimeout(r, 20000)),
    ]);
  } finally {
    stopSession(sessionId);
    delete process.env.DOCKER_SHIM_MODE;
  }
  const runs = dockerRuns();
  assert.equal(runs.length, runsBefore + 1, 'no container was started for the NULL-marker app');
  const run = runs.at(-1);
  assert.ok(run.includes(`appcrane-ask-s${sessionId}`));
  assert.equal(readFileSync(join(ASK_CAPTURE, 'clone_url'), 'utf8'), 'https://github.com/o/AMC_ask-gh');
  assert.equal(run.at(-1),
    'CLONE_URL=$(cat /studio/clone_url) && git clone --depth 1 --branch "$BRANCH" "$CLONE_URL" /workspace && git -C /workspace remote remove origin && git -C /workspace config --local credential.helper "" && tail -f /dev/null');
  assert.equal(calls.length, 0, 'the NULL-marker app called the Messages API directly');
});

test('an unknown repo_backend marker is refused, not routed to either path', async () => {
  calls.length = 0;
  await assert.rejects(ask({ ...localApp, repo_backend: 'Local' }).p, /does not recognise/);
  assert.equal(calls.length, 0);
});

// ---------------------------------------------------------------------------
// The route: same job id, SSE events and permission checks
// ---------------------------------------------------------------------------

test('POST /api/ask/:slug accepts a local app with no github_url and streams the answer over SSE', async (t) => {
  const userKey = 'user-key-asklocal';
  const outsiderKey = 'outsider-key-asklocal';
  const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('u','u@x.test','user',?,1,'human')")
    .run(hashApiKey(userKey)).lastInsertRowid;
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('o','o@x.test','user',?,1,'human')")
    .run(hashApiKey(outsiderKey));
  db.prepare('INSERT INTO app_users (app_id, user_id) VALUES (?, ?)').run(localApp.id, uid);
  const noRepo = db.prepare("SELECT id FROM apps WHERE slug = 'ask-norepo'").get();
  db.prepare('INSERT INTO app_users (app_id, user_id) VALUES (?, ?)').run(noRepo.id, uid);

  const app = express();
  app.use(express.json());
  app.use('/api/ask', askRoutes);
  app.use(errorHandler);
  const server = app.listen(0);
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (slug, key, body) => realFetch(`${base}/api/ask/${slug}`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key }, body: JSON.stringify(body),
  });

  assert.equal((await post(SLUG, outsiderKey, { question: 'q' })).status, 403);
  const nr = await post('ask-norepo', userKey, { question: 'q' });
  assert.equal(nr.status, 400);
  assert.equal((await nr.json()).error.code, 'NO_REPO');

  calls.length = 0;
  reply = (body, i) => (i === 0
    ? message([toolUse('read_file', { path: 'server/config.js' })], 'tool_use')
    : message([text(`Port ${/MAGIC_PORT = (\d+)/.exec(toolResults(body)[0].content)[1]}.`)], 'end_turn'));
  const res = await post(SLUG, userKey, { question: 'Which port?' });
  assert.equal(res.status, 200);
  const { session_id: sessionId, job_id: jobId } = await res.json();
  assert.match(jobId, /^[A-Za-z0-9_-]{22}$/);

  const stream = await realFetch(`${base}/api/ask/stream/${jobId}?token=${userKey}`);
  assert.equal(stream.headers.get('content-type'), 'text/event-stream');
  let raw = '';
  const decoder = new TextDecoder();
  for await (const chunk of stream.body) {
    raw += decoder.decode(chunk, { stream: true });
    if (/"type":"(done|error)"/.test(raw)) break;
  }
  await stream.body.cancel().catch(() => {});
  const events = raw.split('\n').filter((l) => l.startsWith('data: ')).map((l) => JSON.parse(l.slice(6)));
  const done = events.find((e) => e.type === 'done');
  assert.ok(done, `no done event: ${raw}`);
  assert.deepEqual(done, { type: 'done', answer: 'Port 48213.', session_id: sessionId });
  assert.ok(events.some((e) => e.type === 'log' && e.text === '[ask:tool] read_file server/config.js'));
  const stored = db.prepare('SELECT role, content FROM ask_messages WHERE session_id = ? ORDER BY id').all(sessionId);
  assert.deepEqual(stored, [{ role: 'user', content: 'Which port?' }, { role: 'assistant', content: 'Port 48213.' }]);
});

// Last on purpose: it moves the branch, then puts it back.
test('every read is pinned to the commit resolved at the start, even when a push lands mid-answer', async () => {
  calls.length = 0;
  writeFileSync(join(work, 'server', 'config.js'), 'export const MAGIC_PORT = 11111; // moved\n');
  git(['-C', work, 'commit', '-q', '-am', 'moved']);
  try {
    reply = (body, i) => {
      if (i === 0) {
        git(['-C', work, 'push', '-q', lg.repoPath(SLUG), 'main:refs/heads/main']);
        assert.notEqual(git([`--git-dir=${lg.repoPath(SLUG)}`, 'rev-parse', 'refs/heads/main']), TIP);
        return message([toolUse('read_file', { path: 'server/config.js' })], 'tool_use');
      }
      return message([text(toolResults(body)[0].content)], 'end_turn');
    };
    const answer = await ask(localApp).p;
    assert.match(answer, /MAGIC_PORT = 48213/, 'a read followed the branch past the commit the answer started on');
  } finally {
    git(['-C', work, 'reset', '-q', '--hard', TIP]);
    git(['-C', work, 'push', '-q', '--force', lg.repoPath(SLUG), 'main:refs/heads/main']);
  }
});
