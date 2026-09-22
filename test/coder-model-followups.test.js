import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// v2.85.0 — the two things the coder chat gained, and the one thing that makes
// the first of them dangerous.
//
//  1. MODEL SELECTION. `model` travels from a browser into a SHELL STRING that
//     `sh -c` runs inside the app container (runAgent.buildClaudeCmd). The
//     tests below prove BOTH defences independently: the route refuses
//     anything off the allowlist, AND a value that somehow got past the list
//     is still one argv word rather than a second command. The second half is
//     proved by actually running the built command through a real /bin/sh with
//     a `claude` shim that records its argv — not by matching a quote
//     character in a string.
//
//  2. FOLLOW-UPS WHILE RUNNING. Typed-ahead messages are queued in SQLite, not
//     in the browser, so the assertions here read the DB and the HTTP surface
//     rather than any in-memory structure: that IS the claim ("survives a
//     reload, visible to anyone watching").
//
// docker is a PATH shim that plays the container and logs argv. The `exec`
// case sleeps, so a turn is genuinely in flight while the next POST arrives.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-codermodel-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-coder-model';
process.env.GIT_TERMINAL_PROMPT = '0';
delete process.env.APPSTUDIO_CODER_MODEL;

const REAL_FETCH = globalThis.fetch.bind(globalThis);
const REAL_GIT = execFileSync('which', ['git']).toString().trim();

// --- shims -------------------------------------------------------------------
const SHIM = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(DOCKER_LOG, '');
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${DOCKER_LOG}"
case "$1" in
  image)   echo 4 ;;
  inspect) echo true ;;
  run)     echo 0123456789abcdef0123456789abcdef ;;
  exec)
    # Play a turn that takes long enough for a second POST to land mid-flight.
    sleep "\${CRANE_TEST_TURN_SECONDS:-2}"
    printf '%s\\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
    printf '%s\\n' '{"type":"result","usage":{"input_tokens":1,"output_tokens":1}}'
    ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const lg = await import('../server/services/localGit.js');
const coderRoutes = (await import('../server/routes/coder.js')).default;
const { runAgentExec } = await import('../server/services/llm/runAgent.js');
const models = await import('../server/services/llm/coderModels.js');

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });

after(async () => {
  try {
    const { stopHealthChecker } = await import('../server/services/healthChecker.js');
    stopHealthChecker();
  } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

// --- fixtures ----------------------------------------------------------------
const API_KEY = 'testkey-coder-model';
db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin',?,1,'human')"
).run(hashApiKey(API_KEY));

const SLUG = 'modelapp';
await lg.createAppRepo(SLUG, { description: 'model + followups' });
await lg.pushFilesToManagedRepo(SLUG, [
  { path: 'package.json', content: '{"name":"modelapp","version":"1.0.0"}\n' },
], { message: 'seed' });
db.prepare(
  "INSERT INTO apps (name,slot,slug,source_type,repo_backend,github_url,branch) VALUES (?,?,?,'managed','local',NULL,'main')"
).run(SLUG, 991, SLUG);

const api = express();
api.use(express.json());
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = api.listen(0);
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => server.close());

const call = (method, path, body) => REAL_FETCH(`${BASE}${path}`, {
  method,
  headers: { 'X-API-Key': API_KEY, 'Content-Type': 'application/json' },
  ...(body ? { body: JSON.stringify(body) } : {}),
});
const json = async (r) => ({ status: r.status, body: await r.json() });

const dockerLines = () => readFileSync(DOCKER_LOG, 'utf8').split('\n').filter(Boolean)
  .map((l) => l.split('\x1f').slice(0, -1));
const execCmds = () => dockerLines().filter((a) => a[0] === 'exec').map((a) => a[a.length - 1]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 20000, label = 'condition') {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await sleep(60);
  }
  throw new Error(`timed out waiting for ${label}`);
}

// =============================================================================
// 1. The allowlist
// =============================================================================

const INJECTION = 'sonnet; touch /tmp/pwned';

test('the model allowlist is a list of exact strings, and the injection is not in it', () => {
  assert.equal(models.isAllowedCoderModel(INJECTION), false,
    'a shell-metacharacter model passed the allowlist — that is remote code execution in the app container');
  // The things a regex over "safe-looking characters" would also wave through.
  for (const bad of ['sonnet && id', 'sonnet`id`', 'sonnet$(id)', 'sonnet\nid', '--dangerously-skip-permissions', '']) {
    assert.equal(models.isAllowedCoderModel(bad), false, `allowlist accepted ${JSON.stringify(bad)}`);
  }
  // And every value the picker is served is one the validator accepts. If these
  // ever disagree the UI offers a choice that 400s on send.
  for (const m of models.coderModelChoices()) {
    assert.equal(models.isAllowedCoderModel(m.id), true, `${m.id} is offered but refused`);
  }
});

test("the deployment's configured default is always selectable", () => {
  const prev = process.env.APPSTUDIO_CODER_MODEL;
  process.env.APPSTUDIO_CODER_MODEL = 'claude-something-an-operator-pinned';
  try {
    assert.equal(models.defaultCoderModel(), 'claude-something-an-operator-pinned');
    assert.equal(models.isAllowedCoderModel('claude-something-an-operator-pinned'), true,
      'the one model this deployment actually runs must not be the one nobody can pick');
    assert.ok(models.coderModelChoices().some(c => c.id === 'claude-something-an-operator-pinned' && c.is_default));
  } finally {
    if (prev === undefined) delete process.env.APPSTUDIO_CODER_MODEL;
    else process.env.APPSTUDIO_CODER_MODEL = prev;
  }
});

test('GET /api/coder/models serves the same list the validator enforces', async () => {
  const { status, body } = await json(await call('GET', '/api/coder/models'));
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.models) && body.models.length > 0, 'no models offered');
  assert.equal(body.default, models.defaultCoderModel());
  assert.deepEqual(
    body.models.map(m => m.id).sort(),
    models.allowedCoderModels().sort(),
    'the served list and the enforced list are different arrays',
  );
  assert.ok(body.models.some(m => m.is_default), 'nothing is marked as the default');
});

// =============================================================================
// 2. The quoting — the second, independent defence
// =============================================================================

test('the built argv quotes the model, so a metacharacter is one word and not a command', () => {
  // Built by the SAME function a dispatch uses, with the value the allowlist
  // exists to stop — this is what remains if the list is ever edited wrong.
  const cmd = runAgentExec({ containerId: 'c0', prompt: 'hi', model: INJECTION, apiKey: 'k' })
    .getDockerArgs().pop();

  assert.ok(cmd.includes(`--model '${INJECTION}'`),
    `model is not single-quoted in the shell string:\n${cmd}`);
  assert.ok(!/--model sonnet; touch/.test(cmd),
    'the raw, unquoted interpolation is still there');

  // Not a claim about quote characters: run it. `claude` is a shim that
  // records its argv; `touch` would create the marker if the `;` escaped.
  const jail = mkdtempSync(join(ROOT, 'quote-'));
  const marker = join(jail, 'pwned');
  const argvLog = join(jail, 'argv');
  writeFileSync(join(jail, 'claude'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } > "${argvLog}"
`, { mode: 0o755 });
  writeFileSync(join(jail, 'touch'), `#!/bin/sh\n: > "${marker}"\n`, { mode: 0o755 });

  const runnable = runAgentExec({
    containerId: 'c0', prompt: 'hi', model: `sonnet; touch ${marker}`, apiKey: 'k',
    workdir: jail, homeDir: jail,
  }).getDockerArgs().pop();
  execFileSync('/bin/sh', ['-c', runnable], { env: { PATH: `${jail}:${process.env.PATH}`, HOME: jail }, stdio: 'pipe' });

  assert.equal(existsSync(marker), false,
    'the `;` in the model string ran as a second command — the quoting does not hold');
  const argv = readFileSync(argvLog, 'utf8').split('\x1f').slice(0, -1);
  const i = argv.indexOf('--model');
  assert.ok(i >= 0, `claude never saw --model: ${argv.join(' ')}`);
  assert.equal(argv[i + 1], `sonnet; touch ${marker}`,
    'the model did not arrive as a single argv word');
});

// =============================================================================
// 3. The route refuses an off-list model
// =============================================================================

let sessionId;

test('a session starts on the Crane-hosted app', async () => {
  const { status, body } = await json(await call('POST', `/api/coder/${SLUG}/session`));
  assert.equal(status, 201, `session did not start: ${JSON.stringify(body)}`);
  sessionId = body.session_id;
});

test('dispatch with `sonnet; touch /tmp/pwned` is refused, and nothing runs', async () => {
  const execsBefore = execCmds().length;
  const msgsBefore = db.prepare('SELECT COUNT(*) n FROM coder_session_messages WHERE session_id = ?').get(sessionId).n;

  const { status, body } = await json(
    await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt: 'hi', model: INJECTION }),
  );
  assert.equal(status, 400, `expected a refusal, got ${status} ${JSON.stringify(body)}`);
  assert.equal(body.error?.code, 'VALIDATION');

  assert.equal(execCmds().length, execsBefore, 'a container command ran despite the refusal');
  assert.equal(
    db.prepare('SELECT COUNT(*) n FROM coder_session_messages WHERE session_id = ?').get(sessionId).n,
    msgsBefore,
    'the refused prompt was written into the transcript anyway',
  );
});

test('a dispatch names its model on the container command and on the stored turn', async () => {
  const r = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`,
    { prompt: 'first turn', model: 'haiku' }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.queued, false, 'an idle session must start the turn, not queue it');

  await waitFor(() => execCmds().some(c => c.includes("--model 'haiku'")), 20000, 'the exec carrying --model haiku');
  await waitFor(
    () => !!db.prepare("SELECT 1 FROM coder_session_messages WHERE session_id = ? AND role = 'assistant' AND model = 'haiku'").get(sessionId),
    20000, 'the assistant row stamped with its model',
  );

  const user = db.prepare("SELECT model FROM coder_session_messages WHERE session_id = ? AND role = 'user' ORDER BY id DESC LIMIT 1").get(sessionId);
  assert.equal(user.model, 'haiku', 'the user turn does not record which model was asked for');
});

// =============================================================================
// 4. Follow-ups while a turn is running
// =============================================================================

async function startLongTurn(prompt = 'long turn') {
  const r = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.queued, false, 'expected this dispatch to start, not queue');
  return r;
}

test('a message typed while a turn runs is QUEUED, not refused, and order is preserved', async () => {
  await startLongTurn('turn A');

  const q1 = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt: 'then B', model: 'opus' }));
  const q2 = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt: 'then C' }));

  // Before v2.85.0 both of these were `A dispatch is already running`.
  assert.equal(q1.status, 200, JSON.stringify(q1.body));
  assert.equal(q1.body.queued, true, 'a follow-up was not queued');
  assert.equal(q2.body.queued, true);

  const { body } = await json(await call('GET', `/api/coder/${SLUG}/session/${sessionId}/followups`));
  assert.deepEqual(body.followups.map(f => f.prompt), ['then B', 'then C'], 'follow-up order was not preserved');
  assert.equal(body.followups[0].model, 'opus', 'the model chosen for a follow-up was dropped');

  // A pending follow-up is NOT a turn. Writing it into the transcript would
  // claim it had been sent to the model.
  const asTurn = db.prepare(
    "SELECT COUNT(*) n FROM coder_session_messages WHERE session_id = ? AND content IN ('then B','then C')"
  ).get(sessionId).n;
  assert.equal(asTurn, 0, 'a pending follow-up was written into the transcript as though it ran');
});

test('a pending follow-up survives a reload: it comes back with the transcript', async () => {
  // This is the whole reason the queue is server-side. The route below is the
  // one the chat calls on every (re)connect.
  const { body } = await json(await call('GET', `/api/coder/${SLUG}/session/${sessionId}`));
  assert.deepEqual(body.followups.map(f => f.prompt), ['then B', 'then C'],
    'GET /session/:id does not carry the pending queue — an F5 would lose it');
});

test('a pending follow-up can be cancelled before it starts', async () => {
  const before = (await json(await call('GET', `/api/coder/${SLUG}/session/${sessionId}/followups`))).body.followups;
  const victim = before[1];
  const { status, body } = await json(
    await call('DELETE', `/api/coder/${SLUG}/session/${sessionId}/followups/${victim.id}`));
  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual(body.followups.map(f => f.prompt), ['then B']);
  assert.equal(
    db.prepare('SELECT status FROM coder_session_followups WHERE id = ?').get(victim.id).status,
    'cancelled',
  );
  // Cancelling the same row twice is a 404, not a silent success.
  const again = await json(await call('DELETE', `/api/coder/${SLUG}/session/${sessionId}/followups/${victim.id}`));
  assert.equal(again.status, 404);
});

test('the surviving follow-up is dispatched automatically when the turn ends', async () => {
  await waitFor(() => execCmds().some(c => c.includes('then B')), 25000, 'the queued follow-up to run');
  await waitFor(
    () => db.prepare("SELECT status FROM coder_session_followups WHERE prompt = 'then B'").get()?.status === 'dispatched',
    25000, 'the follow-up to be marked dispatched',
  );
  // And it became a real turn only at that point.
  assert.ok(
    db.prepare("SELECT 1 FROM coder_session_messages WHERE session_id = ? AND role = 'user' AND content = 'then B'").get(sessionId),
    'the dispatched follow-up never entered the transcript',
  );
  await waitFor(async () =>
    (await json(await call('GET', `/api/coder/${SLUG}/session/${sessionId}/followups`))).body.followups.length === 0,
    25000, 'the queue to drain');
});

test('Stop CLEARS the pending queue rather than running it', async () => {
  await waitFor(async () =>
    (await json(await call('GET', `/api/coder/${SLUG}/session/${sessionId}`))).body.session.status === 'idle',
    25000, 'the session to go idle');

  await startLongTurn('turn to be stopped');
  const a = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt: 'must not run 1' }));
  const b = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt: 'must not run 2' }));
  assert.equal(a.body.queued, true);
  assert.equal(b.body.queued, true);

  const stop = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/stop`));
  assert.equal(stop.status, 200);

  const after = await json(await call('GET', `/api/coder/${SLUG}/session/${sessionId}/followups`));
  assert.deepEqual(after.body.followups, [],
    'Stop left typed-ahead messages queued — they would fire against a workspace the user just abandoned');
  for (const p of ['must not run 1', 'must not run 2']) {
    assert.equal(db.prepare('SELECT status FROM coder_session_followups WHERE prompt = ?').get(p).status, 'cancelled');
  }

  // Give the queue a chance to misbehave before declaring it did not.
  await sleep(2500);
  const cmds = execCmds();
  assert.ok(!cmds.some(c => c.includes('must not run')),
    'a cancelled follow-up reached the container anyway');
});

test('after a Stop the session still works — the appQueue slot was released', async () => {
  // Agent.stop() suppresses the 'exit' event, so the stopped turn never
  // resolved its appQueue `run()` and the item stayed `running` FOREVER (its
  // rescue timeout is cleared by stop() as well). Observed in the browser:
  // every message after a Stop queued as a follow-up that could never drain.
  // Pre-existing, but it makes the follow-up queue unusable, so it is fixed
  // here rather than left as "the second message is just a bit stuck".
  const { body: q } = await json(await call('GET', `/api/coder/${SLUG}/queue`));
  assert.equal(q.running, null, `appQueue still holds a running item after Stop: ${JSON.stringify(q.running)}`);
  assert.equal(q.depth, 0, `appQueue still has ${q.depth} item(s) waiting after Stop`);

  const r = await json(await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt: 'after the stop' }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.queued, false,
    'a message sent after a Stop was queued behind a turn that is not running — the session is wedged');
  await waitFor(() => execCmds().some(c => c.includes('after the stop')), 25000, 'the post-stop turn to run');
});
