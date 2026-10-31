import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'events';
import { mkdtempSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// SECURITY FIX (review of v2.131.0): a Crew turn never receives the app's
// shared Claude login. The turn runs a prompt another person's agent shaped,
// with network access, and the app login is mounted as a writable copy whose
// rewrite is stored back for the app (claudeCredentials.js pushCopy), so the
// copy could be read out or replaced. Here the real credential decision and
// the real docker argv (runAgentNewArgs) run for each Crew turn, with the app
// login stored for the app in every case:
//   - owner has a Claude token -> CLAUDE_CODE_OAUTH_TOKEN, nothing else;
//   - owner has none, platform key set -> ANTHROPIC_API_KEY, no app login;
//   - neither -> the turn fails with its reason, no container, no admission,
//     no memory reservation left behind.
// Every other caller still falls back to the app login (last test).

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-coder-creds-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.ANTHROPIC_API_KEY;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { defaultCoderRunner } = await import('../server/services/crewAppCoderRunner.js');
const { runAgentNewArgs } = await import('../server/services/llm/runAgent.js');
const { setCredentials } = await import('../server/services/claudeCredentials.js');
const { setUserClaudeToken, clearUserClaudeToken } = await import('../server/services/userClaudeToken.js');

const WORKSPACE = join(process.env.DATA_DIR, 'app-containers', 'shop', 'workspace');
mkdirSync(WORKSPACE, { recursive: true });

const USER_TOKEN = 'sk-ant-oat01-PRETEND-OWNER-TOKEN-1111';
const API_KEY = 'sk-ant-api03-PRETEND-PLATFORM-KEY-2222';
const APP_ACCESS = 'app-shared-access-token-3333';
const APP_REFRESH = 'app-shared-refresh-token-4444';

db.prepare("INSERT INTO users (id, name, email, role, api_key_hash, active, kind) VALUES (42, 'Olga', 'olga@example.com', 'user', 'x-creds-test', 1, 'human')").run();
db.prepare("INSERT INTO apps (id, name, slot, slug, source_type, repo_backend, branch) VALUES (1, 'shop', 1, 'shop', 'managed', 'local', 'main')").run();
const app = db.prepare('SELECT * FROM apps WHERE id = 1').get();
setCredentials('shop', { access_token: APP_ACCESS, refresh_token: APP_REFRESH });

function harness() {
  const calls = { argv: [], started: 0, admitted: 0, reserved: 0, released: 0 };
  const deps = {
    getOrCreateContainer: async () => { calls.started += 1; return { containerId: 'ctr-shop', workspaceDir: WORKSPACE }; },
    setContainerBusy: () => {},
    enqueue: (slug, item) => Promise.resolve().then(item.run),
    admit: async () => { calls.admitted += 1; return { allowed: true }; },
    reserveMemory: () => { calls.reserved += 1; return () => { calls.released += 1; }; },
    removeContainer: () => {},
    // The real argv, from the options the runner hands over.
    runAgentNew: (opts) => {
      calls.argv.push(runAgentNewArgs(opts));
      const r = new EventEmitter();
      r.start = () => setImmediate(() => {
        r.emit('system', { data: { session_id: 'crew-sid' } });
        r.emit('data', { type: 'text', text: 'done' });
        r.emit('exit', 0);
      });
      r.stop = () => {};
      r.getStderrTail = () => [];
      return r;
    },
    issueKey: () => null,
    revokeKey: () => {},
    model: () => 'sonnet',
    permissionMode: () => null,
    systemPrompt: () => 'sys',
    explainTurnFailure: () => null,
  };
  return { deps, calls };
}

function envOf(argv) {
  const out = {};
  for (let i = 0; i < argv.length - 1; i++) {
    if (argv[i] !== '-e') continue;
    const eq = argv[i + 1].indexOf('=');
    out[argv[i + 1].slice(0, eq)] = argv[i + 1].slice(eq + 1);
  }
  return out;
}

function assertNoAppLogin(argv) {
  const joined = argv.join('\n');
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '-v') assert.ok(!/credentials\.json/.test(argv[i + 1]), `credentials mount: ${argv[i + 1]}`);
  }
  assert.ok(!joined.includes(APP_ACCESS) && !joined.includes(APP_REFRESH), 'nothing from the app login');
}

test('owner with a Claude token: only the token, never the app login', async () => {
  setUserClaudeToken(42, USER_TOKEN);
  process.env.ANTHROPIC_API_KEY = API_KEY;
  try {
    const { deps, calls } = harness();
    const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 'c1' }, deps);
    assert.equal(r.ok, true, r.reason);
    const env = envOf(calls.argv[0]);
    assert.equal(env.CLAUDE_CODE_OAUTH_TOKEN, USER_TOKEN);
    assert.ok(!('ANTHROPIC_API_KEY' in env));
    assertNoAppLogin(calls.argv[0]);
  } finally {
    clearUserClaudeToken(42);
    delete process.env.ANTHROPIC_API_KEY;
  }
});

test('owner without a token, platform key set: the platform key, never the app login', async () => {
  process.env.ANTHROPIC_API_KEY = API_KEY;
  try {
    const { deps, calls } = harness();
    const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 'c2' }, deps);
    assert.equal(r.ok, true, r.reason);
    const env = envOf(calls.argv[0]);
    assert.equal(env.ANTHROPIC_API_KEY, API_KEY);
    assert.ok(!('CLAUDE_CODE_OAUTH_TOKEN' in env));
    assertNoAppLogin(calls.argv[0]);
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
  }
});

test('owner without a token and no platform key: the turn fails, nothing starts', async () => {
  const { deps, calls } = harness();
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 'c3' }, deps);
  assert.equal(r.ok, false);
  assert.match(r.reason, /no Claude login of their own and no platform API key is set; Crew turns do not use the app's shared login/);
  assert.equal(calls.argv.length, 0, 'no container');
  assert.equal(calls.started, 0, 'refused at the gate: the app container is not even started');
  assert.equal(calls.admitted, 0, 'no memory admission');
  assert.equal(calls.reserved, calls.released, 'no memory reservation left held');
});

test('the turn re-checks: a token removed after the gate still never falls back to the app login', async () => {
  setUserClaudeToken(42, USER_TOKEN);
  const { deps, calls } = harness();
  const enqueue = deps.enqueue;
  deps.enqueue = (slug, item) => { clearUserClaudeToken(42); return enqueue(slug, item); };
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 'c4' }, deps);
  assert.equal(r.ok, false);
  assert.match(r.reason, /Crew turns do not use the app's shared login/);
  assert.equal(calls.argv.length, 0);
  assert.equal(calls.reserved, calls.released);
});

test('other callers are unchanged: with no token and no key the app login is still mounted', () => {
  const argv = runAgentNewArgs({ image: 'img', workspaceDir: WORKSPACE, prompt: 'p', appSlug: 'shop', actingUserId: 42, apiKey: '' });
  assert.ok(argv.some((a) => /:\/home\/studio\/\.claude\/\.credentials\.json$/.test(a)), 'app login mounted for non-Crew callers');
});
