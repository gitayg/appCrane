import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'events';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The coder turn for a Crew app coder task (services/crewAppCoderRunner.js),
// with the container, queue, MCP key and Claude CLI replaced by fakes that
// emit what runAgentExec emits (system with session_id, data text, result,
// exit). What is pinned:
//   - a Crew turn never uses a person's coder session: no --resume of any
//     coder_sessions conversation, it gets a fresh one, and a follow-up on the
//     same task resumes only that task's conversation;
//   - it runs as the given user (billing), with a read-only coder key that is
//     revoked when the turn ends, through the app's work queue;
//   - busy while someone's interactive session is mid-turn; a failed turn,
//     no credential and a cancel each fail with their reason.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-coder-runner-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { defaultCoderRunner } = await import('../server/services/crewAppCoderRunner.js');

db.prepare("INSERT INTO users (id, name, email, role, api_key_hash, active, kind) VALUES (42, 'Olga', 'olga@example.com', 'user', 'x-runner-test', 1, 'human')").run();
db.prepare("INSERT INTO apps (id, name, slot, slug, source_type, repo_backend, branch) VALUES (1, 'shop', 1, 'shop', 'managed', 'local', 'main')").run();
const app = db.prepare('SELECT * FROM apps WHERE id = 1').get();
// The owner's own interactive session, with its conversation: a Crew turn must never continue it.
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status, claude_session_id) VALUES ('owner-s', 'shop', 42, 'builder/shop', 'idle', 'owner-thread')").run();

function fakes({ script, kind = 'user_oauth', failure = null } = {}) {
  const calls = { exec: [], issued: [], revoked: [], queued: [], busy: [], stopped: 0 };
  const deps = {
    getOrCreateContainer: async () => ({ containerId: 'ctr-shop', credsCleanup: null, claudeSessionId: 'owner-thread' }),
    setContainerBusy: (slug, b) => calls.busy.push(b),
    enqueue: (slug, item) => { calls.queued.push(item.sourceType); return Promise.resolve().then(item.run); },
    runAgentExec: (args) => {
      calls.exec.push(args);
      const r = new EventEmitter();
      r.start = () => setImmediate(() => script(r));
      r.stop = () => { calls.stopped += 1; };
      r.getStderrTail = () => [];
      return r;
    },
    agentCredentialKind: () => kind,
    issueKey: ({ userId, appId }) => { calls.issued.push({ userId, appId }); return { id: 7, apiKey: 'dhk_mcp_fake' }; },
    revokeKey: (id) => calls.revoked.push(id),
    mcpConfig: () => '{}',
    allowedTools: () => [],
    mcpPrompt: 'mcp',
    model: () => 'sonnet',
    permissionMode: () => null,
    systemPrompt: () => 'sys',
    explainTurnFailure: () => failure,
  };
  return { deps, calls };
}
const answer = (sid, text) => (r) => {
  r.emit('system', { type: 'system', data: { session_id: sid } });
  r.emit('data', { type: 'text', text });
  r.emit('result', { isError: false });
  r.emit('exit', 0);
};

test('a first turn starts a fresh conversation, never the owner\'s session, as the given user', async () => {
  const { deps, calls } = fakes({ script: answer('crew-new-1', 'Changed src/cart.js.') });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't1' }, deps);
  assert.deepEqual({ ok: r.ok, text: r.text, sid: r.claudeSessionId }, { ok: true, text: 'Changed src/cart.js.', sid: 'crew-new-1' });
  assert.equal(calls.exec[0].resume, undefined, 'no --resume: the owner thread and the container thread are not continued');
  assert.equal(calls.exec[0].actingUserId, 42);
  assert.equal(calls.exec[0].containerId, 'ctr-shop');
  assert.deepEqual(calls.issued, [{ userId: 42, appId: 1 }]);
  assert.deepEqual(calls.revoked, [7], 'the coder key is revoked when the turn ends');
  assert.deepEqual(calls.queued, ['crew'], "through the app's work queue");
  assert.deepEqual(calls.busy, [true, false]);
  assert.equal(db.prepare("SELECT claude_session_id FROM coder_sessions WHERE id = 'owner-s'").get().claude_session_id, 'owner-thread', "the owner's session is untouched");
});

test("a follow-up on the same task resumes that task's conversation only", async () => {
  const { deps, calls } = fakes({ script: answer('crew-new-1', 'Done.') });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P2', taskId: 't1', resume: 'crew-new-1' }, deps);
  assert.equal(r.ok, true);
  assert.equal(calls.exec[0].resume, 'crew-new-1');
  // A malformed id never reaches the shell.
  const bad = fakes({ script: answer('x', 'y') });
  await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't1', resume: 'a; rm -rf /' }, bad.deps);
  assert.equal(bad.calls.exec[0].resume, undefined);
});

test("busy while someone's interactive coder session is mid-turn", async () => {
  db.prepare("UPDATE coder_sessions SET status = 'active' WHERE id = 'owner-s'").run();
  try {
    const { deps, calls } = fakes({ script: answer('s', 'x') });
    const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't2' }, deps);
    assert.equal(r.busy, true);
    assert.equal(calls.exec.length, 0);
  } finally {
    db.prepare("UPDATE coder_sessions SET status = 'idle' WHERE id = 'owner-s'").run();
  }
});

test('busy while another person holds the app\'s coder workspace, even idle; the owner\'s own session does not count', async () => {
  db.prepare("INSERT INTO users (id, name, email, role, api_key_hash, active, kind) VALUES (43, 'Omar', 'omar@example.com', 'user', 'x-runner-test-2', 1, 'human')").run();
  db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('other-s', 'shop', 43, 'builder/shop', 'idle')").run();
  try {
    const { deps, calls } = fakes({ script: answer('s', 'x') });
    const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't6' }, deps);
    assert.equal(r.busy, true);
    assert.match(r.reason, /in use by another person/);
    assert.equal(calls.exec.length, 0, 'nothing ran in their workspace');
  } finally {
    db.prepare("UPDATE coder_sessions SET status = 'paused' WHERE id = 'other-s'").run();
  }
  // Paused: no longer holding it. The owner's own idle session ('owner-s') never blocks.
  const { deps, calls } = fakes({ script: answer('s', 'ok') });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't7' }, deps);
  assert.equal(r.ok, true);
  assert.equal(calls.exec.length, 1);
});

test('a failed turn fails with its reason', async () => {
  const { deps, calls } = fakes({ script: answer('s', 'API Error: 401'), failure: 'Your Claude token was rejected.' });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't3' }, deps);
  assert.equal(r.ok, false);
  assert.match(r.reason, /token was rejected/);
  assert.deepEqual(calls.revoked, [7]);
});

test('no credential: nothing starts', async () => {
  const { deps, calls } = fakes({ script: answer('s', 'x'), kind: 'none' });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't4' }, deps);
  assert.equal(r.ok, false);
  assert.match(r.reason, /no Claude credential/);
  assert.equal(calls.exec.length, 0);
});

test('canceling the task stops the turn', async () => {
  const ac = new AbortController();
  const { deps, calls } = fakes({ script: () => ac.abort() });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', taskId: 't5', signal: ac.signal }, deps);
  assert.equal(r.ok, false);
  assert.match(r.reason, /canceled/);
  assert.equal(calls.stopped, 1);
  assert.deepEqual(calls.revoked, [7]);
});
