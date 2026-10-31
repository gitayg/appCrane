import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The real coder-session runner for Crew app coder tasks
// (services/crewAppCoderRunner.js), with builderSession's API replaced by a
// fake that publishes the same events a turn publishes (status active → turn →
// error? → status idle / paused) and writes the transcript rows it writes.
// What is pinned: the answer is the turn's last assistant message, a failed
// turn and a stopped container fail with the reason, a session that is
// mid-turn or held by another person is "busy" (and nothing is left queued),
// no credential means no session, and the session is started as the given
// user (whose credential it bills).

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
let n = 0;

function fakeSession({ status = 'idle', occupied = false, turn }) {
  const subs = new Map();
  const calls = { created: [], dispatched: [], cancelled: [], stopped: [] };
  const publish = (id, ev) => { for (const fn of subs.get(id) || []) fn(ev); };
  const api = {
    calls,
    async createSession(a, userId) {
      calls.created.push({ slug: a.slug, userId });
      if (occupied) { const e = new Error('Builder is occupied by Omar.'); e.code = 'BUILDER_OCCUPIED'; throw e; }
      const id = `s-${++n}`;
      db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES (?, ?, ?, 'builder/shop', ?)").run(id, a.slug, userId, status);
      db.prepare("INSERT INTO coder_session_messages (session_id, role, content) VALUES (?, 'assistant', 'an earlier answer')").run(id);
      return id;
    },
    subscribe(id, fn) {
      if (!subs.has(id)) subs.set(id, new Set());
      subs.get(id).add(fn);
      return () => subs.get(id).delete(fn);
    },
    async dispatch(id, prompt, opts) {
      calls.dispatched.push({ id, prompt, userId: opts.userId });
      if (status === 'race') return { queued: true, followup: { id: 77 } };
      db.prepare("INSERT INTO coder_session_messages (session_id, role, content) VALUES (?, 'user', ?)").run(id, prompt);
      publish(id, { type: 'status', status: 'active' });
      setImmediate(() => turn({ id, publish }));
      return { started: true };
    },
    stopDispatch(id) { calls.stopped.push(id); },
    cancelFollowup(id, fid) { calls.cancelled.push({ id, fid }); return true; },
  };
  return api;
}

const answer = (text) => ({ id, publish }) => {
  publish(id, { type: 'turn' });
  db.prepare("INSERT INTO coder_session_messages (session_id, role, content) VALUES (?, 'assistant', ?)").run(id, text);
  publish(id, { type: 'status', status: 'idle', exitCode: 0 });
};
const withCredential = () => 'user_oauth';

test('the answer is the turn\'s last assistant message, from a session started as the given user', async () => {
  const s = fakeSession({ turn: answer('Changed src/cart.js.') });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: s, agentCredentialKind: withCredential });
  assert.deepEqual({ ok: r.ok, text: r.text }, { ok: true, text: 'Changed src/cart.js.' });
  assert.deepEqual(s.calls.created, [{ slug: 'shop', userId: 42 }]);
  assert.equal(s.calls.dispatched[0].userId, 42);
  assert.equal(s.calls.dispatched[0].prompt, 'P');
});

test('a failed turn fails with its reason, not with the failure text as an answer', async () => {
  const s = fakeSession({
    turn: ({ id, publish }) => {
      db.prepare("INSERT INTO coder_session_messages (session_id, role, content) VALUES (?, 'assistant', 'API Error: 401')").run(id);
      publish(id, { type: 'error', message: 'Your Claude token was rejected.', turnFailed: true });
      publish(id, { type: 'status', status: 'idle', exitCode: 1 });
    },
  });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: s, agentCredentialKind: withCredential });
  assert.equal(r.ok, false);
  assert.match(r.reason, /token was rejected/);
});

test('a container stopped mid-turn fails the task', async () => {
  const s = fakeSession({ turn: ({ id, publish }) => publish(id, { type: 'status', status: 'paused', reason: 'idle' }) });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: s, agentCredentialKind: withCredential });
  assert.equal(r.ok, false);
  assert.match(r.reason, /container stopped/);
});

test('a stopped turn with no new answer is not mistaken for the previous answer', async () => {
  const s = fakeSession({ turn: ({ id, publish }) => { publish(id, { type: 'turn' }); publish(id, { type: 'status', status: 'idle' }); } });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: s, agentCredentialKind: withCredential });
  assert.equal(r.ok, false);
  assert.match(r.reason, /without an answer/);
});

test('busy: another person holds the coder, or the session is mid-turn; nothing is left queued', async () => {
  const held = fakeSession({ occupied: true, turn: answer('x') });
  const a = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: held, agentCredentialKind: withCredential });
  assert.equal(a.busy, true);
  assert.match(a.reason, /in use by another person/);

  const mid = fakeSession({ status: 'active', turn: answer('x') });
  const b = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: mid, agentCredentialKind: withCredential });
  assert.equal(b.busy, true);
  assert.equal(mid.calls.dispatched.length, 0, 'nothing dispatched into a running turn');

  const race = fakeSession({ status: 'race', turn: answer('x') });
  const c = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: race, agentCredentialKind: withCredential });
  assert.equal(c.busy, true);
  assert.deepEqual(race.calls.cancelled.map((x) => x.fid), [77], 'a request that slipped into the follow-up queue is taken out again');
});

test('no credential for the owner: no session is started', async () => {
  const s = fakeSession({ turn: answer('x') });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P' }, { session: s, agentCredentialKind: () => 'none' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no Claude credential/);
  assert.equal(s.calls.created.length, 0);
});

test('canceling the task stops the turn', async () => {
  const ac = new AbortController();
  const s = fakeSession({ turn: () => ac.abort() });
  const r = await defaultCoderRunner({ app, userId: 42, prompt: 'P', signal: ac.signal }, { session: s, agentCredentialKind: withCredential });
  assert.equal(r.ok, false);
  assert.match(r.reason, /canceled/);
  assert.equal(s.calls.stopped.length, 1);
});
