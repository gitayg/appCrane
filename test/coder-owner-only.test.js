import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The coder is the app owner's and platform admins' alone. Before this, every
// /api/coder/:slug route checked only that the caller was on the app, so any
// member could read every session's transcript, follow its stream and list its
// changes, and an app admin could release a colleague's work.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-coderowner-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-owner-only-test';

// Starting a session reaches docker; this file asserts only who gets past the
// gate, so a docker that fails at once is the right fake on every host.
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "docker disabled in this test" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const mk = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES (?,?,?,1,?,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, name };
};
const APP = db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,branch) VALUES ('O',1,'own','managed','local','main')").run().lastInsertRowid;
const OWNER = mk('owner'), APPADMIN = mk('appadmin'), MEMBER = mk('member'), OUTSIDER = mk('outsider'), PLATFORM = mk('platform', 'platform_admin');
for (const [u, r] of [[OWNER, 'owner'], [APPADMIN, 'admin'], [MEMBER, 'user']]) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, u.id, r);
}
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('s-own', 'own', ?, 'b', 'paused')").run(OWNER.id);
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('s-pa', 'own', ?, 'b', 'paused')").run(PLATFORM.id);
db.prepare("INSERT INTO coder_session_messages (session_id, role, content) VALUES ('s-own', 'user', 'secret plan')").run();
const REQ = db.prepare("INSERT INTO enhancement_requests (app_slug, user_name, message, status) VALUES ('own', 'member', 'do it', 'new')").run().lastInsertRowid;

const coder = (await import('../server/routes/coder.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/coder', coder); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => {
  server.closeAllConnections?.(); server.close();
  delete process.env.ANTHROPIC_API_KEY;
  rmSync(ROOT, { recursive: true, force: true });
});
const call = async (method, path, who, body) => {
  const ctrl = new AbortController();
  const r = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method, signal: ctrl.signal,
    headers: { 'x-api-key': who.key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined,
  });
  if ((r.headers.get('content-type') || '').startsWith('text/event-stream')) {
    ctrl.abort();
    return { status: r.status, stream: true, body: {} };
  }
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

const REFUSED_ROUTES = [
  ['GET', '/api/coder/own/session'],
  ['GET', '/api/coder/own/session/s-own'],
  ['GET', '/api/coder/own/session/s-own/events'],
  ['POST', '/api/coder/own/session/s-own/dispatch', { prompt: 'hi' }],
  ['GET', '/api/coder/own/session/s-own/changes'],
  ['POST', '/api/coder/own/session/s-own/release', { paths: ['a.js'] }],
  ['POST', '/api/coder/own/session'],
  ['POST', '/api/coder/own/requests/dispatch', { request_ids: [Number(REQ)] }],
  ['GET', '/api/coder/own/session/s-own/followups'],
  ['POST', '/api/coder/own/session/s-own/stop'],
  ['POST', '/api/coder/own/session/s-own/resume'],
  ['POST', '/api/coder/own/session/s-own/attachments', { name: 'a.txt', data: 'aGk=' }],
  ['GET', '/api/coder/own/container'],
  ['GET', '/api/coder/own/queue'],
  ['POST', '/api/coder/own/evict'],
];

test('an app admin, a member and an outsider are refused on every coder route, with one refusal', async () => {
  for (const who of [APPADMIN, MEMBER, OUTSIDER]) {
    for (const [m, p, b] of REFUSED_ROUTES) {
      const r = await call(m, p, who, b);
      assert.equal(r.status, 403, `${who.name}: ${m} ${p} answered ${r.status} ${JSON.stringify(r.body).slice(0, 160)}`);
      assert.equal(r.body.error?.code, 'FORBIDDEN', `${who.name}: ${m} ${p}`);
      assert.equal(r.body.error?.message, 'Only the app owner or a platform admin can use the coder', `${who.name}: ${m} ${p}`);
      assert.doesNotMatch(JSON.stringify(r.body), /secret plan/);
    }
  }
  assert.equal(db.prepare('SELECT status FROM enhancement_requests WHERE id = ?').get(REQ).status, 'new', 'a refused dispatch moved the request');
});

test('a missing app is still a 404, not the owner refusal', async () => {
  const r = await call('GET', '/api/coder/nope/session', MEMBER);
  assert.equal(r.status, 404);
});

test('the owner and a platform admin read the transcript and follow the stream', async () => {
  for (const who of [OWNER, PLATFORM]) {
    const read = await call('GET', '/api/coder/own/session/s-own', who);
    assert.equal(read.status, 200, `${who.name}: ${JSON.stringify(read.body).slice(0, 160)}`);
    assert.equal(read.body.messages[0].content, 'secret plan');
    const stream = await call('GET', '/api/coder/own/session/s-own/events', who);
    assert.equal(stream.status, 200);
    assert.ok(stream.stream, `${who.name}: the stream did not open`);
    const changes = await call('GET', '/api/coder/own/session/s-own/changes', who);
    assert.equal(changes.body.error?.code, 'NO_WORKSPACE', `${who.name}: ${JSON.stringify(changes.body)}`);
  }
});

test('the owner and a platform admin get past the gate to start, send, release and dispatch requests', async () => {
  for (const [who, own] of [[OWNER, 's-own'], [PLATFORM, 's-pa']]) {
    const send = await call('POST', `/api/coder/own/session/${own}/dispatch`, who, { prompt: 'hi' });
    assert.equal(send.body.error?.code, 'SESSION_PAUSED', `${who.name}: ${JSON.stringify(send.body)}`);
    const release = await call('POST', `/api/coder/own/session/${own}/release`, who, { paths: ['a.js'] });
    assert.equal(release.body.error?.code, 'NO_WORKSPACE', `${who.name}: ${JSON.stringify(release.body)}`);
    const reqs = await call('POST', '/api/coder/own/requests/dispatch', who, { request_ids: [] });
    assert.equal(reqs.body.error?.code, 'VALIDATION', `${who.name}: ${JSON.stringify(reqs.body)}`);
    const start = await call('POST', '/api/coder/own/session', who);
    assert.notEqual(start.status, 403, `${who.name}: start refused ${JSON.stringify(start.body)}`);
    assert.notEqual(start.status, 401);
  }
});

test('the per-session owner rule stands: a platform admin cannot send into the owner\'s session', async () => {
  const r = await call('POST', '/api/coder/own/session/s-own/dispatch', PLATFORM, { prompt: 'hi' });
  assert.equal(r.status, 403);
  assert.equal(r.body.error?.code, 'NOT_SESSION_OWNER');
});

test('availability tells an app admin or a member why, and tells the owner nothing of the sort', async () => {
  for (const who of [APPADMIN, MEMBER]) {
    const r = await call('GET', '/api/coder/own/availability', who);
    assert.equal(r.status, 200);
    assert.equal(r.body.available, false);
    assert.equal(r.body.can_release, false);
    assert.equal(r.body.can_dispatch_requests, false);
    assert.deepEqual(r.body.gaps.map((g) => g.code), ['NOT_APP_OWNER']);
    assert.equal(r.body.gaps[0].title, 'Only the app owner or a platform admin can use the coder');
  }
  for (const who of [OWNER, PLATFORM]) {
    const r = await call('GET', '/api/coder/own/availability', who);
    assert.ok(!r.body.gaps.some((g) => g.code === 'NOT_APP_OWNER'), `${who.name}: ${JSON.stringify(r.body.gaps)}`);
    assert.equal(r.body.can_dispatch_requests, true);
  }
  assert.equal((await call('GET', '/api/coder/own/availability', OUTSIDER)).status, 403);
});
