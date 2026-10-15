import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// "When the coder is up, let the platform admin or the app owner select
// requests and dispatch them to the coder to fix" — several at once go into ONE
// session as ONE prompt, worked through in order and released together.
//
// The agent runner is not stubbed in JS: docker is a PATH shim that plays the
// container and logs argv (same seam as coder-model-followups.test.js), so the
// session is started and the turn dispatched by the real builderSession code,
// and the prompt asserted on is the one that reached `docker exec`.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-dispatchreq-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-dispatch-requests';
process.env.GIT_TERMINAL_PROMPT = '0';
process.env.CRANE_TEST_TURN_SECONDS = '0';

const REAL_FETCH = globalThis.fetch.bind(globalThis);

const SHIM = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(DOCKER_LOG, '');
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${DOCKER_LOG}"
case "$1" in
  image)   echo 5 ;;
  inspect) echo true ;;
  run)     echo 0123456789abcdef0123456789abcdef ;;
  exec)
    sleep "\${CRANE_TEST_TURN_SECONDS:-0}"
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
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const lg = await import('../server/services/localGit.js');
const coderRoutes = (await import('../server/routes/coder.js')).default;

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });

after(async () => {
  try {
    const { stopHealthChecker } = await import('../server/services/healthChecker.js');
    stopHealthChecker();
  } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

// --- fixtures ----------------------------------------------------------------
const mkUser = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES (?,?,?,1,?,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
};
const OWNER = mkUser('owner'), APPADMIN = mkUser('appadmin'), MEMBER = mkUser('member');
const PLATFORM = mkUser('platform', 'platform_admin'), OTHER = mkUser('other');

let slot = 900;
async function mkApp(slug, { hosted = true } = {}) {
  if (hosted) {
    await lg.createAppRepo(slug, { description: 'dispatch requests' });
    await lg.pushFilesToManagedRepo(slug, [{ path: 'package.json', content: `{"name":"${slug}","version":"1.0.0"}\n` }], { message: 'seed' });
    return db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,github_url,branch) VALUES (?,?,?,'managed','local',NULL,'main')")
      .run(slug, slot++, slug).lastInsertRowid;
  }
  return db.prepare("INSERT INTO apps (name,slot,slug,source_type,github_url,branch) VALUES (?,?,?,'github','https://github.com/example/x','main')")
    .run(slug, slot++, slug).lastInsertRowid;
}
const role = (appId, u, r) => db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, u.id, r);
const mkReq = (slug, message, { status = 'new', userId = OWNER.id, userName = 'Requester', vulnKey = null } = {}) =>
  Number(db.prepare('INSERT INTO enhancement_requests (app_slug,user_id,user_name,message,status,vuln_key) VALUES (?,?,?,?,?,?)')
    .run(slug, userId, userName, message, status, vulnKey).lastInsertRowid);

const APP = await mkApp('reqapp');
role(APP, OWNER, 'owner'); role(APP, APPADMIN, 'admin'); role(APP, MEMBER, 'user');
const ADMIN_APP = await mkApp('reqplat');
const GH_APP = await mkApp('reqgh', { hosted: false });
role(GH_APP, OWNER, 'owner');
const OTHER_APP = await mkApp('reqother');
role(OTHER_APP, OTHER, 'owner');

const R1 = mkReq('reqapp', '[Element: <button> "Save"] make the Save button green');
const R2 = mkReq('reqapp', 'add a footer with the version');
const VULN = mkReq('reqapp', 'Dependency advisory: lodash 4.17.20 (GHSA-test)', { userId: null, userName: 'AppCrane dependency scan', vulnKey: `[${APP},"npm","lodash","GHSA-test"]` });
const SHIPPED = mkReq('reqapp', 'already done', { status: 'done' });
const FOREIGN = mkReq('reqother', 'secret request on another app', { userId: OTHER.id });
const PLAT_REQ = mkReq('reqplat', 'rename the page title');
const GH_REQ = mkReq('reqgh', 'a request on a GitHub app');

const api = express();
api.use(express.json());
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = api.listen(0);
await new Promise((r) => server.once('listening', r));
after(() => { server.closeAllConnections?.(); server.close(); });

const call = async (who, slug, body) => {
  const r = await REAL_FETCH(`http://127.0.0.1:${server.address().port}/api/coder/${slug}/requests/dispatch`, {
    method: 'POST', headers: { 'X-API-Key': who.key, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const reqRow = (id) => db.prepare('SELECT status, coder_session_id FROM enhancement_requests WHERE id = ?').get(id);
const snapshot = () => db.prepare('SELECT id, status, coder_session_id FROM enhancement_requests ORDER BY id').all();
const userTurns = (sid) => db.prepare("SELECT content FROM coder_session_messages WHERE session_id = ? AND role = 'user'").all(sid);
const execPrompts = () => readFileSync(DOCKER_LOG, 'utf8').split('\x1f\n').filter(Boolean)
  .map((l) => l.split('\x1f')).filter((a) => a[0] === 'exec').map((a) => a[a.length - 1])
  .filter((c) => c.includes('=== Request #'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 20000, label = 'condition') {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return; await sleep(60); }
  throw new Error(`timed out waiting for ${label}`);
}

test('an app admin and a member are refused with 403, and nothing changes', async () => {
  const before = snapshot();
  for (const who of [APPADMIN, MEMBER]) {
    const r = await call(who, 'reqapp', { request_ids: [R1] });
    assert.equal(r.status, 403, `${JSON.stringify(r.body)}`);
    assert.equal(r.body.error?.code, 'FORBIDDEN');
  }
  assert.deepEqual(snapshot(), before);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM coder_sessions WHERE app_slug = 'reqapp'").get().n, 0);
});

test('a request id from another app is refused like an unknown one, and nothing changes', async () => {
  const before = snapshot();
  const foreign = await call(OWNER, 'reqapp', { request_ids: [R1, FOREIGN] });
  const unknown = await call(OWNER, 'reqapp', { request_ids: [R1, 999999] });
  assert.equal(foreign.status, 404, JSON.stringify(foreign.body));
  assert.equal(foreign.body.error?.code, 'NOT_FOUND');
  assert.deepEqual(foreign.body, unknown.body, 'the refusal tells a foreign id apart from a missing one');
  assert.ok(!foreign.body.error.message.includes(String(FOREIGN)), 'the refusal names the foreign id');
  assert.deepEqual(snapshot(), before);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM coder_sessions WHERE app_slug = 'reqapp'").get().n, 0);
});

test('a shipped request is refused, and the open one sent with it is left alone', async () => {
  const before = snapshot();
  const r = await call(OWNER, 'reqapp', { request_ids: [R1, SHIPPED] });
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.error?.code, 'REQUEST_CLOSED');
  assert.match(r.body.error.message, new RegExp(`#${SHIPPED}\\b`));
  assert.deepEqual(snapshot(), before);
});

test('when the coder is not available for the app, the refusal carries the gap', async () => {
  const before = snapshot();
  const r = await call(OWNER, 'reqgh', { request_ids: [GH_REQ] });
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.error?.code, 'CODER_UNAVAILABLE');
  assert.match(r.body.error.message, /code lives in your GitHub repository/);
  assert.equal(r.body.error.gaps?.[0]?.code, 'NOT_CRANE_HOSTED');
  assert.deepEqual(snapshot(), before);
});

test('more than the cap, or the same id twice, is refused', async () => {
  const many = Array.from({ length: 11 }, (_, i) => i + 1);
  assert.equal((await call(OWNER, 'reqapp', { request_ids: many })).body.error?.code, 'TOO_MANY_REQUESTS');
  assert.equal((await call(OWNER, 'reqapp', { request_ids: [R1, R1] })).status, 400);
  assert.equal((await call(OWNER, 'reqapp', { request_ids: [] })).status, 400);
});

let ownerSession;

test('the owner dispatches: one session, one prompt with every request in the order picked', async () => {
  const order = [R2, VULN, R1];
  const r = await call(OWNER, 'reqapp', { request_ids: order });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.session_id);
  assert.equal(r.body.queued, false);
  ownerSession = r.body.session_id;

  const sessions = db.prepare("SELECT id, user_id FROM coder_sessions WHERE app_slug = 'reqapp'").all();
  assert.deepEqual(sessions, [{ id: ownerSession, user_id: OWNER.id }], 'not exactly one session, owned by the caller');

  const turns = userTurns(ownerSession);
  assert.equal(turns.length, 1, `expected one prompt, got ${turns.length}`);
  const at = order.map((id) => turns[0].content.indexOf(`=== Request #${id} `));
  assert.ok(at.every((i) => i >= 0), `a request is missing from the prompt: ${at}`);
  assert.deepEqual([...at].sort((a, b) => a - b), at, 'the requests are not in the order picked');
  assert.match(turns[0].content, /make the Save button green/);
  assert.match(turns[0].content, /lodash 4\.17\.20/);

  await waitFor(() => execPrompts().length > 0, 20000, 'the prompt to reach docker exec');
  const sent = execPrompts();
  assert.equal(sent.length, 1, `expected one agent run carrying the requests, got ${sent.length}`);
  for (const id of order) assert.ok(sent[0].includes(`=== Request #${id} `), `request #${id} never reached the agent`);
});

test('the dispatched requests are in progress and carry the session id; the rest are untouched', () => {
  for (const id of [R1, R2, VULN]) {
    assert.deepEqual(reqRow(id), { status: 'in_progress', coder_session_id: ownerSession }, `request #${id}`);
  }
  assert.deepEqual(reqRow(SHIPPED), { status: 'done', coder_session_id: null });
  assert.deepEqual(reqRow(FOREIGN), { status: 'new', coder_session_id: null });
});

test('a scan-opened request (no requester user) is dispatched like any other', () => {
  assert.equal(db.prepare('SELECT user_id FROM enhancement_requests WHERE id = ?').get(VULN).user_id, null);
  assert.equal(reqRow(VULN).coder_session_id, ownerSession);
  assert.match(userTurns(ownerSession)[0].content, new RegExp(`=== Request #${VULN} \\(filed by AppCrane dependency scan`));
});

test('the dispatch is audit-logged with who, which app and which ids', () => {
  const row = db.prepare("SELECT user_id, app_id, detail FROM audit_log WHERE action = 'coder.dispatch-requests'").get();
  assert.ok(row, 'no audit row');
  assert.equal(row.user_id, OWNER.id);
  assert.equal(row.app_id, APP);
  assert.deepEqual(JSON.parse(row.detail).request_ids, [R2, VULN, R1]);
});

test('a platform admin with no role on the app can dispatch', async () => {
  const r = await call(PLATFORM, 'reqplat', { request_ids: [PLAT_REQ] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(reqRow(PLAT_REQ), { status: 'in_progress', coder_session_id: r.body.session_id });
  assert.equal(db.prepare('SELECT user_id FROM coder_sessions WHERE id = ?').get(r.body.session_id).user_id, PLATFORM.id);
});

test('availability tells the UI who may dispatch', async () => {
  const get = async (who) => (await (await REAL_FETCH(`http://127.0.0.1:${server.address().port}/api/coder/reqapp/availability`,
    { headers: { 'X-API-Key': who.key } })).json()).can_dispatch_requests;
  assert.equal(await get(OWNER), true);
  assert.equal(await get(PLATFORM), true);
  assert.equal(await get(APPADMIN), false);
  assert.equal(await get(MEMBER), false);
});
