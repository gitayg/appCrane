import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, renameSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { WORKSPACE_DOCKER_PRELUDE } from './fixtures/workspaceDockerShim.js';

// v2.111.0 — two things a user hit on one screen of the coder panel.
//
//  1. DELIVERY. The agent tried to commit, could not push, and told the user to
//     push by hand. Every turn now carries an append-prompt saying how its work
//     is delivered (leave it uncommitted; the user releases it from Changes).
//     Read off the real `docker exec` argv a dispatch produces.
//
//  2. TAKE-OVER. A second owner/platform admin met BUILDER_OCCUPIED for as long
//     as the first user's session sat idle, and the panel offered nothing. Now
//     { take_over: true } saves the holder's unreleased work to
//     agent/<userId>/<sessionId> FIRST, then pauses them and starts the new
//     session. Mid-turn stays refused; a rescue that fails touches nothing.
//
// Docker is a shim. Coder-container git (the rescue) is played on the host by
// workspace-docker-shim.mjs, so what lands in the bare repo is real git, read
// back with an independent `git --git-dir`. A `claude` turn is played by the
// shim's own case, which sleeps so a turn is genuinely in flight.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-takeover-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 't'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-takeover';
process.env.GIT_TERMINAL_PROMPT = '0';

const BIN = join(ROOT, 'bin');
const TURN_LOG = join(ROOT, 'turns.log');
mkdirSync(BIN, { recursive: true });
writeFileSync(TURN_LOG, '');
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
case "$1" in exec)
  case "$*" in *"claude -p"*)
    { for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\036'; } >> ${JSON.stringify(TURN_LOG)}
    sleep "\${CRANE_TEST_TURN_SECONDS:-2}"
    printf '%s\\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
    printf '%s\\n' '{"type":"result","usage":{"input_tokens":1,"output_tokens":1}}'
    exit 0 ;;
  esac ;;
esac
${WORKSPACE_DOCKER_PRELUDE}
case "$1" in
  run)     echo c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ff ;;
  image)   echo 5 ;;
  inspect) echo true ;;
esac
exit 0
`);
chmodSync(join(BIN, 'docker'), 0o755);
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const lg = await import('../server/services/localGit.js');
const coder = (await import('../server/routes/coder.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { CODER_DELIVERY_PROMPT, coderSystemPrompt } = await import('../server/services/builder/deliveryPrompt.js');
const { CODER_MCP_PROMPT } = await import('../server/services/coderMcpKey.js');

global.fetch = (() => {
  const real = globalThis.fetch.bind(globalThis);
  return async (url, opts) => (String(url).startsWith('http://127.0.0.1:')
    ? real(url, opts)
    : { ok: false, status: 404, json: async () => ({}), text: async () => '' });
})();

const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/coder', coder); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(async () => {
  server.closeAllConnections?.(); server.close();
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

const mk = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES (?,?,?,1,?,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id: Number(id), key, name };
};
const call = async (method, path, who, body) => {
  const r = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method, headers: { 'x-api-key': who.key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};
const codeOf = (r) => r.body.error?.code ?? r.body.code;

const CLEAN = { PATH: process.env.PATH, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const bareGit = (dir, args) => execFileSync('git', [`--git-dir=${dir}`, ...args], { env: CLEAN }).toString('utf8').trim();
const refsIn = (dir) => bareGit(dir, ['for-each-ref', '--format=%(refname)']).split('\n').filter(Boolean);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 20000, label = 'condition') {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return; await sleep(60); }
  throw new Error(`timed out waiting for ${label}`);
}
const statusOf = (id) => db.prepare('SELECT status FROM coder_sessions WHERE id = ?').get(id)?.status;

async function craneApp(slug, slot) {
  await lg.createAppRepo(slug, { description: slug });
  await lg.pushFilesToManagedRepo(slug, [{ path: 'README.md', content: '# seed\n' }], { message: 'seed' });
  const id = db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,branch) VALUES (?,?,?,'managed','local','main')")
    .run(slug, slot, slug).lastInsertRowid;
  return Number(id);
}

const OWNER = mk('Olive Owner');
const ADMIN = mk('Pat Platform', 'platform_admin');
const APP = 'takeover';
const appId = await craneApp(APP, 931);
db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, OWNER.id, 'owner');

let ownerSession;
let adminSession;

test('the owner starts a session; a second coder user without take_over still meets BUILDER_OCCUPIED', async () => {
  const r = await call('POST', `/api/coder/${APP}/session`, OWNER);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  ownerSession = r.body.session_id;

  const blocked = await call('POST', `/api/coder/${APP}/session`, ADMIN);
  assert.equal(blocked.status, 409, JSON.stringify(blocked.body));
  assert.equal(codeOf(blocked), 'BUILDER_OCCUPIED');
  assert.equal(statusOf(ownerSession), 'idle', 'a refused start touched the holder');
});

test('every coder turn carries the delivery instruction in its append-prompt, once', async () => {
  const r = await call('POST', `/api/coder/${APP}/session/${ownerSession}/dispatch`, OWNER, { prompt: 'first turn' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  await waitFor(() => readFileSync(TURN_LOG, 'utf8').includes('first turn'), 20000, 'the turn exec');
  const argv = readFileSync(TURN_LOG, 'utf8').split('\x1e').filter(Boolean).pop().split('\x1f').slice(0, -1);
  const cmd = argv[argv.length - 1];
  assert.equal((cmd.match(/--append-system-prompt /g) || []).length, 1, `expected exactly one --append-system-prompt:\n${cmd}`);
  for (const phrase of ['leave the changes uncommitted', 'Do not run git commit, git push', 'never ask the user to commit or push', 'Changes tab']) {
    assert.ok(cmd.includes(phrase), `the turn's command does not carry "${phrase}":\n${cmd}`);
  }
  assert.ok(cmd.includes('read-only AppCrane MCP server'), 'the MCP guide was dropped from the append-prompt');
  // A turn that gets no MCP key still gets the delivery instruction.
  assert.equal(coderSystemPrompt(null), CODER_DELIVERY_PROMPT);
  assert.ok(coderSystemPrompt(CODER_MCP_PROMPT).startsWith(CODER_DELIVERY_PROMPT));
  await waitFor(() => statusOf(ownerSession) === 'idle', 20000, 'the turn to end');
});

test('mid-turn, take_over is refused with BUILDER_BUSY and nothing is touched', async () => {
  process.env.CRANE_TEST_TURN_SECONDS = '4';
  try {
    const r = await call('POST', `/api/coder/${APP}/session/${ownerSession}/dispatch`, OWNER, { prompt: 'long turn' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    await waitFor(() => readFileSync(TURN_LOG, 'utf8').includes('long turn'), 20000, 'the long turn to be running');

    const busy = await call('POST', `/api/coder/${APP}/session`, ADMIN, { take_over: true });
    assert.equal(busy.status, 409, JSON.stringify(busy.body));
    assert.equal(codeOf(busy), 'BUILDER_BUSY');
    assert.equal(statusOf(ownerSession), 'active', 'a refused take-over changed the running session');
    assert.equal(refsIn(lg.repoPath(APP)).some((r) => r.startsWith('refs/heads/agent/')), false, 'a refused take-over wrote a rescue branch');
  } finally {
    delete process.env.CRANE_TEST_TURN_SECONDS;
  }
  await waitFor(() => statusOf(ownerSession) === 'idle', 20000, 'the long turn to end');
});

test('idle, take_over saves the holder\'s unreleased work on agent/* first, pauses them, notifies them, and starts the new session', async () => {
  const ws = db.prepare('SELECT workspace_dir FROM coder_sessions WHERE id = ?').get(ownerSession).workspace_dir;
  writeFileSync(join(ws, 'feature.js'), 'export const unreleased = true;\n');

  const r = await call('POST', `/api/coder/${APP}/session`, ADMIN, { take_over: true });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  adminSession = r.body.session_id;
  assert.notEqual(adminSession, ownerSession);

  const bare = lg.repoPath(APP);
  const branch = `refs/heads/agent/${OWNER.id}/${ownerSession}`;
  assert.ok(refsIn(bare).includes(branch), `no rescue branch; refs are ${refsIn(bare).join(', ')}`);
  assert.equal(bareGit(bare, ['show', `${branch}:feature.js`]), 'export const unreleased = true;');
  assert.equal(bareGit(bare, ['ls-tree', '--name-only', 'refs/heads/main']).includes('feature.js'), false, 'the rescue landed on main');

  assert.equal(statusOf(ownerSession), 'paused');
  assert.equal(db.prepare('SELECT user_id FROM coder_sessions WHERE id = ?').get(adminSession).user_id, ADMIN.id);
  const note = db.prepare("SELECT content FROM coder_session_messages WHERE session_id = ? AND role = 'assistant' ORDER BY id DESC LIMIT 1").get(ownerSession)?.content || '';
  assert.match(note, /Pat Platform took over/, `the holder was not told: ${note}`);
  assert.ok(note.includes(`agent/${OWNER.id}/${ownerSession}`), `the note does not say where the work went: ${note}`);
});

test('GET /session answers each viewer with their own session first, with its owner\'s name', async () => {
  const mine = await call('GET', `/api/coder/${APP}/session`, OWNER);
  assert.equal(mine.body.session.id, ownerSession, 'the owner was shown the admin\'s newer session instead of their own');
  assert.equal(mine.body.session.user_name, 'Olive Owner');
  const theirs = await call('GET', `/api/coder/${APP}/session`, ADMIN);
  assert.equal(theirs.body.session.id, adminSession);
  const one = await call('GET', `/api/coder/${APP}/session/${ownerSession}`, ADMIN);
  assert.equal(one.body.session.user_name, 'Olive Owner');
});

test('the displaced owner can resume their paused session only by taking over back', async () => {
  const refused = await call('POST', `/api/coder/${APP}/session/${ownerSession}/resume`, OWNER);
  assert.equal(refused.status, 409, JSON.stringify(refused.body));
  assert.equal(codeOf(refused), 'BUILDER_OCCUPIED');

  const back = await call('POST', `/api/coder/${APP}/session/${ownerSession}/resume`, OWNER, { take_over: true });
  assert.equal(back.status, 200, JSON.stringify(back.body));
  assert.equal(statusOf(ownerSession), 'idle');
  assert.equal(statusOf(adminSession), 'paused');
});

test('a paused session of another user never blocks starting your own', async () => {
  const app2 = 'takeover-paused';
  const id2 = await craneApp(app2, 932);
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(id2, OWNER.id, 'owner');
  db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('old-paused', ?, ?, 'b', 'paused')").run(app2, OWNER.id);
  const r = await call('POST', `/api/coder/${app2}/session`, ADMIN);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(statusOf('old-paused'), 'paused');
});

test('a rescue that fails refuses the take-over and leaves the holder exactly as they were', async () => {
  const ws = db.prepare('SELECT workspace_dir FROM coder_sessions WHERE id = ?').get(ownerSession).workspace_dir;
  writeFileSync(join(ws, 'precious.js'), 'keep me\n');
  const bare = lg.repoPath(APP);
  const aside = `${bare}.aside`;
  renameSync(bare, aside);
  try {
    const r = await call('POST', `/api/coder/${APP}/session`, ADMIN, { take_over: true });
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.equal(codeOf(r), 'TAKEOVER_FAILED');
    assert.equal(statusOf(ownerSession), 'idle', 'the holder was paused although their work was not saved');
    assert.ok(existsSync(join(ws, 'precious.js')), 'the holder\'s workspace was wiped although their work was not saved');
  } finally {
    renameSync(aside, bare);
  }
});
