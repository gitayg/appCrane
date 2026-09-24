import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Coder modes: Auto / Edits only / Plan, each one Claude Code --permission-mode
// (read off `claude --help` in the studio image, Claude Code 2.1.197). The id
// comes from a request body and the mode reaches `sh -c`, so the allowlist is
// tested like the model one: exact strings, refused at the route, refused
// again at the command builder, and quoted.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-codermodes-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-codermodes';
process.env.GIT_TERMINAL_PROMPT = '0';

const REAL_FETCH = globalThis.fetch.bind(globalThis);
const SHIM = join(ROOT, 'bin');
const EXEC_LOG = join(ROOT, 'exec.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(EXEC_LOG, '');
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  image)   echo 5 ;;
  inspect) echo true ;;
  run)     echo 0123456789abcdef0123456789abcdef ;;
  exec)
    for a in "$@"; do last="$a"; done
    printf '%s\\n' "$last" >> "${EXEC_LOG}"
    sleep "\${CRANE_TEST_TURN_SECONDS:-1}"
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
const modes = await import('../server/services/llm/coderModes.js');

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });
after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const argvOf = (permissionMode) => {
  const jail = mkdtempSync(join(ROOT, 'jail-'));
  const log = join(jail, 'argv');
  writeFileSync(join(jail, 'claude'), `#!/bin/sh\n{ for a in "$@"; do printf '%s\\037' "$a"; done; } > "${log}"\n`, { mode: 0o755 });
  const cmd = runAgentExec({ containerId: 'c0', prompt: 'hi', model: 'sonnet', apiKey: 'k', workdir: jail, homeDir: jail, permissionMode })
    .getDockerArgs().pop();
  execFileSync('/bin/sh', ['-c', cmd], { env: { PATH: `${jail}:${process.env.PATH}`, HOME: jail }, stdio: 'pipe' });
  return readFileSync(log, 'utf8').split('\x1f').slice(0, -1);
};

const API_KEY = 'testkey-codermodes';
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin',?,1,'human')")
  .run(hashApiKey(API_KEY));
const SLUG = 'modesapp';
await lg.createAppRepo(SLUG, { description: 'modes' });
await lg.pushFilesToManagedRepo(SLUG, [{ path: 'package.json', content: '{"name":"modesapp"}\n' }], { message: 'seed' });
db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,github_url,branch) VALUES (?,?,?,'managed','local',NULL,'main')")
  .run(SLUG, 993, SLUG);
const api = express();
api.use(express.json());
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = api.listen(0);
await new Promise((r) => server.once('listening', r));
after(() => server.close());
const call = async (method, path, body) => {
  const r = await REAL_FETCH(`http://127.0.0.1:${server.address().port}${path}`, {
    method, headers: { 'X-API-Key': API_KEY, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  return { status: r.status, body: await r.json() };
};
const waitFor = async (fn, label) => {
  const end = Date.now() + 20000;
  while (Date.now() < end) { if (await fn()) return; await new Promise(r => setTimeout(r, 50)); }
  throw new Error(`timed out waiting for ${label}`);
};

test('each mode hands the CLI its own permission mode', () => {
  const expect = { auto: null, edits: 'acceptEdits', plan: 'plan' };
  for (const m of modes.CODER_MODES) {
    const argv = argvOf(modes.permissionModeFor(m.id));
    const i = argv.indexOf('--permission-mode');
    if (expect[m.id] === null) {
      assert.ok(argv.includes('--dangerously-skip-permissions'), `${m.id}: Auto lost its permissions skip`);
      assert.equal(i, -1, `${m.id}: Auto also passed --permission-mode`);
    } else {
      assert.equal(argv[i + 1], expect[m.id], `${m.id}: claude got ${argv.join(' ')}`);
      assert.ok(!argv.includes('--dangerously-skip-permissions'), `${m.id}: still skips every permission check`);
    }
  }
});

test('the command builder refuses a mode that is not on its list, even if a caller skips validation', () => {
  assert.throws(() => argvOf("plan'; touch /tmp/pwned; '"), /unsupported permission mode/i);
  assert.throws(() => modes.permissionModeFor('bypassPermissions'), /Unsupported coder mode/,
    'a CLI mode name was accepted as a coder mode id');
});

test('GET /api/coder/models serves the modes the validator enforces', async () => {
  const { status, body } = await call('GET', '/api/coder/models');
  assert.equal(status, 200);
  assert.deepEqual(body.modes.map(m => m.id), ['auto', 'edits', 'plan']);
  assert.equal(body.default_mode, 'auto');
});

let sid;
test('a turn runs in the chosen mode, and a queued follow-up keeps its own', async () => {
  const s = await call('POST', `/api/coder/${SLUG}/session`);
  assert.equal(s.status, 201, JSON.stringify(s.body));
  sid = s.body.session_id;

  const bad = await call('POST', `/api/coder/${SLUG}/session/${sid}/dispatch`, { prompt: 'x', mode: 'plan; id' });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error?.code, 'VALIDATION');

  process.env.CRANE_TEST_TURN_SECONDS = '2';
  const a = await call('POST', `/api/coder/${SLUG}/session/${sid}/dispatch`, { prompt: 'look around', mode: 'plan' });
  assert.equal(a.status, 200, JSON.stringify(a.body));
  const b = await call('POST', `/api/coder/${SLUG}/session/${sid}/dispatch`, { prompt: 'now edit', mode: 'edits' });
  assert.equal(b.body.queued, true);
  assert.equal(b.body.followup.mode, 'edits', 'the queued follow-up forgot its mode');

  await waitFor(() => readFileSync(EXEC_LOG, 'utf8').split('\n').filter(l => l.includes('claude -p')).length >= 2, 'both turns');
  const cmds = readFileSync(EXEC_LOG, 'utf8').split('\n').filter(l => l.includes('claude -p'));
  assert.match(cmds[0], /--permission-mode 'plan'/, cmds[0]);
  assert.match(cmds[1], /--permission-mode 'acceptEdits'/, 'the follow-up ran in the first turn\'s mode');

  await waitFor(() => db.prepare("SELECT COUNT(*) c FROM coder_session_messages WHERE session_id = ? AND role = 'assistant' AND mode IS NOT NULL").get(sid).c >= 2, 'stored replies');
  const stored = db.prepare("SELECT role, mode FROM coder_session_messages WHERE session_id = ? AND role IN ('user','assistant') AND mode IS NOT NULL ORDER BY id").all(sid);
  assert.deepEqual(stored.map(r => `${r.role}:${r.mode}`), ['user:plan', 'assistant:plan', 'user:edits', 'assistant:edits']);
});
