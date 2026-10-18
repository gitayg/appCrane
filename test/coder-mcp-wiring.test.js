import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The coder turn hands claude its AppCrane MCP connection: the key issued for
// the turn reaches `claude` as --mcp-config (with --strict-mcp-config and the
// allowlist pre-approved), the container can resolve host.docker.internal, and
// the key is revoked when the turn ends. docker is a PATH shim that logs argv;
// the exec's `sh -c` string is then run through a real /bin/sh with a `claude`
// shim, so the claim is about the argv claude receives, not a substring.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-codermcpwire-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-coder-mcp';
process.env.GIT_TERMINAL_PROMPT = '0';
process.env.PORT = '5099';

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
const { CODER_MCP_TOOLS } = await import('../server/services/coderMcpKey.js');

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });

after(async () => {
  try {
    const { stopHealthChecker } = await import('../server/services/healthChecker.js');
    stopHealthChecker();
  } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const API_KEY = 'testkey-coder-mcp-wiring';
const ownerId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin',?,1,'human')"
).run(hashApiKey(API_KEY)).lastInsertRowid;

const SLUG = 'mcpwire';
await lg.createAppRepo(SLUG, { description: 'coder mcp wiring' });
await lg.pushFilesToManagedRepo(SLUG, [{ path: 'package.json', content: '{"name":"mcpwire","version":"1.0.0"}\n' }], { message: 'seed' });
const appId = db.prepare(
  "INSERT INTO apps (name,slot,slug,source_type,repo_backend,github_url,branch) VALUES (?,?,?,'managed','local',NULL,'main')"
).run(SLUG, 993, SLUG).lastInsertRowid;

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
const dockerLines = () => readFileSync(DOCKER_LOG, 'utf8').split('\n').filter(Boolean)
  .map((l) => l.split('\x1f').slice(0, -1));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, ms = 20000, label = 'condition') {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return; await sleep(60); }
  throw new Error(`timed out waiting for ${label}`);
}

let sessionId;

test('the coder container can resolve host.docker.internal', async () => {
  const r = await call('POST', `/api/coder/${SLUG}/session`);
  const body = await r.json();
  assert.equal(r.status, 201, JSON.stringify(body));
  sessionId = body.session_id;
  const run = dockerLines().find((a) => a[0] === 'run' && a.includes('appcrane.container.type=app'));
  assert.ok(run, 'no coder container was started');
  const i = run.indexOf('--add-host');
  assert.ok(i >= 0 && run[i + 1] === 'host.docker.internal:host-gateway', `run argv: ${run.join(' ')}`);
});

test('a turn passes claude a strict --mcp-config for this app\'s key, pre-approves the allowlist, and revokes the key at turn end', async () => {
  const r = await call('POST', `/api/coder/${SLUG}/session/${sessionId}/dispatch`, { prompt: 'check the scan' });
  assert.equal(r.status, 200, JSON.stringify(await r.json()));
  await waitFor(() => dockerLines().some((a) => a[0] === 'exec' && a[a.length - 1].includes('check the scan')), 20000, 'the turn exec');
  const exec = dockerLines().find((a) => a[0] === 'exec' && a[a.length - 1].includes('check the scan'));
  const shellCmd = exec[exec.length - 1];

  // Run the exact shell string against a claude shim and read the argv it got.
  const jail = mkdtempSync(join(ROOT, 'sh-'));
  const argvLog = join(jail, 'argv');
  writeFileSync(join(jail, 'claude'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } > "${argvLog}"
`, { mode: 0o755 });
  const runnable = shellCmd.replaceAll("'/workspace'", `'${jail}'`).replaceAll('/workspace', jail);
  execFileSync('/bin/sh', ['-c', runnable], { env: { PATH: `${jail}:${process.env.PATH}`, HOME: jail }, stdio: 'pipe' });
  const argv = readFileSync(argvLog, 'utf8').split('\x1f').slice(0, -1);

  const ci = argv.indexOf('--mcp-config');
  assert.ok(ci >= 0, `claude got no --mcp-config: ${argv.join(' ')}`);
  const cfg = JSON.parse(argv[ci + 1]);
  assert.deepEqual(Object.keys(cfg.mcpServers), ['appcrane']);
  const srv = cfg.mcpServers.appcrane;
  assert.equal(srv.type, 'http');
  assert.equal(srv.url, 'http://host.docker.internal:5099/api/mcp');
  assert.match(srv.headers['X-API-Key'], /^dhk_mcp_/);
  assert.ok(argv.includes('--strict-mcp-config'), 'a workspace .mcp.json could add or replace servers');

  const ai = argv.indexOf('--allowedTools');
  assert.ok(ai >= 0, 'the read-only tools are not pre-approved');
  const allowed = argv.slice(ai + 1, ai + 1 + CODER_MCP_TOOLS.length);
  assert.deepEqual(allowed, CODER_MCP_TOOLS.map((t) => `mcp__appcrane__${t}`));
  const pi = argv.indexOf('--append-system-prompt');
  assert.ok(pi >= 0 && /read-only AppCrane MCP server/.test(argv[pi + 1]), 'the agent is not told about the tools');
  assert.equal(argv[argv.length - 2], '--', 'the prompt is no longer after --');

  const row = db.prepare('SELECT * FROM user_mcp_keys WHERE key_hash = ?').get(hashApiKey(srv.headers['X-API-Key']));
  assert.ok(row, 'the key in the config is not a stored key');
  assert.equal(row.user_id, ownerId);
  assert.equal(row.app_id, appId);
  assert.equal(row.coder_session_id, sessionId);
  assert.equal(row.read_only, 1);

  await waitFor(() => db.prepare('SELECT revoked_at FROM user_mcp_keys WHERE id = ?').get(row.id).revoked_at, 20000, 'the key to be revoked at turn end');
});
