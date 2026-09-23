import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Measured against the real CLI in the studio image with an invalid key:
// ten `api_retry` events (error_status 401) over 179,997 ms, then a result with
// is_error and exit 1. For those three minutes the panel showed nothing, and
// what it finally showed was a grey reply bubble reading "Failed to
// authenticate". The turn must end at the first 401 and name what to fix.
//
// docker is a shim: `exec` prints one 401 retry and then keeps "retrying" for
// 30 seconds, like the real CLI would.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-authfast-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-authfast';
process.env.GIT_TERMINAL_PROMPT = '0';

const REAL_FETCH = globalThis.fetch.bind(globalThis);
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
case "$1" in
  image)   echo 4 ;;
  inspect) echo true ;;
  run)     echo 0123456789abcdef0123456789abcdef ;;
  exec)
    printf '%s\\n' '{"type":"system","subtype":"api_retry","attempt":1,"max_retries":10,"error_status":401,"error":"authentication_failed"}'
    # exec: one process, like the real \`docker exec\` the turn stops.
    exec sleep 30
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
const { subscribe } = await import('../server/services/builder/builderSession.js');

global.fetch = async () => ({ ok: false, status: 404, json: async () => ({}), text: async () => '' });

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const API_KEY = 'testkey-authfast';
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin',?,1,'human')")
  .run(hashApiKey(API_KEY));
const SLUG = 'authfast';
await lg.createAppRepo(SLUG, { description: 'auth fail fast' });
await lg.pushFilesToManagedRepo(SLUG, [{ path: 'package.json', content: '{"name":"authfast"}\n' }], { message: 'seed' });
db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,github_url,branch) VALUES (?,?,?,'managed','local',NULL,'main')")
  .run(SLUG, 992, SLUG);

const api = express();
api.use(express.json());
api.use('/api/coder', coderRoutes);
api.use(errorHandler);
const server = api.listen(0);
await new Promise((r) => server.once('listening', r));
after(() => server.close());
const call = (method, path, body) => REAL_FETCH(`http://127.0.0.1:${server.address().port}${path}`, {
  method, headers: { 'X-API-Key': API_KEY, 'Content-Type': 'application/json' },
  ...(body ? { body: JSON.stringify(body) } : {}),
});

test('a rejected key ends the turn at the first 401 and says which key to replace', async () => {
  const s = await call('POST', `/api/coder/${SLUG}/session`);
  const { session_id: id } = await s.json();
  assert.equal(s.status, 201);

  const events = [];
  subscribe(id, (e) => events.push(e));
  const started = Date.now();
  const d = await call('POST', `/api/coder/${SLUG}/session/${id}/dispatch`, { prompt: 'hi' });
  assert.equal(d.status, 200, JSON.stringify(await d.json()));

  const end = Date.now() + 20000;
  while (Date.now() < end && !events.some(e => e.type === 'status' && e.status === 'idle')) {
    await new Promise(r => setTimeout(r, 50));
  }
  const took = Date.now() - started;
  assert.ok(took < 20000, `the turn sat through the retries (${took} ms) instead of ending at the first 401`);

  const err = events.find(e => e.type === 'error' && e.turnFailed);
  assert.ok(err, `no failure was shown; events: ${JSON.stringify(events.map(e => e.type))}`);
  assert.match(err.message, /platform's Anthropic API key was rejected[\s\S]*ANTHROPIC_API_KEY/);

  const row = db.prepare("SELECT content FROM coder_session_messages WHERE session_id = ? AND role = 'assistant' ORDER BY id DESC LIMIT 1").get(id);
  assert.match(row.content, /API key was rejected/, 'the transcript keeps the raw failure as if it were an answer');
  assert.equal(db.prepare('SELECT status FROM coder_sessions WHERE id = ?').get(id).status, 'idle');
});
