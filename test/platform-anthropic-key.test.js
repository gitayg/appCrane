import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync, chmodSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// The platform Anthropic API key lives encrypted in the database, set by a
// platform admin. Boot moves an old .env / environment value in and drops it
// from .env and process.env; nothing reads process.env after that, and no
// docker argv carries the key.

const ROOT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = mkdtempSync(join(tmpdir(), 'crane-anthropic-key-'));
process.env.DATA_DIR = DATA;
// Env files land here, so the leftover check sees only this run's files.
process.env.TMPDIR = join(DATA, 'tmp');
mkdirSync(process.env.TMPDIR);
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.ANTHROPIC_API_KEY;

const SHIM = join(DATA, 'bin');
const DOCKER_LOG = join(DATA, 'docker.log');
mkdirSync(SHIM, { recursive: true });
// Records each argv (fields split by \037), for an --env-file the file's
// permissions and contents at the moment docker would read it, and for a
// `docker run -i` what arrived on stdin.
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; printf '\\n'; } >> "${DOCKER_LOG}"
prev=""
for a in "$@"; do
  if [ "$prev" = "--env-file" ]; then
    printf 'ENVFILE %s %s\\n' "$(ls -l "$a" | cut -c1-10)" "$(cat "$a")" >> "${DOCKER_LOG}"
  fi
  prev="$a"
done
if [ "$1" = run ]; then
  for a in "$@"; do
    if [ "$a" = "-i" ]; then printf 'STDIN %s\\n' "$(cat)" >> "${DOCKER_LOG}"; break; fi
  done
fi
case "$1" in
  run) echo shimcontainer ;;
  inspect) echo running ;;
  image) echo 6 ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey, decrypt } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const pak = await import('../server/services/platformAnthropicKey.js');
const { migratePlatformAnthropicKey } = await import('../server/services/platformAnthropicKeyBoot.js');
const { runAgentNew, runAgentNewArgs, runAgentExec } = await import('../server/services/llm/runAgent.js');
const { runAskJob, stopSession } = await import('../server/services/askClaude.js');
const settingsRouter = (await import('../server/routes/settings.js')).default;
const appstudioRouter = (await import('../server/routes/appstudio.js')).default;

initDb();
const db = getDb();

const KEY = 'sk-ant-api03-PLATFORM-KEY-UNDER-TEST-0001';
const OTHER = 'sk-ant-api03-SOMETHING-IN-THE-ENV-9999';
const KEY_USER = 'dhk_user_anthropic_lowpriv';
const KEY_ADMIN = 'dhk_user_anthropic_admin';
const ins = db.prepare('INSERT INTO users (name, email, role, api_key_hash) VALUES (?, ?, ?, ?)');
ins.run('Low', 'low@example.test', 'user', hashApiKey(KEY_USER));
ins.run('Admin', 'admin@example.test', 'platform_admin', hashApiKey(KEY_ADMIN));

const rawStored = () => db.prepare('SELECT value FROM settings WHERE key = ?').get(pak.SETTING_KEY)?.value;
const quietLog = () => {
  const lines = [];
  const rec = (m) => lines.push(String(m));
  return { lines, info: rec, warn: rec, error: rec };
};

const app = express();
app.use(express.json());
app.use('/api/settings', settingsRouter);
app.use('/api/appstudio', appstudioRouter);
app.use(errorHandler);
const server = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
after(async () => {
  server.closeAllConnections?.(); server.unref(); server.close();
  (await import('../server/services/appstudio/worker.js')).stopWorker();
});
const BASE = `http://127.0.0.1:${server.address().port}`;
async function call(method, path, apiKey, body) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(apiKey ? { 'X-API-Key': apiKey } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: r.status, body: await r.text() };
}

test('the key is stored encrypted, and read back through the getter', () => {
  pak.setPlatformAnthropicKey(KEY, null);
  const raw = rawStored();
  assert.ok(raw, 'a row is written');
  assert.notEqual(raw, KEY);
  assert.ok(!raw.includes(KEY) && !raw.includes(KEY.slice(8)), 'no plaintext in the row');
  assert.equal(decrypt(raw), KEY);
  pak.resetPlatformAnthropicKeyCache();
  assert.equal(pak.getPlatformAnthropicKey(), KEY, 'read from the database, not a cache');
  assert.deepEqual(pak.status(), { configured: true, source: 'database', suffix: KEY.slice(-4) });
  assert.throws(() => pak.setPlatformAnthropicKey('sk-ant\nINJECTED=1'), pak.InvalidAnthropicKeyError);
  pak.clearPlatformAnthropicKey();
});

test('boot migration: stores the env key encrypted, removes only its .env line, unsets process.env', () => {
  const envPath = join(DATA, 'boot.env');
  const before = `# AppCrane\r\nPORT=5001\n\n# the key\nANTHROPIC_API_KEY=${KEY}\n  # indented comment\nENCRYPTION_KEY=${'d'.repeat(64)}\nOTHER=a=b\n`;
  const expected = `# AppCrane\r\nPORT=5001\n\n# the key\n  # indented comment\nENCRYPTION_KEY=${'d'.repeat(64)}\nOTHER=a=b\n`;
  writeFileSync(envPath, before);
  chmodSync(envPath, 0o640);
  process.env.ANTHROPIC_API_KEY = KEY;

  const r = migratePlatformAnthropicKey({ envPath, db, fromProvider: false, log: quietLog() });
  assert.deepEqual([r.migrated, r.envLinesRemoved], [true, 1]);
  assert.equal(readFileSync(envPath, 'utf8'), expected, 'every other byte kept');
  assert.equal(statSync(envPath).mode & 0o777, 0o640, 'file mode kept');
  assert.ok(!('ANTHROPIC_API_KEY' in process.env), 'process.env no longer carries it');
  assert.equal(decrypt(rawStored()), KEY);
  assert.deepEqual(readdirSync(DATA).filter((f) => f.includes('.tmp')), [], 'no temp file left');
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'platform.anthropic-key-migrated'").all();
  assert.equal(audit.length, 1);
  assert.ok(!audit[0].detail.includes(KEY), 'audit without the value');

  // Idempotent: a second boot changes nothing.
  const again = migratePlatformAnthropicKey({ envPath, db, fromProvider: false, log: quietLog() });
  assert.deepEqual([again.migrated, again.envLinesRemoved], [false, 0]);
  assert.equal(readFileSync(envPath, 'utf8'), expected);
});

test('after boot the getter never reads process.env', () => {
  process.env.ANTHROPIC_API_KEY = OTHER;
  try {
    assert.equal(pak.getPlatformAnthropicKey(), KEY);
    pak.clearPlatformAnthropicKey();
    assert.equal(pak.getPlatformAnthropicKey(), null, 'no key stored: none, not the env value');
    assert.equal(pak.status().configured, false);
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
  }
});

test('a key from the secrets provider is copied, and the provider is left alone', () => {
  const envPath = join(DATA, 'provider.env');
  const text = 'APPCRANE_SECRETS_PROVIDER=aws-secrets-manager\nAPPCRANE_SECRETS_ID=plat\n';
  writeFileSync(envPath, text);
  process.env.ANTHROPIC_API_KEY = KEY;
  const lg = quietLog();
  const r = migratePlatformAnthropicKey({ envPath, db, fromProvider: true, log: lg });
  assert.deepEqual([r.migrated, r.fromProvider], [true, true]);
  assert.equal(pak.getPlatformAnthropicKey(), KEY);
  assert.equal(readFileSync(envPath, 'utf8'), text);
  assert.ok(lg.lines.some((l) => /can be removed from that secret/.test(l)), lg.lines.join('\n'));
  assert.ok(!lg.lines.join('\n').includes(KEY), 'no value logged');
  assert.ok(!('ANTHROPIC_API_KEY' in process.env));
});

test('docker argv never carries the key: run, exec and the Ask container', async () => {
  const ws = join(DATA, 'ws');
  mkdirSync(ws, { recursive: true });
  writeFileSync(DOCKER_LOG, '');
  const run = runAgentNew({ image: 'appcrane/studio:test', workspaceDir: ws, prompt: 'hi' });
  const runArgs = run.getDockerArgs();
  assert.ok(!runArgs.some((a) => a.includes(KEY)), 'docker run argv');
  // `docker run --env-file` copies the values into the container's Config.Env,
  // where `docker inspect` shows them: run mode writes the key to stdin instead.
  assert.ok(!runArgs.includes('--env-file'), 'no env file on docker run');
  assert.deepEqual(run.getStdinCredential(), { name: 'ANTHROPIC_API_KEY', value: KEY });
  await new Promise((res) => { run.on('exit', res); run.on('error', res); run.start(); });
  const runLog = readFileSync(DOCKER_LOG, 'utf8');
  assert.match(runLog, new RegExp(`^STDIN ${KEY}$`, 'm'), 'docker run got the key on stdin');
  assert.ok(!/^ENVFILE/m.test(runLog), 'and read no env file');
  const inspected = runAgentNewArgs({ image: 'appcrane/studio:test', workspaceDir: ws, prompt: 'hi' });
  assert.ok(!inspected.includes('-i') && !inspected.some((a) => a.includes(KEY) || a.includes('read -r')), 'the inspection argv delivers no credential');

  const exec = runAgentExec({ containerId: 'c1', prompt: 'hi' });
  const execArgs = exec.getDockerArgs();
  assert.ok(!execArgs.some((a) => a.includes(KEY)), 'docker exec argv');
  const envFile = execArgs[execArgs.indexOf('--env-file') + 1];
  assert.equal(statSync(envFile).mode & 0o777, 0o600);
  assert.equal(statSync(dirname(envFile)).mode & 0o777, 0o700);
  assert.equal(readFileSync(envFile, 'utf8'), `ANTHROPIC_API_KEY=${KEY}\n`);
  await new Promise((res) => { exec.on('exit', res); exec.on('error', res); exec.start(); });
  assert.ok(!existsSync(envFile), 'the env file is gone once docker has run');

  writeFileSync(DOCKER_LOG, '');
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch, github_url) VALUES ('a', 'ask-app', 91, 'github', 'main', 'https://example.test/r.git')").run();
  const askApp = db.prepare("SELECT * FROM apps WHERE slug = 'ask-app'").get();
  await runAskJob({ sessionId: 'pak1', app: askApp, question: 'q', history: [] });
  stopSession('pak1');
  const logText = readFileSync(DOCKER_LOG, 'utf8');
  const argvLines = logText.split('\n').filter((l) => !l.startsWith('ENVFILE'));
  const runLine = argvLines.find((l) => l.startsWith('run\x1f-d'));
  assert.ok(runLine, 'the Ask container was started');
  assert.ok(!runLine.includes('ANTHROPIC_API_KEY') && !runLine.includes('--env-file'), 'the long-lived Ask container gets no key at all');
  assert.ok(!argvLines.some((l) => l.includes(KEY)), 'no docker argv in the Ask path holds the key');
  const seen = logText.split('\n').filter((l) => l.startsWith('ENVFILE'));
  assert.deepEqual(seen, [`ENVFILE -rw------- ANTHROPIC_API_KEY=${KEY}`], 'the agent exec read the key from an env file');
  assert.ok(envFile.startsWith(process.env.TMPDIR), envFile);
  const leftover = readdirSync(process.env.TMPDIR).filter((f) => f.startsWith('appcrane-env-'));
  assert.deepEqual(leftover, [], 'no env file is left behind');
});

test('the generic settings routes never return or accept the stored key', async () => {
  const raw = rawStored();
  const bulk = await call('GET', '/api/settings', KEY_ADMIN);
  assert.equal(bulk.status, 200);
  assert.ok(!(pak.SETTING_KEY in JSON.parse(bulk.body).settings));
  assert.ok(!bulk.body.includes(raw) && !bulk.body.includes(KEY));
  for (const k of [KEY_ADMIN, KEY_USER]) {
    const one = await call('GET', `/api/settings/${pak.SETTING_KEY}`, k);
    assert.equal(one.status, 403);
    assert.ok(!one.body.includes(raw) && !one.body.includes(KEY));
  }
  const put = await call('PUT', `/api/settings/${pak.SETTING_KEY}`, KEY_ADMIN, { value: 'plaintext' });
  assert.equal(put.status, 403);
  assert.equal(rawStored(), raw, 'unchanged');
});

test('anthropic-key routes: admin only, value never echoed or audited', async () => {
  for (const [m, body] of [['GET'], ['PUT', { key: OTHER }], ['DELETE']]) {
    assert.equal((await call(m, '/api/appstudio/anthropic-key', KEY_USER, body)).status, 403, `${m} as a non-admin`);
    assert.equal((await call(m, '/api/appstudio/anthropic-key', null, body)).status, 401, `${m} anonymous`);
  }
  assert.equal(pak.getPlatformAnthropicKey(), KEY, 'a refused PUT changed nothing');

  const put = await call('PUT', '/api/appstudio/anthropic-key', KEY_ADMIN, { key: OTHER });
  assert.equal(put.status, 200, put.body);
  assert.ok(!put.body.includes(OTHER));
  assert.equal(pak.getPlatformAnthropicKey(), OTHER);
  assert.equal(decrypt(rawStored()), OTHER);
  assert.ok(!('ANTHROPIC_API_KEY' in process.env), 'PUT does not set process.env');

  const get = JSON.parse((await call('GET', '/api/appstudio/anthropic-key', KEY_ADMIN)).body);
  assert.deepEqual(get, { configured: true, source: 'database', suffix: OTHER.slice(-4) });

  const del = await call('DELETE', '/api/appstudio/anthropic-key', KEY_ADMIN);
  assert.equal(del.status, 200);
  assert.equal(rawStored(), undefined);
  assert.equal(JSON.parse((await call('GET', '/api/appstudio/anthropic-key', KEY_ADMIN)).body).configured, false);

  const audit = db.prepare("SELECT action, detail FROM audit_log WHERE action LIKE 'appstudio.%anthropic-key'").all();
  assert.deepEqual(audit.map((a) => a.action).sort(), ['appstudio.clear-anthropic-key', 'appstudio.set-anthropic-key']);
  const all = db.prepare('SELECT detail FROM audit_log').all().map((r) => r.detail || '').join('\n');
  assert.ok(!all.includes(OTHER) && !all.includes(KEY), 'no audit row holds a key');
});

test('no server or cli code reads process.env.ANTHROPIC_API_KEY except the key service', () => {
  const offenders = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules') continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js') && !p.endsWith('platformAnthropicKey.js')) {
        if (/process\.env\.ANTHROPIC_API_KEY|process\.env\[['"]ANTHROPIC_API_KEY/.test(readFileSync(p, 'utf8'))) offenders.push(p);
      }
    }
  };
  walk(join(ROOT_DIR, 'server'));
  walk(join(ROOT_DIR, 'cli'));
  assert.deepEqual(offenders, []);
});
