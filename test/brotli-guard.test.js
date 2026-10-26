import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { gzipSync, brotliCompressSync } from 'zlib';
import zlib from 'node:zlib';
import net from 'net';
import express from 'express';

// CVE-2026-111497 ("Node2Shell"): the Brotli decoder bundled with Node before
// 22.23.4 / 24.22.1 / 26.12.1 writes out of bounds on malformed input, and
// body-parser 2.x hands every `Content-Encoding: br` body to it. AppCrane must
// answer such a request 415 before any parser, raw or JSON, and before auth.

const { namesBrotli, createBrotliGuard } = await import('../server/middleware/brotliGuard.js');

test('namesBrotli: br anywhere in the coding list, any case, any spacing', () => {
  for (const v of ['br', 'BR', ' br ', 'gzip, br', 'gzip,br', 'br, gzip', 'identity , Br , gzip', ['gzip', 'br']]) {
    assert.equal(namesBrotli(v), true, JSON.stringify(v));
  }
  for (const v of [undefined, '', 'gzip', 'deflate', 'identity', 'x-brotli', 'brotli', 'gzip, xbr', 'abr', ['gzip']]) {
    assert.equal(namesBrotli(v), false, JSON.stringify(v));
  }
});

async function listen(app) {
  return new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
}

function spyBrotli() {
  const calls = [];
  const orig = zlib.createBrotliDecompress;
  const set = (value) => Object.defineProperty(zlib, 'createBrotliDecompress', { configurable: true, enumerable: true, writable: false, value });
  set(function (...a) { calls.push('createBrotliDecompress'); return orig.apply(this, a); });
  return { calls, restore: () => set(orig) };
}

async function miniApp(withGuard) {
  const app = express();
  if (withGuard) app.use(createBrotliGuard({ warn: () => {} }));
  app.use(express.json());
  app.post('/x', (req, res) => res.json({ got: req.body }));
  const srv = await listen(app);
  return { srv, url: `http://127.0.0.1:${srv.address().port}/x` };
}

const BODY = JSON.stringify({ hello: 'world' });

test('in-process: a br body never reaches zlib with the guard; it does without it', async () => {
  const spy = spyBrotli();
  try {
    const guarded = await miniApp(true);
    const r = await fetch(guarded.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'br' }, body: brotliCompressSync(BODY) });
    assert.equal(r.status, 415);
    assert.equal((await r.json()).error.code, 'UNSUPPORTED_CONTENT_ENCODING');
    assert.deepEqual(spy.calls, [], 'the guarded app still called the Brotli decoder');
    const gz = await fetch(guarded.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, body: gzipSync(BODY) });
    assert.deepEqual(await gz.json(), { got: { hello: 'world' } }, 'gzip bodies must still be parsed');
    guarded.srv.close();

    const open = await miniApp(false);
    const r2 = await fetch(open.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'br' }, body: brotliCompressSync(BODY) });
    assert.equal(r2.status, 200);
    assert.deepEqual(spy.calls, ['createBrotliDecompress'], 'control: without the guard body-parser decodes Brotli, so the spy is live');
    open.srv.close();
  } finally {
    spy.restore();
  }
});

test('logs at most once a minute and counts what it did not log', () => {
  let t = 1_000_000;
  const lines = [];
  const guard = createBrotliGuard({ now: () => t, warn: (m) => lines.push(m) });
  const req = { headers: { 'content-encoding': 'br' }, method: 'POST', path: '/p' };
  const res = { set() { return this; }, status() { return this; }, json() { return this; } };
  for (let i = 0; i < 5; i++) guard(req, res, () => assert.fail('next() called for a br body'));
  assert.equal(lines.length, 1);
  t += 60_000;
  guard(req, res, () => assert.fail('next() called for a br body'));
  assert.equal(lines.length, 2);
  assert.match(lines[1], /4 more refused/);
  let passed = false;
  guard({ headers: { 'content-encoding': 'gzip' }, method: 'POST', path: '/p' }, res, () => { passed = true; });
  assert.equal(passed, true);
});

// ---- the real server --------------------------------------------------------

let child, base, dataDir, spyFile;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-brotli-'));
  spyFile = join(dataDir, 'brotli-calls.txt');
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['--import', './test/fixtures/brotli-spy.mjs', 'server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1', BROTLI_SPY_FILE: spyFile,
      ENCRYPTION_KEY: 'e'.repeat(64), CRANE_DOMAIN: 'crane.example.com', LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 160; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

// Raw-body routes mounted before express.json (webhook, A2A, git, LLM gateway,
// client errors), routes with their own parsers (staged uploads, webhooks), and
// authenticated JSON routes, which must answer 415 rather than 401.
const ROUTES = [
  ['POST', '/api/github-app/webhook', 'application/json'],
  ['POST', '/a2a', 'application/json'],
  ['POST', '/git/demo.git/git-upload-pack', 'application/x-git-upload-pack-request'],
  ['POST', '/api/service/llm/v1/messages', 'application/json'],
  ['POST', '/api/client-errors', 'application/json'],
  ['POST', '/api/files/staged/chunked', 'application/json'],
  ['PUT', '/api/files/staged/abc?offset=0', 'application/octet-stream'],
  ['POST', '/api/webhooks/some-token', 'application/json'],
  ['POST', '/api/auth/login', 'application/json'],
  ['POST', '/api/apps', 'application/json'],
  ['PUT', '/api/settings/some_key', 'application/json'],
  ['POST', '/api/mcp', 'application/json'],
  ['POST', '/oauth/token', 'application/x-www-form-urlencoded'],
];

test('real server: every route family answers a br body 415, before auth, and zlib never sees it', async () => {
  const body = brotliCompressSync(BODY);
  for (const [method, path, type] of ROUTES) {
    for (const ce of ['br', 'gzip, BR', ' Br ']) {
      const r = await fetch(base + path, { method, headers: { 'Content-Type': type, 'Content-Encoding': ce }, body });
      assert.equal(r.status, 415, `${method} ${path} [${ce}] answered ${r.status}`);
      const j = await r.json();
      assert.equal(j.error.code, 'UNSUPPORTED_CONTENT_ENCODING', `${method} ${path}`);
    }
  }
  assert.equal(existsSync(spyFile) ? readFileSync(spyFile, 'utf8') : '', '', 'the Brotli decoder was called');
});

test('real server: identity and gzip bodies are still accepted', async () => {
  const report = JSON.stringify({ message: 'brotli-guard test report' });
  const plain = await fetch(`${base}/api/client-errors`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: report });
  assert.equal(plain.status, 204);
  const gz = await fetch(`${base}/api/client-errors`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, body: gzipSync(report) });
  assert.equal(gz.status, 204);
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, body: gzipSync(JSON.stringify({ email: 'x@example.com', password: 'nope' })) });
  assert.notEqual(login.status, 415);
});
