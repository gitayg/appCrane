import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import net from 'net';
import Database from 'better-sqlite3';

// The dashboard frames apps in its app tabs. Its CSP said frame-src 'self',
// which covered every app while apps lived under /<slug>. With app isolation
// on, apps are on their own hosts and Chrome refused every app tab with "This
// content is blocked" (seen on a live box, 2026-10-27, right after isolation
// was turned on). Driven against the real server process, because the policy
// is assembled in server/index.js from a setting read per request.

const HOST = 'crane.example.com';
let child;
let base;
let port;
let dataDir;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function get(path, host = HOST) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET', headers: { Host: host, Accept: 'text/html' } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res));
    });
    req.on('error', reject);
    req.end();
  });
}

const frameSrc = (r) => (r.headers['content-security-policy'] || '').match(/frame-src ([^;]+)/)?.[1] ?? null;

function setDomain(value) {
  const db = new Database(join(dataDir, 'deployhub.db'));
  db.prepare(`INSERT INTO settings (key, value) VALUES ('app_isolation_domain', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(value);
  db.close();
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-iso-frames-'));
  port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY: 'e'.repeat(64), CRANE_DOMAIN: HOST, LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const db = new Database(join(dataDir, 'deployhub.db'));
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('admin','admin@example.com','platform_admin','x',1)").run();
  db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('Supply','supply',9001,'github')").run();
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

test('off: the dashboard frames only itself, as before', async () => {
  setDomain('');
  for (const path of ['/launch', '/applications', '/login-legacy']) {
    const r = await get(path);
    assert.equal(frameSrc(r), "'self'", `${path} ${r.statusCode} ${r.headers.location || ''}`);
  }
});

test('on: the dashboard may frame every app host under the isolation domain, and nothing else', async () => {
  setDomain(HOST);
  for (const path of ['/launch', '/applications', '/login-legacy']) {
    assert.equal(frameSrc(await get(path)), `'self' https://*.${HOST}`, path);
  }
  setDomain('');
});

test('on: a sign-in error page on an app host may be shown inside the dashboard', async () => {
  setDomain(HOST);
  const r = await get('/__appcrane/session?code=nope', `supply.${HOST}`);
  assert.equal(r.statusCode, 403);
  assert.equal(r.headers['x-frame-options'], undefined, 'X-Frame-Options would hide the message behind "refused to connect"');
  assert.equal(r.headers['content-security-policy'], `frame-ancestors https://${HOST}`);
  setDomain('');
});
