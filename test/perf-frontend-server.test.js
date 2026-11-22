import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import net from 'net';
import Database from 'better-sqlite3';

// The real server: hashed admin-app assets are cached for a year, the shell is
// not; and the "does a platform admin exist" answer, asked on every request by
// the setup guard, is remembered once it is yes.

let child, base, dataDir;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-perf-frontend-'));
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY: 'f'.repeat(64), CRANE_DOMAIN: 'crane.example.com', LOG_LEVEL: 'error',
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

test('hashed admin-app assets are immutable for a year; the shell is revalidated', async () => {
  const asset = readdirSync(new URL('../docs/admin-app/assets/', import.meta.url)).find(f => /^index-[\w-]+\.js$/.test(f));
  assert.ok(asset, 'no built entry chunk under docs/admin-app/assets');
  const a = await fetch(`${base}/docs/admin-app/assets/${asset}`);
  assert.equal(a.status, 200);
  assert.equal(a.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  const shell = await fetch(`${base}/docs/admin-app/index.html`);
  assert.equal(shell.status, 200);
  assert.equal(shell.headers.get('cache-control'), 'no-cache');
  const login = await fetch(`${base}/docs/login.html`);
  assert.notEqual(login.headers.get('cache-control'), 'public, max-age=31536000, immutable');
});

test('setup guard: "no admin" is re-read every time, "admin exists" is remembered', async () => {
  const info = async () => (await (await fetch(`${base}/api/info`)).json()).status;
  assert.equal(await info(), 'needs_init');
  assert.equal((await fetch(`${base}/api/apps`)).status, 503);

  const db = new Database(join(dataDir, 'deployhub.db'));
  try {
    db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('a','a@example.com','platform_admin','h',1,'human')").run();
    assert.equal(await info(), 'ready');
    assert.equal((await fetch(`${base}/api/apps`)).status, 401);

    // No code path removes the last platform admin; a row deleted behind the
    // server's back shows the answer is no longer read from the table.
    db.prepare("DELETE FROM users WHERE role = 'platform_admin'").run();
    assert.equal(await info(), 'ready');
    assert.equal((await fetch(`${base}/api/apps`)).status, 401);
  } finally {
    db.close();
  }
});
