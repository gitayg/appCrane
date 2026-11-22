import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import net from 'net';
import crypto from 'crypto';
import Database from 'better-sqlite3';

// The IT setup page and API as mounted by server/index.js: the full middleware
// stack (setup guard, global limiter, the /api requireAuth catch-all), so a
// setup session that reaches no other route is proven on the real server.

const REPO = fileURLToPath(new URL('..', import.meta.url));
let child, base, dataDir;
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const ADMIN_SESS = `sess_${crypto.randomBytes(16).toString('hex')}`;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-it-setup-server-'));
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO,
    env: { ...process.env, DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1', ENCRYPTION_KEY: 'c'.repeat(64), LOG_LEVEL: 'error', APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1' },
    stdio: 'ignore',
  });
  for (let i = 0; i < 120; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const db = new Database(join(dataDir, 'deployhub.db'));
  const admin = db.prepare("INSERT INTO users (name,email,role,active,kind) VALUES ('admin','admin@t.test','platform_admin',1,'human')").run().lastInsertRowid;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(admin, sha(ADMIN_SESS));
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

test('mounted: admin issues a link, the page opens it, the session is refused everywhere else', async () => {
  const created = await fetch(`${base}/api/it-setup-links`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ADMIN_SESS}` }, body: JSON.stringify({ label: 'Server test', scopes: ['domains'] }) });
  assert.equal(created.status, 201);
  const { url } = await created.json();
  const token = new URL(url).hash.slice(3);

  const page = await fetch(`${base}/it-setup`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);

  const open = await fetch(`${base}/api/it-setup/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  assert.equal(open.status, 200);
  const { csrf } = await open.json();
  const cookie = open.headers.getSetCookie()[0].split(';')[0];
  const session = cookie.split('=')[1];

  const state = await fetch(`${base}/api/it-setup/state`, { headers: { Cookie: cookie } });
  assert.equal(state.status, 200);
  const add = await fetch(`${base}/api/it-setup/domains`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie, 'X-IT-Setup-CSRF': csrf }, body: '{"domain":"server.example.test"}' });
  assert.equal(add.status, 201);

  for (const p of ['/api/apps', '/api/auth/oidc/admin-config', '/api/settings/siem', '/api/users', '/api/it-setup-links', '/api/audit']) {
    for (const headers of [{ Cookie: `cc_token=${session}; cc_itsetup=${session}` }, { Authorization: `Bearer ${session}` }, { 'X-API-Key': session }]) {
      const r = await fetch(base + p, { headers });
      assert.ok([401, 403].includes(r.status), `${p} ${Object.keys(headers)[0]} -> ${r.status}`);
    }
  }
});
