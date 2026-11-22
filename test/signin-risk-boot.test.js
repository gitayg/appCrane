import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import net from 'net';
import Database from 'better-sqlite3';

// Sign-in risk against the real server process (server/index.js): the
// /api/signin-security mount, the public "not you?" link, the lockout through
// the real middleware stack, the stale-sweep job registration, and the host
// break-glass `crane signin unlock`.

const ENCRYPTION_KEY = 'f'.repeat(64);
let child, base, dataDir;
const sha = (s) => createHash('sha256').update(s).digest('hex');
const ADMIN_KEY = `dhk_admin_${randomBytes(16).toString('hex')}`;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'crane-signin-boot-'));
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    env: {
      ...process.env,
      DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1',
      ENCRYPTION_KEY, LOG_LEVEL: 'error',
      APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1',
    },
    stdio: 'ignore',
  });
  let up = false;
  for (let i = 0; i < 160 && !up; i++) {
    try { const r = await fetch(`${base}/api/info`); up = r.ok; } catch (_) { /* booting */ }
    if (!up) await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(up, 'server did not boot');
  const { hashPassword } = await import('../server/services/encryption.js');
  const db = new Database(join(dataDir, 'deployhub.db'));
  db.prepare("INSERT INTO users (name,email,username,role,api_key_hash,active) VALUES ('admin','admin@t.test','admin','platform_admin',?,1)").run(sha(ADMIN_KEY));
  db.prepare("INSERT INTO users (name,email,username,role,api_key_hash,password_hash,active) VALUES ('bob','bob@t.test','bob','user','z',?,1)").run(hashPassword('a long enough password'));
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auth_mfa_required', 'off')").run();
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('signin_risk_policy', '{\"lockout_threshold\":3}')").run();
  db.close();
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

const q = (sql, ...a) => { const db = new Database(join(dataDir, 'deployhub.db'), { readonly: true }); const r = db.prepare(sql).get(...a); db.close(); return r; };
const login = (password) => fetch(`${base}/api/identity/login`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ login: 'bob', password }),
});
const crane = (...args) => execFileSync(process.execPath, ['cli/index.js', ...args], {
  env: { ...process.env, DATA_DIR: dataDir, ENCRYPTION_KEY, LOG_LEVEL: 'error', HOME: dataDir }, encoding: 'utf8',
});

test('the router is mounted: admin-only overview, public not-me link', async () => {
  assert.equal((await fetch(`${base}/api/signin-security`)).status, 401);
  const r = await fetch(`${base}/api/signin-security`, { headers: { 'X-API-Key': ADMIN_KEY } });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.policy.lockout_threshold, 3);
  assert.ok(Array.isArray(body.stale));

  const g = await fetch(`${base}/api/signin-security/not-me?t=${'a'.repeat(43)}`);
  assert.equal(g.status, 410);
  assert.match(g.headers.get('content-type'), /text\/html/);
  const p = await fetch(`${base}/api/signin-security/not-me`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `t=${'a'.repeat(43)}`,
  });
  assert.equal(p.status, 410);
});

test('the stale sweep job is registered with Job Health', async () => {
  const r = await fetch(`${base}/api/settings/job-health`, { headers: { 'X-API-Key': ADMIN_KEY } });
  assert.equal(r.status, 200);
  const body = await r.json();
  const jobs = Array.isArray(body) ? body : body.jobs;
  const job = jobs.find((j) => j.id === 'signin-stale-sweep');
  assert.ok(job, 'listed');
  assert.equal(job.started_in_process, true, 'started at boot');
});

test('host break-glass: crane signin unlock lifts a lock on the real server, audited, no network', async () => {
  for (let i = 0; i < 3; i++) assert.equal((await login('wrong')).status, 401);
  const locked = await login('a long enough password');
  assert.equal(locked.status, 429);
  assert.equal((await locked.json()).error.code, 'SIGNIN_LOCKED');
  assert.match(crane('signin', 'locked'), /bob/);

  const out = crane('signin', 'unlock', 'bob');
  assert.match(out, /Unlocked bob/);
  const audit = q("SELECT * FROM audit_log WHERE action = 'signin-unlock' ORDER BY id DESC");
  assert.ok(audit, 'audited');
  assert.equal(audit.user_id, null);
  assert.equal(JSON.parse(audit.detail).via, 'cli');
  assert.ok(q("SELECT 1 FROM events WHERE kind = 'login.risk.unlocked'"));
  assert.equal((await login('a long enough password')).status, 200, 'unlocked');
  assert.match(crane('signin', 'locked'), /No account is locked/);
});

test('crane signin unlock refuses an unknown user', () => {
  assert.throws(() => crane('signin', 'unlock', 'nobody-here'), /No user matches/);
});
