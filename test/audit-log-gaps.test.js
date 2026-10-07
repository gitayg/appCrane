import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Audit-log gaps from the 2026-10-06 squash scan (ENISA SbD 4.5/4.10).
// Authentication was not audited at all: no row for a password, OIDC or SAML
// login, successful or failed. Nor were Ask Claude, coder dispatch or file
// staging. Prompts and questions are recorded by LENGTH, never content.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-auditgaps-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
const { initDb, getDb } = await import('../server/db.js');
const { hashPassword } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const uid = db.prepare("INSERT INTO users (name,email,username,role,active,api_key_hash,password_hash) VALUES ('Dana','dana@acme.test','dana','user',1,'h',?)")
  .run(hashPassword('correct horse battery staple')).lastInsertRowid;

const identity = (await import('../server/routes/identity.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/identity', identity);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = `http://127.0.0.1:${server.address().port}`;
const login = (l, p) => fetch(`${base}/api/identity/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ login: l, password: p }) });
const rows = (action) => db.prepare('SELECT user_id, detail FROM audit_log WHERE action = ? ORDER BY id').all(action);

test('a successful password login is audited, without the password', async () => {
  assert.equal((await login('dana', 'correct horse battery staple')).status, 200);
  const r = rows('login').at(-1);
  assert.ok(r, 'no login row');
  assert.equal(r.user_id, uid);
  assert.match(r.detail, /"method":"password"/);
  assert.doesNotMatch(r.detail, /horse/);
});

test('failed logins are audited: wrong password and unknown user', async () => {
  assert.equal((await login('dana', 'wrong-password-123')).status, 401);
  assert.equal((await login('nobody', 'whatever-123456')).status, 401);
  const failed = rows('login-failed');
  assert.ok(failed.some(r => r.user_id === uid && /bad_password/.test(r.detail)), 'wrong password not audited');
  assert.ok(failed.some(r => r.user_id === null && /unknown_user/.test(r.detail) && /nobody/.test(r.detail)), 'unknown user not audited');
  assert.ok(failed.every(r => !/wrong-password|whatever/.test(r.detail)), 'a password reached the audit log');
});

test('OIDC, SAML, Ask Claude, coder dispatch and file staging write audit rows', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'routes');
  const expect = {
    'oidc.js': [/auditLogin\([^)]*'ok'/, /auditLogin\([^)]*'failed'/],
    'saml.js': [/auditLogin\([^)]*'ok'/, /auditLogin\([^)]*'failed'/],
    'ask.js': [/logAudit\([^)]*'ask'/],
    'coder.js': [/logAudit\([^)]*'coder-dispatch'/],
    'files.js': [/logAudit\([^)]*'file-stage'/],
  };
  for (const [f, res] of Object.entries(expect)) {
    const src = readFileSync(join(root, f), 'utf8');
    for (const re of res) assert.match(src, re, `${f} does not write the expected audit row (${re})`);
  }
  // Content never goes in: the coder prompt and the Ask question are lengths.
  assert.doesNotMatch(readFileSync(join(root, 'coder.js'), 'utf8'), /logAudit\([^)]*prompt:\s*prompt/);
  assert.doesNotMatch(readFileSync(join(root, 'ask.js'), 'utf8'), /logAudit\([^)]*question:\s*question/);
});
