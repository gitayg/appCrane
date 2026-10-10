import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Security audit 2026-10-09 (Anthropic defending-code harness):
//   H3 every coder turn runs on the session OWNER's personal Claude token, but
//      getSession only checked the session belongs to the app: any member could
//      send turns, attachments or a resume into a colleague's session.
//   H6 a global admin could issue an MCP key for a platform admin, and the key
//      authenticates as that user.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-sessowner-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const mk = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES (?,?,?,1,?,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
};
const APP = db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,branch) VALUES ('S',1,'sess','managed','local','main')").run().lastInsertRowid;
const OWNER = mk('owner'), MEMBER = mk('member'), APPADMIN = mk('appadmin'), PLATFORM = mk('platform', 'platform_admin'), GADMIN = mk('gadmin', 'admin');
for (const [u, r] of [[OWNER, 'user'], [MEMBER, 'user'], [APPADMIN, 'admin']]) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, u.id, r);
}
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('s-idle', 'sess', ?, 'b', 'idle')").run(OWNER.id);
db.prepare("INSERT INTO coder_sessions (id, app_slug, user_id, branch_name, status) VALUES ('s-paused', 'sess', ?, 'b', 'paused')").run(OWNER.id);

const coder = (await import('../server/routes/coder.js')).default;
const keys = (await import('../server/routes/userMcpKeys.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/coder', coder); a.use('/api', keys); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });
const call = async (method, path, who, body) => {
  const r = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method, headers: { 'x-api-key': who.key, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

test('H3: another member cannot feed, resume or edit the queue of a colleague\'s session', async () => {
  for (const who of [MEMBER, APPADMIN, PLATFORM]) {
    for (const [m, p, b] of [
      ['POST', '/api/coder/sess/session/s-idle/dispatch', { prompt: 'hi' }],
      ['POST', '/api/coder/sess/session/s-idle/attachments', { name: 'a.txt', data: 'aGk=' }],
      ['POST', '/api/coder/sess/session/s-paused/resume'],
      ['DELETE', '/api/coder/sess/session/s-idle/followups/1'],
    ]) {
      const r = await call(m, p, who, b);
      assert.equal(r.status, 403, `${m} ${p} was allowed for a non-owner (${r.status})`);
      assert.equal(r.body.error?.code ?? r.body.code, 'NOT_SESSION_OWNER');
    }
  }
});

test('H3: the owner passes the ownership gate', async () => {
  const r = await call('POST', '/api/coder/sess/session/s-idle/attachments', OWNER, { name: 'a.txt', data: 'aGk=' });
  assert.notEqual(r.body.error?.code ?? r.body.code, 'NOT_SESSION_OWNER');
});

test('H3: stopping a colleague\'s turn is the owner\'s or an app admin\'s', async () => {
  assert.equal((await call('POST', '/api/coder/sess/session/s-idle/stop', MEMBER)).status, 403);
  assert.equal((await call('POST', '/api/coder/sess/session/s-idle/stop', APPADMIN)).status, 200);
});

test('H6: only a platform admin may issue an MCP key for another user', async () => {
  assert.equal((await call('POST', `/api/users/${PLATFORM.id}/mcp-keys`, GADMIN, {})).status, 403);
  assert.equal((await call('POST', `/api/users/${MEMBER.id}/mcp-keys`, GADMIN, {})).status, 403);
  assert.equal((await call('POST', `/api/users/${MEMBER.id}/mcp-keys`, PLATFORM, {})).status, 200);
});
