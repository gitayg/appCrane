import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// MCP tool calls write their audit row directly (auditMcpCall), not through
// logAudit, so they need their own hook into the event store.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-evmcp-'));
process.env.ENCRYPTION_KEY = '8'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const APP = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('E','evmcp',1,'managed','main')").run().lastInsertRowid;
const uid = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)').run('owner', 'owner@t.test', 'user', hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, uid, 'owner');
db.prepare('INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?,?,?,?)').run(APP, 'sandbox', 'API_TOKEN', encrypt('secret-sandbox'));
const { callTool } = await import('../server/services/mcpTools.js');

test('an MCP tool call lands in the event store, linked to its audit row, with no secret in it', async () => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
  await callTool(user, 'appcrane_get_secret', { slug: 'evmcp', env: 'sandbox' });
  const audit = db.prepare("SELECT id FROM audit_log WHERE action = 'mcp.appcrane_get_secret' ORDER BY id DESC LIMIT 1").get();
  assert.ok(audit, 'no MCP audit row');
  const ev = db.prepare("SELECT * FROM events WHERE ref_table = 'audit_log' AND ref_id = ?").get(audit.id);
  assert.ok(ev, 'the MCP call was audited but never reached the event store');
  assert.equal(ev.app_id, APP);
  assert.equal(ev.user_id, uid);
  assert.doesNotMatch(JSON.stringify(ev), /secret-sandbox/);
});
