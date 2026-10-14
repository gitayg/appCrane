import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Operator decision (v2.107.5): revealing a PRODUCTION secret's value is the
// app owner's or a platform admin's call, over REST (?reveal=true) and MCP
// (appcrane_reveal_secret). App admins and members keep the masked list;
// sandbox reveals are unchanged.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-prodreveal-'));
process.env.ENCRYPTION_KEY = '9'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const APP = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('R','reveal',1,'managed','main')").run().lastInsertRowid;
const mk = (name, role, appRole) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)').run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  if (appRole) db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, id, appRole);
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
const OWNER = mk('owner', 'user', 'owner');
const APPADMIN = mk('appadmin', 'user', 'admin');
const MEMBER = mk('member', 'user', 'user');
const PLATFORM = mk('platform', 'platform_admin', 'user');
for (const env of ['production', 'sandbox']) db.prepare('INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?,?,?,?)').run(APP, env, 'API_TOKEN', encrypt(`secret-${env}`));

const envRoutes = (await import('../server/routes/envVars.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');
const server = await new Promise((r) => { const a = express(); a.use(express.json()); a.use('/api/apps', envRoutes); a.use(errorHandler); const s = a.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const get = (who, env, reveal) => fetch(`http://127.0.0.1:${server.address().port}/api/apps/reveal/env/${env}${reveal ? '?reveal=true' : ''}`, { headers: { 'x-api-key': who.key } });

test('REST: production reveal is refused to app admins and members, allowed to the owner and a platform admin', async () => {
  for (const who of [APPADMIN, MEMBER]) assert.equal((await get(who, 'production', true)).status, 403, `${who.row.name} revealed a production secret`);
  for (const who of [OWNER, PLATFORM]) assert.equal((await get(who, 'production', true)).status, 200, `${who.row.name} was refused`);
  assert.equal((await get(MEMBER, 'production', false)).status, 200, 'the masked list must stay available');
  assert.equal((await get(MEMBER, 'sandbox', true)).status, 200, 'sandbox reveals are unchanged');
});

test('MCP: appcrane_reveal_secret on production needs the owner or a platform admin', async () => {
  await assert.rejects(callTool(APPADMIN.row, 'appcrane_reveal_secret', { slug: 'reveal', env: 'production', key: 'API_TOKEN' }), /owner or a platform admin/);
  const r = await callTool(OWNER.row, 'appcrane_reveal_secret', { slug: 'reveal', env: 'production', key: 'API_TOKEN' });
  assert.match(JSON.stringify(r), /secret-production/);
  const s = await callTool(APPADMIN.row, 'appcrane_reveal_secret', { slug: 'reveal', env: 'sandbox', key: 'API_TOKEN' });
  assert.match(JSON.stringify(s), /secret-sandbox/);
});
