import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// The app page's Resource Limits card sent { resource_limits: { max_ram_mb,
// max_cpu_percent } }, but PUT /api/apps/:slug read only the top-level fields.
// The nested object was ignored: 200, "Resource limits saved", nothing saved,
// and a non-platform-admin was never told the change is platform-admin only.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-limits-'));
process.env.ENCRYPTION_KEY = '1'.repeat(64);
const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const mk = (name, role) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)').run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
};
const PLATFORM = mk('platform', 'platform_admin');
const OWNER = mk('owner', 'user');
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch,resource_limits) VALUES ('L','limits',1,'managed','main','{\"max_ram_mb\":512,\"max_cpu_percent\":50}')").run().lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, OWNER.id);

const apps = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/apps', apps); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const put = (who, body) => fetch(`http://127.0.0.1:${server.address().port}/api/apps/limits`, {
  method: 'PUT', headers: { 'content-type': 'application/json', 'x-api-key': who.key }, body: JSON.stringify(body),
});
const limits = () => JSON.parse(db.prepare('SELECT resource_limits r FROM apps WHERE id = ?').get(appId).r);

test('the nested form the card sends is saved, not ignored', async () => {
  const r = await put(PLATFORM, { resource_limits: { max_ram_mb: 1024, max_cpu_percent: 75 } });
  assert.equal(r.status, 200);
  assert.deepEqual(limits(), { max_ram_mb: 1024, max_cpu_percent: 75 });
});

test('the top-level form still works', async () => {
  assert.equal((await put(PLATFORM, { max_ram_mb: 768 })).status, 200);
  assert.equal(limits().max_ram_mb, 768);
});

test('a non-platform-admin is refused, not told "saved"', async () => {
  const r = await put(OWNER, { resource_limits: { max_ram_mb: 4096 } });
  assert.equal(r.status, 403);
  assert.equal(limits().max_ram_mb, 768);
});

test('the card sends the fields the server reads, and says how the change applies', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'studio-web/src/pages/AppManager.tsx'), 'utf8');
  const card = src.slice(src.indexOf('function LimitsCard'), src.indexOf('interface DeployCardProps'));
  assert.match(card, /max_ram_mb: ram, max_cpu_percent: cpu \}\)/);
  assert.doesNotMatch(card, /Save &amp; Redeploy/, 'the button promises a redeploy it does not do');
});
