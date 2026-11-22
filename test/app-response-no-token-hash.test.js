import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

const ROOT = mkdtempSync(join(tmpdir(), 'crane-app-token-hash-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const key = generateApiKey('dhk_admin');
const uid = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('m','m@t.test','user',?,1,'human')").run(hashApiKey(key)).lastInsertRowid;
const appId = db.prepare("INSERT INTO apps (name,slug,slot,branch,service_token_hash) VALUES ('h','hashapp',301,'main',?)").run('a'.repeat(64)).lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, uid);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) { /* best effort */ }
});

test('app responses never carry the service token hash', async () => {
  for (const path of ['/api/apps/hashapp', '/api/apps']) {
    const res = await fetch(`${BASE}${path}`, { headers: { 'X-API-Key': key } });
    assert.equal(res.status, 200, path);
    const text = await res.text();
    assert.ok(text.includes('hashapp'), `${path} lists the app`);
    assert.ok(!text.includes('service_token_hash') && !text.includes('a'.repeat(64)), `${path} leaks the service token hash`);
  }
});
