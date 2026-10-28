import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// A failed deploy said why only inside its full log (hundreds of lines) and in
// the owners' e-mail. A CI job polling the deployment saw status "failed" and
// nothing else (seen 2026-10-28: six failed relay deploys, each a health check
// missing "status", reported to CI as just "failed"). The reason is now its own
// field on every surface a caller polls: REST list, REST log, appcrane_wait_deploy
// and appcrane_get_deploy_log.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-failreason-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const deployRoutes = (await import('../server/routes/deploy.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

global.fetch = ((real) => async (url, opts) => {
  if (String(url).startsWith('http://127.0.0.1')) return real(url, opts);
  return { ok: true, status: 200, headers: new Headers(), text: async () => '{}', json: async () => ({}) };
})(global.fetch);

const key = generateApiKey('dhk_user');
const adminId = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('fradmin','fr@acme.test','platform_admin',1,?)")
  .run(hashApiKey(key)).lastInsertRowid;
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);

// A managed app whose local repository was never created: the clone fails, a
// real failure through deployApp's own failure path.
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch,repo_backend) VALUES ('Fr','frbroken',20031,'managed','main','local')")
  .run().lastInsertRowid;
const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);

const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', deployRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
const base = `http://127.0.0.1:${server.address().port}`;
const get = (path) => fetch(base + path, { headers: { 'x-api-key': key } }).then((r) => r.json());

after(async () => {
  server.closeAllConnections?.(); server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}

const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)")
  .run(appId, adminId).lastInsertRowid;
await deployApp(depId, app, 'sandbox', getPortsForSlot(app.slot)).catch(() => {});
const row = db.prepare('SELECT status, log, failure_reason FROM deployments WHERE id = ?').get(depId);
const REASON = row.failure_reason || 'missing: the comparisons below must not pass on null === null';

test('the failed deploy stores its one-line reason, the same text as the log\'s DEPLOY FAILED line', () => {
  assert.equal(row.status, 'failed', row.log);
  const logLine = /DEPLOY FAILED: (.*)/.exec(row.log)?.[1];
  assert.ok(logLine, `control: the deploy did not fail through deployApp's failure path: ${row.log}`);
  assert.ok(row.failure_reason, 'failure_reason is empty');
  assert.ok(row.failure_reason.startsWith(logLine), `${row.failure_reason} vs ${logLine}`);
});

test('REST: the deployment list and the deploy log both carry the reason', async () => {
  const list = await get('/api/apps/frbroken/deployments/sandbox');
  const d = list.deployments.find((x) => x.id === depId);
  assert.equal(d.status, 'failed');
  assert.equal(d.failure_reason, REASON);
  const log = await get(`/api/apps/frbroken/deployments/sandbox/${depId}/log`);
  assert.equal(log.status, 'failed');
  assert.equal(log.failure_reason, REASON);
});

test('MCP: appcrane_wait_deploy and appcrane_get_deploy_log both carry the reason', async () => {
  const w = await tool('appcrane_wait_deploy', { deployment_id: depId, timeout_sec: 1 });
  assert.equal(w.status, 'failed');
  assert.equal(w.failure_reason, REASON);
  const l = await tool('appcrane_get_deploy_log', { deployment_id: depId });
  assert.equal(l.failure_reason, REASON);
});

test('a deploy that has not failed has no reason', async () => {
  const okId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'live', ?)")
    .run(appId, adminId).lastInsertRowid;
  const w = await tool('appcrane_wait_deploy', { deployment_id: okId, timeout_sec: 1 });
  assert.equal(w.status, 'live');
  assert.equal(w.failure_reason, null);
});
