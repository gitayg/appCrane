import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// POST /api/apps/:slug/restart/:env rebuilds the container's whole environment
// from scratch. It must hand the app the same APPCRANE_IDENTITY_SECRET a deploy
// does, for THAT environment: without it a restarted app silently stops
// verifying identity signatures (tenantKey falls back to unverified headers).

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-restart-sec-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);

const SHIM = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify(args) + '\\n');
if (args[0] === 'network' && args[1] === 'inspect') { process.stdout.write('false|172.20.0.0/16 '); process.exit(0); }
if (args[0] === 'inspect' && args.join(' ').includes('.Config.Env')) {
  process.stdout.write(JSON.stringify(['PATH=/usr/bin', 'APPCRANE_TENANT_ROOT=/data/tenants', 'APPCRANE_TENANT_QUOTA_BYTES=52428800', 'SECRET_NOT_PLATFORM=x']) + '\\n');
  process.exit(0);
}
if (args[0] === 'inspect') { process.stdout.write('example/app:1\\n'); process.exit(0); }
process.stdout.write('0123456789abcdef\\n');
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const KEY = generateApiKey('dhk_user');
const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('o','o@t.test','user',1,?)").run(hashApiKey(KEY)).lastInsertRowid;
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('R','restartme',1,'managed','main')").run().lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, uid);

const deployRoutes = (await import('../server/routes/deploy.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { identitySecretFor } = await import('../server/services/identitySignature.js');
const server = await new Promise((r) => {
  const app = express();
  app.use(express.json());
  app.use('/api/apps', deployRoutes);
  app.use(errorHandler);
  const s = app.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = `http://127.0.0.1:${server.address().port}`;

for (const env of ['production', 'sandbox']) {
  test(`a ${env} restart gives the app its ${env} identity secret`, async () => {
    const r = await fetch(`${base}/api/apps/restartme/restart/${env}`, { method: 'POST', headers: { 'x-api-key': KEY } });
    const body = await r.json();
    assert.equal(r.status, 200, JSON.stringify(body));
    assert.ok(body.injected_keys.includes('APPCRANE_IDENTITY_SECRET'),
      'restart dropped APPCRANE_IDENTITY_SECRET: a restarted app stops verifying identity');
    const run = readFileSync(LOG, 'utf8').trim().split('\n').map(l => JSON.parse(l))
      .filter(a => a[0] === 'run' && a.some(x => x.includes(`appcrane-restartme-${env}`))).at(-1);
    assert.ok(run, 'no docker run was issued');
    assert.ok(run.includes(`APPCRANE_IDENTITY_SECRET=${identitySecretFor(db, appId, env)}`),
      `the ${env} container did not get the ${env} secret`);
  });
}

test('a restart keeps a multitenant app\'s tenant root and per-user quota', async () => {
  db.prepare("UPDATE apps SET multitenant = 1 WHERE id = ?").run(appId);
  const r = await fetch(`${base}/api/apps/restartme/restart/production`, { method: 'POST', headers: { 'x-api-key': KEY } });
  assert.equal(r.status, 200);
  const run = readFileSync(LOG, 'utf8').trim().split('\n').map(l => JSON.parse(l))
    .filter(a => a[0] === 'run' && a.some(x => x.includes('appcrane-restartme-production'))).at(-1);
  assert.ok(run.includes('APPCRANE_TENANT_ROOT=/data/tenants'), 'restart dropped the tenant root');
  assert.ok(run.includes('APPCRANE_TENANT_QUOTA_BYTES=52428800'), 'restart dropped the per-user quota');
  assert.ok(!run.includes('SECRET_NOT_PLATFORM=x'), 'restart copied a non-platform variable from the old container');
});
