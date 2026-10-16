import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The per-env Docker volume a declared path is mounted through
// (appcrane-vols-<slug>-<env>, volumeHelper.js) is named after the slug, so it
// must go when the slug goes: on app delete, and on rename. Only the daemon's
// record — the data on disk stays exactly as before.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-volclean-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'),
  '#!/usr/bin/env node\n' +
  'require("fs").appendFileSync(process.env.CRANE_VOLCLEAN_LOG, JSON.stringify(process.argv.slice(2)) + "\\n");\n',
  { mode: 0o755 });
process.env.CRANE_VOLCLEAN_LOG = LOG;
process.env.PATH = `${SHIM}:${process.env.PATH}`;
const volumeRms = () => (existsSync(LOG) ? readFileSync(LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [])
  .filter((a) => a[0] === 'volume' && a[1] === 'rm').map((a) => a.at(-1));

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const key = generateApiKey('dhk_user');
const userId = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('p','p@acme.test','platform_admin',1,?)")
  .run(hashApiKey(key)).lastInsertRowid;

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { renameApp } = await import('../server/services/appRename.js');
const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', appsRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });

test('deleting an app removes both envs\' volumes and leaves the data on disk', async () => {
  db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('V','vclean',990,'upload')").run();
  const data = join(process.env.DATA_DIR, 'apps', 'vclean', 'production', 'shared', 'volumes', 'config');
  mkdirSync(data, { recursive: true });
  writeFileSync(join(data, 'state'), 'KEEP');
  const r = await fetch(`http://127.0.0.1:${server.address().port}/api/apps/vclean?confirm=true`, {
    method: 'DELETE', headers: { 'x-api-key': key },
  });
  assert.equal(r.status, 200, await r.text());
  assert.deepEqual(volumeRms().sort(), ['appcrane-vols-vclean-production', 'appcrane-vols-vclean-sandbox']);
  assert.equal(readFileSync(join(data, 'state'), 'utf8'), 'KEEP');
});

test('renaming an app removes the volumes named after the old slug', async () => {
  db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('R','vold',991,'upload')").run();
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'vold'").get();
  mkdirSync(join(process.env.DATA_DIR, 'apps', 'vold'), { recursive: true });
  writeFileSync(LOG, '');
  await renameApp({ app, newSlug: 'vnew', redirect: false, user: { id: userId, role: 'platform_admin' } });
  assert.deepEqual(volumeRms().sort(), ['appcrane-vols-vold-production', 'appcrane-vols-vold-sandbox']);
});
