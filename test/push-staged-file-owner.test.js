import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// appcrane_push_staged_file copied with plain `docker cp`, which keeps the
// staged file's owner. AppCrane stages as root, so the file landed root-owned
// and an app running as node could not change it (the appcrane_cp half of this
// was fixed in v2.123.1). `docker cp -a` gives it to the container's user:
// measured on Linux, 0:0 without -a, 1000:1000 with it.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-staged-owner-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
require('fs').appendFileSync(${JSON.stringify(LOG)}, JSON.stringify(process.argv.slice(2)) + '\\n');
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('s','s@t.test','user',1,?)").run(hashApiKey(generateApiKey('dhk_user'))).lastInsertRowid;
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('S','stager',1,'managed','main')").run().lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, uid);
const USER = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
const { callTool } = await import('../server/services/mcpTools.js');

const scratch = join(mkdtempSync(join(tmpdir(), 'crane-staged-blob-')), 'orders.json');
writeFileSync(scratch, '{}');
db.prepare("INSERT INTO staged_files (token,user_id,filename,size_bytes,sha256,scratch_path,expires_at) VALUES ('tok1',?,'orders.json',2,'x',?,datetime('now','+1 hour'))").run(uid, scratch);

test('the staged file is copied with -a, so the container user owns it', async () => {
  await callTool(USER, 'appcrane_push_staged_file', { slug: 'stager', env: 'sandbox', token: 'tok1', dest: '/data/order-status/orders.json' });
  const cp = readFileSync(LOG, 'utf8').trim().split('\n').map((l) => JSON.parse(l)).find((a) => a[0] === 'cp');
  assert.deepEqual(cp, ['cp', '-a', scratch, 'appcrane-stager-sandbox:/data/order-status/orders.json']);
});
