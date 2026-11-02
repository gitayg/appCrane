import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import express from 'express';

// The backup/restore/copy-data routes, the dashboard storage rollup and the
// appcrane_ls/cat/push_staged_file tools run child processes while serving a
// request. Run synchronously, each one froze the whole process for its
// duration, including the forward_auth check every hosted app's every request
// waits on (measured: 660 ms verify latency during a 30 MB tar).
//
// Each command is replaced on PATH by a shim that sleeps SLOW_S and then runs
// the real binary, so the request takes at least that long; a 20 ms interval
// in the same process must keep firing the whole time (largest gap bound).

const SLOW_S = 1.2;
const MAX_GAP_MS = 400;

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-reqpath-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const real = (cmd) => execFileSync('/bin/sh', ['-c', `command -v ${cmd}`]).toString().trim();
const SHIM = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM, { recursive: true });
for (const cmd of ['tar', 'rsync', 'cp']) {
  writeFileSync(join(SHIM, cmd), `#!/bin/sh\nsleep ${SLOW_S}\nexec ${real(cmd)} "$@"\n`, { mode: 0o755 });
}
writeFileSync(join(SHIM, 'du'), `#!/bin/sh\nsleep ${SLOW_S}\nprintf '4242\\t%s\\n' "$2"\n`, { mode: 0o755 });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
if [ "$1" = inspect ]; then echo false; exit 0; fi
sleep ${SLOW_S}
if [ "$3" = stat ]; then echo 5; else echo shim-out; fi
`, { mode: 0o755 });
const REAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM}:${REAL_PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
initDb(process.env.DATA_DIR);
const db = getDb();

const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('R','rp-app',1,'managed','main')").run().lastInsertRowid;
const key = generateApiKey('dhk_user');
const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('o','o@t.test','platform_admin',1,?)").run(hashApiKey(key)).lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, uid);
const USER = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);

for (const env of ['production', 'sandbox']) {
  const d = join(process.env.DATA_DIR, 'apps', 'rp-app', env, 'shared', 'data');
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, 'f.txt'), env);
}

const backupRoutes = await import('../server/routes/backups.js');
const monitoringRoutes = await import('../server/routes/monitoring.js');
const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', backupRoutes.default);
  a.use('/api', monitoringRoutes.default);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => {
  server.closeAllConnections?.(); server.close();
  process.env.PATH = REAL_PATH;
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});
const base = `http://127.0.0.1:${server.address().port}`;
const call = async (method, path, body) => {
  const r = await fetch(base + path, {
    method, headers: { 'x-api-key': key, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, body: await r.json().catch(() => null) };
};

// Runs fn while a 20 ms interval ticks; returns its result and the largest
// gap between ticks (or between the start and the first tick).
async function withTicker(fn) {
  let last = Date.now();
  let maxGap = 0;
  const t = setInterval(() => { const n = Date.now(); maxGap = Math.max(maxGap, n - last); last = n; }, 20);
  const t0 = Date.now();
  try {
    const result = await fn();
    maxGap = Math.max(maxGap, Date.now() - last);
    return { result, maxGap, ms: Date.now() - t0 };
  } finally {
    clearInterval(t);
  }
}

const assertLoopFree = (r, what) => {
  assert.ok(r.ms >= SLOW_S * 1000, `${what} should have waited on the slow shim (${r.ms} ms)`);
  assert.ok(r.maxGap < MAX_GAP_MS, `${what} blocked the event loop for ${r.maxGap} ms`);
};

let backupId;
test('POST /backup: tar runs without blocking the event loop', async () => {
  const r = await withTicker(() => call('POST', '/api/apps/rp-app/backup/sandbox'));
  assert.equal(r.result.status, 200, JSON.stringify(r.result.body));
  backupId = r.result.body.backup.id;
  assertLoopFree(r, 'backup');
});

test('POST /restore: tar -x runs without blocking the event loop', async () => {
  const r = await withTicker(() => call('POST', `/api/apps/rp-app/restore/${backupId}`, {}));
  assert.equal(r.result.status, 200, JSON.stringify(r.result.body));
  assertLoopFree(r, 'restore');
});

test('POST /copy-data: rsync runs without blocking the event loop', async () => {
  const r = await withTicker(() => call('POST', '/api/apps/rp-app/copy-data'));
  assert.equal(r.result.status, 200, JSON.stringify(r.result.body));
  assertLoopFree(r, 'copy-data');
});

test('POST /backup: a failing tar still answers BACKUP_FAILED with its stderr', async () => {
  const shim = join(SHIM, 'tar');
  writeFileSync(shim, '#!/bin/sh\necho "tar: disk full" >&2\nexit 2\n', { mode: 0o755 });
  try {
    const r = await call('POST', '/api/apps/rp-app/backup/production');
    assert.equal(r.status, 500);
    assert.equal(r.body.error.code, 'BACKUP_FAILED');
    assert.match(r.body.error.message, /^Backup failed: Command failed: tar -czf .*\ntar: disk full/);
  } finally {
    writeFileSync(shim, `#!/bin/sh\nsleep ${SLOW_S}\nexec ${real('tar')} "$@"\n`, { mode: 0o755 });
  }
});

test('GET /dashboard/app-storage: du calls run concurrently (4 at a time) off the event loop', async () => {
  for (let i = 2; i <= 8; i++) {
    db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(`R${i}`, `rp-app${i}`, i);
    mkdirSync(join(process.env.DATA_DIR, 'apps', `rp-app${i}`), { recursive: true });
  }
  const r = await withTicker(() => call('GET', '/api/dashboard/app-storage'));
  assert.equal(r.result.status, 200, JSON.stringify(r.result.body));
  assert.equal(r.result.body.apps.length, 8);
  assert.ok(r.result.body.apps.every((a) => a.total_bytes === 4242), JSON.stringify(r.result.body));
  assertLoopFree(r, 'app-storage');
  // 8 apps, 4 at a time: two rounds of the shim, not eight.
  assert.ok(r.ms < SLOW_S * 1000 * 4, `app-storage took ${r.ms} ms; du ran one at a time`);
});

test('mapLimit never has more than `limit` in flight and keeps order', async () => {
  const { mapLimit } = await import('../server/services/diskUsage.js');
  let inFlight = 0;
  let peak = 0;
  const out = await mapLimit([1, 2, 3, 4, 5, 6, 7, 8, 9], 4, async (n) => {
    inFlight++; peak = Math.max(peak, inFlight);
    await new Promise((r) => setTimeout(r, 10 * (10 - n)));
    inFlight--;
    return n * 2;
  });
  assert.equal(peak, 4);
  assert.deepEqual(out, [2, 4, 6, 8, 10, 12, 14, 16, 18]);
});

test('appcrane_ls / appcrane_cat / appcrane_push_staged_file: docker runs without blocking the event loop', async () => {
  const { callTool: rawCall } = await import('../server/services/mcpTools.js');
  const callTool = async (...a) => JSON.parse((await rawCall(...a)).content[0].text);
  const ls = await withTicker(() => callTool(USER, 'appcrane_ls', { slug: 'rp-app', path: '/app' }));
  assert.equal(ls.result.listing, 'shim-out\n');
  assertLoopFree(ls, 'appcrane_ls');

  const cat = await withTicker(() => callTool(USER, 'appcrane_cat', { slug: 'rp-app', path: '/app/x.txt' }));
  assert.equal(cat.result.size, 5);
  assert.equal(cat.result.content, 'shim-out\n');
  assert.ok(cat.ms >= SLOW_S * 2000, `cat should run stat then cat (${cat.ms} ms)`);
  assert.ok(cat.maxGap < MAX_GAP_MS, `appcrane_cat blocked the event loop for ${cat.maxGap} ms`);

  const scratch = join(mkdtempSync(join(tmpdir(), 'crane-reqpath-blob-')), 'a.json');
  writeFileSync(scratch, '{}');
  db.prepare("INSERT INTO staged_files (token,user_id,filename,size_bytes,sha256,scratch_path,expires_at) VALUES ('rptok',?,'a.json',2,'x',?,datetime('now','+1 hour'))").run(uid, scratch);
  const cp = await withTicker(() => callTool(USER, 'appcrane_push_staged_file', { slug: 'rp-app', env: 'sandbox', token: 'rptok', dest: '/data/a.json' }));
  assert.equal(cp.result.app, 'rp-app');
  assertLoopFree(cp, 'appcrane_push_staged_file');
});

test('a failing docker exec surfaces its stderr, as before', async () => {
  writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "No such container: x" >&2\nexit 1\n', { mode: 0o755 });
  const { callTool } = await import('../server/services/mcpTools.js');
  await assert.rejects(callTool(USER, 'appcrane_ls', { slug: 'rp-app', path: '/app' }), /ls failed in appcrane-rp-app-sandbox:\/app: No such container: x/);
});
