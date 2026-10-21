import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import express from 'express';

// A restore stops the app containers that use the restored data, restores, and
// starts them again even when the restore fails; while it runs the app is
// locked against deploys, restarts and a second restore. No daemon: a recording
// `docker` shim on PATH answers inspect/stop/restart and the restore commands,
// and can be told to hold pg_restore (to observe the lock), fail it, or fail
// the restart.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mdbstop-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const LOG = join(process.env.DATA_DIR, 'docker.log');
const HOLD = join(process.env.DATA_DIR, 'hold-restore');
const FAIL_RESTORE = join(process.env.DATA_DIR, 'fail-restore');
const FAIL_START = join(process.env.DATA_DIR, 'fail-start');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const argv = process.argv.slice(2);
if (argv.includes('pg_restore')) { try { fs.readFileSync(0); } catch (_) {} }
fs.appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, JSON.stringify(argv) + '\\n');
const dir = process.env.CRANE_TEST_DIR;
const has = (x) => argv.includes(x);
if (argv[0] === 'inspect' && argv.includes('{{.State.Running}}')) { process.stdout.write('true\\n'); process.exit(0); }
if (argv[0] === 'restart' && fs.existsSync(dir + '/fail-start')) { process.stderr.write('Error: cannot start container\\n'); process.exit(1); }
if (has('pg_restore')) {
  while (fs.existsSync(dir + '/hold-restore')) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  if (fs.existsSync(dir + '/fail-restore')) { process.stderr.write('pg_restore: error: bad dump\\n'); process.exit(1); }
}
`, { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = LOG;
process.env.CRANE_TEST_DIR = process.env.DATA_DIR;
const REAL_PATH = process.env.PATH;
process.env.PATH = `${SHIM_DIR}:${REAL_PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const mdb = await import('../server/services/managedDb.js');
const { encrypt, generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { SANDBOX_TENANT, setSeparateSandboxDb } = await import('../server/services/sandboxDb.js');
const { errorHandler } = await import('../server/utils/errors.js');
const guard = await import('../server/services/managedDbRestoreGuard.js');

initDb(process.env.DATA_DIR);
const db = getDb();

const A = Number(db.prepare(
  "INSERT INTO apps (name, slug, slot, source_type, branch) VALUES ('rs-a', 'rs-a', 1, 'managed', 'main')",
).run().lastInsertRowid);
const seed = (tenant) => {
  const { database, username } = mdb.namesForScope({ appId: A, tenant });
  db.prepare(`INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
    VALUES (?, ?, 'postgres', ?, ?, ?)`).run(A, tenant || '', database, username, encrypt('AppPw_' + 'y'.repeat(30)));
  return database;
};
const PROD_DB = seed('');
const SAND_DB = seed(SANDBOX_TENANT);

const ops = {
  ...mdb.backupAccess,
  ensureServer: async () => {},
  runAdminSql: async () => '',
  runAdminMongo: async () => {},
  adminCoordsFor: () => ({ port: 47017, adminPassword: 'x' }),
  ensureRedisInstance: async () => {},
  containerFor: (e) => `x-${e}`,
  clientCert: () => ({ certPem: 'CERT\n', keyPem: 'KEY\n' }),
};

const mkUser = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, name };
};
const OWNER = mkUser('owner');
const PLATFORM = mkUser('platform', 'platform_admin');
for (const [u, r] of [[OWNER, 'owner'], [PLATFORM, 'user']]) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(A, u.id, r);
}

const backupRoutes = await import('../server/routes/backups.js');
const deployRoutes = await import('../server/routes/deploy.js');
backupRoutes.__setBackupDbOpsForTests(ops);
const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', backupRoutes.default);
  a.use('/api/apps', deployRoutes.default);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => {
  server.closeAllConnections?.();
  server.close();
  process.env.PATH = REAL_PATH;
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});
const base = `http://127.0.0.1:${server.address().port}`;
const call = async (method, path, who, body) => {
  const r = await fetch(base + path, {
    method, headers: { 'x-api-key': who.key, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, body: await r.json().catch(() => null) };
};

function mkBackup(env, tenant, dbName) {
  const dir = join(process.env.DATA_DIR, 'backups', 'rs-a');
  mkdirSync(dir, { recursive: true });
  const stamp = Math.random().toString(16).slice(2);
  const tar = join(dir, `${env}-${stamp}.tar.gz`);
  const empty = mkdtempSync(join(process.env.DATA_DIR, 'e-'));
  execFileSync('tar', ['-czf', tar, '-C', empty, '.']);
  const file = join(dir, `${env}-${stamp}.postgres.dump`);
  writeFileSync(file, 'DUMP');
  return Number(db.prepare('INSERT INTO backups (app_id, env, size_bytes, file_path, databases) VALUES (?,?,?,?,?)')
    .run(A, env, 1, tar, JSON.stringify([{ engine: 'postgres', tenant, db_name: dbName, file, size_bytes: 4 }])).lastInsertRowid);
}

const docker = () => (existsSync(LOG) ? readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const at = (argvs, pred) => argvs.findIndex(pred);
const stopOf = (env) => (a) => a[0] === 'stop' && a[1] === `appcrane-rs-a-${env}`;
const startOf = (env) => (a) => a[0] === 'restart' && a[1] === `appcrane-rs-a-${env}`;
const isRestore = (a) => a.includes('pg_restore');

beforeEach(() => {
  for (const f of [LOG, HOLD, FAIL_RESTORE, FAIL_START]) rmSync(f, { force: true });
  setSeparateSandboxDb(db, A, false);
  guard.__resetRestoreLocksForTests();
});

test('restore stops the app container before the restore command and starts it after', async () => {
  setSeparateSandboxDb(db, A, true);
  const r = await call('POST', `/api/apps/rs-a/restore/${mkBackup('production', '', PROD_DB)}`, OWNER, {});
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const log = docker();
  const stop = at(log, stopOf('production'));
  const restore = at(log, isRestore);
  const start = at(log, startOf('production'));
  assert.ok(stop >= 0 && restore > stop && start > restore, `order stop(${stop}) < restore(${restore}) < start(${start}): ${JSON.stringify(log)}`);
  assert.equal(at(log, stopOf('sandbox')), -1, 'a separate sandbox keeps running for a production restore');
  assert.deepEqual(r.body.steps.map((s) => `${s.step}${s.env ? ':' + s.env : ''}:${s.ok}`), ['stop:production:true', 'restore:true', 'start:production:true']);
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'restore-run' ORDER BY id DESC LIMIT 1").get();
  const detail = JSON.parse(audit.detail);
  assert.equal(detail.outcome, 'ok');
  assert.ok(detail.steps.every((s) => Number.isInteger(s.ms)), 'each step carries its timing');
});

test('a production restore whose database sandbox shares stops and starts both environments', async () => {
  const r = await call('POST', `/api/apps/rs-a/restore/${mkBackup('production', '', PROD_DB)}`, OWNER, {});
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const log = docker();
  for (const env of ['production', 'sandbox']) {
    assert.ok(at(log, stopOf(env)) >= 0 && at(log, stopOf(env)) < at(log, isRestore), `${env} stopped before the restore`);
    assert.ok(at(log, startOf(env)) > at(log, isRestore), `${env} started after the restore`);
  }
});

test('sandbox restore of the separate sandbox database stops only the sandbox app', async () => {
  setSeparateSandboxDb(db, A, true);
  const r = await call('POST', `/api/apps/rs-a/restore/${mkBackup('sandbox', SANDBOX_TENANT, SAND_DB)}`, OWNER, {});
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const log = docker();
  assert.ok(at(log, stopOf('sandbox')) >= 0 && at(log, startOf('sandbox')) > at(log, isRestore));
  assert.equal(at(log, stopOf('production')), -1, 'production is not stopped');
  assert.equal(at(log, startOf('production')), -1, 'production is not restarted');
});

test('a failing restore still starts the app again and reports the failure', async () => {
  setSeparateSandboxDb(db, A, true);
  writeFileSync(FAIL_RESTORE, '1');
  const r = await call('POST', `/api/apps/rs-a/restore/${mkBackup('production', '', PROD_DB)}`, OWNER, {});
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'RESTORE_FAILED');
  assert.match(r.body.error.message, /bad dump/);
  const log = docker();
  assert.ok(at(log, startOf('production')) > at(log, isRestore), 'the app is started after the failed restore');
  assert.deepEqual(r.body.steps.map((s) => `${s.step}:${s.ok}`), ['stop:true', 'restore:false', 'start:true']);
  assert.equal(guard.restoreInProgress('rs-a'), false, 'the lock is released');
});

test('a start that fails after the restore is reported as APP_START_FAILED', async () => {
  setSeparateSandboxDb(db, A, true);
  writeFileSync(FAIL_START, '1');
  const r = await call('POST', `/api/apps/rs-a/restore/${mkBackup('production', '', PROD_DB)}`, OWNER, {});
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'APP_START_FAILED');
  assert.match(r.body.error.message, /did not start again/);
  assert.deepEqual(r.body.databases_restored.map((d) => d.engine), ['postgres']);
});

test('while a restore runs: deploys, restarts, container starts and a second restore are refused', async () => {
  setSeparateSandboxDb(db, A, true);
  writeFileSync(HOLD, '1');
  const id = mkBackup('production', '', PROD_DB);
  const first = call('POST', `/api/apps/rs-a/restore/${id}`, OWNER, {});
  let status;
  for (let i = 0; i < 200; i++) {
    status = (await call('GET', '/api/apps/rs-a/restore-status', OWNER)).body;
    if (status.phase === 'restoring') break;
    await new Promise((r) => setTimeout(r, 25));
  }
  try {
    assert.equal(status.phase, 'restoring', JSON.stringify(status));

    const deploy = await call('POST', '/api/apps/rs-a/deploy/production', OWNER, {});
    assert.equal(deploy.status, 409, JSON.stringify(deploy.body));
    assert.equal(deploy.body.error.code, 'RESTORE_IN_PROGRESS');

    const restart = await call('POST', '/api/apps/rs-a/restart/production', OWNER, {});
    assert.equal(restart.status, 409, JSON.stringify(restart.body));
    assert.equal(restart.body.error.code, 'RESTORE_IN_PROGRESS');

    const { startApp } = await import('../server/services/docker.js');
    await assert.rejects(startApp({ slug: 'rs-a', env: 'production', image: 'x' }), (e) => e.code === 'RESTORE_IN_PROGRESS');

    const second = await call('POST', `/api/apps/rs-a/restore/${id}`, OWNER, {});
    assert.equal(second.status, 409, JSON.stringify(second.body));
    assert.equal(second.body.error.code, 'RESTORE_IN_PROGRESS');
  } finally {
    rmSync(HOLD, { force: true });
  }
  const done = await first;
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(docker().filter((a) => isRestore(a)).length, 1, 'the second restore never ran');
});

test('keep_running (skip stopping) is platform-admin only, and then nothing is stopped', async () => {
  setSeparateSandboxDb(db, A, true);
  const id = mkBackup('production', '', PROD_DB);
  const owner = await call('POST', `/api/apps/rs-a/restore/${id}`, OWNER, { keep_running: true });
  assert.equal(owner.status, 403, JSON.stringify(owner.body));
  assert.equal(at(docker(), isRestore), -1, 'refused before anything ran');
  const admin = await call('POST', `/api/apps/rs-a/restore/${id}`, PLATFORM, { keep_running: true });
  assert.equal(admin.status, 200, JSON.stringify(admin.body));
  const log = docker();
  assert.ok(at(log, isRestore) >= 0);
  assert.equal(at(log, (a) => a[0] === 'stop' || a[0] === 'restart'), -1, 'no stop, no start');
});
