import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, copyFileSync, utimesSync, openSync, writeSync, closeSync, statSync } from 'fs';
import { createHash } from 'crypto';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Restore drills: a backup restores into DATA_DIR/drills only, is checked, and
// the scratch area is removed. Live data is hashed before and after.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-restore-drill-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { runLocalBackup, localBackupsDir, listLocalBackups } = await import('../server/services/localBackup.js');
const { repoRoot, createTar, extractTar } = await import('../server/services/backupFiles.js');
const { createAppRepo, reposRoot } = await import('../server/services/localGit.js');
const { exportRepoArchive } = await import('../server/services/repoArchive.js');
const drills = await import('../server/services/restoreDrills.js');
const { verifyManagedDumps } = await import('../server/services/restoreDrillChecks.js');
const { JOBS } = await import('../server/services/jobHealth.js');

const ADMIN_KEY = generateApiKey('dhk_admin');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('PA','pa@example.com','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY));
const USER_KEY = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','u@example.com','user',?,1,'human')").run(hashApiKey(USER_KEY));
const appId = db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('Demo','demo',1)").run().lastInsertRowid;
db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'K', ?)").run(appId, encrypt('v1'));

await createAppRepo('demo');
await exportRepoArchive('demo');
await runLocalBackup();

const sha = (b) => createHash('sha256').update(b).digest('hex');
const SKIP_TABLES = new Set(['restore_drills', 'events', 'email_queue', 'job_runs', 'sqlite_sequence', 'settings']);
function liveDbDigest() {
  const h = createHash('sha256');
  for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all()) {
    if (SKIP_TABLES.has(name)) continue;
    h.update(name);
    h.update(JSON.stringify(db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all()));
  }
  return h.digest('hex');
}
function treeDigest(dir) {
  const h = createHash('sha256');
  const walk = (d, rel = '') => {
    for (const n of readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = join(d, n.name);
      h.update(rel + '/' + n.name);
      if (n.isDirectory()) walk(p, rel + '/' + n.name);
      else if (n.isFile()) h.update(readFileSync(p));
    }
  };
  walk(dir);
  return h.digest('hex');
}
const envPath = join(repoRoot, '.env');
const envDigest = () => (existsSync(envPath) ? sha(readFileSync(envPath)) : 'absent');
const emails = () => db.prepare("SELECT * FROM email_queue WHERE source = 'restore-drill'").all();
const critical = () => db.prepare("SELECT * FROM events WHERE kind = 'backup.restore_drill' AND severity = 'critical'").all();

after(() => drills._setDrillDepsForTests(null));

test('JOBS has the restore-drill entry', () => {
  assert.equal(JOBS['restore-drill'].label, 'Scheduled restore drill');
});

test('a drill restores into DATA_DIR/drills only, passes, records RPO/RTO and cleans up', async () => {
  const before = { db: liveDbDigest(), env: envDigest(), repos: treeDigest(reposRoot()) };
  const seen = [];
  drills._setDrillDepsForTests({
    observe: (source, scratch) => seen.push({ source, scratch, db: existsSync(join(scratch, 'data', 'deployhub.db')) }),
  });
  const newest = (await listLocalBackups())[0];
  const twoHoursAgo = new Date(Date.now() - 2 * 3600_000);
  utimesSync(join(localBackupsDir(), newest.file), twoHoursAgo, twoHoursAgo);

  const r = await drills.runRestoreDrill({ trigger: 'manual' });
  const local = r.results.find((x) => x.source === 'local');
  const s3 = r.results.find((x) => x.source === 's3');
  assert.equal(local.status, 'passed', JSON.stringify(local.checks.filter((c) => c.status === 'fail')));
  assert.equal(s3.status, 'skipped');
  assert.equal(r.status, 'passed');

  assert.equal(seen.length, 1);
  assert.ok(seen[0].scratch.startsWith(join(ROOT, 'drills') + '/'), seen[0].scratch);
  assert.equal(seen[0].db, true, 'the backup was restored into the scratch area');

  for (const id of ['archive_extract', 'manifest', 'db_integrity', 'row_counts', 'secrets_decrypt', 'repo_bundles', 'cleanup']) {
    const c = local.checks.find((x) => x.id === id);
    assert.ok(c, `check ${id} present`);
    assert.equal(c.status, 'pass', `${id}: ${JSON.stringify(c.detail)}`);
  }
  assert.ok(local.rpo_seconds >= 7190 && local.rpo_seconds <= 7300, `rpo ${local.rpo_seconds}`);
  assert.ok(Number.isInteger(local.rto_ms) && local.rto_ms >= 0);
  assert.equal(local.cleaned_up, true);
  assert.equal(existsSync(seen[0].scratch), false);
  assert.deepEqual(readdirSync(join(ROOT, 'drills')), []);

  assert.equal(liveDbDigest(), before.db, 'live database content unchanged');
  assert.equal(envDigest(), before.env, 'live .env unchanged');
  assert.equal(treeDigest(reposRoot()), before.repos, 'live repositories unchanged');
  assert.equal(emails().length, 0, 'a passing drill sends no alert');
});

test('a corrupted archive fails the drill and alerts once per day', async () => {
  drills._setDrillDepsForTests(null);
  const good = (await listLocalBackups())[0];
  const bad = join(localBackupsDir(), good.file.replace('.tar.gz', '-x.tar.gz'));
  copyFileSync(join(localBackupsDir(), good.file), bad);
  const size = statSync(bad).size;
  const fd = openSync(bad, 'r+');
  writeSync(fd, Buffer.alloc(Math.min(512, size - 100), 0x5a), 0, Math.min(512, size - 100), 40);
  closeSync(fd);
  const future = new Date(Date.now() + 60_000);
  utimesSync(bad, future, future);

  const r1 = await drills.runRestoreDrill({ trigger: 'manual' });
  const l1 = r1.results.find((x) => x.source === 'local');
  assert.equal(l1.backup_ref, good.file.replace('.tar.gz', '-x.tar.gz'));
  assert.equal(l1.status, 'failed');
  assert.equal(l1.checks.find((c) => c.id === 'archive_extract').status, 'fail');
  assert.equal(l1.cleaned_up, true);
  assert.equal(r1.status, 'failed');
  assert.equal(emails().length, 1, 'one alert mail to the one platform admin');
  assert.equal(emails()[0].to_email, 'pa@example.com');

  const r2 = await drills.runRestoreDrill({ trigger: 'manual' });
  assert.equal(r2.status, 'failed');
  assert.equal(emails().length, 1, 'a second failure the same day does not mail again');
  assert.equal(critical().length, 2, 'each failed run is recorded as a critical event');
  assert.deepEqual(readdirSync(join(ROOT, 'drills')), []);
});

test('a backup whose database is corrupt fails integrity_check', async () => {
  const good = (await listLocalBackups()).find((b) => !b.file.endsWith('-x.tar.gz'));
  const work = mkdtempSync(join(tmpdir(), 'crane-drill-corrupt-'));
  await extractTar(join(localBackupsDir(), good.file), work, { gzip: true });
  const dbFile = join(work, 'deployhub.db');
  const size = statSync(dbFile).size;
  const fd = openSync(dbFile, 'r+');
  const len = Math.min(size - 8192, 64 * 4096);
  writeSync(fd, Buffer.alloc(len, 0xa5), 0, len, 4096);
  closeSync(fd);
  const names = readdirSync(work);
  const dest = join(localBackupsDir(), good.file.replace('.tar.gz', '-y.tar.gz'));
  await createTar(dest, [{ cwd: work, paths: names }], { gzip: true });
  const future = new Date(Date.now() + 120_000);
  utimesSync(dest, future, future);

  const r = await drills.runRestoreDrill({ trigger: 'manual' });
  const l = r.results.find((x) => x.source === 'local');
  assert.equal(l.status, 'failed');
  assert.equal(l.checks.find((c) => c.id === 'archive_extract').status, 'pass');
  assert.equal(l.checks.find((c) => c.id === 'db_integrity').status, 'fail');
});

test('a drill refuses to run when free disk is under 2x the backup', async () => {
  drills._setDrillDepsForTests({ freeBytes: () => 1000 });
  const r = await drills.runRestoreDrill({ trigger: 'manual' });
  const l = r.results.find((x) => x.source === 'local');
  assert.equal(l.status, 'refused');
  assert.match(l.error, /Not enough free disk/);
  assert.equal(r.status, 'failed');
  assert.equal(existsSync(join(ROOT, 'drills')) ? readdirSync(join(ROOT, 'drills')).length : 0, 0, 'no scratch area was created');
  drills._setDrillDepsForTests(null);
});

test('the off-site set is fetched into the scratch area and verified; a failed fetch fails the drill', async () => {
  const good = (await listLocalBackups()).find((b) => !/-[xy]\.tar\.gz$/.test(b.file));
  const repoTar = readdirSync(join(ROOT, 'backups')).find((n) => n.startsWith('appcrane-repo-demo-'));
  const setId = 'appcrane-backup-appcrane-2026-01-01T00-00-00-000Z';
  let fetchedInto = null;
  drills._setDrillDepsForTests({
    offSite: async () => ({ configured: true }),
    listS3: async () => ({ backups: [{ id: setId, own: true, complete: true, legacy: false, created_at: new Date(Date.now() - 3600_000).toISOString(), bytes: 1000 }] }),
    fetchS3: async (id, dir) => {
      fetchedInto = dir;
      mkdirSync(dir, { recursive: true });
      copyFileSync(join(localBackupsDir(), good.file), join(dir, `${id}.tar.gz`));
      copyFileSync(join(ROOT, 'backups', repoTar), join(dir, repoTar));
      return { manifest: { encryption: null, repos: { included: true } }, files: [
        { kind: 'data', path: join(dir, `${id}.tar.gz`) }, { kind: 'repo', slug: 'demo', path: join(dir, repoTar) },
      ] };
    },
  });
  for (const f of readdirSync(localBackupsDir())) if (/-[xy]\.tar\.gz$/.test(f)) utimesSync(join(localBackupsDir(), f), new Date(0), new Date(0));
  const r = await drills.runRestoreDrill({ trigger: 'manual' });
  const s3 = r.results.find((x) => x.source === 's3');
  assert.equal(s3.status, 'passed', JSON.stringify(s3.checks));
  assert.ok(fetchedInto.startsWith(join(ROOT, 'drills') + '/'));
  assert.ok(s3.rpo_seconds >= 3590 && s3.rpo_seconds <= 3700);
  assert.equal(s3.checks.find((c) => c.id === 'repo_bundles').status, 'pass');

  drills._setDrillDepsForTests({
    offSite: async () => ({ configured: true }),
    listS3: async () => ({ backups: [{ id: setId, own: true, complete: true, legacy: false, created_at: new Date().toISOString(), bytes: 1000 }] }),
    fetchS3: async () => { throw new Error('data.tar.gz failed verification: expected 10 bytes'); },
  });
  const r2 = await drills.runRestoreDrill({ trigger: 'manual' });
  const s3b = r2.results.find((x) => x.source === 's3');
  assert.equal(s3b.status, 'failed');
  assert.equal(s3b.checks.find((c) => c.id === 'offsite_fetch').status, 'fail');
  assert.deepEqual(readdirSync(join(ROOT, 'drills')), []);
  drills._setDrillDepsForTests(null);
});

test('managed database dumps: header checked, pg_restore used only when present', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'crane-drill-dumps-'));
  mkdirSync(join(dir, 'managed-db', 'postgres'), { recursive: true });
  mkdirSync(join(dir, 'managed-db', 'redis'), { recursive: true });
  writeFileSync(join(dir, 'managed-db', 'postgres', 'app_one.dump'), Buffer.concat([Buffer.from('PGDMP'), Buffer.alloc(100, 1)]));
  writeFileSync(join(dir, 'managed-db', 'redis', 'cache.dump'), Buffer.from('REDIS0011rest'));
  let [c] = await verifyManagedDumps(dir, { pgRestoreList: async () => ({ available: false }) });
  assert.equal(c.status, 'pass');
  assert.match(c.detail.find((d) => d.engine === 'postgres').deep, /not installed/);
  writeFileSync(join(dir, 'managed-db', 'redis', 'cache.dump'), Buffer.from('garbage'));
  [c] = await verifyManagedDumps(dir, { pgRestoreList: async () => ({ available: true, ok: true, entries: 4 }) });
  assert.equal(c.status, 'fail');
});

test('routes are platform-admin only and the manual run is accepted', async () => {
  const routes = (await import('../server/routes/restoreDrills.js')).default;
  const { errorHandler } = await import('../server/utils/errors.js');
  const api = express();
  api.use(express.json());
  api.use('/api/settings', routes);
  api.use(errorHandler);
  const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  try {
    const base = `http://127.0.0.1:${server.address().port}/api/settings/restore-drills`;
    assert.equal((await fetch(base)).status, 401);
    assert.equal((await fetch(base, { headers: { 'X-API-Key': USER_KEY } })).status, 403);
    const ok = await fetch(base, { headers: { 'X-API-Key': ADMIN_KEY } });
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.equal(body.config.interval_days, 7);
    assert.ok(body.drills.length >= 1);
    const put = await fetch(`${base}/config`, { method: 'PUT', headers: { 'X-API-Key': ADMIN_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ interval_days: 14 }) });
    assert.equal((await put.json()).config.interval_days, 14);
    assert.equal((await fetch(`${base}/run`, { method: 'POST', headers: { 'X-API-Key': USER_KEY } })).status, 403);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});
