import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The low-disk guard: a deploy refuses to start, before any build work, when a
// filesystem it writes to (DATA_DIR, Docker's data root) is at the critical
// level of the Job Health thresholds, and says which filesystem and how much is
// free. A rollback is not refused. Unit cases use an injected statfs; the deploy
// cases go through the real deployApp and the real statfs, with the floor raised
// above any real disk and a `docker` shim that records every call.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-diskguard-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(ROOT, 'bin');
const DOCKER_CALLS = join(ROOT, 'docker-calls.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
require('fs').appendFileSync(process.env.CRANE_DOCKER_CALLS, process.argv.slice(2).join(' ') + '\\n');
process.exit(1);
`, { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;
process.env.CRANE_DOCKER_CALLS = DOCKER_CALLS;
const dockerCalls = () => (existsSync(DOCKER_CALLS) ? readFileSync(DOCKER_CALLS, 'utf8').trim().split('\n').filter(Boolean) : []);

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { checkDiskHeadroom, assertDiskHeadroom } = await import('../server/services/hostResources.js');
const { deployApp } = await import('../server/services/deployer.js');

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const fs = (freeGb, totalGb = 100) => ({ bavail: freeGb * 256, bsize: 4 * MiB, blocks: totalGb * 256 });
function deps({ dataFree = 50, dockerFree = 50, sameDevice = false, statfsThrows = false } = {}) {
  return {
    dataDir: () => '/srv/crane-data',
    dockerRootDir: async () => '/var/lib/docker',
    deviceOf: (p) => (sameDevice || p === '/srv/crane-data' ? 1 : 2),
    statfs: (p) => {
      if (statfsThrows) throw new Error('statfs broke');
      return p === '/srv/crane-data' ? fs(dataFree) : fs(dockerFree);
    },
  };
}
const setSetting = (k, v) => db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
const clearSetting = (k) => db.prepare('DELETE FROM settings WHERE key = ?').run(k);
after(() => clearSetting('host_alert_disk_floor_gb'));

test('plenty of space on both filesystems: allowed', async () => {
  const r = await checkDiskHeadroom({ deps: deps() });
  assert.equal(r.ok, true);
  assert.equal(r.filesystems.length, 2);
});

test('DATA_DIR below the 5 GB floor: refused with the filesystem and its free space named', async () => {
  await assert.rejects(assertDiskHeadroom('deploy demo/sandbox', { deps: deps({ dataFree: 4 }) }), (e) => {
    assert.equal(e.code, 'DISK_LOW');
    assert.equal(e.status, 507);
    assert.equal(e.message,
      'Refusing to deploy demo/sandbox: the filesystem holding DATA_DIR (/srv/crane-data) has 4.0 GB free of 100.0 GB (4.0%), '
      + 'below the floor of 5 GB. Free space on that filesystem (old images, backups, logs) and retry; '
      + 'the floor is set in Settings > Job Health.');
    return true;
  });
});

test('the percent rule does not refuse: 90 GB free on a 2 TB disk (4.4%) is allowed', async () => {
  const r = await checkDiskHeadroom({ deps: { ...deps(), statfs: () => fs(90, 2048) } });
  assert.equal(r.ok, true, JSON.stringify(r.blocked));
});

test('the absolute floor is the platform setting', async () => {
  setSetting('host_alert_disk_floor_gb', '60');
  try {
    assert.equal((await checkDiskHeadroom({ deps: deps({ dataFree: 50 }) })).ok, false);
  } finally { clearSetting('host_alert_disk_floor_gb'); }
});

test('the Docker data root is checked too', async () => {
  const r = await checkDiskHeadroom({ deps: deps({ dockerFree: 3 }) });
  assert.equal(r.ok, false);
  assert.deepEqual(r.blocked.map((f) => f.path), ['/var/lib/docker']);
});

test('one filesystem holding both is checked once and named for both', async () => {
  const r = await checkDiskHeadroom({ deps: deps({ sameDevice: true, dataFree: 2 }) });
  assert.equal(r.filesystems.length, 1);
  assert.deepEqual(r.blocked[0].names, ['DATA_DIR', 'Docker data root']);
});

test('need: space the action will write is subtracted before the floor is applied', async () => {
  assert.equal((await checkDiskHeadroom({ deps: deps({ dataFree: 7 }) })).ok, true);
  assert.equal((await checkDiskHeadroom({ deps: deps({ dataFree: 7 }), need: 3 * GiB })).ok, false);
});

test('a filesystem that cannot be read is unknown and does not block', async () => {
  const r = await checkDiskHeadroom({ deps: deps({ statfsThrows: true }) });
  assert.equal(r.ok, true);
  assert.ok(r.filesystems.every((f) => f.level === 'unknown'));
});

db.prepare("INSERT INTO apps (name, slug, slot, source_type, image_ref, container_port) VALUES ('Disk App', 'diskapp', 43, 'image', 'nginx:1', 80)").run();
const app = db.prepare("SELECT * FROM apps WHERE slug = 'diskapp'").get();
const newDeploy = () => db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'sandbox', 'pending')").run(app.id).lastInsertRowid;

test('a deploy on a disk under the floor is refused before any build work, and the row says why', async () => {
  setSetting('host_alert_disk_floor_gb', '1000000');
  const id = newDeploy();
  const before = dockerCalls().length;
  await assert.rejects(deployApp(id, app, 'sandbox', { sand_be: 1, prod_be: 2 }), (e) => e.code === 'DISK_LOW');
  const row = db.prepare('SELECT status, failure_reason FROM deployments WHERE id = ?').get(id);
  assert.equal(row.status, 'failed');
  assert.match(row.failure_reason, /^Refusing to deploy diskapp\/sandbox: the filesystem holding DATA_DIR \(.+\) has .+ free of .+, below the floor of 1000000 GB/);
  // Only the docker-root lookup ran; no pull, build, run or inspect.
  assert.deepEqual(dockerCalls().slice(before), ['info --format {{.DockerRootDir}}']);
});

test('deployApp writes its log through the quiet writer: start and failure reach the platform log at their levels', async () => {
  setSetting('host_alert_disk_floor_gb', '1000000');
  const log = (await import('../server/utils/logger.js')).default;
  const seen = { info: [], error: [] };
  const orig = { info: log.info, error: log.error };
  log.info = (m) => seen.info.push(m);
  log.error = (m) => seen.error.push(m);
  const id = newDeploy();
  try { await deployApp(id, app, 'sandbox', { sand_be: 1, prod_be: 2 }); } catch (_) {} finally { Object.assign(log, orig); }
  assert.ok(seen.info.includes(`[deploy:${id}] diskapp/sandbox started`), seen.info.join('\n'));
  assert.ok(seen.error.some((m) => m.startsWith(`[deploy:${id}] DEPLOY FAILED: Refusing to deploy diskapp/sandbox`)), seen.error.join('\n'));
  assert.ok(!seen.info.some((m) => m.startsWith(`[deploy:${id}] DEPLOY FAILED`)), 'the failure is logged once, at error, not echoed again at info');
});

test('a rollback is not refused on the same disk', async () => {
  setSetting('host_alert_disk_floor_gb', '1000000');
  const id = newDeploy();
  let err = null;
  try { await deployApp(id, app, 'sandbox', { sand_be: 1, prod_be: 2 }, { rollback: true, imageRef: 'nginx:1', releaseCheck: 'skip' }); } catch (e) { err = e; }
  assert.notEqual(err?.code, 'DISK_LOW', err?.message);
  assert.doesNotMatch(db.prepare('SELECT failure_reason FROM deployments WHERE id = ?').get(id).failure_reason || '', /Refusing to deploy/);
});

test('self-update is refused on a disk under the floor, and ?force=1 does not skip it', () => {
  const src = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
  const route = src.slice(src.indexOf("app.post('/api/self-update'"), src.indexOf("app.post('/api/self-update'") + 4000);
  const guard = route.indexOf("assertDiskHeadroom('self-update')");
  assert.ok(guard > 0, 'self-update route does not call the disk guard');
  const forceBlockEnd = route.indexOf('}', route.indexOf('if (!req.query.force)'));
  assert.ok(guard > forceBlockEnd, 'the disk guard sits inside the ?force=1 skip');
  assert.match(route, /e\.code === 'DISK_LOW'\) return res\.status\(507\)/);
});
