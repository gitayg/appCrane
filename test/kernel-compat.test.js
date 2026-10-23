import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';

const execFileAsync = promisify(execFile);

// MongoDB 8.0 stops at startup on Linux 6.19 through 7.0.13 (its 8.0 release
// notes). AppCrane refuses before starting it, names the kernel, stops waiting
// as soon as a database container has exited, and reports the host in Job
// Health and on the managed-database status.

const SUFFIX = crypto.randomBytes(4).toString('hex');
const PREFIX = `crane-kctest-${SUFFIX}`;
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-kc-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.MANAGED_DB_CONTAINER_PREFIX = PREFIX;
delete process.env.MANAGED_DB_MONGO_SKIP_KERNEL_CHECK;

let dockerOk = false;
try {
  execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'pipe' });
  dockerOk = true;
} catch (_) { /* left false */ }
const noDocker = dockerOk ? false : 'no reachable Docker daemon on this host';

const { initDb, getDb } = await import('../server/db.js');
const kc = await import('../server/services/kernelCompat.js');
const mdb = await import('../server/services/managedDb.js');
const jh = await import('../server/services/jobHealth.js');
const { runMongoKernelCheck } = await import('../server/services/mongoKernelCheck.js');

const created = [];
before(() => initDb(process.env.DATA_DIR));
after(async () => {
  kc._setKernelSourceForTests(null);
  for (const name of created) await execFileAsync('docker', ['rm', '-f', name]).catch(() => {});
  try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {}
});

test('kernel range: 6.19.0 through 7.0.13 is incompatible, everything else is not, garbage is unknown', () => {
  const table = [
    ['6.18.0', 'compatible'],
    ['6.18.19-generic', 'compatible'],
    ['6.12.76-linuxkit', 'compatible'],
    ['6.8.0-1017-azure', 'compatible'],
    ['6.19', 'incompatible'],
    ['6.19.0', 'incompatible'],
    ['6.19.3', 'incompatible'],
    ['7.0.0-1017-azure', 'incompatible'],
    ['7.0.0-38-generic', 'incompatible'],
    ['7.0.13-foo', 'incompatible'],
    ['7.0.14', 'compatible'],
    ['7.0.14-arch1-1', 'compatible'],
    ['7.1', 'compatible'],
    ['7.1.0', 'compatible'],
    ['5.15.0', 'compatible'],
    ['', 'unknown'],
    ['garbage', 'unknown'],
    [null, 'unknown'],
    [undefined, 'unknown'],
  ];
  for (const [release, want] of table) {
    assert.equal(kc.mongoKernelStatus(release), want, `${release}`);
  }
  assert.deepEqual(kc.parseKernelVersion('7.0.0-1017-azure'), [7, 0, 0]);
});

test('the message is the agreed wording with the kernel in it', () => {
  assert.equal(
    kc.mongoKernelMessage('7.0.0-1017-azure'),
    "MongoDB 8.0 can't run on this server's kernel (7.0.0-1017-azure); upgrade to Linux 7.0.14 or later",
  );
});

test('only MongoDB 8 and later images are pre-checked', () => {
  assert.equal(kc.imageHasKernelCheck('mongo:8.0'), true);
  assert.equal(kc.imageHasKernelCheck('mongo:8.0.34-noble'), true);
  assert.equal(kc.imageHasKernelCheck('registry.example.test:5000/mongo:9'), true);
  assert.equal(kc.imageHasKernelCheck('mongo'), true);
  assert.equal(kc.imageHasKernelCheck('mongo:latest'), true);
  assert.equal(kc.imageHasKernelCheck('mongo:7.0'), false);
  assert.equal(kc.imageHasKernelCheck('mongo:6.0.20'), false);
});

test('provisioning mongo on an affected kernel refuses before anything starts, with the exact message', async () => {
  kc._setKernelSourceForTests(async () => '7.0.0-1017-azure');
  try {
    const appId = Number(getDb().prepare('INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)').run('KC', `kc-${SUFFIX}`, 951).lastInsertRowid);
    const t0 = Date.now();
    await assert.rejects(mdb.provision({ appId }, 'mongo'), (e) => {
      assert.equal(e.code, 'MONGO_KERNEL_INCOMPATIBLE');
      assert.equal(e.message, "MongoDB 8.0 can't run on this server's kernel (7.0.0-1017-azure); upgrade to Linux 7.0.14 or later");
      return true;
    });
    assert.ok(Date.now() - t0 < 5000, 'refused at once');
    assert.equal(getDb().prepare("SELECT COUNT(*) AS n FROM managed_databases WHERE engine = 'mongo'").get().n, 0);
    assert.equal(getDb().prepare("SELECT COUNT(*) AS n FROM managed_db_servers WHERE engine = 'mongo'").get().n, 0);
    await assert.rejects(mdb.ensureServer('mongo'), { code: 'MONGO_KERNEL_INCOMPATIBLE' });
  } finally {
    kc._setKernelSourceForTests(null);
  }
});

test('an unknown kernel does not block (mongod still decides)', async () => {
  kc._setKernelSourceForTests(async () => { throw new Error('Cannot connect to the Docker daemon'); });
  try {
    const c = await kc.dockerHostMongoCompat({ fresh: true });
    assert.equal(c.status, 'unknown');
    await kc.assertMongoKernelCompatible('mongo:8.0');
  } finally {
    kc._setKernelSourceForTests(null);
  }
});

async function runExiting(name, script) {
  created.push(name);
  await execFileAsync('docker', ['rm', '-f', name]).catch(() => {});
  await execFileAsync('docker', ['run', '-d', '--name', name, '--restart=on-failure:2', 'alpine:3', 'sh', '-c', script], { timeout: 60000 });
}

test('waiting for a server stops as soon as its container has exited, with the exit code and the last log lines',
  { skip: noDocker, timeout: 60000 }, async () => {
  const name = `${PREFIX}-postgres`;
  await runExiting(name, 'echo "init: superuser password=S3cretPw0rdXYZ"; echo "FATAL: data directory has wrong ownership" >&2; exit 3');
  const t0 = Date.now();
  await assert.rejects(mdb._waitReadyForTests('postgres', 45432, { secrets: ['S3cretPw0rdXYZ'] }), (e) => {
    assert.match(e.message, /stopped with exit code 3 before it became ready/);
    assert.match(e.message, /data directory has wrong ownership/);
    assert.ok(!e.message.includes('S3cretPw0rdXYZ'), 'the secret is redacted');
    assert.match(e.message, /\[redacted\]/);
    return true;
  });
  const took = Date.now() - t0;
  assert.ok(took < 30000, `returned in ${took}ms, not the 120000ms timeout`);
});

test('a mongo container that stops with mongod\'s kernel refusal reports the kernel message',
  { skip: noDocker, timeout: 60000 }, async () => {
  kc._setKernelSourceForTests(async () => '7.0.0-1017-azure');
  try {
    const name = `${PREFIX}-mongo`;
    await runExiting(name, 'echo "MongoDB cannot start: Linux kernel versions 6.19 and newer has a known incompatibility with this version of MongoDB."; exit 14');
    await assert.rejects(mdb._waitReadyForTests('mongo', 47017), (e) => {
      assert.equal(e.code, 'MONGO_KERNEL_INCOMPATIBLE');
      assert.equal(e.message, "MongoDB 8.0 can't run on this server's kernel (7.0.0-1017-azure); upgrade to Linux 7.0.14 or later");
      return true;
    });
  } finally {
    kc._setKernelSourceForTests(null);
  }
});

test('Job Health warns on an affected kernel and is ok otherwise', async () => {
  jh._resetJobHealthForTests();
  jh.jobStarted('mongo-kernel');
  const find = () => jh.getJobHealth().find(j => j.id === 'mongo-kernel');
  try {
    kc._setKernelSourceForTests(async () => '6.19.3');
    await jh.trackJob('mongo-kernel', () => runMongoKernelCheck({ image: 'mongo:8.0' }));
    let j = find();
    assert.equal(j.status, 'warning');
    assert.equal(j.detail.status, 'incompatible');
    assert.equal(j.detail.message, "MongoDB 8.0 can't run on this server's kernel (6.19.3); upgrade to Linux 7.0.14 or later");

    kc._setKernelSourceForTests(async () => '7.0.14');
    await jh.trackJob('mongo-kernel', () => runMongoKernelCheck({ image: 'mongo:8.0' }));
    j = find();
    assert.equal(j.status, 'ok');
    assert.equal(j.detail.status, 'compatible');

    kc._setKernelSourceForTests(async () => 'garbage');
    await jh.trackJob('mongo-kernel', () => runMongoKernelCheck({ image: 'mongo:8.0' }));
    assert.equal(find().status, 'ok');
    assert.equal(find().detail.status, 'unknown');

    kc._setKernelSourceForTests(async () => '6.19.3');
    await jh.trackJob('mongo-kernel', () => runMongoKernelCheck({ image: 'mongo:7.0' }));
    assert.equal(find().status, 'ok');
    assert.equal(find().detail.status, 'not-applicable');
  } finally {
    kc._setKernelSourceForTests(null);
    jh._resetJobHealthForTests();
  }
});

test('the managed-database status reports the kernel check on the mongo row', async () => {
  kc._setKernelSourceForTests(async () => '7.0.0-1017-azure');
  try {
    const rows = await mdb.serverStatus();
    const m = rows.find(r => r.engine === 'mongo');
    assert.deepEqual(m.kernel_compat, {
      kernel: '7.0.0-1017-azure',
      status: 'incompatible',
      message: "MongoDB 8.0 can't run on this server's kernel (7.0.0-1017-azure); upgrade to Linux 7.0.14 or later",
    });
    assert.equal(rows.find(r => r.engine === 'postgres').kernel_compat, undefined);
  } finally {
    kc._setKernelSourceForTests(null);
  }
});

test('the live mongo tests skip by name on an affected Docker host kernel', { timeout: 120000 }, async () => {
  const env = { ...process.env, CRANE_TEST_DOCKER_KERNEL: '7.0.0-1017-azure' };
  delete env.NODE_TEST_CONTEXT;
  delete env.DATA_DIR;
  delete env.MANAGED_DB_CONTAINER_PREFIX;
  const t0 = Date.now();
  const r = await execFileAsync(process.execPath, ['--test', '--test-reporter=tap', 'test/managed-db-mongo.test.js'], { env, timeout: 110000, maxBuffer: 16 * 1024 * 1024 })
    .catch((e) => e);
  const out = String(r.stdout || '');
  assert.equal(r.code ?? 0, 0, out.slice(-3000));
  const skips = out.split('\n').filter(l => /# SKIP MongoDB 8\.0 can't run on this server's kernel \(7\.0\.0-1017-azure\)/.test(l));
  assert.equal(skips.length, 3, out.slice(-3000));
  assert.ok(Date.now() - t0 < 60000, 'no live server was waited for');
});
