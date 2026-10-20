import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Server memory and disk through Job Health: thresholds decide the level, a
// warning or critical level e-mails platform admins (only) once per resource,
// level and 6-hour window, a recovery is mailed once, and a sample that cannot
// be read is "unknown" instead of an exception.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-host-res-'));
process.env.ENCRYPTION_KEY = 'h'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const hr = await import('../server/services/hostResources.js');
const { getJobHealth } = await import('../server/services/jobHealth.js');

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

let n = 0;
function user(role) {
  n++;
  db.prepare('INSERT INTO users (name, email, role, api_key_hash) VALUES (?,?,?,?)').run(`U${n}`, `u${n}@example.test`, role, `h${n}`);
  return `u${n}@example.test`;
}
const ADMIN_A = user('platform_admin');
const ADMIN_B = user('platform_admin');
const PLAIN = user('user');

const meminfo = (availMb, totalMb = 8192) => `MemTotal:       ${totalMb * 1024} kB\nMemFree:  1 kB\nMemAvailable:   ${availMb * 1024} kB\n`;

function deps({ availMb = 4096, diskFreeGb = 50, diskTotalGb = 100, committed = 2000, capacity = 7000, fail = false } = {}) {
  if (fail) {
    return {
      platform: 'linux',
      readFile: () => { throw new Error('EACCES /proc/meminfo'); },
      freemem: () => { throw new Error('no os'); }, totalmem: () => { throw new Error('no os'); },
      statfs: () => { throw new Error('statfs broke'); },
      deviceOf: () => { throw new Error('stat broke'); },
      dockerRootDir: async () => { throw new Error('docker down'); },
      measure: async () => { throw new Error('docker down'); },
      dataDir: () => '/data',
    };
  }
  return {
    platform: 'linux',
    readFile: () => meminfo(availMb),
    statfs: () => ({ bavail: diskFreeGb * 256, bsize: 4 * MiB, blocks: diskTotalGb * 256 }),
    deviceOf: () => 42,
    dockerRootDir: async () => '/var/lib/docker',
    measure: async () => ({ committedBytes: committed * MiB, capacityBytes: capacity * MiB, totalBytes: 8192 * MiB, reserveBytes: 1024 * MiB, totalSource: 'docker' }),
    dataDir: () => '/data',
  };
}

function mails() {
  return db.prepare("SELECT to_email, subject, idempotency_key FROM email_queue WHERE source = 'host-resources' ORDER BY id").all();
}

beforeEach(() => {
  hr._resetHostResourcesForTests();
  db.prepare("DELETE FROM email_queue WHERE source = 'host-resources'").run();
  db.prepare("DELETE FROM settings WHERE key LIKE 'host_alert_%'").run();
});

test('thresholds decide ok / warning / critical / unknown', () => {
  const t = { warnPct: 10, critPct: 5, floorBytes: 512 * MiB };
  assert.equal(hr.levelFor({ freeBytes: 2 * GiB, totalBytes: 8 * GiB }, t), 'ok');
  assert.equal(hr.levelFor({ freeBytes: 0.7 * GiB, totalBytes: 8 * GiB }, t), 'warning');
  assert.equal(hr.levelFor({ freeBytes: 0.35 * GiB, totalBytes: 8 * GiB }, t), 'critical', 'below 5%');
  assert.equal(hr.levelFor({ freeBytes: 500 * MiB, totalBytes: 2 * GiB }, t), 'critical', 'below the 512 MB floor at 24%');
  assert.equal(hr.levelFor({ freeBytes: NaN, totalBytes: 8 * GiB }, t), 'unknown');
  assert.deepEqual(hr.parseMeminfo(meminfo(1000, 4000)), { availableBytes: 1000 * 1024 * 1024, totalBytes: 4000 * 1024 * 1024 });
});

test('settings override the thresholds', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('host_alert_mem_warn_pct', '60')").run();
  const { sample } = await hr.runHostCheck({ deps: deps({ availMb: 4000 }) });
  assert.equal(sample.resources.find(r => r.id === 'memory').level, 'warning');
});

test('healthy host: all ok, nothing mailed, the sample is on the Job Health row', async () => {
  const { sample, mailed } = await hr.runHostCheck({ deps: deps() });
  assert.equal(sample.overall, 'ok');
  assert.deepEqual(mailed, []);
  const disks = sample.resources.filter(r => r.id.startsWith('disk:'));
  assert.equal(disks.length, 1, 'three paths on one device are one filesystem');
  assert.equal(disks[0].label, 'Disk free (DATA_DIR, Docker data root, root filesystem)');
  const row = getJobHealth().find(j => j.id === 'host-resources');
  assert.equal(row.label, 'Server memory and disk check');
  assert.equal(row.detail.overall, 'ok');
});

test('critical memory e-mails every platform admin once per window, and nobody else', async () => {
  const now = Date.UTC(2026, 9, 20, 1, 0, 0);
  const r1 = await hr.runHostCheck({ deps: deps({ availMb: 300 }), now });
  await hr.runHostCheck({ deps: deps({ availMb: 300 }), now: now + 60 * 60_000 });
  assert.equal(r1.sample.resources.find(r => r.id === 'memory').level, 'critical');
  const rows = mails();
  assert.deepEqual(rows.map(r => r.to_email).sort(), [ADMIN_A, ADMIN_B].sort());
  assert.ok(!rows.some(r => r.to_email === PLAIN));
  assert.match(rows[0].subject, /Server critical: Memory available/);

  await hr.runHostCheck({ deps: deps({ availMb: 300 }), now: now + 6 * 60 * 60_000 });
  assert.equal(mails().length, 4, 'a reminder in the next 6-hour window');
});

test('over-committed memory and low disk are warnings; recovery is mailed once', async () => {
  const now = Date.UTC(2026, 9, 20, 7, 0, 0);
  const { sample } = await hr.runHostCheck({ deps: deps({ committed: 9000, capacity: 7000, diskFreeGb: 8, diskTotalGb: 100 }), now });
  assert.equal(sample.resources.find(r => r.id === 'committed').level, 'warning');
  assert.equal(sample.resources.find(r => r.id.startsWith('disk:')).level, 'warning');
  assert.equal(sample.overall, 'warning');
  assert.equal(mails().length, 4, 'two resources x two admins');

  db.prepare("DELETE FROM email_queue WHERE source = 'host-resources'").run();
  await hr.runHostCheck({ deps: deps(), now: now + 5 * 60_000 });
  await hr.runHostCheck({ deps: deps(), now: now + 10 * 60_000 });
  const rows = mails();
  assert.equal(rows.length, 4, 'one recovery per resource per admin, not repeated');
  assert.ok(rows.every(r => /^\[AppCrane\] Recovered: /.test(r.subject)));
});

test('a sample that cannot be read is unknown, never throws and mails nothing', async () => {
  const { sample, mailed } = await hr.runHostCheck({ deps: deps({ fail: true }) });
  assert.equal(sample.overall, 'unknown');
  assert.ok(sample.resources.length >= 3);
  assert.ok(sample.resources.every(r => r.level === 'unknown'), JSON.stringify(sample.resources));
  assert.deepEqual(mailed, []);
  assert.equal(mails().length, 0);
});
