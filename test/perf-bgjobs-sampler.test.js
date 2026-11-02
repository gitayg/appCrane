import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Background jobs ask Docker once per tick, not once per app: the metrics
// sampler reads every running container from one ps + inspect + stats, and
// memory admission, CPU admission and the host monitor share one cached
// snapshot. Docker is a PATH shim that logs each invocation.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-perf-bgjobs-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync, readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv[0] + "\\n");\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) if (r.match.every(t => argv.includes(t)) && (!r.name || argv.includes(r.name))) { setTimeout(() => { process.stdout.write(r.stdout || ""); process.exit(r.code || 0); }, r.delay || 0); return; }\n' +
  'process.exit(1);\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const MiB = 1024 * 1024;
const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const snap = await import('../server/services/dockerSnapshot.js');
const { sampleMetricsOnce } = await import('../server/services/metricsSampler.js');
const cpu = await import('../server/services/cpuAdmission.js');
const mem = await import('../server/services/memoryAdmission.js');

const calls = () => (existsSync(ARGV_LOG) ? readFileSync(ARGV_LOG, 'utf8').split('\n').filter(Boolean) : []);

const APPS = 20;
const slugs = [];
for (let i = 0; i < APPS; i++) {
  const slug = `perf${i}`;
  db.prepare('INSERT INTO apps (name, slug, slot, source_type, image_ref) VALUES (?, ?, ?, ?, ?)').run(slug, slug, 700 + i, 'image', 'nginx:1');
  slugs.push(slug);
}

// Every app runs production; even apps also run sandbox; perf1-sandbox is exited.
const containers = [];
for (const [i, slug] of slugs.entries()) {
  containers.push({ name: `appcrane-${slug}-production`, status: 'running', cpu: `${i}.5%`, mem: `${10 + i}MiB / 1GiB` });
  if (i % 2 === 0) containers.push({ name: `appcrane-${slug}-sandbox`, status: 'running', cpu: '1.25%', mem: '1.5GiB / 4GiB' });
}
containers.push({ name: 'appcrane-perf1-sandbox', status: 'exited' });

function host({ delay = 0 } = {}) {
  const line = (c) => [`/${c.name}`, c.status, 1, '2026-11-01T00:00:00Z', 0, 512 * MiB, 256 * MiB, 5e8, 0, 0, 128,
    JSON.stringify({ appcrane: 'true', slug: c.name.split('-')[1], env: c.name.split('-')[2] }), 'nginx:1'].join('\t');
  writeFileSync(RULES, JSON.stringify([
    { match: ['info'], stdout: `4\t${8192 * MiB}\t/var/lib/docker\n`, delay },
    { match: ['ps', '-q'], stdout: containers.map((_, i) => `id${i}`).join('\n') + '\n', delay },
    { match: ['inspect', snap.SNAPSHOT_INSPECT_FORMAT], stdout: containers.map(line).join('\n') + '\n', delay },
    { match: ['stats', '--no-stream'], stdout: containers.filter((c) => c.status === 'running').map((c) => `${c.name}\t${c.cpu}\t${c.mem}`).join('\n') + '\n', delay },
  ]));
}

beforeEach(() => {
  snap._resetDockerSnapshotForTests();
  cpu._resetCpuAdmissionForTests();
  mem._resetMemoryAdmissionForTests();
  if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG);
  db.prepare('DELETE FROM metrics_history').run();
});

test('one sampler tick is three docker processes for 20 apps, and stores what getProcessMetrics reported', async () => {
  host();
  await sampleMetricsOnce();
  assert.deepEqual(calls().sort(), ['inspect', 'ps', 'stats'], `docker calls: ${calls().join(', ')}`);
  const rows = db.prepare('SELECT a.slug, m.env, m.cpu_percent, m.mem_mb FROM metrics_history m JOIN apps a ON a.id = m.app_id ORDER BY a.id, m.env').all();
  assert.equal(rows.length, APPS + APPS / 2, 'every running app-env, and not the exited one');
  assert.ok(!rows.some((r) => r.slug === 'perf1' && r.env === 'sandbox'));
  const p3 = rows.find((r) => r.slug === 'perf3' && r.env === 'production');
  assert.equal(p3.cpu_percent, 3.5);
  assert.equal(p3.mem_mb, 13 * MiB, 'same value and unit (bytes) as getProcessMetrics().memory');
  const s0 = rows.find((r) => r.slug === 'perf0' && r.env === 'sandbox');
  assert.equal(s0.mem_mb, Math.round(1.5 * 1024 * MiB));
});

test('a sampler tick when Docker does not answer stores nothing and does not throw', async () => {
  writeFileSync(RULES, '[]');
  await sampleMetricsOnce();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM metrics_history').get().n, 0);
});

test('memory admission, CPU admission and the host disk lookup at once share one info, one ps and one inspect', async () => {
  host({ delay: 150 });
  const hr = await import('../server/services/hostResources.js');
  await Promise.all([cpu.measureCpu(), mem.measureMemory(), mem.measureMemory(), cpu.measureCpu(), hr.checkDiskHeadroom()]);
  const c = calls();
  assert.equal(c.filter((x) => x === 'info').length, 1, c.join(', '));
  assert.equal(c.filter((x) => x === 'ps').length, 1, c.join(', '));
  assert.equal(c.filter((x) => x === 'inspect').length, 1, c.join(', '));
  const m = await mem.measureMemory();
  assert.equal(m.totalBytes, 8192 * MiB);
  assert.equal(m.committedBytes, 256 * MiB * (containers.length), 'each counted at its reservation');
  assert.equal((await cpu.measureCpu()).committedCores, 0.5 * containers.length);
  assert.equal(calls().length, c.length, 'within the TTL nothing more is asked');
});

test('a container start invalidates the snapshot: a read in flight at the start is not cached, the next check sees the new container', async () => {
  host({ delay: 150 });
  const inFlight = cpu.measureCpu();
  while (!calls().includes('ps')) await new Promise((r) => setTimeout(r, 5));
  containers.push({ name: 'appcrane-new-production', status: 'running', cpu: '0%', mem: '1MiB / 1GiB' });
  mem.reserveMemory('appcrane-new-production', 256 * MiB)();
  await inFlight;
  host();
  const after = await cpu.measureCpu();
  containers.pop();
  assert.equal(calls().filter((x) => x === 'ps').length, 2, 'asked Docker again after the start');
  assert.ok(after.containers.some((c) => c.name === 'appcrane-new-production'));
});
