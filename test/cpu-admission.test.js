import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// CPU admission: the sum of running containers' --cpus caps plus the new one
// against host cores minus a reserve. warn (default) starts and tells the
// platform admins, refuse throws INSUFFICIENT_CPU, off measures nothing.
// Docker is a PATH shim whose `info`, `ps` and `inspect` answers script the host.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-cpu-admission-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync, readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.join(" ") + "\\n");\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) if (r.match.every(t => argv.includes(t))) { process.stdout.write(r.stdout || ""); process.exit(r.code || 0); }\n' +
  'process.exit(1);\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const cpu = await import('../server/services/cpuAdmission.js');
const { admitContainer } = await import('../server/services/memoryAdmission.js');

const NANO = 1e9;
const labels = (o) => JSON.stringify(o);
function host({ ncpu = 2, containers = [] }) {
  const ids = containers.map((_, i) => `id${i}`).join('\n');
  const lines = containers.map((c) => [`/${c.name}`, Math.round((c.cpus || 0) * NANO), 0, 0, c.shares ?? 128, labels(c.labels || { appcrane: 'true', slug: c.name, env: 'production' })].join('\t')).join('\n');
  writeFileSync(RULES, JSON.stringify([
    { match: ['info'], stdout: `${ncpu}\n` },
    { match: ['ps', '-q'], stdout: ids ? `${ids}\n` : '' },
    { match: ['inspect'], stdout: lines ? `${lines}\n` : '' },
  ]));
}
// ratio 1 (caps may total no more than capacity) for the tests of the
// arithmetic; the default over-commit has its own tests below.
function setMode(mode, reserve = null, ratio = 1) {
  db.prepare("DELETE FROM settings WHERE key IN ('cpu_admission_mode', 'cpu_reserve_cores', 'cpu_overcommit_ratio', 'memory_admission_mode')").run();
  if (ratio !== null) db.prepare("INSERT INTO settings (key, value) VALUES ('cpu_overcommit_ratio', ?)").run(String(ratio));
  db.prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
  if (mode) db.prepare("INSERT INTO settings (key, value) VALUES ('cpu_admission_mode', ?)").run(mode);
  if (reserve !== null) db.prepare("INSERT INTO settings (key, value) VALUES ('cpu_reserve_cores', ?)").run(String(reserve));
}

beforeEach(() => {
  cpu._resetCpuAdmissionForTests();
  setMode(null);
});

test('default reserve is 0.5 core or 25%, whichever is larger', () => {
  assert.equal(cpu.defaultReserveCores(1), 0.5);
  assert.equal(cpu.defaultReserveCores(2), 0.5);
  assert.equal(cpu.defaultReserveCores(16), 4);
  assert.equal(cpu.getCpuAdmissionSettings(db).mode, 'warn', 'warn is the default');
});

test('measurement: committed is the sum of caps, an uncapped container counts 0 and is flagged', async () => {
  host({ ncpu: 2, containers: [{ name: 'a', cpus: 0.5 }, { name: 'b', cpus: 1 }, { name: 'db', cpus: 0, shares: 0, labels: { appcrane: 'true', 'appcrane-db': 'postgres' } }] });
  const m = await cpu.measureCpu({ fresh: true });
  assert.equal(m.error, null);
  assert.equal(m.cores, 2);
  assert.equal(m.capacityCores, 1.5);
  assert.equal(m.committedCores, 1.5);
  assert.deepEqual(m.containers.filter((c) => c.uncapped).map((c) => c.name), ['db']);
  assert.deepEqual(cpu.containersWithoutWeight(m).map((c) => c.name), ['db'], 'the database at the default weight is listed');
});

test('decide: fits, does not fit, and a start that does not raise the total is always allowed', () => {
  const measurement = { capacityCores: 1.5, committedCores: 1.5, containers: [{ name: 'appcrane-x-production', cores: 0.5 }, { name: 'other', cores: 1 }] };
  const fresh = cpu.decideCpu({ measurement, name: 'appcrane-new-production', newCores: 0.5 });
  assert.equal(fresh.allowed, false);
  assert.equal(fresh.afterCores, 2);
  const redeploy = cpu.decideCpu({ measurement, name: 'appcrane-x-production', newCores: 0.5 });
  assert.equal(redeploy.allowed, true, 'same-size redeploy');
  assert.equal(redeploy.notRaising, true);
  const roomy = cpu.decideCpu({ measurement: { ...measurement, capacityCores: 3 }, name: 'n', newCores: 1 });
  assert.equal(roomy.allowed, true);
  assert.equal(roomy.fits, true);
});

test('warn mode: starts, returns the warning, tells admins once', async () => {
  setMode('warn');
  host({ ncpu: 2, containers: [{ name: 'a', cpus: 1 }, { name: 'b', cpus: 0.5 }] });
  const told = [];
  const r = await cpu.admitCpu({ name: 'appcrane-new-production', cpus: 0.5, slug: 'new', env: 'production', notifyCpu: async (n) => told.push(n) });
  assert.equal(r.allowed, true);
  assert.equal(r.warned, true);
  assert.match(r.message, /CPU warning: .*asks for 0\.5 CPU, 0 is free \(1\.5 of 1\.5 CPU of caps allowed: 1\.5 CPU capacity x 1\)/);
  assert.equal(told.length, 1);
  assert.equal(told[0].outcome, 'warned');
});

test('refuse mode: throws INSUFFICIENT_CPU and tells admins', async () => {
  setMode('refuse');
  host({ ncpu: 2, containers: [{ name: 'a', cpus: 1.5 }] });
  const told = [];
  await assert.rejects(
    cpu.admitCpu({ name: 'appcrane-new-production', cpus: 0.5, slug: 'new', env: 'production', notifyCpu: async (n) => told.push(n) }),
    (e) => e.code === 'INSUFFICIENT_CPU' && e.status === 409 && /Not enough CPU/.test(e.message),
  );
  assert.equal(told[0].outcome, 'refused');
});

test('off mode: no measurement at all', async () => {
  setMode('off');
  writeFileSync(ARGV_LOG, '');
  host({ ncpu: 2, containers: [{ name: 'a', cpus: 2 }] });
  const r = await cpu.admitCpu({ name: 'n', cpus: 4 });
  assert.equal(r.skipped, true);
  assert.equal((await import('fs')).readFileSync(ARGV_LOG, 'utf8'), '', 'docker was never asked');
});

test('a measurement that fails admits the start', async () => {
  setMode('refuse');
  writeFileSync(RULES, JSON.stringify([{ match: ['info'], stdout: '2\n' }]));
  const r = await cpu.admitCpu({ name: 'n', cpus: 1 });
  assert.equal(r.allowed, true);
  assert.equal(r.unknown, true);
});

test('the reserve setting is honoured', async () => {
  setMode('refuse', 1.5);
  host({ ncpu: 2, containers: [] });
  await assert.rejects(cpu.admitCpu({ name: 'n', cpus: 1 }), /0\.5 is free/);
});

test('admitContainer runs CPU admission when cpus is given (the hook every start path uses)', async () => {
  setMode('refuse');
  host({ ncpu: 2, containers: [{ name: 'a', cpus: 1.5 }] });
  await assert.rejects(admitContainer({ name: 'appcrane-z-production', memoryMb: 256, cpus: 1, kind: 'app', slug: 'z', env: 'production' }), { code: 'INSUFFICIENT_CPU' });
  cpu._resetCpuAdmissionForTests();
  const ok = await admitContainer({ name: 'appcrane-z-production', memoryMb: 256, kind: 'app', slug: 'z', env: 'production' });
  assert.equal(ok.cpu, undefined, 'no cpus, no CPU check');
});

// The default. CPU caps are ceilings and CPU is compressible: an app capped at
// 1 CPU uses nothing while idle, and under contention the --cpu-shares weights
// (cpuPriority.js) decide who runs, with the host services far ahead. Holding
// the sum of ceilings to the host's cores warned on every deploy of a normal
// host (crane.glick.run, 2026-10-28: 8 cores, 2 reserved, 8.9 CPU of caps; 235
// warnings and e-mails in a week), and stood in the way of giving an app room
// to burst. The sum may now reach capacity times cpu_overcommit_ratio, 4 by
// default.

test('default over-commit: caps may total 4x capacity, so the measured host is quiet', async () => {
  setMode('warn', null, null);
  assert.equal(cpu.getCpuAdmissionSettings(db).overcommitRatio, 4);
  // crane.glick.run as measured: 8 cores, default reserve 2, 8.9 CPU of caps.
  host({ ncpu: 8, containers: [{ name: 'a', cpus: 4 }, { name: 'b', cpus: 4 }, { name: 'c', cpus: 0.9 }] });
  const told = [];
  const r = await cpu.admitCpu({ name: 'appcrane-new-production', cpus: 0.5, slug: 'new', env: 'production', notifyCpu: async (n) => told.push(n) });
  assert.equal(r.warned, false, r.message);
  assert.equal(told.length, 0, 'no e-mail');
  const roomy = await cpu.admitCpu({ name: 'appcrane-burst-production', cpus: 8, slug: 'burst', env: 'production', notifyCpu: async (n) => told.push(n) });
  assert.equal(roomy.warned, false, 'an app may be capped at every core of the host');
});

test('past the over-commit limit it still warns, and says what the limit is', async () => {
  setMode('warn', null, null);
  host({ ncpu: 2, containers: [{ name: 'a', cpus: 2 }, { name: 'b', cpus: 2 }] }); // capacity 1.5, limit 6
  const told = [];
  const ok = await cpu.admitCpu({ name: 'appcrane-c-production', cpus: 2, slug: 'c', env: 'production', notifyCpu: async (n) => told.push(n) });
  assert.equal(ok.warned, false, '6 of 6');
  cpu._resetCpuAdmissionForTests();
  const over = await cpu.admitCpu({ name: 'appcrane-d-production', cpus: 2.5, slug: 'd', env: 'production', notifyCpu: async (n) => told.push(n) });
  assert.equal(over.warned, true);
  assert.match(over.message, /asks for 2\.5 CPU, 2 is free \(4 of 6 CPU of caps allowed: 1\.5 CPU capacity x 4\)/);
});

test('the over-commit setting is honoured, and nonsense falls back to the default', async () => {
  setMode('refuse', null, 2);
  host({ ncpu: 2, containers: [{ name: 'a', cpus: 2.5 }] }); // capacity 1.5, limit 3
  await assert.rejects(cpu.admitCpu({ name: 'n', cpus: 1 }), /0\.5 is free/);
  for (const bad of ['0', '0.5', '-1', 'x', '']) {
    setMode('warn', null, bad);
    assert.equal(cpu.getCpuAdmissionSettings(db).overcommitRatio, 4, bad);
  }
});

test('Settings > Server capacity: shows the allowance, saves the ratio, refuses nonsense', async () => {
  const express = (await import('express')).default;
  const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
  const { errorHandler } = await import('../server/utils/errors.js');
  const key = generateApiKey('dhk_user');
  db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('cpuadm','cpuadm@acme.test','platform_admin',1,?)").run(hashApiKey(key));
  const a = express();
  a.use(express.json());
  a.use('/api/settings', (await import('../server/routes/jobHealth.js')).default);
  a.use(errorHandler);
  const s = await new Promise((r) => { const x = a.listen(0, '127.0.0.1', () => r(x)); });
  const base = `http://127.0.0.1:${s.address().port}/api/settings/server-capacity`;
  const call = (method, body) => fetch(base, { method, headers: { 'x-api-key': key, 'content-type': 'application/json' }, body: body && JSON.stringify(body) });
  try {
    setMode('warn', null, null);
    host({ ncpu: 2, containers: [{ name: 'a', cpus: 1 }] });
    const got = await (await call('GET')).json();
    assert.equal(got.cpu.overcommit_ratio, 4);
    assert.equal(got.cpu.limit_cores, 6);
    assert.equal(got.settings.cpu.overcommitRatio, 4);
    const put = await call('PUT', { cpu_overcommit_ratio: 2.5 });
    assert.equal(put.status, 200);
    assert.equal(cpu.getCpuAdmissionSettings(db).overcommitRatio, 2.5);
    assert.equal((await call('PUT', { cpu_overcommit_ratio: 0.5 })).status, 400);
    assert.equal(cpu.getCpuAdmissionSettings(db).overcommitRatio, 2.5, 'a refused write changes nothing');
    assert.equal((await call('PUT', { cpu_overcommit_ratio: null })).status, 200);
    assert.equal(cpu.getCpuAdmissionSettings(db).overcommitRatio, 4, 'null goes back to the default');
  } finally {
    s.closeAllConnections?.(); s.close();
  }
});
