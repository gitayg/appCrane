import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir, totalmem } from 'os';
import { join } from 'path';

// Memory admission control: a container whose cap would push the sum of all
// running caps past the host's capacity is refused BEFORE the running one is
// touched. Docker is a recording PATH shim (the image-deploy.test.js pattern)
// whose answers to `docker info`, `ps`, `inspect` and `stats` script the host.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mem-admission-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const ARGV_LOG = join(process.env.DATA_DIR, 'docker-argv.log');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync, readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'appendFileSync(process.env.CRANE_TEST_DOCKER_LOG, argv.map(a => a + "\\n").join("") + "\\0");\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) {\n' +
  '  if (r.match.every(tok => argv.includes(tok))) {\n' +
  '    process.stdout.write(r.stdout || "");\n' +
  '    process.stderr.write(r.stderr || "");\n' +
  '    process.exit(r.code || 0);\n' +
  '  }\n' +
  '}\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 },
);
process.env.CRANE_TEST_DOCKER_LOG = ARGV_LOG;
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const adm = await import('../server/services/memoryAdmission.js');
const { notifyMemoryAdmission } = await import('../server/services/memoryAdmissionMail.js');
const docker = await import('../server/services/docker.js');
const deployer = await import('../server/services/deployer.js');
const appContainer = await import('../server/services/builder/appContainer.js');

/**
 * Script the host: total RAM (null = docker info fails), running containers
 * [{ name, mb, labels }] (mb 0 = no limit), and their usage (null = stats fails).
 */
function host({ totalMb = 4096, containers = [], usage = {}, statsFail = false }) {
  const ids = containers.map((_, i) => `id${i}`);
  writeFileSync(RULES, JSON.stringify([
    { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
    totalMb == null
      ? { match: ['info', '--format', '{{.MemTotal}}'], stderr: 'Cannot connect to the Docker daemon', code: 1 }
      : { match: ['info', '--format', '{{.MemTotal}}'], stdout: `${totalMb * MiB}\n` },
    { match: ['ps', '-q'], stdout: ids.join('\n') + (ids.length ? '\n' : '') },
    { match: ['inspect', adm.INSPECT_FORMAT], stdout: containers.map(c => `/${c.name}\t${c.mb * MiB}\t${JSON.stringify(c.labels || {})}\t${c.image || ''}`).join('\n') + '\n' },
    statsFail
      ? { match: ['stats', '--no-stream'], stderr: 'stats broke', code: 1 }
      : { match: ['stats', '--no-stream'], stdout: Object.entries(usage).map(([n, mb]) => `${n}\t${mb}MiB / 3.8GiB`).join('\n') + '\n' },
  ]));
}

function calls() {
  if (!existsSync(ARGV_LOG)) return [];
  return readFileSync(ARGV_LOG, 'utf8').split('\0').filter(r => r.trim()).map(r => r.split('\n').filter(Boolean));
}

function setSetting(key, value) {
  db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(key, value);
}

let n = 0;
function makeUser(role = 'user', kind = 'human') {
  n++;
  const id = db.prepare('INSERT INTO users (name, email, role, api_key_hash) VALUES (?,?,?,?)')
    .run(`User ${n}`, `user${n}@example.test`, role, `hash-${n}-${Math.random()}`).lastInsertRowid;
  if (kind !== 'human') db.prepare('UPDATE users SET kind = ? WHERE id = ?').run(kind, id);
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

let slot = 400;
function makeApp(slug, ramMb = 512, extra = {}) {
  const id = db.prepare(`INSERT INTO apps (name, slug, slot, source_type, image_ref, resource_limits) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(slug, slug, slot++, extra.source_type || 'image', 'nginx:1', JSON.stringify({ max_ram_mb: ramMb, max_cpu_percent: 50 })).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

const app = (slug, env) => ({ name: `appcrane-${slug}-${env}`, labels: { slug, env } });

function mailRows() {
  return db.prepare("SELECT to_email, subject, body_text, body_html, idempotency_key FROM email_queue WHERE source = 'memory-admission' ORDER BY id").all();
}

const ADMIN = makeUser('platform_admin');

beforeEach(() => {
  adm._resetMemoryAdmissionForTests();
  if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG);
  db.prepare("DELETE FROM email_queue WHERE source = 'memory-admission'").run();
  setSetting(adm.MODE_KEY, 'refuse');
  setSetting(adm.RESERVE_KEY, '0');
});

const startOpts = (slug, env, memoryMb, admission) => ({
  slug, env, image: 'nginx:1', hostPort: 39001, memoryMb, cpus: 0.5, ...(admission !== undefined ? { admission } : {}),
});

// ---------------------------------------------------------------- pure parts

test('parseMemUsage reads docker stats figures in binary and decimal units', () => {
  assert.equal(adm.parseMemUsage('100MiB / 7.6GiB'), 100 * MiB);
  assert.equal(adm.parseMemUsage('1.5GiB / 7.6GiB'), 1.5 * GiB);
  assert.equal(adm.parseMemUsage('2MB / 1GB'), 2e6);
  assert.equal(adm.parseMemUsage('--'), null);
});

test('default reserve is 1 GiB or 10% of RAM, whichever is larger', () => {
  assert.equal(adm.defaultReserveBytes(4 * GiB), GiB);
  assert.equal(adm.defaultReserveBytes(32 * GiB), Math.floor(3.2 * GiB));
});

// ------------------------------------------------------------- measurement

test('capacity comes from docker info minus the reserve; committed sums running caps', async () => {
  setSetting(adm.RESERVE_KEY, '');
  host({ totalMb: 8192, containers: [{ ...app('a', 'production'), mb: 512 }, { ...app('a', 'sandbox'), mb: 256 }] });
  const m = await adm.measureMemory({ fresh: true });
  assert.equal(m.totalSource, 'docker');
  assert.equal(m.totalBytes, 8192 * MiB);
  assert.equal(m.reserveBytes, GiB, '10% of 8 GiB is under the 1 GiB floor');
  assert.equal(m.capacityBytes, 7168 * MiB);
  assert.equal(m.committedBytes, 768 * MiB);
});

test('a container with no limit counts at its current usage, or at the default when usage cannot be read', async () => {
  host({ containers: [{ name: 'foreign', mb: 0 }, { ...app('b', 'production'), mb: 512 }], usage: { foreign: 300 } });
  let m = await adm.measureMemory({ fresh: true });
  assert.equal(m.containers.find(c => c.name === 'foreign').countedFrom, 'usage');
  assert.equal(m.committedBytes, (300 + 512) * MiB);

  host({ containers: [{ name: 'foreign', mb: 0 }], statsFail: true });
  m = await adm.measureMemory({ fresh: true });
  assert.equal(m.containers[0].countedFrom, 'default');
  assert.equal(m.committedBytes, adm.DEFAULT_UNLIMITED_MB * MiB);
});

// apphub, 30 Oct 2026: 24 containers AppCrane did not start, each capped at the
// whole server, made the mail say 333,717 MB were committed on a 14,131 MB box.
test('a container AppCrane did not start counts at its usage, not its cap; AppCrane\'s own count at their cap', async () => {
  host({
    totalMb: 15701,
    containers: [
      { name: 'bold_clarke', mb: 14131, image: 'example/worker:1' },
      { name: 'gracious_tu', mb: 14131, image: 'example/worker:1' },
      { ...app('c', 'production'), mb: 512, image: 'appcrane-c:live' },
    ],
    usage: { bold_clarke: 277, gracious_tu: 275 },
  });
  const m = await adm.measureMemory({ fresh: true });
  const foreign = m.containers.find(c => c.name === 'bold_clarke');
  assert.equal(foreign.countedFrom, 'usage');
  assert.equal(foreign.image, 'example/worker:1');
  assert.equal(m.containers.find(c => c.name === 'appcrane-c-production').countedFrom, 'cap');
  assert.equal(m.committedBytes, (277 + 275 + 512) * MiB);

  db.prepare("DELETE FROM email_queue WHERE source = 'memory-admission'").run();
  const v = adm.decide({ measurement: m, name: 'appcrane-d-sandbox', newBytes: 512 * MiB });
  await notifyMemoryAdmission({ db, outcome: 'warned', message: 'warn', verdict: v, measurement: m, subject: 'd (sandbox)', what: 'deploy', slug: 'd', env: 'sandbox' });
  const admin = mailRows().find(r => r.to_email === ADMIN.email);
  assert.match(admin.body_text, /bold_clarke \[image example\/worker:1\]: cap 14131 MB, using 277 MB, not started by AppCrane, counted at its usage/);
  assert.match(admin.body_text, /c \(production\) \[image appcrane-c:live\]: cap 512 MB/);
  assert.match(admin.body_html, /image example\/worker:1/);
});

test('docker info failing falls back to this machine\'s RAM and says so', async () => {
  host({ totalMb: null, containers: [] });
  const m = await adm.measureMemory({ fresh: true });
  assert.equal(m.totalSource, 'os');
  assert.equal(m.totalBytes, totalmem());
});

// ---------------------------------------------------------------- admission

test('refuse mode: over capacity throws INSUFFICIENT_MEMORY and the running container is NOT stopped', async () => {
  // 4096 MB capacity; 3584 committed by another app plus this app's own 256 MB.
  host({ containers: [{ ...app('big', 'production'), mb: 3584 }, { ...app('svc', 'production'), mb: 256 }] });
  const sent = [];
  await assert.rejects(
    docker.startApp(startOpts('svc', 'production', 1024, { notify: async (a) => { sent.push(a); } })),
    (e) => {
      assert.equal(e.code, 'INSUFFICIENT_MEMORY');
      assert.equal(e.status, 409);
      assert.match(e.message, /svc \(production\) needs 1024 MB, 512 MB is free \(3840\/4096 MB committed\)/);
      assert.match(e.message, /Nothing was changed — the current version is still running\. Try again later/);
      return true;
    },
  );
  const touched = calls().filter(c => ['stop', 'rm', 'run'].includes(c[0]));
  assert.deepEqual(touched, [], 'no stop, rm or run once refused');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].outcome, 'refused');
});

test('a same-size redeploy is allowed exactly at the boundary, and a fit at the boundary is allowed', async () => {
  // committed == capacity, the app's own 512 MB included: replacing it with 512 fits.
  host({ containers: [{ ...app('big', 'production'), mb: 3584 }, { ...app('svc', 'production'), mb: 512 }] });
  await docker.startApp(startOpts('svc', 'production', 512));
  assert.equal(calls().filter(c => c[0] === 'run').length, 1, 'the container was started');
  assert.ok(calls().some(c => c[0] === 'stop' && c.includes('appcrane-svc-production')), 'and the old one replaced');

  // committed - replaced + new == capacity exactly: allowed; one MB more is not.
  const m = await adm.measureMemory({ fresh: true });
  assert.equal(adm.decide({ measurement: m, name: 'appcrane-new-production', newBytes: 0 }).allowed, true);
  host({ containers: [{ ...app('big', 'production'), mb: 3584 }] });
  const m2 = await adm.measureMemory({ fresh: true });
  assert.equal(adm.decide({ measurement: m2, name: 'appcrane-new-production', newBytes: 512 * MiB }).allowed, true);
  assert.equal(adm.decide({ measurement: m2, name: 'appcrane-new-production', newBytes: 513 * MiB }).allowed, false);
});

test('rollback: a same-or-smaller cap is admitted on an over-committed host; a larger one is refused before anything changes', async () => {
  const a = makeApp('rb1', 512);
  const owner = makeUser();
  db.prepare("INSERT INTO deployments (app_id, env, status, image_ref, started_at) VALUES (?, 'production', 'rolled_back', 'nginx@sha256:aa', datetime('now','-2 hours'))").run(a.id);
  db.prepare("INSERT INTO deployments (app_id, env, status, image_ref, started_at) VALUES (?, 'production', 'live', 'nginx@sha256:bb', datetime('now','-1 hours'))").run(a.id);
  // 6000 MB committed against 4096: already over capacity.
  host({ containers: [{ ...app('big', 'production'), mb: 5488 }, { ...app('rb1', 'production'), mb: 512 }] });
  const ok = await deployer.admitAppStart({ app: a, env: 'production', userId: owner.id, what: 'rollback', notify: async () => {} });
  assert.equal(ok.allowed, true);
  assert.equal(ok.overCommitted, true);

  db.prepare('UPDATE apps SET resource_limits = ? WHERE id = ?').run(JSON.stringify({ max_ram_mb: 1024 }), a.id);
  const bigger = db.prepare('SELECT * FROM apps WHERE id = ?').get(a.id);
  const before = db.prepare('SELECT id, status FROM deployments WHERE app_id = ? ORDER BY id').all(a.id);
  await assert.rejects(deployer.rollbackApp(bigger, 'production', undefined, owner.id), { code: 'INSUFFICIENT_MEMORY' });
  assert.deepEqual(db.prepare('SELECT id, status FROM deployments WHERE app_id = ? ORDER BY id').all(a.id), before,
    'no rollback row inserted and the live deployment still live');
  assert.equal(calls().filter(c => ['pull', 'run', 'stop'].includes(c[0])).length, 0);
});

test('warn mode starts the container and notifies; off mode skips the measurement entirely', async () => {
  setSetting(adm.MODE_KEY, 'warn');
  host({ containers: [{ ...app('big', 'production'), mb: 4000 }] });
  const sent = [];
  const r = await adm.admitContainer({ name: 'appcrane-w1-sandbox', memoryMb: 512, slug: 'w1', env: 'sandbox', notify: async (a) => { sent.push(a); } });
  assert.equal(r.allowed, true);
  assert.equal(r.warned, true);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].outcome, 'warned');
  await docker.startApp(startOpts('w1', 'sandbox', 512, { notify: async (a) => { sent.push(a); } }));
  assert.equal(calls().filter(c => c[0] === 'run').length, 1, 'warn mode still starts it');

  setSetting(adm.MODE_KEY, 'off');
  if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG);
  adm._resetMemoryAdmissionForTests();
  await docker.startApp(startOpts('w2', 'sandbox', 99999));
  assert.equal(calls().filter(c => c[0] === 'info' || c[0] === 'ps').length, 0, 'off: no measurement');
  assert.equal(calls().filter(c => c[0] === 'run').length, 1);
});

test('the route pre-check records a failed deployment carrying the reason', async () => {
  const a = makeApp('pre1', 1024);
  const u = makeUser();
  host({ containers: [{ ...app('big', 'production'), mb: 3800 }] });
  await assert.rejects(deployer.refuseDeployForMemory({ db, app: a, env: 'sandbox', userId: u.id }), { code: 'INSUFFICIENT_MEMORY' });
  const row = db.prepare('SELECT status, deployed_by, log FROM deployments WHERE app_id = ?').get(a.id);
  assert.equal(row.status, 'failed');
  assert.equal(row.deployed_by, u.id);
  assert.match(row.log, /^DEPLOY REFUSED: Not enough memory on the server for this deploy: pre1 \(sandbox\) needs 1024 MB/);
});

test('an automatic deploy refused in deployApp fails with the reason in its log, before any pull, and mails the owners', async () => {
  const a = makeApp('auto1', 1024);
  const owner = makeUser();
  const member = makeUser();
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(a.id, owner.id);
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(a.id, member.id);
  const dep = db.prepare("INSERT INTO deployments (app_id, env, status, log) VALUES (?, 'production', 'pending', 'webhook')").run(a.id).lastInsertRowid;
  host({ containers: [{ ...app('big', 'production'), mb: 3800 }] });
  await assert.rejects(deployer.deployApp(dep, a, 'production', { prod_be: 39010, sand_be: 39011 }), { code: 'INSUFFICIENT_MEMORY' });
  const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(dep);
  assert.equal(row.status, 'failed');
  assert.match(row.log, /DEPLOY FAILED: Not enough memory on the server for this deploy: auto1 \(production\) needs 1024 MB/);
  assert.equal(calls().filter(c => ['pull', 'run', 'stop'].includes(c[0])).length, 0);
  const to = mailRows().map(r => r.to_email);
  assert.ok(to.includes(owner.email), 'owner told to try again later');
  assert.ok(!to.includes(member.email), 'a member is not');
  assert.ok(to.includes(ADMIN.email), 'platform admin told');
});

test('the coder container is refused the same way, before anything is cloned or started', async () => {
  const a = makeApp('coder1', 512, { source_type: 'managed' });
  host({ containers: [{ ...app('big', 'production'), mb: 3000 }] });
  await assert.rejects(appContainer.getOrCreate(a, () => {}, { userId: ADMIN.id }), (e) => {
    assert.equal(e.code, 'INSUFFICIENT_MEMORY');
    assert.match(e.message, /this coder session: the coder for coder1 needs 2048 MB, 1096 MB is free.*Nothing was started\./);
    return true;
  });
  assert.equal(calls().filter(c => ['run', 'build', 'image'].includes(c[0])).length, 0);
});

// ------------------------------------------------------------------ e-mail

function verdict() {
  return { newBytes: 1024 * MiB, replacedBytes: 256 * MiB, committedBytes: 3840 * MiB, capacityBytes: 4096 * MiB, freeBytes: 512 * MiB, afterBytes: 4608 * MiB };
}
function measurement() {
  return {
    totalBytes: 4096 * MiB, totalSource: 'docker', reserveBytes: 0, capacityBytes: 4096 * MiB,
    containers: [
      { name: 'appcrane-big-production', label: 'big <img src=x> (production)', capBytes: 3584 * MiB, countedBytes: 3584 * MiB, unlimited: false },
      { name: 'other', label: 'other', capBytes: 0, countedBytes: 100 * MiB, unlimited: true },
    ],
  };
}

test('user and admin e-mails: deployer (not owners) for a manual deploy, owners for an automatic one, admins once per app per hour, escaped', async () => {
  host({ containers: [], usage: { 'appcrane-big-production': 2000 } });
  const a = makeApp('mail1', 1024);
  const owner = makeUser();
  const deployerUser = makeUser();
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(a.id, owner.id);
  const args = {
    db, outcome: 'refused', message: 'Not enough memory <b>now</b>', verdict: verdict(), measurement: measurement(),
    subject: 'mail1 (production)', what: 'deploy', slug: 'mail1', env: 'production', appId: a.id,
  };

  await notifyMemoryAdmission({ ...args, userId: deployerUser.id, automatic: false });
  await notifyMemoryAdmission({ ...args, userId: deployerUser.id, automatic: false });
  let rows = mailRows();
  assert.deepEqual(rows.map(r => r.to_email).sort(), [ADMIN.email, deployerUser.email].sort(), 'once each within the hour; owner not mailed');
  const admin = rows.find(r => r.to_email === ADMIN.email);
  assert.ok(!admin.body_html.includes('<img src=x>') && admin.body_html.includes('&lt;img src=x&gt;'), 'container label escaped');
  assert.ok(!admin.body_html.includes('<b>now</b>') && admin.body_html.includes('&lt;b&gt;now&lt;/b&gt;'), 'message escaped');
  assert.match(admin.body_text, /big <img src=x> \(production\): cap 3584 MB, using 2000 MB/);
  assert.match(admin.body_text, /other: no limit, usage unknown/);
  assert.match(rows.find(r => r.to_email === deployerUser.email).body_text, /try again later/i);

  db.prepare("DELETE FROM email_queue WHERE source = 'memory-admission'").run();
  await notifyMemoryAdmission({ ...args, userId: null, automatic: true });
  rows = mailRows();
  assert.deepEqual(rows.map(r => r.to_email).sort(), [ADMIN.email, owner.email].sort(), 'automatic: owners, not the deployer');

  db.prepare("DELETE FROM email_queue WHERE source = 'memory-admission'").run();
  await notifyMemoryAdmission({ ...args, outcome: 'warned', userId: deployerUser.id });
  assert.deepEqual(mailRows().map(r => r.to_email), [ADMIN.email], 'warn: admins only');

  const audit = db.prepare("SELECT action, detail FROM audit_log WHERE app_id = ? AND action LIKE 'memory.admission.%' ORDER BY id").all(a.id);
  assert.deepEqual(audit.map(r => r.action), ['memory.admission.refused', 'memory.admission.refused', 'memory.admission.refused', 'memory.admission.warned']);
  assert.equal(JSON.parse(audit[0].detail).need_mb, 1024);
});

test('the default mode is warn: an unset or unknown setting never blocks a start', async () => {
  const { DEFAULT_MODE } = await import('../server/services/memoryAdmission.js');
  assert.equal(DEFAULT_MODE, 'warn');
});
