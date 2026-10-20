import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-job-health-'));

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const jh = await import('../server/services/jobHealth.js');
const jobHealthRouter = (await import('../server/routes/jobHealth.js')).default;

initDb();
const db = getDb();

const HOUR = 60 * 60 * 1000;
const find = (id, now) => jh.getJobHealth(now).find(j => j.id === id);

beforeEach(() => {
  jh._resetJobHealthForTests();
  db.prepare('DELETE FROM job_runs').run();
});

test('a job that runs is ok, with its last run and next expected run', async () => {
  jh.jobStarted('crew-retention');
  const out = await jh.trackJob('crew-retention', async () => 42);
  assert.equal(out, 42);
  const j = find('crew-retention');
  assert.equal(j.status, 'ok');
  assert.equal(j.last_run.ok, true);
  assert.equal(j.last_error, null);
  assert.ok(Date.parse(j.next_expected_run) > Date.now() + 23 * HOUR);
  assert.equal(j.history.length, 1);
});

test('a job that throws is failing with a sanitised error, and the error still reaches the job', async () => {
  jh.jobStarted('vuln-scan');
  const secret = 'ghp_' + 'a'.repeat(36);
  const boom = new Error(`clone https://user:${secret}@example.test/x failed; password=hunter2 at /srv/secret-dir/data/deployhub.db Bearer abc.def.ghi`);
  await assert.rejects(jh.trackJob('vuln-scan', async () => { throw boom; }), boom);
  const j = find('vuln-scan');
  assert.equal(j.status, 'failing');
  assert.ok(j.last_error, 'error recorded');
  for (const leak of [secret, 'hunter2', 'user:', '/srv/secret-dir', 'abc.def.ghi']) {
    assert.ok(!j.last_error.includes(leak), `"${leak}" leaked into: ${j.last_error}`);
  }
  assert.match(j.last_error, /deployhub\.db/);
});

test('a job that catches its own error is failing when it notes the failure', async () => {
  jh.jobStarted('metrics-sampler');
  await jh.trackJob('metrics-sampler', async () => { jh.noteJobFailure('metrics-sampler', new Error('docker gone')); });
  assert.equal(find('metrics-sampler').status, 'failing');
  assert.equal(find('metrics-sampler').last_error, 'docker gone');
});

test('a job past its expected window is late', async () => {
  jh.jobStarted('credential-check');
  await jh.trackJob('credential-check', async () => {});
  assert.equal(find('credential-check').status, 'ok');
  assert.equal(find('credential-check', Date.now() + 2 * HOUR).status, 'late');
});

test('a started job with no run yet is never-run, then late once its window passes', () => {
  jh.jobStarted('request-digest');
  assert.equal(find('request-digest').status, 'never-run');
  assert.equal(find('request-digest', Date.now() + 40 * HOUR).status, 'late');
});

test('a job not started in this process, or turned off, is disabled', () => {
  assert.equal(find('offsite-backup').status, 'disabled');
  jh.jobStarted('offsite-backup', { enabled: () => false });
  assert.equal(find('offsite-backup').status, 'disabled');
});

test('a reporting failure never breaks the job', async () => {
  jh.jobStarted('disk-quota');
  db.exec('ALTER TABLE job_runs RENAME TO job_runs_gone');
  try {
    assert.equal(await jh.trackJob('disk-quota', async () => 'done'), 'done');
    assert.equal(jh.trackJobSync('disk-quota', () => 'sync-done'), 'sync-done');
    await assert.rejects(jh.trackJob('disk-quota', async () => { throw new Error('real'); }), /real/);
    assert.doesNotThrow(() => jh.noteJobFailure('disk-quota', { toString() { throw new Error('bad'); } }));
  } finally {
    db.exec('ALTER TABLE job_runs_gone RENAME TO job_runs');
  }
});

test('history is bounded per job', async () => {
  jh.jobStarted('email-queue');
  for (let i = 0; i < jh.HISTORY_LIMIT + 15; i++) {
    await jh.trackJob('email-queue', async () => { throw new Error(`fail ${i}`); }).catch(() => {});
  }
  const n = db.prepare("SELECT COUNT(*) AS n FROM job_runs WHERE job = 'email-queue'").get().n;
  assert.equal(n, jh.HISTORY_LIMIT);
  const j = find('email-queue');
  assert.equal(j.history.length, jh.HISTORY_LIMIT);
  assert.equal(j.history[0].error, `fail ${jh.HISTORY_LIMIT + 14}`);
  assert.equal(j.since_boot.runs, jh.HISTORY_LIMIT + 15);
  assert.ok(j.queue && typeof j.queue.queued === 'number', 'queue depth surfaced');
});

// ── API authorization ──────────────────────────────────────────────────────

let seq = 0;
function mkUser(role) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`jh${n}`, `jh${n}@t.test`, role, hashApiKey(key), 'human').lastInsertRowid;
  return { key, id };
}
const appId = db.prepare('INSERT INTO apps (name,slug,slot,source_type,auth_mode,branch) VALUES (?,?,?,?,?,?)')
  .run('jhapp', 'jhapp', 1, 'image', 'forward_auth', 'main').lastInsertRowid;
const PLATFORM = mkUser('platform_admin');
const OWNER = mkUser('user');
const MEMBER = mkUser('user');
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, OWNER.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(appId, MEMBER.id);

const app = express();
app.use(express.json());
app.use('/api/settings', jobHealthRouter);
app.use(errorHandler);
const server = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
after(() => { jh._resetJobHealthForTests(); server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

async function call(method, path, key) {
  const r = await fetch(`${BASE}${path}`, { method, headers: key ? { 'X-API-Key': key } : {} });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

test('GET /api/settings/job-health is platform-admin only', async () => {
  assert.equal((await call('GET', '/api/settings/job-health')).status, 401);
  assert.equal((await call('GET', '/api/settings/job-health', OWNER.key)).status, 403);
  assert.equal((await call('GET', '/api/settings/job-health', MEMBER.key)).status, 403);
  const ok = await call('GET', '/api/settings/job-health', PLATFORM.key);
  assert.equal(ok.status, 200);
  assert.ok(ok.body.jobs.some(j => j.id === 'vuln-scan'));
  assert.equal(ok.body.jobs.find(j => j.id === 'credential-check').can_run_now, true);
  assert.equal(ok.body.jobs.find(j => j.id === 'vuln-scan').can_run_now, false);
});

test('POST run-now is platform-admin only and refuses jobs without a safe trigger', async () => {
  assert.equal((await call('POST', '/api/settings/job-health/credential-check/run', OWNER.key)).status, 403);
  assert.equal((await call('POST', '/api/settings/job-health/credential-check/run', MEMBER.key)).status, 403);
  assert.equal((await call('POST', '/api/settings/job-health/vuln-scan/run', PLATFORM.key)).status, 400);
  assert.equal((await call('POST', '/api/settings/job-health/nope/run', PLATFORM.key)).status, 404);
});
