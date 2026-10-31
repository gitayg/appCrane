import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A cron job whose container is gone must not `docker exec` every tick (a
// production box logged ~14k "No such container" lines a day doing that). It is
// skipped with the reason on the row, logged once on pause and once on resume,
// mailed once per outage to the app's owners and admins, and resumes on its own.
// Driven through the real runCronJob with a `docker` shim on PATH.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cron-nc-'));
process.env.DATA_DIR = join(ROOT, 'data');
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(ROOT, 'bin');
const STATE = join(ROOT, 'container-state');
const EXECS = join(ROOT, 'execs.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const { appendFileSync, readFileSync } = require('fs');
const argv = process.argv.slice(2);
const state = readFileSync(process.env.CRANE_CRON_STATE, 'utf8').trim();
if (argv[0] === 'inspect') {
  if (state === 'missing') { process.stderr.write('Error: No such object: ' + argv[argv.length - 1] + '\\n'); process.exit(1); }
  process.stdout.write(state === 'running' ? 'true|running\\n' : 'false|exited\\n');
  process.exit(0);
}
if (argv[0] === 'exec') {
  appendFileSync(process.env.CRANE_CRON_EXECS, argv.join(' ') + '\\n');
  if (state === 'missing') { process.stderr.write('Error response from daemon: No such container: ' + argv[1] + '\\n'); process.exit(1); }
  process.stdout.write('did the work\\n');
  process.exit(0);
}
process.exit(0);
`, { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;
process.env.CRANE_CRON_STATE = STATE;
process.env.CRANE_CRON_EXECS = EXECS;
const setState = (s) => writeFileSync(STATE, s);
const execCount = () => (existsSync(EXECS) ? readFileSync(EXECS, 'utf8').trim().split('\n').filter(Boolean).length : 0);

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const log = (await import('../server/utils/logger.js')).default;
const { runCronJob } = await import('../server/services/cronScheduler.js');
const { CRON_MAIL_SOURCE } = await import('../server/services/cronContainerGuard.js');

const lines = { warn: [], info: [] };
log.warn = (m) => lines.warn.push(m);
log.info = (m) => lines.info.push(m);

let seq = 0;
const mkUser = (email, role = 'user') => db.prepare('INSERT INTO users (name, email, role, api_key_hash) VALUES (?,?,?,?)')
  .run(`U${++seq}`, email, role, `hash-cron-${seq}`).lastInsertRowid;
mkUser('platform@example.test', 'platform_admin');
const owner = mkUser('owner@example.test');
const appAdmin = mkUser('appadmin@example.test');
const member = mkUser('member@example.test');
db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('Cron App', 'cronapp', 41)").run();
const app = db.prepare("SELECT * FROM apps WHERE slug = 'cronapp'").get();
const grant = db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)');
grant.run(app.id, owner, 'owner');
grant.run(app.id, appAdmin, 'admin');
grant.run(app.id, member, 'user');

const insertJob = db.prepare("INSERT INTO app_cron_jobs (app_id, env, name, schedule, command, timeout_seconds) VALUES (?, 'sandbox', ?, '* * * * *', 'echo hi', 30)");
insertJob.run(app.id, 'nightly');
insertJob.run(app.id, 'hourly');
const job = (name) => db.prepare('SELECT * FROM app_cron_jobs WHERE app_id = ? AND name = ?').get(app.id, name);
const mails = () => db.prepare('SELECT to_email, subject, app_id, env FROM email_queue WHERE source = ? ORDER BY id').all(CRON_MAIL_SOURCE);
const pauseLines = () => lines.warn.filter((l) => l.includes('paused'));
const resumeLines = () => lines.info.filter((l) => l.includes('resumed'));

test('a missing container skips every run without exec, with the reason on the row and returned to a manual run', async () => {
  setState('missing');
  for (let i = 0; i < 3; i++) {
    const r = await runCronJob(job('nightly'));
    assert.equal(r.skipped, true);
    assert.equal(r.reason, 'skipped: container appcrane-cronapp-sandbox does not exist');
  }
  await runCronJob(job('hourly'));
  assert.equal(execCount(), 0, 'docker exec must not run against a missing container');
  const row = job('nightly');
  assert.match(row.last_log, /skipped: container appcrane-cronapp-sandbox does not exist/);
  assert.equal(row.last_exit_code, null);
  assert.ok(row.last_run_at, 'last_run_at is set so the tick does not re-fire within the minute');
});

test('the pause is logged once per job, not once per tick', () => {
  assert.equal(pauseLines().length, 2, pauseLines().join('\n'));
  assert.ok(pauseLines().some((l) => l.includes(':nightly')));
  assert.ok(pauseLines().some((l) => l.includes(':hourly')));
});

test('one mail per outage of the app+env, to owners and app admins only', () => {
  const q = mails();
  assert.deepEqual(q.map((m) => m.to_email).sort(), ['appadmin@example.test', 'owner@example.test']);
  assert.ok(q.every((m) => m.app_id === app.id && m.env === 'sandbox'));
  assert.match(q[0].subject, /Cron jobs paused: cronapp\/sandbox has no running container/);
});

test('a stopped container is skipped too, with its status', async () => {
  setState('stopped');
  const r = await runCronJob(job('nightly'));
  assert.equal(r.reason, 'skipped: container appcrane-cronapp-sandbox is not running (status: exited)');
  assert.equal(execCount(), 0);
  assert.equal(mails().length, 2, 'same outage: no second mail');
  assert.equal(pauseLines().length, 2, 'same outage: no second pause line');
});

test('when the container is back the job runs, logs one resume line, and a later outage mails again', async () => {
  setState('running');
  const r = await runCronJob(job('nightly'));
  assert.equal(r.ran, true);
  assert.equal(r.exitCode, 0);
  assert.equal(execCount(), 1);
  await runCronJob(job('nightly'));
  assert.equal(resumeLines().filter((l) => l.includes(':nightly')).length, 1, resumeLines().join('\n'));

  setState('missing');
  await new Promise((res) => setTimeout(res, 5)); // a new outage gets a new start time
  await runCronJob(job('nightly'));
  assert.equal(mails().length, 4, 'a new outage is mailed once more');
  assert.equal(execCount(), 2);
});
