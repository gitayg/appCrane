import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';

// LIVE against the local Docker daemon. A container near its memory limit is
// auto-restarted through the health checker's real path (healthChecker.js
// autoRestart -> restartCapture -> docker.js restartApp), and the incident must
// hold the memory it had BEFORE the restart, its log tail (scrubbed) and its
// exit state. Then the docker events watcher sees an OOM-killed container that
// Docker restarts on its own, records each death as 'oom', trips the loop rule
// and queues the owner mail; and a planned stop with a 'restart' audit row is
// recorded as 'manual' with memory read at the kill.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-restart-docker-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const execFileAsync = promisify(execFile);
let noDocker = false;
try { execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 10000, stdio: 'ignore' }); } catch { noDocker = 'Docker daemon not reachable'; }

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { autoRestart } = await import('../server/services/healthChecker.js');
const watcher = await import('../server/services/restartWatcher.js');
const incidents = await import('../server/services/restartIncidents.js');

const tag = `${process.pid}${Date.now() % 100000}`;
const live = [];
const dk = (args, timeout = 60000) => execFileAsync('docker', args, { timeout }).then(r => r.stdout.trim());

function mkApp(slug, slot) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch,repo_backend) VALUES (?,?,?,'managed','main','local')")
    .run(slug, slug, slot).lastInsertRowid);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const owner = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('rd-owner','rd-owner@t.test','user','x',1,'human')").run().lastInsertRowid);

async function runApp(slug, env, flags, cmd) {
  const name = `appcrane-${slug}-${env}`;
  live.push(name);
  await dk(['rm', '-f', name]).catch(() => {});
  await dk(['run', '-d', '--name', name, '--label', 'appcrane=true', '--label', `slug=${slug}`, '--label', `env=${env}`,
    ...flags, 'alpine:3', 'sh', '-c', cmd]);
  return name;
}

const waitFor = async (fn, ms = 60000) => {
  const until = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) return v;
    await new Promise(r => setTimeout(r, 500));
  }
};

after(async () => {
  watcher.stopRestartWatcher();
  for (const n of live) await dk(['rm', '-f', n], 20000).catch(() => {});
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

test('LIVE: a health restart records memory.current/max from BEFORE the restart, the scrubbed log tail and the exit state', { skip: noDocker }, async () => {
  const app = mkApp(`rdmem${tag}`, 701);
  const name = await runApp(app.slug, 'sandbox', ['--memory=64m', '--memory-swap=64m', '--shm-size=128m'],
    'echo booting; echo "api_key=sk_live_abcdefghijklmnop1234"; dd if=/dev/zero of=/dev/shm/fill bs=1M count=61 2>/dev/null; echo filled-61mb; sleep 600');
  await waitFor(async () => (await dk(['logs', name])).includes('filled-61mb'), 20000);
  const startedBefore = await dk(['inspect', '-f', '{{.State.StartedAt}}', name]);

  const r = await autoRestart({ app_id: app.id, env: 'sandbox', slug: app.slug, fail_threshold: 3 }, { newFails: 3, status: 0, probeError: 'ECONNREFUSED' });
  assert.equal(r.outcome, 'restarted', JSON.stringify(r));
  const inc = r.incident;
  assert.ok(inc, 'an incident was recorded');
  assert.equal(inc.trigger, 'health');
  assert.equal(inc.action, 'restarted');
  assert.equal(inc.memory.max, 64 * 1024 * 1024, JSON.stringify(inc.memory));
  assert.ok(inc.memory.current >= 0.95 * inc.memory.max, `memory.current ${inc.memory.current} is the pre-restart fill`);
  assert.equal(inc.kind, 'memory');
  assert.match(inc.summary, /^memory 9\d% of 64 MB(, a process inside was OOM-killed)? \(health check failed 3 times: ECONNREFUSED\)$/);
  assert.ok(inc.log_tail.some(l => l.includes('filled-61mb')), JSON.stringify(inc.log_tail));
  assert.ok(inc.log_tail.every(l => !l.includes('sk_live_abcdefghijklmnop1234')), 'the secret in the log is scrubbed');
  assert.ok(inc.log_tail.some(l => /api_key=\[redacted\]/.test(l)), JSON.stringify(inc.log_tail));
  assert.equal(inc.exit_state.status, 'running');
  assert.equal(inc.exit_state.started_at, startedBefore);

  const startedAfter = await dk(['inspect', '-f', '{{.State.StartedAt}}', name]);
  assert.notEqual(startedAfter, startedBefore, 'the container really was restarted');
  const row = db.prepare('SELECT * FROM restart_incidents WHERE id = ?').get(inc.id);
  assert.equal(row.memory_current, inc.memory.current);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE app_id = ? AND action = 'health-restart'").get(app.id));
});

test('LIVE: the docker events watcher records OOM deaths Docker restarts on its own, trips the loop rule and mails the owner once', { skip: noDocker }, async () => {
  const app = mkApp(`rdoom${tag}`, 702);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(app.id, owner);
  watcher._setAttributeDelayForTests(1000);
  watcher.startRestartWatcher();
  await waitFor(() => watcher.watcherConnected(), 10000);
  await new Promise(r => setTimeout(r, 1500));
  await runApp(app.slug, 'sandbox', ['--memory=16m', '--memory-swap=16m', '--restart=on-failure:2'], 'echo booting-oom; exec tail /dev/zero');

  const rows = await waitFor(() => {
    const r = db.prepare("SELECT * FROM restart_incidents WHERE app_id = ? AND trigger = 'oom' ORDER BY id").all(app.id);
    return r.length >= 3 ? r : null;
  }, 60000);
  assert.ok(rows, 'three OOM deaths were recorded (one start plus two on-failure restarts)');
  for (const r of rows) {
    assert.equal(r.action, 'observed');
    assert.equal(r.kind, 'memory');
    assert.match(r.summary, /OOM-killed/);
    // From the die event itself: the inspect that follows can already see the
    // run Docker restarted, with OOMKilled reset.
    assert.equal(JSON.parse(r.detail).exit_code, 137);
    assert.ok(JSON.parse(r.log_tail).some(l => l.includes('booting-oom')), r.log_tail);
    assert.match(r.not_captured, /cgroup was gone/);
  }
  const st = incidents.getStability({ appId: app.id, env: 'sandbox' });
  assert.equal(st.unstable, true);
  assert.equal(st.rule, '3 restarts in 10 min');
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE app_id = ? AND action = 'restart-loop-detected'").get(app.id));
  const mails = db.prepare("SELECT * FROM email_queue WHERE app_id = ? AND source = 'restart-loop'").all(app.id);
  assert.equal(mails.length, 1, 'one mail per episode');
  assert.equal(mails[0].to_email, 'rd-owner@t.test');
  assert.match(mails[0].body_text, /Cause: memory/);
});

test('LIVE: a planned stop with a restart audit row is recorded as manual, with memory read at the kill', { skip: noDocker }, async () => {
  const app = mkApp(`rdman${tag}`, 703);
  watcher.startRestartWatcher();
  await waitFor(() => watcher.watcherConnected(), 10000);
  const name = await runApp(app.slug, 'production', ['--memory=64m', '--memory-swap=64m'], 'echo up-manual; trap "echo bye; sleep 2; exit 0" TERM; while true; do sleep 1; done');
  await waitFor(async () => (await dk(['logs', name])).includes('up-manual'), 20000);
  db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?, ?, 'restart', ?)")
    .run(owner, app.id, JSON.stringify({ method: 'POST', params: { slug: app.slug, env: 'production' } }));
  await dk(['stop', '-t', '5', name]);
  const row = await waitFor(() => db.prepare('SELECT * FROM restart_incidents WHERE app_id = ?').get(app.id), 30000);
  assert.ok(row, 'the stop was recorded');
  assert.equal(row.trigger, 'manual');
  assert.equal(row.summary, 'manual restart');
  assert.ok(row.memory_max === 64 * 1024 * 1024 && row.memory_current > 0, `memory read at the kill: ${row.memory_current}/${row.memory_max} ${row.not_captured}`);
  assert.ok(JSON.parse(row.log_tail).some(l => l.includes('up-manual')));
});
