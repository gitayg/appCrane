import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Restart incidents without Docker (a recording shim answers every docker call
// with a failure): classification and summary text, the loop rule tripping
// once, the owner mail once per episode (platform admins when there is no
// owner), the health checker's backoff (skip, then retry, then a longer wait),
// what clears unstable, the docker-events watcher's attribution, retention, and
// the incidents route and health response through the real routers.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-restarts-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
const DOCKER_LOG = join(ROOT, 'docker-argv.log');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh\necho "$*" >> "${DOCKER_LOG}"\necho "no docker" >&2\nexit 1\n`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const ri = await import('../server/services/restartIncidents.js');
const { autoRestart } = await import('../server/services/healthChecker.js');
const watcher = await import('../server/services/restartWatcher.js');

const MiB = 1024 * 1024;
const T0 = Date.parse('2026-11-24T14:00:00Z');
const min = (n) => T0 + n * 60_000;

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(name, `${name}@t.test`, role, hashApiKey(key), 'human').lastInsertRowid);
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
let slot = 640;
function mkApp(slug) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch,repo_backend) VALUES (?,?,?,'managed','main','local')")
    .run(slug, slug, ++slot).lastInsertRowid);
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(id, env);
    db.prepare('INSERT INTO health_state (app_id, env, consecutive_fails) VALUES (?, ?, 0)').run(id, env);
  }
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function grant(app, u, role) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(app.id, u.id, role);
}
const health = (app, env, now, mem) => ri.recordIncident({
  appId: app.id, env, trigger: 'health', action: 'restarted', now,
  capture: mem ? { memory: { current: mem[0], max: mem[1], source: 'host-cgroup', oom_kill: 0 }, log_tail: ['2026-11-24T14:11:00Z heap at 507MB'], state: { status: 'running' } } : {},
  detail: { consecutive_fails: 3, probe_error: 'ECONNREFUSED' },
});
const mails = (app) => db.prepare("SELECT * FROM email_queue WHERE app_id = ? AND source = 'restart-loop' ORDER BY id").all(app.id);

const admin = mkUser('rs-platadmin', 'platform_admin');
const owner = mkUser('rs-owner');
const appAdmin = mkUser('rs-appadmin');
const member = mkUser('rs-member');
const outsider = mkUser('rs-outsider');

test('classify: the production case reads "memory 99% of 512 MB", and each trigger has its own summary', () => {
  const c = ri.classify({ trigger: 'health', action: 'restarted', capture: { memory: { current: 507 * MiB, max: 512 * MiB } }, detail: { consecutive_fails: 3, probe_error: 'ECONNREFUSED' } });
  assert.deepEqual(c, { kind: 'memory', summary: 'memory 99% of 512 MB (health check failed 3 times: ECONNREFUSED)' });
  assert.deepEqual(ri.classify({ trigger: 'health', action: 'restarted', capture: { memory: { current: 200 * MiB, max: 512 * MiB } }, detail: { consecutive_fails: 3, probe_error: 'ECONNREFUSED' } }),
    { kind: 'health', summary: 'health check failed 3 times: ECONNREFUSED' });
  assert.equal(ri.classify({ trigger: 'health', action: 'restarted', capture: { memory: { current: 100 * MiB, max: 512 * MiB, oom_kill: 2 } }, detail: { consecutive_fails: 3 } }).summary,
    'memory 19% of 512 MB, 2 OOM kills inside the container (health check failed 3 times)');
  assert.deepEqual(ri.classify({ trigger: 'crash', action: 'observed', detail: { exit_code: 3, docker_restarts: true } }),
    { kind: 'exit', summary: 'exited with code 3, restarted by Docker' });
  assert.deepEqual(ri.classify({ trigger: 'oom', action: 'observed', capture: { state: { limit_bytes: 512 * MiB } }, detail: { exit_code: 137 } }),
    { kind: 'memory', summary: 'memory limit 512 MB, OOM-killed' });
  assert.deepEqual(ri.classify({ trigger: 'manual', action: 'observed' }), { kind: 'planned', summary: 'manual restart' });
  assert.equal(ri.classify({ trigger: 'health', action: 'skipped', detail: { consecutive_fails: 3, probe_error: 'ETIMEDOUT' } }).summary,
    'auto-restart skipped (restart loop): health check failed 3 times: ETIMEDOUT');
});

test('loop: the 3rd unplanned restart in 10 minutes marks the env unstable, audits it and mails the owner once per episode', async () => {
  const app = mkApp('rs-loop');
  grant(app, owner, 'owner');
  await health(app, 'sandbox', min(0), [507 * MiB, 512 * MiB]);
  await ri.recordIncident({ appId: app.id, env: 'sandbox', trigger: 'manual', action: 'observed', now: min(1) });
  await ri.recordIncident({ appId: app.id, env: 'sandbox', trigger: 'health', action: 'skipped', now: min(1), detail: { consecutive_fails: 3 } });
  await health(app, 'sandbox', min(2), [507 * MiB, 512 * MiB]);
  assert.equal(ri.getStability({ appId: app.id, env: 'sandbox', now: min(2) }).unstable, false, 'planned and skipped rows do not count');
  await health(app, 'sandbox', min(8), [507 * MiB, 512 * MiB]);
  const st = ri.getStability({ appId: app.id, env: 'sandbox', now: min(8) });
  assert.equal(st.unstable, true);
  assert.equal(st.rule, '3 restarts in 10 min');
  assert.equal(st.next_restart_at, '2026-11-24 14:13:00');
  assert.equal(ri.getStability({ appId: app.id, env: 'production', now: min(8) }).unstable, false, 'per env');
  const audit = db.prepare("SELECT detail FROM audit_log WHERE app_id = ? AND action = 'restart-loop-detected'").all(app.id);
  assert.equal(audit.length, 1);
  assert.match(audit[0].detail, /memory 99% of 512 MB/);

  let m = mails(app);
  assert.equal(m.length, 1);
  assert.equal(m[0].to_email, 'rs-owner@t.test');
  assert.match(m[0].subject, /rs-loop \(sandbox\) is restarting in a loop/);
  assert.match(m[0].body_text, /Cause: memory 99% of 512 MB \(health check failed 3 times: ECONNREFUSED\)/);
  assert.match(m[0].body_text, /not before 2026-11-24 14:13:00 UTC/);

  await health(app, 'sandbox', min(9), [507 * MiB, 512 * MiB]);
  assert.equal(mails(app).length, 1, 'still one mail: same episode');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE app_id = ? AND action = 'restart-loop-detected'").get(app.id).n, 1);
});

test('loop: the 1-hour rule (6 in 60 min) trips on spread-out restarts too', async () => {
  const app = mkApp('rs-long');
  grant(app, owner, 'owner');
  for (const t of [0, 11, 22, 33, 44]) await health(app, 'production', min(t));
  assert.equal(ri.getStability({ appId: app.id, env: 'production', now: min(44) }).unstable, false);
  await health(app, 'production', min(55));
  assert.equal(ri.getStability({ appId: app.id, env: 'production', now: min(55) }).rule, '6 restarts in 60 min');
});

test('loop: settings override the defaults; invalid values fall back', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('restart_loop_short_count', '2'), ('restart_loop_long_minutes', 'abc')").run();
  try {
    const s = ri.loopSettings();
    assert.equal(s.restart_loop_short_count, 2);
    assert.equal(s.restart_loop_long_minutes, 60);
    const app = mkApp('rs-setting');
    await health(app, 'sandbox', min(0));
    await health(app, 'sandbox', min(1));
    assert.equal(ri.getStability({ appId: app.id, env: 'sandbox', now: min(1) }).rule, '2 restarts in 10 min');
  } finally {
    db.prepare("DELETE FROM settings WHERE key IN ('restart_loop_short_count', 'restart_loop_long_minutes')").run();
  }
});

test('mail: an app with no owner mails the platform admins instead', async () => {
  const app = mkApp('rs-orphan');
  for (const t of [0, 1, 2]) await health(app, 'sandbox', min(t));
  const m = mails(app);
  assert.deepEqual(m.map(x => x.to_email), ['rs-platadmin@t.test']);
  assert.match(m[0].body_text, /administer the AppCrane/);
});

test('backoff: an unstable env is not restarted until next_restart_at, then the wait doubles', async () => {
  const app = mkApp('rs-backoff');
  grant(app, owner, 'owner');
  for (const t of [0, 1, 2]) await health(app, 'sandbox', Date.now() - (3 - t) * 60_000);
  assert.equal(ri.getStability({ appId: app.id, env: 'sandbox' }).unstable, true);
  const cfg = { app_id: app.id, env: 'sandbox', slug: app.slug, fail_threshold: 3 };

  writeFileSync(DOCKER_LOG, '');
  const r = await autoRestart(cfg, { newFails: 3, status: 0, probeError: 'ECONNREFUSED' });
  assert.equal(r.outcome, 'skipped');
  assert.match(r.incident.summary, /^auto-restart skipped \(restart loop\): health check failed 3 times: ECONNREFUSED$/);
  assert.match(r.incident.detail.skipped_reason, /restart loop \(3 restarts in 10 min\); next automatic restart after/);
  assert.ok(r.incident.not_captured.some(x => /exit state: no docker/.test(x)), JSON.stringify(r.incident.not_captured));
  assert.doesNotMatch(readFileSync(DOCKER_LOG, 'utf8'), /^restart /m, 'docker restart was not run');

  db.prepare("UPDATE restart_stability SET next_restart_at = ? WHERE app_id = ? AND env = 'sandbox'").run(ri.sqlTime(Date.now() - 1000), app.id);
  const r2 = await autoRestart(cfg, { newFails: 7, status: 0, probeError: 'ECONNREFUSED' });
  assert.match(readFileSync(DOCKER_LOG, 'utf8'), /^restart appcrane-rs-backoff-sandbox$/m, 'the retry ran docker restart');
  assert.equal(r2.outcome, 'error', 'the shim fails the restart');
  assert.equal(r2.incident.action, 'failed');
  const row = db.prepare("SELECT * FROM restart_stability WHERE app_id = ? AND env = 'sandbox'").get(app.id);
  assert.equal(row.backoff_level, 1, 'a failed restart does not push the backoff out');
  ri.noteBackoffRestart({ appId: app.id, env: 'sandbox', now: T0 });
  assert.equal(db.prepare("SELECT next_restart_at FROM restart_stability WHERE app_id = ? AND env = 'sandbox'").get(app.id).next_restart_at, '2026-11-24 14:10:00', 'level 2 = 10 min');
  assert.equal(ri.backoffMinutes(10, ri.loopSettings()), 360, 'capped');
});

test('backoff: past the fail threshold, only an unstable env whose wait has run out is retried', async () => {
  const { backoffRetryDue } = await import('../server/services/healthChecker.js');
  const app = mkApp('rs-retry');
  const cfg = { app_id: app.id, env: 'sandbox', slug: app.slug, fail_threshold: 3 };
  assert.equal(backoffRetryDue(cfg), false, 'a stable env keeps the old rule: one restart per failure streak');
  for (const t of [3, 2, 1]) await health(app, 'sandbox', Date.now() - t * 60_000);
  assert.equal(backoffRetryDue(cfg), false, 'unstable, inside the wait');
  db.prepare("UPDATE restart_stability SET next_restart_at = ? WHERE app_id = ? AND env = 'sandbox'").run(ri.sqlTime(Date.now() - 1000), app.id);
  assert.equal(backoffRetryDue(cfg), true);
});

test('backoff: a stable env is restarted at the threshold exactly as before', async () => {
  const app = mkApp('rs-stable');
  writeFileSync(DOCKER_LOG, '');
  const r = await autoRestart({ app_id: app.id, env: 'production', slug: app.slug, fail_threshold: 3 }, { newFails: 3 });
  assert.match(readFileSync(DOCKER_LOG, 'utf8'), /^restart appcrane-rs-stable-production$/m);
  assert.equal(r.incident.trigger, 'health');
});

test('clear: a deploy, a manual restart, or a healthy quiet period clears unstable; a quiet period while still failing does not', async () => {
  const trip = async (app) => { for (const t of [0, 1, 2]) await health(app, 'sandbox', min(t)); assert.equal(ri.getStability({ appId: app.id, env: 'sandbox', now: min(3) }).unstable, true); };

  const a = mkApp('rs-clear-deploy');
  await trip(a);
  db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, 'sandbox', 'live', ?, ?)").run(a.id, ri.sqlTime(min(4)), ri.sqlTime(min(5)));
  const sa = ri.getStability({ appId: a.id, env: 'sandbox', now: min(6) });
  assert.equal(sa.unstable, false);
  assert.match(sa.cleared_reason, /^deployment #\d+$/);
  await new Promise(r => setTimeout(r, 50));
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE app_id = ? AND action = 'restart-loop-cleared'").get(a.id), 'the clear is audited');

  const b = mkApp('rs-clear-manual');
  await trip(b);
  db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail, created_at) VALUES (?, ?, 'restart', ?, ?)")
    .run(owner.id, b.id, JSON.stringify({ params: { slug: b.slug, env: 'production' } }), ri.sqlTime(min(4)));
  assert.equal(ri.getStability({ appId: b.id, env: 'sandbox', now: min(5) }).unstable, true, 'a restart of the OTHER env does not clear it');
  db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail, created_at) VALUES (?, ?, 'restart', ?, ?)")
    .run(owner.id, b.id, JSON.stringify({ params: { slug: b.slug, env: 'sandbox' } }), ri.sqlTime(min(4)));
  assert.equal(ri.getStability({ appId: b.id, env: 'sandbox', now: min(5) }).cleared_reason, 'manual restart');

  const c = mkApp('rs-clear-quiet');
  await trip(c);
  db.prepare("UPDATE health_state SET consecutive_fails = 9 WHERE app_id = ? AND env = 'sandbox'").run(c.id);
  assert.equal(ri.getStability({ appId: c.id, env: 'sandbox', now: min(200) }).unstable, true, 'still failing: not cleared');
  db.prepare("UPDATE health_state SET consecutive_fails = 0 WHERE app_id = ? AND env = 'sandbox'").run(c.id);
  assert.equal(ri.getStability({ appId: c.id, env: 'sandbox', now: min(50) }).unstable, true, 'healthy but inside the quiet hour');
  assert.equal(ri.getStability({ appId: c.id, env: 'sandbox', now: min(200) }).cleared_reason, 'quiet for 60 min');

  for (const t of [201, 202, 203]) await health(c, 'sandbox', min(t));
  assert.equal(ri.getStability({ appId: c.id, env: 'sandbox', now: min(203) }).episode, 2, 'a new loop is a new episode');
  assert.equal(mails(c).length, 2, 'one mail per episode (to the platform admin: no owner)');
});

test('watcher: a die with no kill before it is a crash; a die after a kill is attributed, or left to the path that recorded it', async () => {
  const app = mkApp('rs-watch');
  const ev = (Action, attrs = {}, id = 'c1') => ({ Type: 'container', Action, Actor: { ID: id, Attributes: { name: `appcrane-${app.slug}-sandbox`, slug: app.slug, env: 'sandbox', ...attrs } } });
  const crash = await watcher.handleEvent(ev('die', { exitCode: '3' }), { delayMs: 0 });
  assert.equal(crash.trigger, 'crash');
  assert.equal(crash.summary, 'exited with code 3');
  assert.ok(crash.not_captured.some(x => /cgroup was gone/.test(x)));

  await watcher.handleEvent(ev('oom', {}, 'c2'), { delayMs: 0 });
  const oom = await watcher.handleEvent(ev('die', { exitCode: '137' }, 'c2'), { delayMs: 0 });
  assert.equal(oom.trigger, 'oom');

  db.prepare("INSERT INTO env_sleep (app_id, env, state) VALUES (?, 'sandbox', 'sleeping')").run(app.id);
  await watcher.handleEvent(ev('kill', { signal: '15' }, 'c3'), { delayMs: 0 });
  const slept = await watcher.handleEvent(ev('die', { exitCode: '0' }, 'c3'), { delayMs: 0 });
  assert.equal(slept.trigger, 'sleep');
  assert.equal(slept.summary, 'put to sleep');
  db.prepare("DELETE FROM env_sleep WHERE app_id = ?").run(app.id);

  ri.expectPlanned(app.id, 'sandbox', 'health');
  await watcher.handleEvent(ev('kill', { signal: '15' }, 'c4'), { delayMs: 0 });
  assert.equal(await watcher.handleEvent(ev('die', { exitCode: '137' }, 'c4'), { delayMs: 0 }), null, 'the health checker records its own');

  const other = { Type: 'container', Action: 'die', Actor: { ID: 'x', Attributes: { name: 'appcrane-rs-watch-sandbox-candidate', slug: app.slug, env: 'sandbox', exitCode: '1' } } };
  assert.equal(await watcher.handleEvent(other, { delayMs: 0 }), null, 'only the env container itself');

  const app2 = mkApp('rs-watch2');
  const ev2 = (Action, attrs = {}) => ({ Type: 'container', Action, Actor: { ID: 'd1', Attributes: { name: `appcrane-${app2.slug}-production`, slug: app2.slug, env: 'production', ...attrs } } });
  await watcher.handleEvent(ev2('kill', { signal: '15' }), { delayMs: 0 });
  assert.equal((await watcher.handleEvent(ev2('die', { exitCode: '0' }), { delayMs: 0 })).trigger, 'stop');
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'deploying')").run(app2.id);
  await watcher.handleEvent(ev2('kill', { signal: '15' }), { delayMs: 0 });
  assert.equal((await watcher.handleEvent(ev2('die', { exitCode: '0' }), { delayMs: 0 })).trigger, 'deploy');
});

test('container recovery records a recovery incident for both outcomes', async () => {
  const cr = await import('../server/services/containerRecovery.js');
  const { logAudit } = await import('../server/middleware/audit.js');
  const { assertNoInflightDeploy } = await import('../server/services/deployer.js');
  const app = mkApp('rs-recover');
  const liveId = Number(db.prepare(`INSERT INTO deployments (app_id, env, version, status, commit_hash, release_path, started_at, finished_at)
      VALUES (?, 'sandbox', '1.0.0', 'live', 'abc1234', '/x/r1', datetime('now', '-1 hour'), datetime('now', '-1 hour'))`).run(app.id).lastInsertRowid);
  const t = { app_id: app.id, env: 'sandbox', slug: app.slug, live_id: liveId, version: '1.0.0', commit_hash: 'abc1234', release_path: '/x/r1', source_type: 'managed', name: `appcrane-${app.slug}-sandbox`, state: 'exited' };
  const deps = (deployApp) => ({ db, assertNoInflightDeploy, deployApp, getPortsForSlot: () => ({}), imageCached: async () => true, fileExists: () => true, logAudit, notify: async () => {}, now: () => Date.now() });
  await cr.recoverOne(t, deps(async (id) => { db.prepare("UPDATE deployments SET status = 'live', finished_at = datetime('now') WHERE id = ?").run(id); }));
  await cr.recoverOne(t, deps(async () => { throw new Error('disk full'); }));
  const rows = db.prepare("SELECT trigger, action, summary FROM restart_incidents WHERE app_id = ? ORDER BY id").all(app.id);
  assert.deepEqual(rows, [
    { trigger: 'recovery', action: 'recovered', summary: 'container exited; live release started again' },
    { trigger: 'recovery', action: 'failed', summary: 'container exited; recovery failed: disk full' },
  ]);
  cr.__testables.attempts.clear();
});

test('capture: docker stats first; docker exec (for the OOM counters) only well under the limit; a stopping container\'s "0B" is not its memory', async () => {
  const { readMemory } = await import('../server/services/restartCapture.js');
  const shim = join(SHIM, 'docker');
  const failing = readFileSync(shim, 'utf8');
  const fake = (stats, exec = true) => writeFileSync(shim, `#!/bin/sh\necho "$*" >> "${DOCKER_LOG}"\n` +
    `if [ "$1" = stats ]; then echo "${stats}"; exit 0; fi\n` +
    (exec ? `if [ "$1" = exec ]; then printf '33554432\\n---\\n67108864\\n---\\noom 1\\noom_kill 1\\n'; exit 0; fi\n` : '') +
    'echo "no docker" >&2\nexit 1\n', { mode: 0o755 });
  try {
    fake('0B / 64MiB', false);
    await assert.rejects(readMemory({ name: 'appcrane-x-sandbox', running: true }), /docker stats read 0 B/,
      'a 0B reading from a stopping container is not recorded as its memory');

    fake('61.98MiB / 64MiB');
    writeFileSync(DOCKER_LOG, '');
    const full = await readMemory({ name: 'appcrane-x-sandbox', running: true });
    assert.equal(full.source, 'docker-stats');
    assert.equal(Math.floor(full.current / full.max * 100), 96);
    assert.doesNotMatch(readFileSync(DOCKER_LOG, 'utf8'), /^exec /m, 'no process is started inside a container at its limit');

    fake('20MiB / 64MiB');
    const roomy = await readMemory({ name: 'appcrane-x-sandbox', running: true });
    assert.deepEqual([roomy.source, roomy.current, roomy.max, roomy.oom_kill], ['docker-exec', 32 * MiB, 64 * MiB, 1]);

    writeFileSync(shim, failing, { mode: 0o755 });
    await assert.rejects(readMemory({ name: 'appcrane-x-sandbox', running: true }), /docker stats: no docker; docker exec: no docker/);
  } finally {
    writeFileSync(shim, failing, { mode: 0o755 });
  }
});

test('image trust refusal: an enforce-mode refusal of the auto-restart is recorded as restart_refused, docker restart never runs, no restart-loop mail', async () => {
  const app = mkApp('rs-refused');
  grant(app, owner, 'owner');
  const shim = join(SHIM, 'docker');
  const failing = readFileSync(shim, 'utf8');
  writeFileSync(shim, `#!/bin/sh\necho "$*" >> "${DOCKER_LOG}"\ncase "$*" in *'{{.Image}}'*) echo "sha256:${'a'.repeat(64)}|appcrane/rs-refused:abc|appcrane/rs-refused:abc"; exit 0;; esac\necho "no docker" >&2\nexit 1\n`, { mode: 0o755 });
  db.prepare("INSERT INTO settings (key, value) VALUES ('image_trust_mode', 'enforce')").run();
  writeFileSync(DOCKER_LOG, '');
  try {
    const r = await autoRestart({ app_id: app.id, env: 'sandbox', slug: app.slug, fail_threshold: 3 }, { newFails: 3, probeError: 'ECONNREFUSED' });
    assert.equal(r.outcome, 'refused', JSON.stringify(r));
    assert.equal(r.incident.trigger, 'restart_refused');
    assert.equal(r.incident.action, 'failed');
    assert.match(r.incident.summary, /^auto-restart refused by image trust: refusing to start rs-refused\/sandbox restart: UNSIGNED: no signature/);
    assert.doesNotMatch(readFileSync(DOCKER_LOG, 'utf8'), /^restart /m, 'docker restart was not run');
    for (let i = 0; i < 3; i++) await autoRestart({ app_id: app.id, env: 'sandbox', slug: app.slug, fail_threshold: 3 }, { newFails: 3 });
    assert.equal(ri.getStability({ appId: app.id, env: 'sandbox' }).unstable, false, 'a refusal is not a restart: no loop');
    assert.equal(mails(app).length, 0);
    assert.equal(ri.incidentCounts({ appId: app.id, env: 'sandbox', sinceMs: 0 }).refused, 4);
  } finally {
    db.prepare("DELETE FROM settings WHERE key = 'image_trust_mode'").run();
    writeFileSync(shim, failing, { mode: 0o755 });
  }
});

test('probe timers: runCheck drops the timer of a disabled env or a deleted app', async () => {
  const hc = await import('../server/services/healthChecker.js');
  const app = mkApp('rs-timer');
  hc.refreshAppChecks(app.id);
  assert.equal(hc.isCheckScheduled(app.id, 'sandbox'), true);
  db.prepare("UPDATE health_configs SET enabled = 0 WHERE app_id = ? AND env = 'sandbox'").run(app.id);
  await hc.runCheck({ app_id: app.id, env: 'sandbox', slug: app.slug, slot: app.slot, fail_threshold: 3, down_threshold: 5, endpoint: '/api/health' });
  assert.equal(hc.isCheckScheduled(app.id, 'sandbox'), false, 'disabled at runtime');
  assert.equal(hc.isCheckScheduled(app.id, 'production'), true);
  db.prepare('DELETE FROM apps WHERE id = ?').run(app.id);
  await hc.runCheck({ app_id: app.id, env: 'production', slug: app.slug, slot: app.slot, fail_threshold: 3, down_threshold: 5, endpoint: '/api/health' });
  assert.equal(hc.isCheckScheduled(app.id, 'production'), false, 'app deleted');
});

test('retention: incidents past the window go, and each env keeps at most the cap', () => {
  const app = mkApp('rs-retention');
  const ins = db.prepare("INSERT INTO restart_incidents (app_id, env, trigger, action, kind, summary, created_at) VALUES (?, ?, 'crash', 'observed', 'exit', 'x', ?)");
  ins.run(app.id, 'sandbox', ri.sqlTime(Date.now() - 91 * 86_400_000));
  for (let i = 0; i < 5; i++) ins.run(app.id, 'production', ri.sqlTime(Date.now() - i * 1000));
  const before = db.prepare('SELECT COUNT(*) AS n FROM restart_incidents').get().n;
  const r = ri.pruneIncidents({ cap: 3 });
  assert.ok(r.aged >= 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM restart_incidents WHERE app_id = ? AND env = 'production'").get(app.id).n, 3);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM restart_incidents WHERE app_id = ? AND env = 'sandbox'").get(app.id).n, 0);
  assert.ok(db.prepare('SELECT COUNT(*) AS n FROM restart_incidents').get().n < before);
});

// ── HTTP ──────────────────────────────────────────────────────────────────

const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api', (await import('../server/routes/restartIncidents.js')).default);
api.use('/api/apps', (await import('../server/routes/health.js')).default);
api.use(errorHandler);
const server = await new Promise(r => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  server.closeAllConnections?.(); server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});
async function call(as, path) {
  const res = await fetch(`${BASE}${path}`, { headers: as ? { 'X-API-Key': as.key } : {} });
  return { status: res.status, body: await res.json().catch(() => null) };
}

const routeApp = mkApp('rs-route');
grant(routeApp, owner, 'owner'); grant(routeApp, appAdmin, 'admin'); grant(routeApp, member, 'user');
await health(routeApp, 'sandbox', Date.now() - 60_000, [507 * MiB, 512 * MiB]);
await ri.recordIncident({ appId: routeApp.id, env: 'production', trigger: 'crash', action: 'observed', capture: { log_tail: ['prod line'] }, detail: { exit_code: 1 } });

test('GET incidents: owner and platform admin get the log tail; app admin and member get summaries only; outsider 403; anonymous 401; unknown 404', async () => {
  for (const u of [owner, admin]) {
    const r = await call(u, `/api/apps/${routeApp.slug}/incidents?env=sandbox`);
    assert.equal(r.status, 200, u.name);
    assert.equal(r.body.log_tail_visible, true);
    assert.equal(r.body.incidents.length, 1);
    assert.deepEqual(r.body.incidents[0].log_tail, ['2026-11-24T14:11:00Z heap at 507MB']);
    assert.equal(r.body.incidents[0].summary, 'memory 99% of 512 MB (health check failed 3 times: ECONNREFUSED)');
    assert.equal(r.body.envs.sandbox.last_incident.summary, 'memory 99% of 512 MB (health check failed 3 times: ECONNREFUSED)');
    assert.equal(r.body.envs.sandbox.last_7_days.unplanned, 1);
    assert.equal(r.body.envs.production, undefined, 'env filter');
  }
  for (const u of [appAdmin, member]) {
    const r = await call(u, `/api/apps/${routeApp.slug}/incidents`);
    assert.equal(r.status, 200, u.name);
    assert.equal(r.body.log_tail_visible, false);
    assert.equal(r.body.incidents.length, 2);
    for (const i of r.body.incidents) assert.equal('log_tail' in i, false, `${u.name} must not see container output`);
    assert.equal(r.body.incidents.find(i => i.env === 'sandbox').memory.current, 507 * MiB, 'the figures are not secret');
  }
  assert.equal((await call(outsider, `/api/apps/${routeApp.slug}/incidents`)).status, 403);
  assert.equal((await call(null, `/api/apps/${routeApp.slug}/incidents`)).status, 401);
  assert.equal((await call(owner, '/api/apps/rs-nope/incidents')).status, 404);
  assert.equal((await call(owner, `/api/apps/${routeApp.slug}/incidents?env=b-production`)).status, 400);
});

test('GET health/:env carries last_incident and unstable', async () => {
  const r = await call(member, `/api/apps/${routeApp.slug}/health/sandbox`);
  assert.equal(r.status, 200);
  assert.equal(r.body.unstable, false);
  assert.equal(r.body.last_incident.summary, 'memory 99% of 512 MB (health check failed 3 times: ECONNREFUSED)');
  assert.equal(r.body.last_incident.trigger, 'health');
  assert.ok(r.body.last_incident.created_at);
  const p = await call(member, `/api/apps/${routeApp.slug}/health/production`);
  assert.equal(p.body.last_incident.trigger, 'crash');
  assert.equal(existsSync(ROOT), true);
});

test('MCP appcrane_get_health carries last_incident and unstable', async () => {
  const { callTool } = await import('../server/services/mcpTools.js');
  const r = await callTool(member, 'appcrane_get_health', { slug: routeApp.slug, env: 'sandbox' });
  const out = JSON.parse(r.content[0].text);
  assert.equal(out.unstable, false);
  assert.equal(out.last_incident.summary, 'memory 99% of 512 MB (health check failed 3 times: ECONNREFUSED)');
});

test('PUT health/:env takes effect at once: disabling drops the probe timer, enabling schedules it again', async () => {
  const hc = await import('../server/services/healthChecker.js');
  const app = mkApp('rs-put');
  grant(app, owner, 'owner');
  hc.refreshAppChecks(app.id);
  assert.equal(hc.isCheckScheduled(app.id, 'sandbox'), true);
  const put = (body) => fetch(`${BASE}/api/apps/${app.slug}/health/sandbox`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-API-Key': owner.key }, body: JSON.stringify(body) });
  assert.equal((await put({ enabled: false })).status, 200);
  assert.equal(hc.isCheckScheduled(app.id, 'sandbox'), false);
  assert.equal(hc.isCheckScheduled(app.id, 'production'), true, 'the other env is untouched');
  assert.equal((await put({ enabled: true })).status, 200);
  assert.equal(hc.isCheckScheduled(app.id, 'sandbox'), true);
  hc.stopHealthChecker();
});
