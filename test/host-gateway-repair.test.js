import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The host-gateway Job Health run recreates the app containers whose
// /etc/hosts maps host.docker.internal to "invalid IP" (measured in production
// after a dockerd reload), through the same recreateEnvContainer the Restart
// button uses. Docker and the recreation are injected; the database, the
// settings, every guard (deploy rows, the restore lock, a restart in flight,
// sleep state, a sleep in flight) and the audit and incident rows are real.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-hostgw-repair-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.HOST_GATEWAY_IP;

// A `docker` on PATH for the real restart held in flight by guard (b): it waits
// while the gate file exists, then fails (no container), touching nothing.
const SHIM = join(ROOT, 'bin');
const GATE = join(ROOT, 'docker-gate');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const wait = () => { if (fs.existsSync(${JSON.stringify(GATE)})) return setTimeout(wait, 10); process.exit(1); };
wait();
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const hg = await import('../server/services/hostGateway.js');
const jh = await import('../server/services/jobHealth.js');
const { recreateEnvContainer } = await import('../server/services/containerRecreate.js');
const { runWithAppStopped, __resetRestoreLocksForTests } = await import('../server/services/managedDbRestoreGuard.js');
const envWake = await import('../server/services/envWake.js');

const HOSTS_OK = '127.0.0.1\tlocalhost\n172.17.0.1\thost.docker.internal\n';
const HOSTS_BROKEN = '127.0.0.1\tlocalhost\ninvalid IP\thost.docker.internal\n';

let slot = 10;
function addApp(slug) {
  return db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES (?, ?, ?, 'managed', 'main')").run(slug, slug, slot++).lastInsertRowid;
}

// A fake daemon whose containers' /etc/hosts the fake recreate rewrites.
function world({ gateway = '172.17.0.1 ', gatewayError = null, gatewayOkReads = Infinity, os = 'Ubuntu 22.04.4 LTS', containers = {}, fixes = true, recreateError = null } = {}) {
  const hosts = { ...containers };
  const calls = [];
  const recreated = [];
  let active = 0;
  let maxActive = 0;
  const exec = (args) => {
    calls.push(args);
    if (args[0] === 'info') return `${os}\n`;
    if (args[0] === 'network') {
      if (gatewayOkReads-- <= 0) { const e = new Error('Command failed'); e.stderr = 'Error response from daemon: network bridge not found'; throw e; }
      if (gatewayError) { const e = new Error('Command failed'); e.stderr = gatewayError; throw e; }
      return `${gateway}\n`;
    }
    if (args[0] === 'ps') return Object.keys(hosts).join('\n') + '\n';
    if (args[0] === 'exec') return hosts[args[1]];
    throw new Error(`unexpected docker ${args.join(' ')}`);
  };
  const recreate = async (args) => {
    if (args.precheck) { const no = await args.precheck(); if (no) throw Object.assign(new Error(`Not recreated: ${no}. The running container was left alone.`), { code: 'RECREATE_SKIPPED' }); }
    args.onStop?.();
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise((r) => setTimeout(r, 5));
    recreated.push(args);
    active--;
    if (recreateError) throw new Error(recreateError);
    if (fixes) hosts[`appcrane-${args.app.slug}-${args.env}`] = HOSTS_OK;
  };
  return { exec, recreate, calls, recreated, hosts, maxActive: () => maxActive };
}

let clock = Date.parse('2026-11-25T10:00:00Z');

function install(w) {
  hg._setHostGatewayExecForTests(w.exec);
  hg._setRepairDepsForTests({
    recreate: w.recreate,
    now: () => clock,
    notify: async (m) => { notices.push(m); },
  });
}

async function run() {
  jh.jobStarted('host-gateway', { cadenceMs: 3_600_000 });
  let error = null;
  try { await jh.trackJob('host-gateway', () => hg.runHostGatewayCheck()); } catch (e) { error = e; }
  return { error, job: jh.getJobHealth().find((j) => j.id === 'host-gateway') };
}

const notices = [];
const auditRows = (action) => db.prepare('SELECT * FROM audit_log WHERE action = ? ORDER BY id').all(action);

after(() => {
  hg._setHostGatewayExecForTests(null);
  hg._setRepairDepsForTests(null);
  rmSync(ROOT, { recursive: true, force: true });
});

beforeEach(() => {
  jh._resetJobHealthForTests();
  hg._resetHostGatewayCacheForTests();
  db.prepare('DELETE FROM apps').run();
  db.prepare("DELETE FROM settings WHERE key IN ('host_gateway_auto_repair', 'host_gateway_repairs')").run();
  db.prepare('DELETE FROM audit_log').run();
  db.prepare('DELETE FROM restart_incidents').run();
  notices.length = 0;
  clock += 24 * 3_600_000;
});

test('a broken app container is recreated as the system actor, re-read, and the run passes', async () => {
  const appId = addApp('voip');
  const w = world({ containers: { 'appcrane-voip-production': HOSTS_BROKEN, 'appcrane-fine-sandbox': HOSTS_OK } });
  install(w);
  const { error, job } = await run();
  assert.equal(error, null, error?.message);
  assert.equal(job.status, 'ok');
  assert.equal(w.recreated.length, 1);
  assert.equal(w.recreated[0].app.id, appId);
  assert.equal(w.recreated[0].env, 'production');
  assert.equal(w.recreated[0].actor, 'system:host-gateway');
  assert.equal(w.recreated[0].reason, 'host-gateway-repair');
  const reads = w.calls.filter((a) => a[0] === 'exec' && a[1] === 'appcrane-voip-production');
  assert.equal(reads.length, 2, 'the container was not read again after the recreate');
  assert.deepEqual(job.detail.repaired.map((x) => [x.name, x.outcome]), [['appcrane-voip-production', 'fixed']]);
  assert.match(job.detail.message, /Recreated and fixed \(1\): appcrane-voip-production/);
  const restart = auditRows('restart');
  assert.equal(restart.length, 1);
  assert.equal(restart[0].app_id, appId);
  assert.equal(restart[0].actor_kind, 'system');
  assert.match(restart[0].detail, /"env":"production"/, 'the restart watcher matches a planned restart on this');
  const done = auditRows('host-gateway-repair');
  assert.equal(done.length, 1);
  assert.equal(JSON.parse(done[0].detail).outcome, 'fixed');
  const inc = db.prepare('SELECT * FROM restart_incidents').all();
  assert.equal(inc.length, 1, 'no restart incident was recorded');
  assert.deepEqual([inc[0].app_id, inc[0].env, inc[0].trigger, inc[0].action, inc[0].kind, inc[0].summary],
    [appId, 'production', 'host-gateway-repair', 'restarted', 'planned', 'recreated to repair host.docker.internal']);
  assert.deepEqual(notices.map((m) => [m.appId, m.env, m.outcome]), [[appId, 'production', 'fixed']]);
});

test('only app environment containers are recreated; helpers and unknown slugs are listed and fail the run', async () => {
  addApp('real');
  const w = world({
    containers: {
      'appcrane-real-sandbox': HOSTS_BROKEN,
      'appcrane-db-postgres': HOSTS_BROKEN,
      'appcrane-crew-coder-real': HOSTS_BROKEN,
      'appcrane-ghost-production': HOSTS_BROKEN,
    },
  });
  install(w);
  const { error, job } = await run();
  assert.deepEqual(w.recreated.map((r) => r.app.slug), ['real']);
  assert.deepEqual(job.detail.not_repaired.map((x) => x.name).sort(),
    ['appcrane-crew-coder-real', 'appcrane-db-postgres', 'appcrane-ghost-production']);
  assert.ok(job.detail.not_repaired.every((x) => /not an app environment container/.test(x.reason)));
  assert.equal(job.status, 'failing');
  assert.match(error.message, /3 container\(s\) still cannot resolve/);
  assert.match(job.detail.message, /Restart on the app page stops, removes and starts a new container/);
});

test('host_gateway_auto_repair off: nothing is recreated and the run fails with the reason', async () => {
  addApp('voip');
  db.prepare("INSERT INTO settings (key, value) VALUES ('host_gateway_auto_repair', '0')").run();
  const w = world({ containers: { 'appcrane-voip-production': HOSTS_BROKEN } });
  install(w);
  const { error, job } = await run();
  assert.equal(w.recreated.length, 0);
  assert.ok(error);
  assert.match(job.detail.not_repaired[0].reason, /auto-repair is off \(host_gateway_auto_repair\)/);
});

test('guard (a): a fallback gateway or Docker Desktop host-gateway is never recreated into', async () => {
  addApp('voip');
  for (const opts of [{ gatewayError: 'Error response from daemon: network bridge not found' }, { os: 'Docker Desktop' }]) {
    hg._resetHostGatewayCacheForTests();
    jh._resetJobHealthForTests();
    const w = world({ ...opts, containers: { 'appcrane-voip-production': HOSTS_BROKEN } });
    install(w);
    const { error, job } = await run();
    assert.equal(w.recreated.length, 0, JSON.stringify(opts));
    assert.ok(error);
    assert.match(job.detail.not_repaired[0].reason, /new containers would get host\.docker\.internal:host-gateway/);
  }
});

test('guard (b): deploy of any age, restore, restart, sleep in progress and a sleeping env each skip the container (real guards)', async () => {
  const appId = addApp('voip');
  const app = () => db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  const hold = () => { let open; const p = new Promise((r) => { open = r; }); return { p, open }; };
  const cases = [
    ['a deploy is in progress', async () => {
      db.prepare("INSERT INTO deployments (app_id, env, status, started_at) VALUES (?, 'production', 'building', datetime('now', '-2 hours'))").run(appId);
      return () => db.prepare('DELETE FROM deployments').run();
    }],
    ['a database restore is in progress', async () => {
      const h = hold();
      const p = runWithAppStopped({ app: app(), envs: ['production'], keepRunning: true }, () => h.p);
      return async () => { h.open(); await p; };
    }],
    ['a restart is in progress', async () => {
      writeFileSync(GATE, '');
      const p = recreateEnvContainer({ app: app(), env: 'production', actor: { id: 1 } }).catch(() => {});
      return async () => { rmSync(GATE); await p; };
    }],
    ['a sleep or wake is in progress', async () => {
      const h = hold();
      envWake._setWakeDepsForTests({ db, docker: () => h.p, invalidate: async () => {}, audit: async () => {} });
      const p = envWake.sleepEnv(app(), 'production', 'idle');
      return async () => { h.open(); await p; envWake._setWakeDepsForTests(null); db.prepare('DELETE FROM env_sleep').run(); };
    }],
    ['the environment is asleep or waking', async () => {
      db.prepare("INSERT INTO env_sleep (app_id, env, state) VALUES (?, 'production', 'waking')").run(appId);
      return () => db.prepare('DELETE FROM env_sleep').run();
    }],
  ];
  for (const [reason, on] of cases) {
    jh._resetJobHealthForTests();
    const w = world({ containers: { 'appcrane-voip-production': HOSTS_BROKEN } });
    install(w);
    const off = await on();
    const { error, job } = await run();
    await off();
    assert.equal(w.recreated.length, 0, `recreated while ${reason}`);
    assert.ok(error, reason);
    assert.equal(job.detail.not_repaired[0].reason, reason);
  }
  assert.ok(!existsSync(GATE));
  __resetRestoreLocksForTests();
});

test('guard (c): the same container is recreated at most once in 6 hours, persisted in settings', async () => {
  addApp('voip');
  const w = world({ containers: { 'appcrane-voip-production': HOSTS_BROKEN } });
  install(w);
  assert.equal((await run()).error, null);
  assert.equal(w.recreated.length, 1);
  const state = JSON.parse(db.prepare("SELECT value FROM settings WHERE key = 'host_gateway_repairs'").get().value);
  assert.equal(state['appcrane-voip-production'], clock);

  w.hosts['appcrane-voip-production'] = HOSTS_BROKEN;
  clock += 60 * 60_000;
  jh._resetJobHealthForTests();
  const second = await run();
  assert.equal(w.recreated.length, 1, 'recreated again inside 6 hours');
  assert.match(second.job.detail.not_repaired[0].reason, /at most once in 6 hours/);
  assert.ok(second.error);

  clock += 6 * 60 * 60_000;
  jh._resetJobHealthForTests();
  assert.equal((await run()).error, null);
  assert.equal(w.recreated.length, 2, 'not recreated once the 6 hours had passed');
});

test('guard (d): at most 3 recreations per run, one at a time', async () => {
  const containers = {};
  for (const s of ['a1', 'a2', 'a3', 'a4', 'a5']) { addApp(s); containers[`appcrane-${s}-sandbox`] = HOSTS_BROKEN; }
  const w = world({ containers });
  install(w);
  const { error, job } = await run();
  assert.equal(w.recreated.length, 3);
  assert.equal(w.maxActive(), 1, 'recreations overlapped');
  assert.equal(job.detail.repaired.length, 3);
  assert.equal(job.detail.not_repaired.length, 2);
  assert.ok(job.detail.not_repaired.every((x) => /3 recreated in this run already/.test(x.reason)));
  assert.ok(error, 'two are still broken');
});

test('re-check: a recreate that leaves the mapping broken, or throws, is reported still broken and fails the run', async () => {
  addApp('voip');
  for (const opts of [{ fixes: false }, { recreateError: 'IMAGE_UNTRUSTED: refused' }]) {
    db.prepare("DELETE FROM settings WHERE key = 'host_gateway_repairs'").run();
    jh._resetJobHealthForTests();
    const w = world({ ...opts, containers: { 'appcrane-voip-production': HOSTS_BROKEN } });
    install(w);
    const { error, job } = await run();
    assert.equal(w.recreated.length, 1);
    assert.ok(error, JSON.stringify(opts));
    assert.equal(job.detail.still_broken[0].outcome, 'still broken');
    assert.equal(job.detail.repaired.length, 0);
    if (opts.recreateError) assert.match(job.detail.still_broken[0].error, /recreate failed: IMAGE_UNTRUSTED/);
  }
});

test('the gateway decision is read again before each recreate and right before the stop; a fallback then skips it', async () => {
  addApp('voip');
  // Read 1 is the check's own decision. Read 2 (before the recreate) fails: skipped, nothing recorded.
  let w = world({ gatewayOkReads: 1, containers: { 'appcrane-voip-production': HOSTS_BROKEN } });
  install(w);
  let r = await run();
  assert.equal(w.recreated.length, 0);
  assert.match(r.job.detail.not_repaired[0].reason, /new containers would get host\.docker\.internal:host-gateway \(fallback\)/);
  // Read 3 (the recreate's precheck, right before the stop) fails: aborted before the stop.
  hg._resetHostGatewayCacheForTests();
  jh._resetJobHealthForTests();
  w = world({ gatewayOkReads: 2, containers: { 'appcrane-voip-production': HOSTS_BROKEN } });
  install(w);
  r = await run();
  assert.equal(w.recreated.length, 0, 'stopped although the precheck said the mapping would not be fixed');
  assert.match(r.job.detail.not_repaired[0].reason, /new containers would get host\.docker\.internal:host-gateway/);
  assert.ok(r.error);
  assert.equal(auditRows('restart').length, 0, 'a restart was audited for a recreate that never stopped anything');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM restart_incidents').get().n, 0);
  assert.equal(notices.length, 0);
  assert.equal(JSON.parse(db.prepare("SELECT value FROM settings WHERE key = 'host_gateway_repairs'").get().value)['appcrane-voip-production'], undefined,
    'an aborted recreate still counts against the 6 hour window');
});

test('the owner notice: one plain mail per repaired environment to the app owners', async () => {
  const { notifyHostGatewayRepair } = await import('../server/services/hostGatewayRepairMail.js');
  const appId = addApp('voip');
  db.prepare("DELETE FROM users WHERE email LIKE '%@gw.test'").run();
  const uid = db.prepare("INSERT INTO users (name, email, role, active) VALUES ('Owner', 'owner@gw.test', 'user', 1)").run().lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')").run(appId, uid);
  db.prepare("INSERT INTO users (name, email, role, active) VALUES ('Admin', 'admin@gw.test', 'platform_admin', 1)").run();
  const at = clock;
  for (let i = 0; i < 2; i++) {
    await notifyHostGatewayRepair({ db, appId, env: 'production', outcome: 'fixed', lineBefore: 'invalid IP\thost.docker.internal', lineAfter: '172.17.0.1\thost.docker.internal', at });
  }
  const mails = db.prepare("SELECT * FROM email_queue WHERE source = 'host-gateway-repair' AND app_id = ?").all(appId);
  assert.equal(mails.length, 1, 'not exactly one mail per repaired environment');
  assert.equal(mails[0].to_email, 'owner@gw.test');
  assert.match(mails[0].subject, /voip \(production\) was restarted to repair host\.docker\.internal/);
  assert.match(mails[0].body_text, /Result: fixed/);
  assert.doesNotMatch(mails[0].body_text, /[—…“”]/);
});
