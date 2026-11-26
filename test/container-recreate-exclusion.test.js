import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// While AppCrane recreates an environment on its own (the host-gateway repair,
// a system actor), nothing else may replace or stop that container: the
// Restart route answers 409, a database restore refuses, a second automatic
// recreate refuses, the env sleeper skips the env, and a deploy's container
// swap waits (bounded). The recreate is real and held in flight by a docker
// shim that blocks while a gate file exists.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-recreate-excl-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
const GATE = join(ROOT, 'gate');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const wait = () => { if (fs.existsSync(${JSON.stringify(GATE)})) return setTimeout(wait, 10); process.exit(1); };
wait();
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const KEY = generateApiKey('dhk_user');
const uid = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES ('o','o@t.test','user',1,?)").run(hashApiKey(KEY)).lastInsertRowid;
const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES ('X', 'excl', 5, 'managed', 'main')").run().lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, uid);
db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, 'sandbox', 'live', datetime('now', '-30 days'), datetime('now', '-30 days'))").run(appId);
const app = () => db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);

const cr = await import('../server/services/containerRecreate.js');
const { runWithAppStopped } = await import('../server/services/managedDbRestoreGuard.js');
const policy = await import('../server/services/sleepPolicy.js');
const activity = await import('../server/services/envActivity.js');
const sleeper = await import('../server/services/envSleeper.js');
const wake = await import('../server/services/envWake.js');
const sleptCalls = [];
wake._setWakeDepsForTests({ db, docker: async (args) => { sleptCalls.push(args.join(' ')); return ''; }, invalidate: async () => {}, audit: async () => {}, notifyInactive: async () => {} });

const deployRoutes = (await import('../server/routes/deploy.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', deployRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(async () => {
  wake._setWakeDepsForTests(null);
  server.closeAllConnections?.(); server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  rmSync(ROOT, { recursive: true, force: true });
});
const restart = (env) => fetch(`http://127.0.0.1:${server.address().port}/api/apps/excl/restart/${env}`, { method: 'POST', headers: { 'x-api-key': KEY } });

const MIN = 60_000;
const T0 = Date.now();

test('an automatic recreate in flight excludes restart, restore, a second recreate and the sleeper; a deploy swap waits for it', async () => {
  policy.setAppPolicy(db, appId, { sandbox_idle_minutes: 15 }, null);
  activity.noteRequest(appId, 'sandbox', null, T0);
  const listContainers = async () => new Map([['appcrane-excl-sandbox', 'running']]);

  writeFileSync(GATE, '');
  const held = cr.recreateEnvContainer({ app: app(), env: 'sandbox', actor: 'system:host-gateway', reason: 'host-gateway-repair' }).catch((e) => e);
  assert.ok(cr.automaticRecreateInFlight(appId, 'sandbox'));

  const r = await restart('sandbox');
  const body = await r.json();
  assert.equal(r.status, 409, JSON.stringify(body));
  assert.equal(body.error?.code ?? body.code, 'RECREATE_IN_PROGRESS', JSON.stringify(body));
  assert.match(JSON.stringify(body), /AppCrane is recreating the excl sandbox container automatically \(host\.docker\.internal repair\)\. Try again in a minute\./);

  let worked = false;
  await assert.rejects(runWithAppStopped({ app: app(), envs: ['sandbox'], keepRunning: true }, async () => { worked = true; }), (e) => e.code === 'RECREATE_IN_PROGRESS' && e.status === 409);
  assert.equal(worked, false, 'the restore ran beside the recreate');

  await assert.rejects(cr.recreateEnvContainer({ app: app(), env: 'sandbox', actor: 'system:host-gateway' }), (e) => e.code === 'RECREATE_IN_PROGRESS');

  const s1 = await sleeper.runSleeper({ now: () => T0 + 20 * MIN, listContainers, processStart: 0 });
  assert.deepEqual(s1.skipped, [{ name: 'appcrane-excl-sandbox', why: 'busy' }]);
  assert.deepEqual(sleptCalls, [], 'the sleeper stopped the container mid-recreate');

  const logs = [];
  await assert.rejects(cr.waitForAutomaticRecreate(app(), 'sandbox', { timeoutMs: 50, onWait: (l) => logs.push(l) }), (e) => e.code === 'RECREATE_IN_PROGRESS' && /still running after 0 s, so nothing was stopped/.test(e.message));
  assert.match(logs[0], /Waiting for AppCrane's automatic recreate of excl sandbox/);
  const waited = cr.waitForAutomaticRecreate(app(), 'sandbox', { timeoutMs: 20_000 });
  let waitedDone = false;
  waited.then(() => { waitedDone = true; });
  await new Promise((res) => setTimeout(res, 50));
  assert.equal(waitedDone, false, 'the deploy swap did not wait');

  rmSync(GATE);
  await held;
  await waited;
  assert.equal(cr.automaticRecreateInFlight(appId, 'sandbox'), null);

  assert.notEqual((await restart('sandbox')).status, 409, 'still refused after the recreate ended');
  const s2 = await sleeper.runSleeper({ now: () => T0 + 21 * MIN, listContainers, processStart: 0 });
  assert.equal(s2.slept.length, 1, JSON.stringify(s2));
});

test('a manual restart in flight does not refuse another manual restart (unchanged), but does refuse the automatic one', async () => {
  writeFileSync(GATE, '');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
  const held = cr.recreateEnvContainer({ app: app(), env: 'production', actor: user }).catch((e) => e);
  assert.equal(cr.automaticRecreateInFlight(appId, 'production'), null);
  assert.ok(cr.recreateInFlight(appId, 'production'));
  await assert.rejects(cr.recreateEnvContainer({ app: app(), env: 'production', actor: 'system:host-gateway' }), (e) => e.code === 'RECREATE_IN_PROGRESS');
  const second = cr.recreateEnvContainer({ app: app(), env: 'production', actor: user }).catch((e) => e);
  rmSync(GATE);
  assert.equal((await held).code, 'NO_CONTAINER');
  assert.equal((await second).code, 'NO_CONTAINER');
  assert.equal(cr.recreateInFlight(appId, 'production'), false);
});
