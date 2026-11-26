import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

// Scenario A of the review: a deploy that starts while the host-gateway repair
// is recreating the same environment must end with the deploy's image running,
// never the old one the repair captured. Real database rows, the real
// runHostGatewayCheck, the real recreateEnvContainer and a real deployApp of an
// image app; Docker is a recording shim on PATH that keeps one piece of state
// (which image the container runs) and can pause one command.
//
//   A1  the deploy row appears before the repair's stop: the repair re-checks
//       right before dockerStop, aborts, and stops nothing.
//   A2  the deploy reaches its own container swap after the repair's stop:
//       deployApp waits for the repair, then replaces its container.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-hostgw-race-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.HOST_GATEWAY_IP;

const OLD = `old@sha256:${'aa'.repeat(32)}`;
const NEW = `kc@sha256:${'c3'.repeat(32)}`;
const SHIM = join(ROOT, 'bin');
const LOG = join(ROOT, 'docker.log');
const STATE = join(ROOT, 'running-image');
const PAUSE = join(ROOT, 'pause');
const WAITING = join(ROOT, 'waiting');
const RELEASE = join(ROOT, 'release');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const fs = require('fs');
const a = process.argv.slice(2);
const j = a.join(' ');
const out = (s) => { process.stdout.write(s); process.exit(0); };
fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify(a) + '\\n');
const pause = fs.existsSync(${JSON.stringify(PAUSE)}) ? fs.readFileSync(${JSON.stringify(PAUSE)}, 'utf8') : null;
const finish = () => {
  if (a[0] === 'run') {
    const img = a.includes(${JSON.stringify(OLD)}) ? 'OLD' : a.includes(${JSON.stringify(NEW)}) ? 'NEW' : null;
    if (img && !j.includes('appcrane-roothelper')) { fs.writeFileSync(${JSON.stringify(STATE)}, img); fs.appendFileSync(${JSON.stringify(LOG)}, JSON.stringify(['done-run', img]) + '\\n'); }
    out('0123456789abcdef\\n');
  }
  if (a[0] === 'stop' || (a[0] === 'rm' && a[1] === '-f')) { fs.writeFileSync(${JSON.stringify(STATE)}, ''); out(''); }
  if (a[0] === 'inspect' && j.includes('.Config.Env')) out('[]\\n');
  if (a[0] === 'inspect' && j.includes('.Config.Image')) {
    const s = fs.existsSync(${JSON.stringify(STATE)}) ? fs.readFileSync(${JSON.stringify(STATE)}, 'utf8') : '';
    if (!s) process.exit(1);
    const ref = s === 'OLD' ? ${JSON.stringify(OLD)} : ${JSON.stringify(NEW)};
    out(ref + '|' + ref + '\\n');
  }
  if (a[0] === 'image' && a[1] === 'inspect') out(${JSON.stringify(NEW)} + '\\n');
  if (a[0] === 'network' && a[1] === 'inspect') out('false|172.20.0.0/16\\n');
  if (a[0] === 'images') out('');
  out('0123456789abcdef\\n');
};
const match = pause && ((pause === 'env' && a[0] === 'inspect' && j.includes('.Config.Env'))
  || (pause === 'run-old' && a[0] === 'run' && a.includes(${JSON.stringify(OLD)})));
if (!match) finish();
fs.rmSync(${JSON.stringify(PAUSE)});
fs.writeFileSync(${JSON.stringify(WAITING)}, '');
const wait = () => { if (!fs.existsSync(${JSON.stringify(RELEASE)})) return setTimeout(wait, 10); fs.rmSync(${JSON.stringify(RELEASE)}); fs.rmSync(${JSON.stringify(WAITING)}); finish(); };
wait();
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};
const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();
const hg = await import('../server/services/hostGateway.js');
const jh = await import('../server/services/jobHealth.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

const HOSTS_BROKEN = '127.0.0.1\tlocalhost\ninvalid IP\thost.docker.internal\n';
const HOSTS_OK = '127.0.0.1\tlocalhost\n172.17.0.1\thost.docker.internal\n';
// The check's own docker calls (ps, exec cat /etc/hosts, the gateway decision).
hg._setHostGatewayExecForTests((args) => {
  if (args[0] === 'info') return 'Ubuntu 22.04.4 LTS\n';
  if (args[0] === 'network') return '172.17.0.1 \n';
  if (args[0] === 'ps') return 'appcrane-race-sandbox\n';
  if (args[0] === 'exec') return lines().some((l) => l[0] === 'done-run') ? HOSTS_OK : HOSTS_BROKEN;
  throw new Error(`unexpected ${args.join(' ')}`);
});

const servers = [];
let slot = null;
let userId;
before(async () => {
  const listen = (port) => new Promise((res) => {
    const s = http.createServer((req, out) => { out.writeHead(200, { 'content-type': 'application/json' }); out.end('{"status":"ok"}'); });
    s.on('error', () => res(null));
    s.listen(port, '127.0.0.1', () => res(s));
  });
  for (let s = 13300; s < 13400 && slot === null; s++) {
    const sand = await listen(getPortsForSlot(s).sand_be);
    if (sand) { slot = s; servers.push(sand); }
  }
  assert.ok(slot !== null, 'no free slot');
  userId = db.prepare("INSERT INTO users (name,email,role,active,kind) VALUES ('U','race@t.test','platform_admin',1,'human')").run().lastInsertRowid;
});
after(() => {
  hg._setHostGatewayExecForTests(null);
  for (const s of servers) { s.closeAllConnections?.(); s.close(); }
  rmSync(ROOT, { recursive: true, force: true });
});

const lines = () => readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
const until = async (cond, ms = 20_000) => {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) return false; await new Promise((r) => setTimeout(r, 20)); }
  return true;
};

function setup() {
  db.prepare('DELETE FROM apps').run();
  db.prepare("DELETE FROM settings WHERE key = 'host_gateway_repairs'").run();
  const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, image_ref, container_port, health_path) VALUES ('race', 'race', ?, 'image', 'kc:26', 3000, '/health')")
    .run(slot).lastInsertRowid;
  db.prepare("INSERT INTO deployments (app_id, env, status, image_ref, deployed_by) VALUES (?, 'sandbox', 'live', ?, ?)").run(appId, OLD, userId);
  writeFileSync(STATE, 'OLD');
  writeFileSync(LOG, '');
  jh._resetJobHealthForTests();
  hg._resetHostGatewayCacheForTests();
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
}

async function startDeploy(app) {
  const id = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)").run(app.id, userId).lastInsertRowid;
  const p = deployApp(id, app, 'sandbox', getPortsForSlot(slot), {});
  return { id, p };
}

const runCheck = () => { jh.jobStarted('host-gateway', { cadenceMs: 3_600_000 }); return jh.trackJob('host-gateway', () => hg.runHostGatewayCheck()).then(() => null, (e) => e); };

test('A1: a deploy that starts before the repair stops the container: the repair aborts, the deploy\'s image runs', async () => {
  const app = setup();
  writeFileSync(PAUSE, 'env');
  const check = runCheck();
  assert.ok(await until(() => existsSync(WAITING)), 'the repair never reached its recreate');
  const dep = await startDeploy(app);
  writeFileSync(RELEASE, '');
  await check;
  await dep.p;
  const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(dep.id);
  assert.equal(row.status, 'live', row.log);
  assert.equal(readFileSync(STATE, 'utf8'), 'NEW', 'the old image is running after the deploy');
  assert.deepEqual(lines().filter((l) => l[0] === 'done-run').map((l) => l[1]), ['NEW'], 'the repair started the old image');
  const job = jh.getJobHealth().find((j) => j.id === 'host-gateway');
  assert.equal(job.detail.not_repaired[0].reason, 'a deploy is in progress');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'restart'").get().n, 0);
});

test('A2: a deploy that reaches its swap while the repair is starting the old image waits, then its image runs', async () => {
  const app = setup();
  writeFileSync(PAUSE, 'run-old');
  const check = runCheck();
  assert.ok(await until(() => existsSync(WAITING)), 'the repair never reached its docker run');
  const dep = await startDeploy(app);
  // The deploy either logs that it waits for the repair, or (without the wait)
  // runs its own container first.
  await until(() => /Waiting for AppCrane's automatic recreate/.test(db.prepare('SELECT log FROM deployments WHERE id = ?').get(dep.id).log || '')
    || lines().some((l) => l[0] === 'done-run' && l[1] === 'NEW'));
  writeFileSync(RELEASE, '');
  await check;
  await dep.p;
  const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(dep.id);
  assert.equal(row.status, 'live', row.log);
  assert.match(row.log, /Waiting for AppCrane's automatic recreate of race sandbox/);
  assert.deepEqual(lines().filter((l) => l[0] === 'done-run').map((l) => l[1]), ['OLD', 'NEW']);
  assert.equal(readFileSync(STATE, 'utf8'), 'NEW', 'the old image is running after the deploy');
});

test('A3: the real recreate runs the precheck right before the stop, and a refusal or a renamed app stops nothing', async () => {
  const { recreateEnvContainer } = await import('../server/services/containerRecreate.js');
  let app = setup();
  await assert.rejects(recreateEnvContainer({ app, env: 'sandbox', actor: 'system:host-gateway', precheck: async () => 'the gateway is not an IP' }),
    (e) => e.code === 'RECREATE_SKIPPED' && /Not recreated: the gateway is not an IP\. The running container was left alone\./.test(e.message));
  app = setup();
  const stale = { ...app };
  db.prepare("UPDATE apps SET slug = 'race2' WHERE id = ?").run(app.id);
  await assert.rejects(recreateEnvContainer({ app: stale, env: 'sandbox', actor: 'system:host-gateway' }),
    (e) => e.code === 'RECREATE_SKIPPED' && /renamed or deleted/.test(e.message));
  assert.deepEqual(lines().filter((l) => ['stop', 'run'].includes(l[0]) && !l.join(' ').includes('roothelper')), [], 'something was stopped or started');
  assert.equal(readFileSync(STATE, 'utf8'), 'OLD');
});
