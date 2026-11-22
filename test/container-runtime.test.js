import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import express from 'express';

// gVisor runtime policy (services/containerRuntime.js, migration 250).
//
// Measured through the real code paths: the policy routes on a real express
// app with real bearer sessions, and docker.startApp() building its argv
// against a recording `docker` shim on PATH (the same shim as
// test/container-port.test.js), whose `docker info` answer decides whether
// the host has runsc. The live half (a runsc container actually reporting
// the gVisor kernel) is in the report: it needs a daemon with runsc
// registered, which this Mac's Docker Desktop does not have.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-runtime-'));
process.env.ENCRYPTION_KEY = 'r'.repeat(64);
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

const RUNC_ONLY = '{"io.containerd.runc.v2":{"path":"runc"},"runc":{"path":"runc"}}';
const WITH_RUNSC = '{"io.containerd.runc.v2":{"path":"runc"},"runc":{"path":"runc"},"runsc":{"path":"/usr/local/bin/runsc","runtimeArgs":["--platform=systrap"]}}';
let applied = 'runc';
function setHost(runtimesJson) {
  writeFileSync(RULES, JSON.stringify([
    { match: ['info', '--format'], stdout: `${runtimesJson}\n` },
    { match: ['inspect', '--format', '{{.HostConfig.Runtime}}'], stdout: `${applied}\n` },
    { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
    { match: ['images', '--filter'], stdout: '' },
  ]));
  CR._setDockerForTests(null);
}
function dockerCalls() {
  if (!existsSync(ARGV_LOG)) return [];
  return readFileSync(ARGV_LOG, 'utf8').split('\0').filter((r) => r.trim() !== '').map((r) => r.split('\n').filter((l) => l !== ''));
}
function clearDockerCalls() { if (existsSync(ARGV_LOG)) rmSync(ARGV_LOG); }
const appRuns = () => dockerCalls().filter((c) => c[0] === 'run' && !c.includes('appcrane-roothelper=true'));

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const CR = await import('../server/services/containerRuntime.js');
const { startApp } = await import('../server/services/docker.js');
const { applyEgressPlan } = await import('../server/services/egress/container.js');
const runtimeRoutes = await import('../server/routes/containerRuntime.js');
const healthRoutes = (await import('../server/routes/health.js')).default;
setHost(RUNC_ONLY);

function mkUser(role) {
  const tag = randomBytes(4).toString('hex');
  const id = db.prepare("INSERT INTO users (name, email, username, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, 'human')")
    .run(`u${tag}`, `u${tag}@t.test`, `u${tag}`, role, hashApiKey(randomBytes(16).toString('hex'))).lastInsertRowid;
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  return { id, token };
}
let slot = 700;
function mkApp(slug) {
  const id = db.prepare('INSERT INTO apps (name, slug, slot, source_type) VALUES (?, ?, ?, ?)').run(slug, slug, ++slot, 'managed').lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(id, env);
    db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  }
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const seat = (app, user, role) => db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, user.id, role);

const ADMIN = mkUser('platform_admin');
const OWNER = mkUser('user');
const MEMBER = mkUser('user');
const OUTSIDER = mkUser('user');
const APP = mkApp('rt-app');
seat(APP, OWNER, 'owner');
seat(APP, MEMBER, 'user');

const server = express();
server.use(express.json());
server.use('/api/container-runtime', runtimeRoutes.adminRouter);
server.use('/api/apps', runtimeRoutes.appRouter);
server.use('/api/apps', healthRoutes);
server.use(errorHandler);
const listener = await new Promise((r) => { const s = server.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${listener.address().port}`;
after(() => listener.close());

async function call(method, path, body, who) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(who ? { Authorization: `Bearer ${who.token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch (_) {}
  return { status: res.status, body: json };
}
const code = (r) => r.body?.code || r.body?.error?.code;

beforeEach(() => {
  setHost(RUNC_ONLY);
  applied = 'runc';
  CR._setPlanFloorForTests(null);
  db.prepare("DELETE FROM settings WHERE key = 'container_runtime_default'").run();
  db.prepare('DELETE FROM app_container_runtime').run();
});

// ---- platform default ----

test('settings: platform admin only; runsc refused on a runc-only host, accepted once dockerd lists runsc', async () => {
  assert.equal((await call('GET', '/api/container-runtime/settings', null, OWNER)).status, 403);
  assert.equal((await call('GET', '/api/container-runtime/settings')).status, 401);
  const g = await call('GET', '/api/container-runtime/settings', null, ADMIN);
  assert.equal(g.status, 200);
  assert.equal(g.body.default, 'runc');
  assert.deepEqual(g.body.host, { runtimes: ['io.containerd.runc.v2', 'runc'], runsc: false, error: null });

  const refused = await call('PUT', '/api/container-runtime/settings', { default: 'runsc' }, ADMIN);
  assert.equal(refused.status, 409);
  assert.equal(code(refused), 'RUNTIME_UNAVAILABLE');
  assert.equal(CR.platformDefault(), 'runc');

  setHost(WITH_RUNSC);
  const ok = await call('PUT', '/api/container-runtime/settings', { default: 'runsc' }, ADMIN);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.default, 'runsc');
  assert.equal((await call('PUT', '/api/container-runtime/settings', { default: 'kata' }, ADMIN)).status, 400);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'container-runtime-default'").get());
});

// ---- per-app override ----

test('app override: owner may raise to runsc but not set runc or clear a raise; members and outsiders cannot change it', async () => {
  setHost(WITH_RUNSC);
  assert.equal((await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runsc' }, MEMBER)).status, 403);
  assert.ok([403, 404].includes((await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runsc' }, OUTSIDER)).status));
  assert.ok([403, 404].includes((await call('GET', '/api/apps/rt-app/runtime', null, OUTSIDER)).status));

  const up = await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runsc' }, OWNER);
  assert.equal(up.status, 200);
  assert.equal(up.body.runtime, 'runsc');
  assert.equal(up.body.source, 'app');

  const clear = await call('PUT', '/api/apps/rt-app/runtime', { runtime: null }, OWNER);
  assert.equal(clear.status, 403, 'clearing would lower runsc to the runc default');
  const runc = await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runc', reason: 'legacy app needs it' }, OWNER);
  assert.equal(runc.status, 403);
  assert.equal(CR.effectiveRuntime(APP).runtime, 'runsc');
});

test('app override: a platform admin may set runc only with a reason; it is listed as an exception under a runsc default', async () => {
  setHost(WITH_RUNSC);
  await call('PUT', '/api/container-runtime/settings', { default: 'runsc' }, ADMIN);
  assert.equal((await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runc' }, ADMIN)).status, 400);
  const r = await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runc', reason: 'needs io_uring, gVisor lacks it' }, ADMIN);
  assert.equal(r.status, 200);
  assert.equal(r.body.runtime, 'runc');
  assert.equal(r.body.below_platform_default, true);
  const s = await call('GET', '/api/container-runtime/settings', null, ADMIN);
  assert.deepEqual(s.body.exceptions.map((e) => [e.slug, e.runtime, e.reason]), [['rt-app', 'runc', 'needs io_uring, gVisor lacks it']]);
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'container-runtime-app' ORDER BY id DESC").get();
  assert.match(audit.detail, /"from":"runsc","to":"runc"/);
  const owner = await call('PUT', '/api/apps/rt-app/runtime', { runtime: null }, OWNER);
  assert.equal(owner.status, 200, 'clearing a runc exception raises isolation, which an owner may do');
  assert.equal(owner.body.runtime, 'runsc');
});

test('plan floor runsc: no override can set runc, an older runc override is outranked', async () => {
  setHost(WITH_RUNSC);
  await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runc', reason: 'set before the plan existed' }, ADMIN);
  CR._setPlanFloorForTests((_db, app) => (app.slug === 'rt-app' ? 'runsc' : null));
  const eff = CR.effectiveRuntime(APP);
  assert.equal(eff.runtime, 'runsc');
  assert.equal(eff.source, 'plan');
  const r = await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runc', reason: 'trying to go below the plan' }, ADMIN);
  assert.equal(r.status, 409);
  assert.equal(code(r), 'PLAN_RUNTIME_FLOOR');
});

test('health shows desired and applied runtime, with drift when the container predates the policy', async () => {
  setHost(WITH_RUNSC);
  await call('PUT', '/api/apps/rt-app/runtime', { runtime: 'runsc' }, OWNER);
  const h = await call('GET', '/api/apps/rt-app/health/production', null, MEMBER);
  assert.equal(h.status, 200);
  assert.equal(h.body.runtime.desired, 'runsc');
  assert.equal(h.body.runtime.applied, 'runc');
  assert.equal(h.body.runtime.drift, true);
  assert.match(h.body.runtime.notice, /recreated/);
  applied = 'runsc';
  setHost(WITH_RUNSC);
  const h2 = await call('GET', '/api/apps/rt-app/health/production', null, MEMBER);
  assert.equal(h2.body.runtime.drift, false);
});

// ---- the docker run argv ----

const START = { env: 'production', image: 'node:20', hostPort: 4400, memoryMb: 256, cpus: 0.5, admission: false };

test('runc (the default): the argv carries no --runtime and no docker info is made', async () => {
  const a = mkApp('rt-plain');
  clearDockerCalls();
  await startApp({ ...START, slug: a.slug });
  const runs = appRuns();
  assert.equal(runs.length, 1);
  assert.ok(!runs[0].some((t) => t.startsWith('--runtime')), JSON.stringify(runs[0]));
  assert.ok(!dockerCalls().some((c) => c[0] === 'info'));
});

test('runsc on a host that has it: --runtime=runsc before the image', async () => {
  setHost(WITH_RUNSC);
  const a = mkApp('rt-gvisor');
  await CR.setAppOverride(a, 'runsc', { id: OWNER.id }, { isPlatformAdmin: false });
  clearDockerCalls();
  await startApp({ ...START, slug: a.slug });
  const run = appRuns()[0];
  const at = run.indexOf('--runtime=runsc');
  assert.ok(at > 0, JSON.stringify(run));
  assert.ok(at < run.indexOf('node:20'));
  const { appArgs } = applyEgressPlan(run, { anchor: 'crane-egress-anchor.x.production' });
  assert.ok(appArgs.includes('--runtime=runsc'), 'the egress argv rewrite keeps the runtime');
});

test('fail closed: runsc required on a runc-only host refuses the start and leaves the running container alone', async () => {
  setHost(WITH_RUNSC);
  const a = mkApp('rt-refused');
  await CR.setAppOverride(a, 'runsc', { id: OWNER.id }, { isPlatformAdmin: false });
  setHost(RUNC_ONLY);
  clearDockerCalls();
  await assert.rejects(startApp({ ...START, slug: a.slug }), (e) => e.code === 'RUNTIME_UNAVAILABLE' && /does not fall back to runc/.test(e.message));
  const calls = dockerCalls();
  assert.ok(!calls.some((c) => ['run', 'stop', 'rm'].includes(c[0])), JSON.stringify(calls.map((c) => c[0])));
});

test('plan floor runsc with a runc platform default and no override: a runc-only host refuses to start the app', async () => {
  const a = mkApp('rt-plan');
  CR._setPlanFloorForTests((_db, app) => (app.slug === 'rt-plan' ? 'runsc' : null));
  clearDockerCalls();
  await assert.rejects(startApp({ ...START, slug: a.slug }), (e) => e.code === 'RUNTIME_UNAVAILABLE');
  assert.equal(appRuns().length, 0);
  setHost(WITH_RUNSC);
  clearDockerCalls();
  await startApp({ ...START, slug: a.slug });
  assert.ok(appRuns()[0].includes('--runtime=runsc'));
});
