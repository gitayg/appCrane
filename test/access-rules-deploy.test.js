import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

// deployhub.json `access` at deploy: bad rules fail the deploy before the build,
// good ones are stored for that environment and replace the previous release's.
// Driven through a real deployApp with `docker` and `git` shims (Docker on the
// dev box is not usable, and the claim is about the deployer, not Docker).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-accessdeploy-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM_DIR = join(ROOT, 'bin');
const DOCKER_EVENTS = join(ROOT, 'docker-events.jsonl');
const MANIFEST = join(ROOT, 'manifest.json');
mkdirSync(SHIM_DIR, { recursive: true });

writeFileSync(join(SHIM_DIR, 'docker'), `#!/usr/bin/env node
const { appendFileSync } = require('fs');
const argv = process.argv.slice(2);
let code = 0, out = '0123456789abcdef\\n';
if (argv[0] === 'build') out = 'Successfully built deadbeef\\n';
else if (argv[0] === 'version') out = '29.0.0\\n';
else if (argv[0] === 'image' && argv[1] === 'inspect') { code = 1; out = ''; }
else if (argv[0] === 'inspect') { code = 1; out = ''; }
else if (argv[0] === 'network' && argv[1] === 'inspect') out = 'false|172.20.0.0/16\\n';
else if (argv[0] === 'images' || argv[0] === 'ps') out = '';
appendFileSync(process.env.CRANE_DOCKER_EVENTS, JSON.stringify({ verb: argv[0] }) + '\\n');
process.stdout.write(out);
process.exit(code);
`, { mode: 0o755 });

writeFileSync(join(SHIM_DIR, 'git'), `#!/usr/bin/env node
const { mkdirSync, writeFileSync, readFileSync } = require('fs');
const { join } = require('path');
const argv = process.argv.slice(2);
const SHA = '${'ab'.repeat(20)}';
if (argv[0] === 'clone') {
  const dir = argv[argv.length - 1];
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'acc', version: '1.0.0', main: 'server.js' }));
  writeFileSync(join(dir, 'deployhub.json'), readFileSync(process.env.CRANE_TEST_MANIFEST, 'utf8'));
  writeFileSync(join(dir, 'server.js'), 'require("http").createServer((q,s)=>s.end("ok")).listen(3000);\\n');
  process.exit(0);
}
if (argv[0] === '-C') {
  if (argv[2] === 'rev-parse') { process.stdout.write((argv[3] === '--short' ? SHA.slice(0, 7) : SHA) + '\\n'); process.exit(0); }
  if (argv[2] === 'log') { process.stdout.write('fixture commit\\n'); process.exit(0); }
}
process.exit(0);
`, { mode: 0o755 });

process.env.CRANE_DOCKER_EVENTS = DOCKER_EVENTS;
process.env.CRANE_TEST_MANIFEST = MANIFEST;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { getRules } = await import('../server/services/accessRules.js');
db.prepare("INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled','0') ON CONFLICT(key) DO UPDATE SET value='0'").run();

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

let slot = null;
let ports = null;
let userId;
const servers = [];
const startHealthServer = (port) => new Promise((res) => {
  const s = http.createServer((_q, out) => { out.writeHead(200, { 'content-type': 'application/json' }); out.end('{"status":"ok","version":"1.0.0"}'); });
  s.on('error', () => res(null));
  s.listen(port, '127.0.0.1', () => res(s));
});

before(async () => {
  for (let s = 13500; s < 13600 && slot === null; s++) {
    const p = getPortsForSlot(s);
    const sand = await startHealthServer(p.sand_be);
    if (!sand) continue;
    const prod = await startHealthServer(p.prod_be);
    if (!prod) { sand.close(); continue; }
    slot = s; ports = p; servers.push(sand, prod);
  }
  assert.ok(slot !== null, 'no slot with both ports free');
  userId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('U','ad@example.com','platform_admin','unused',1,'human')").run().lastInsertRowid;
  db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,github_url,branch,container_port,health_path) '
    + "VALUES ('acc','acc-deploy',?,'github','https://github.com/example-owner/example-repo','main',3000,'/health')",
  ).run(slot);
});
after(() => { for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); } });

async function deployWith(manifest, env = 'sandbox') {
  writeFileSync(MANIFEST, JSON.stringify({ version: '1.0.0', port: 3000, ...manifest }));
  if (existsSync(DOCKER_EVENTS)) rmSync(DOCKER_EVENTS);
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'acc-deploy'").get();
  const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, ?, 'pending', ?)").run(app.id, env, userId).lastInsertRowid;
  let error = null;
  try { await deployApp(depId, app, env, ports, {}); } catch (e) { error = e; }
  const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(depId);
  const verbs = existsSync(DOCKER_EVENTS) ? readFileSync(DOCKER_EVENTS, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l).verb) : [];
  return { app, row, error, verbs };
}

test('valid rules are stored for the deployed environment only', async () => {
  const rules = [{ path: '/admin/*', roles: ['admin'] }, { path: '/api/settings', methods: ['PUT'], roles: ['owner'] }];
  const { app, row } = await deployWith({ access: { rules } });
  assert.equal(row.status, 'live', row.log);
  assert.deepEqual(getRules(db, app.id, 'sandbox', 'manifest').rules, rules);
  assert.equal(getRules(db, app.id, 'production', 'manifest'), null, 'a sandbox deploy wrote production rules');
});

test('invalid rules fail the deploy before the build, and keep the previous rules', async () => {
  const { app, row, error, verbs } = await deployWith({ access: { rules: [{ path: '/admin/*', roles: ['member'] }] } });
  assert.ok(error, 'deploy with invalid rules succeeded');
  assert.equal(row.status, 'failed');
  assert.match(row.log, /deployhub\.json access\.rules\[0\]\.roles: unknown role "member"/);
  assert.ok(!verbs.includes('build'), `the build ran anyway: ${verbs.join(',')}`);
  assert.equal(getRules(db, app.id, 'sandbox', 'manifest').rules.length, 2, 'a failed deploy changed the live rules');
});

test('a release without an access block clears the previous release\'s rules', async () => {
  const { app, row } = await deployWith({});
  assert.equal(row.status, 'live', row.log);
  assert.equal(getRules(db, app.id, 'sandbox', 'manifest'), null);
});
