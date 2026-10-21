import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

// Deployments write deploy.started / deploy.succeeded / deploy.failed /
// deploy.rollback to the event store, off a real deployApp run of an image app
// against a `docker` PATH shim and a real health endpoint (the
// image-deploy.test.js harness).

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-events-deploy-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const RULES = join(process.env.DATA_DIR, 'docker-rules.json');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'),
  '#!/usr/bin/env node\n' +
  'const { readFileSync, existsSync } = require("fs");\n' +
  'const argv = process.argv.slice(2);\n' +
  'const rf = process.env.CRANE_TEST_DOCKER_RULES;\n' +
  'const rules = rf && existsSync(rf) ? JSON.parse(readFileSync(rf, "utf8")) : [];\n' +
  'for (const r of rules) {\n' +
  '  if (r.match.every(tok => argv.includes(tok))) {\n' +
  '    process.stdout.write(r.stdout || ""); process.stderr.write(r.stderr || ""); process.exit(r.code || 0);\n' +
  '  }\n' +
  '}\n' +
  'process.stdout.write("0123456789abcdef\\n");\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const DIGEST = `sha256:${'c3'.repeat(32)}`;
writeFileSync(RULES, JSON.stringify([
  { match: ['image', 'inspect'], stdout: `nginx@${DIGEST}\n` },
  { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
  { match: ['images', '--filter'], stdout: '' },
]));

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();

const { deployApp, rollbackApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

const servers = [];
function listen(port) {
  return new Promise((res) => {
    const s = http.createServer((req, out) => { out.writeHead(200, { 'content-type': 'application/json' }); out.end('{"status":"ok"}'); });
    s.on('error', () => res(null));
    s.listen(port, '127.0.0.1', () => res(s));
  });
}
let SLOT = null;
let PORTS = null;
for (let slot = 12545; slot < 12645 && SLOT === null; slot++) {
  const ports = getPortsForSlot(slot);
  const s = await listen(ports.sand_be);
  if (!s) continue;
  SLOT = slot; PORTS = ports; servers.push(s);
}
assert.ok(SLOT !== null, 'no free sandbox port');
after(() => { for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); } });

const userId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('D','d@t.test','platform_admin','unused',1,'human')").run().lastInsertRowid;
db.prepare("INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,health_path) VALUES ('Web','ev-web',?,'image','nginx:1',80,'/health')").run(SLOT);
const app = db.prepare("SELECT * FROM apps WHERE slug = 'ev-web'").get();
const newDeployment = () => db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)").run(app.id, userId).lastInsertRowid;
const deployEvents = () => db.prepare("SELECT kind, severity, app_id, user_id, ref_table, ref_id FROM events WHERE kind LIKE 'deploy.%' ORDER BY id").all();

test('a successful deploy writes deploy.started then deploy.succeeded, linked to the deployment', async () => {
  db.prepare('DELETE FROM events').run();
  const id = newDeployment();
  await deployApp(id, app, 'sandbox', PORTS);
  assert.equal(db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(id).status, 'live');
  assert.deepEqual(deployEvents(), [
    { kind: 'deploy.started', severity: 'info', app_id: app.id, user_id: userId, ref_table: 'deployments', ref_id: id },
    { kind: 'deploy.succeeded', severity: 'info', app_id: app.id, user_id: userId, ref_table: 'deployments', ref_id: id },
  ]);
});

test('a second deploy then a rollback writes deploy.rollback', async () => {
  await deployApp(newDeployment(), app, 'sandbox', PORTS);
  db.prepare('DELETE FROM events').run();
  await rollbackApp(app, 'sandbox', null, userId);
  const kinds = deployEvents().map(e => e.kind);
  assert.deepEqual(kinds, ['deploy.rollback', 'deploy.started', 'deploy.succeeded']);
});

test('a failed deploy writes deploy.failed with the scrubbed reason', async () => {
  db.prepare('DELETE FROM events').run();
  const broken = { ...app, source_type: 'github', github_url: null };
  const id = newDeployment();
  await assert.rejects(deployApp(id, broken, 'sandbox', PORTS));
  const ev = deployEvents();
  assert.deepEqual(ev.map(e => [e.kind, e.severity, e.ref_id]), [['deploy.started', 'info', id], ['deploy.failed', 'warning', id]]);
  const summary = db.prepare("SELECT summary FROM events WHERE kind = 'deploy.failed'").get().summary;
  assert.match(summary, /^Deploy to sandbox failed: /);
});
