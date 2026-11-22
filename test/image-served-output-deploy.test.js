import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

// deployApp hands the image it is about to start to the in-deploy release
// check, so a production-only release (no sandbox) has its served output read
// from that image, and a secret in it stops the deploy before any container
// changes. Docker is a shim here (the extraction itself is exercised against
// real Docker in image-served-output.test.js); the scan is the release-check
// test seam, which records what it was asked to read.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-imgout-deploy-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(ROOT, 'bin');
const RULES = join(ROOT, 'docker-rules.json');
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
writeFileSync(join(SHIM_DIR, 'caddy'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.CRANE_TEST_DOCKER_RULES = RULES;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;
const DIGEST = `sha256:${'e5'.repeat(32)}`;
writeFileSync(RULES, JSON.stringify([
  { match: ['image', 'inspect'], stdout: `nginx@${DIGEST}\n` },
  { match: ['network', 'inspect'], stdout: 'false|172.20.0.0/16\n' },
  { match: ['images', '--filter'], stdout: '' },
  { match: ['run', 'aquasec/trivy'], code: 1 },
]));

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug', 'error']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('memory_admission_mode', 'off')").run();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { submitIntake, reviewIntake } = await import('../server/services/appIntake.js');
const rc = await import('../server/services/releaseCheck.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { emptySupabase } = await import('../server/services/servedOutputScan.js');

const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Ada','ada@t.test','platform_admin',?,1,'human')").run(hashApiKey(generateApiKey('dhk_admin'))).lastInsertRowid;
const ownerId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Owen','owen@t.test','user','x',1,'human')").run().lastInsertRowid;
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);

const asked = [];
let findings = [];
rc._setReleaseCheckDepsForTests({
  scanApp: async () => ({ status: 'ok', findings_json: null }),
  scanTree: async () => ({ status: 'ok', findings_json: null }),
  crawlServed: async () => { throw new Error('no sandbox runs this release; nothing should be crawled'); },
  probeUnauth: async () => ({ ok: true, error: null, openapi: null, requests: 1, truncated: false, discovered: {}, skipped: {}, reads: [], writes: [], write_candidates: [] }),
  scanImageOutput: async (a) => {
    asked.push(a.image);
    return { ok: true, error: null, dirs: ['/usr/share/nginx/html'], scan: { ok: true, findings, scanned: [{ path: '/usr/share/nginx/html/app.js', bytes: 10 }], truncated: false, supabase: emptySupabase() } };
  },
});

const servers = [];
function listen(port) {
  return new Promise((res) => {
    const s = http.createServer((q, out) => { out.writeHead(200, { 'content-type': 'application/json' }); out.end('{"status":"ok"}'); });
    s.on('error', () => res(null));
    s.listen(port, '127.0.0.1', () => res(s));
  });
}
let SLOT = null;
for (let slot = 13145; slot < 13245 && SLOT === null; slot++) {
  const s = await listen(getPortsForSlot(slot).prod_be);
  if (s) { SLOT = slot; servers.push(s); }
}
assert.ok(SLOT !== null, 'no free port');

after(async () => {
  rc._setReleaseCheckDepsForTests(null);
  for (const s of servers) { s.closeAllConnections?.(); s.unref(); s.close(); }
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker?.();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

test('a production-only image deploy is checked against its own image and refused for a served secret', async () => {
  const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type,image_ref,container_port,health_path) VALUES ('Img','imgout-dep',?,'image','nginx:1',80,'/health')").run(SLOT).lastInsertRowid;
  db.prepare("INSERT INTO health_state (app_id, env) VALUES (?, 'production')").run(id);
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  submitIntake(app, { data_classification: 'confidential', owner: ownerId, db });
  reviewIntake(db, app, { decision: 'approve' }, admin);
  const ports = getPortsForSlot(SLOT);

  findings = [{ file: '/usr/share/nginx/html/app.js', line: 1, rule: 'stripe-live-secret', preview: 'sk_liv... (33 chars)' }];
  const bad = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'production', 'pending', ?)").run(id, adminId).lastInsertRowid;
  await deployApp(bad, app, 'production', ports).catch(() => {});
  assert.deepEqual(asked, [`nginx@${DIGEST}`], 'the scan read the digest-pinned image the deploy was about to start');
  const row = db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(bad);
  assert.equal(row.status, 'failed', row.log);
  assert.match(row.log, /fail: No secrets in served output: Built image nginx@sha256:e5/);

  findings = [];
  const ok = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'production', 'pending', ?)").run(id, adminId).lastInsertRowid;
  await deployApp(ok, app, 'production', ports);
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(ok).status, 'live');
});
