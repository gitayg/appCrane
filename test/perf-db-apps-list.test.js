import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// GET /api/apps used to run about eleven queries per app (health x2, latest
// deploy x2, members, owners, aliases, URL settings). It now reads each kind
// once for the whole list. The response must not change: the snapshot below
// was captured from the per-app code, against this exact seed.

const SNAPSHOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'perf-db-apps-list.snapshot.json');

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-perf-db-apps-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

// No Docker in this test: `docker ps` answers with no containers.
const binDir = mkdtempSync(join(tmpdir(), 'crane-perf-db-bin-'));
writeFileSync(join(binDir, 'docker'), '#!/bin/sh\nexit 0\n');
chmodSync(join(binDir, 'docker'), 0o755);
process.env.PATH = `${binDir}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const ADMIN_KEY = generateApiKey('dhk_admin');
const USER_KEY = generateApiKey('dhk_user');
const mkUser = (name, role, key) => db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')",
).run(name, `${name.toLowerCase()}@example.com`, role, hashApiKey(key || `unused-${name}`)).lastInsertRowid;
const admin = mkUser('Admin', 'platform_admin', ADMIN_KEY);
const viewer = mkUser('Viewer', 'user', USER_KEY);
const others = ['Olga', 'Ben', 'Cara', 'Dov', 'Eli'].map(n => mkUser(n, 'user'));

const apps = [
  ['Alpha', 'alpha', 'private'], ['Bravo', 'bravo', 'public'], ['Charlie', 'charlie', 'private'],
  ['Delta', 'delta', 'hidden'], ['Echo', 'echo', 'private'], ['Foxtrot', 'foxtrot', 'public'],
].map(([name, slug, visibility], i) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,visibility,created_at) VALUES (?,?,?,'managed',?,?)",
).run(name, slug, i + 1, visibility, `2026-01-0${i + 1} 10:00:00`).lastInsertRowid);
const [A, B, C, D, E, F] = apps;

const role = (app, user, r) => db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(app, user, r);
// Inserted out of user-id order so member order is the row order, not the id order.
role(A, others[3], 'user'); role(A, others[0], 'owner'); role(A, viewer, 'user'); role(A, others[1], 'owner');
role(B, others[2], 'owner'); role(B, others[4], 'none');
role(C, others[4], 'owner'); role(C, others[1], 'admin');
role(D, others[0], 'owner'); role(D, viewer, 'owner');
role(E, others[2], 'owner'); role(E, others[3], 'user');
role(F, viewer, 'admin');

const deploy = (app, env, version, status, started, finished) => db.prepare(
  'INSERT INTO deployments (app_id,env,version,status,started_at,finished_at) VALUES (?,?,?,?,?,?)',
).run(app, env, version, status, started, finished);
deploy(A, 'production', '1.0.0', 'live', '2026-02-01 10:00:00', '2026-02-01 10:01:00');
deploy(A, 'production', '1.1.0', 'failed', '2026-02-03 10:00:00', '2026-02-03 10:02:00');
deploy(A, 'production', '1.0.5', 'live', '2026-02-02 10:00:00', '2026-02-02 10:01:00');
deploy(A, 'sandbox', '1.2.0-rc', 'building', '2026-02-04 10:00:00', null);
deploy(B, 'sandbox', '0.1.0', 'live', '2026-02-05 10:00:00', '2026-02-05 10:03:00');
deploy(C, 'production', '3.0.0', 'live', '2026-02-06 10:00:00', '2026-02-06 10:01:00');
deploy(D, 'production', '9.9.9', 'rolled_back', '2026-02-07 10:00:00', '2026-02-07 10:04:00');
deploy(F, 'production', '2.0.0', 'live', '2026-02-08 10:00:00', '2026-02-08 10:01:00');
deploy(F, 'production', '2.1.0', 'live', '2026-02-09 10:00:00', '2026-02-09 10:01:00');

const health = (app, env, status, down, ms) => db.prepare(
  'INSERT INTO health_state (app_id,env,last_check_at,last_status,last_response_ms,is_down) VALUES (?,?,?,?,?,?)',
).run(app, env, '2026-03-01 12:00:00', status, ms, down);
health(A, 'production', 200, 0, 12); health(A, 'sandbox', 500, 1, 40);
health(C, 'production', 302, 0, 7); health(F, 'sandbox', 200, 0, 3);

const alias = (app, domain, created) => db.prepare(
  'INSERT INTO app_domain_aliases (app_id,domain,source,created_at) VALUES (?,?,?,?)',
).run(app, domain, 'manual', created);
alias(A, 'old-alpha.example.test', '2026-01-10 00:00:00'); alias(A, 'older-alpha.example.test', '2026-01-09 00:00:00');
alias(F, 'fox.example.test', '2026-01-11 00:00:00');

db.prepare("INSERT INTO enhancement_requests (app_slug, message, user_id, status) VALUES ('charlie', 'Access request for app charlie', ?, 'new')").run(viewer);
db.prepare('INSERT INTO app_settings (app_id, show_sandbox) VALUES (?, 0)').run(B);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.close();
});

async function list(key) {
  const res = await fetch(`${BASE}/api/apps`, { headers: { 'X-API-Key': key } });
  assert.equal(res.status, 200);
  return res.text();
}

test('GET /api/apps returns exactly what the per-app queries returned (admin and member)', async () => {
  const got = { admin: await list(ADMIN_KEY), member: await list(USER_KEY) };
  if (process.env.PERF_DB_CAPTURE === '1') writeFileSync(SNAPSHOT, JSON.stringify(got, null, 2) + '\n');
  const want = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
  assert.equal(got.admin, want.admin);
  assert.equal(got.member, want.member);
});

test('the latest deploy of an app/env is read from an index, without a sort', () => {
  const plan = db.prepare(
    'EXPLAIN QUERY PLAN SELECT version, status, finished_at FROM deployments WHERE app_id = ? AND env = ? ORDER BY started_at DESC LIMIT 1',
  ).all(A, 'production').map(r => r.detail).join(' | ');
  assert.match(plan, /idx_deployments_app_env_started/);
  assert.doesNotMatch(plan, /TEMP B-TREE/);
});
