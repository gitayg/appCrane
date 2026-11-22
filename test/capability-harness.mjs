// Shared set-up for the capability approval tests: a temp DATA_DIR, the real
// routers on 127.0.0.1:0, people with an API key AND a dashboard session, and a
// managed database engine double (the real one docker-runs Postgres).

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

export const ROOT = mkdtempSync(join(tmpdir(), 'crane-capabilities-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

const SHIM_DIR = join(ROOT, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'docker'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
writeFileSync(join(SHIM_DIR, 'caddy'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
export const db = getDb();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');

let seq = 0;
export function mkUser({ name, role = 'user', kind = 'human' } = {}) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const session = generateApiKey('sess');
  const id = db.prepare('INSERT INTO users (name, username, email, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, ?, 1, ?)')
    .run(name || `Person ${n}`, `cap${n}`, `cap${n}@t.test`, role, hashApiKey(key), kind).lastInsertRowid;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(session));
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key, session };
}

export function mkApp(slug, cols = {}) {
  const keys = ['name', 'slug', 'slot', 'source_type', ...Object.keys(cols)];
  const vals = [`App ${slug}`, slug, getNextSlot(db), 'github', ...Object.values(cols)];
  const id = db.prepare(`INSERT INTO apps (${keys.join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`).run(...vals).lastInsertRowid;
  for (const env of ['production', 'sandbox']) db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, ?, 'live')").run(id, env);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

export const appRow = (app) => db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
export const assign = (app, u, role) => db.prepare(`INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
  ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role`).run(app.id, u.id, role);
export const setSetting = (k, v) => db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
export const capRows = (app, capability) => db.prepare('SELECT * FROM capability_requests WHERE app_id = ? AND capability = ? ORDER BY id').all(app.id, capability);
export const auditRows = (action, appId = null) => db.prepare(`SELECT * FROM audit_log WHERE action = ? ${appId == null ? '' : 'AND app_id = ?'} ORDER BY id`).all(...(appId == null ? [action] : [action, appId]));

// Engine double: writes a real managed_databases row, which is what the
// capability check reads to decide "this app already has that engine".
export const provisioned = [];
const engine = {
  SUPPORTED_ENGINES: ['postgres', 'mariadb', 'mongo', 'redis'],
  async provision(scope, eng) {
    provisioned.push([scope.appId, scope.tenant ?? '', eng]);
    const has = db.prepare('SELECT 1 FROM managed_databases WHERE app_id = ? AND tenant = ? AND engine = ?').get(scope.appId, scope.tenant ?? '', eng);
    if (!has) {
      db.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, ?, ?, ?, ?, 'enc:x')")
        .run(scope.appId, scope.tenant ?? '', eng, `db_${scope.appId}_${eng}`, `u_${scope.appId}_${eng}`);
    }
    return { engine: eng, password: 'never-returned' };
  },
  listForApp(appId) {
    return db.prepare('SELECT id, app_id, tenant, engine, db_name, db_user, created_at FROM managed_databases WHERE app_id = ?').all(appId);
  },
  async deprovision() { return true; },
};
(await import('../server/routes/managedDb.js')).__setEngineForTests(engine);
(await import('../server/services/mcpTools.js')).__setManagedDbForTests(engine);

let server;
export let BASE;
export async function startServer() {
  const api = express();
  api.use(express.json());
  api.use('/api/service', (await import('../server/routes/serviceApi.js')).default);
  api.use('/api/apps', (await import('../server/routes/apps.js')).default);
  api.use('/api/apps', (await import('../server/routes/managedDb.js')).default);
  api.use('/api/apps', (await import('../server/routes/appSecretConnections.js')).default);
  api.use('/api/apps', (await import('../server/routes/llmGateway.js')).appRouter);
  api.use('/api', (await import('../server/routes/capabilities.js')).default);
  api.use((await import('../server/utils/errors.js')).errorHandler);
  server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
  BASE = `http://127.0.0.1:${server.address().port}`;
}

export async function stopServer() {
  server?.closeAllConnections?.();
  server?.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker?.();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
}

/** who: a user from mkUser; as: 'key' (X-API-Key, default) or 'session' (dashboard). */
export async function call(who, method, path, body, { as = 'key', headers = {} } = {}) {
  const h = { 'Content-Type': 'application/json', ...headers };
  if (who) {
    if (as === 'session') h.Authorization = `Bearer ${who.session}`;
    else h['X-API-Key'] = who.key;
  }
  const r = await fetch(`${BASE}${path}`, { method, headers: h, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: r.status, body: await r.json().catch(() => null) };
}

export async function requestCap(owner, app, capability, scope, reason = 'the app needs it') {
  const r = await call(owner, 'POST', `/api/apps/${app.slug}/capability-requests`, { capability, scope, reason });
  if (r.status !== 201 && r.status !== 200) throw new Error(`request failed: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body.request;
}

export async function approve(admin, id, body = {}) {
  const r = await call(admin, 'POST', `/api/capability-requests/${id}/approve`, body, { as: 'session' });
  if (r.status !== 200) throw new Error(`approve failed: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body.request;
}

export async function grantCap(owner, admin, app, capability, scope, body = {}) {
  const req = await requestCap(owner, app, capability, scope);
  return approve(admin, req.id, body);
}
