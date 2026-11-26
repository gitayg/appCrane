import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, copyFileSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import express from 'express';
import Database from 'better-sqlite3';

// Whole-platform archives (v2.147.0): export and import take a dashboard
// session only (no user API key), a fresh step-up, and an import names this
// instance in `confirm`. Every attempt that passes the gates is audited, and a
// successful import is also recorded in the restored database (the live
// connection keeps the replaced file until the restart).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cfg-guard-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.APPCRANE_NO_RESTART_AFTER_IMPORT = '1';
process.env.CRANE_DOMAIN = 'https://Crane.T.Test/';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');

const user = (name, role) => {
  const key = generateApiKey('dhk_t');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')").run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
};
const session = (userId, ageMinutes) => {
  const tok = randomBytes(24).toString('base64url');
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, datetime('now','+1 day'), datetime('now', ?))`).run(userId, hashApiKey(tok), `-${ageMinutes} minutes`);
  return tok;
};
const ADMIN = user('pa', 'platform_admin');
const ADMIN2 = user('pb', 'platform_admin');
const PLAIN = user('pu', 'user');
const FRESH = session(ADMIN.id, 0);
const FRESH2 = session(ADMIN2.id, 0);
const STALE = session(ADMIN.id, 60);
const PLAIN_FRESH = session(PLAIN.id, 0);

const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/settings', settingsRoutes);
api.use(errorHandler);
const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const key = (k) => ({ 'X-API-Key': k });
const sha = (b) => createHash('sha256').update(b).digest('hex');
const audits = (action) => db.prepare('SELECT user_id, detail FROM audit_log WHERE action = ? ORDER BY id').all(action).map((r) => ({ user_id: r.user_id, ...JSON.parse(r.detail) }));
const setSetting = (k, v) => db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(k, v);
const json = async (r) => ({ status: r.status, body: await r.json() });

const importJson = (headers, body, query = '') => fetch(`${BASE}/api/settings/config/import${query}`, {
  method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

test('instance name: CRANE_DOMAIN without scheme, slash or case', async () => {
  const r = await json(await fetch(`${BASE}/api/settings/config/instance`, { headers: bearer(FRESH) }));
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { instance: 'crane.t.test' });
});

test('download export: API key and plain user refused, stale session must step up, fresh session audited with the sha256', async () => {
  const k = await json(await fetch(`${BASE}/api/settings/config/export`, { headers: key(ADMIN.key) }));
  assert.equal(k.status, 403);
  assert.equal(k.body.error.code, 'SESSION_REQUIRED');
  const p = await fetch(`${BASE}/api/settings/config/export`, { headers: bearer(PLAIN_FRESH) });
  assert.equal(p.status, 403);
  const s = await json(await fetch(`${BASE}/api/settings/config/export`, { headers: bearer(STALE) }));
  assert.equal(s.status, 401);
  assert.equal(s.body.error.code, 'STEP_UP_REQUIRED');
  assert.equal(s.body.error.step_up.action, 'platform_archive');
  assert.equal(s.body.error.step_up.mode, 'reauth');
  assert.deepEqual(audits('config-export'), [], 'a refused export was audited as an export');

  const ok = await fetch(`${BASE}/api/settings/config/export`, { headers: bearer(FRESH) });
  assert.equal(ok.status, 200);
  const body = Buffer.from(await ok.arrayBuffer());
  const rows = audits('config-export');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].user_id, ADMIN.id);
  assert.equal(rows[0].kind, 'download');
  assert.equal(rows[0].sha256, sha(body));
  assert.equal(rows[0].bytes, body.length);
});

test('on-host export: API key refused, job audited, status only for its own admin', async () => {
  const k = await importJsonLike('POST', '/api/settings/config/export', key(ADMIN.key));
  assert.equal(k.status, 403);
  const s = await importJsonLike('POST', '/api/settings/config/export', bearer(STALE));
  assert.equal(s.status, 401);
  const r = await importJsonLike('POST', '/api/settings/config/export', bearer(FRESH));
  assert.equal(r.status, 202);
  const id = r.body.job_id;
  let st;
  for (let i = 0; i < 200; i++) {
    st = await json(await fetch(`${BASE}/api/settings/config/export/${id}`, { headers: bearer(FRESH) }));
    if (st.body.state !== 'running') break;
    await new Promise((res) => setTimeout(res, 50));
  }
  assert.equal(st.body.state, 'done', JSON.stringify(st.body));
  assert.equal((await fetch(`${BASE}/api/settings/config/export/${id}`, { headers: key(ADMIN.key) })).status, 403);
  assert.equal((await fetch(`${BASE}/api/settings/config/export/${id}`, { headers: bearer(FRESH2) })).status, 404, 'another admin read this job');
  assert.equal(audits('config-export-started').length, 1);
  const done = audits('config-export').filter((a) => a.kind === 'on-host');
  assert.equal(done.length, 1);
  assert.equal(done[0].sha256, sha(readFileSync(st.body.result.path)));
});

async function importJsonLike(method, path, headers) {
  return json(await fetch(`${BASE}${path}`, { method, headers: { ...headers, 'Content-Type': 'application/json' }, body: '{}' }));
}

let ARCHIVE;
test('import: API key, plain user, stale session, missing and wrong confirm are all refused, nothing replaced', async () => {
  const { exportDataArchive } = await import('../server/services/configBackup.js');
  setSetting('guard_marker', 'IN-ARCHIVE');
  const out = await exportDataArchive({});
  mkdirSync(join(ROOT, 'backups'), { recursive: true });
  ARCHIVE = 'guard.tar.gz';
  copyFileSync(out.path, join(ROOT, 'backups', ARCHIVE));
  setSetting('guard_marker', 'LIVE');
  const marker = () => new Database(join(ROOT, 'deployhub.db'), { readonly: true }).prepare("SELECT value FROM settings WHERE key = 'guard_marker'").get()?.value;

  const k = await json(await importJson(key(ADMIN.key), { path: ARCHIVE, confirm: 'crane.t.test' }));
  assert.equal(k.status, 403);
  assert.equal(k.body.error.code, 'SESSION_REQUIRED');
  const p = await json(await importJson(bearer(PLAIN_FRESH), { path: ARCHIVE, confirm: 'crane.t.test' }));
  assert.equal(p.status, 403);
  const s = await json(await importJson(bearer(STALE), { path: ARCHIVE, confirm: 'crane.t.test' }));
  assert.equal(s.status, 401);
  assert.equal(s.body.error.code, 'STEP_UP_REQUIRED');
  const none = await json(await importJson(bearer(FRESH), { path: ARCHIVE }));
  assert.equal(none.status, 400);
  assert.equal(none.body.error.code, 'CONFIRM_REQUIRED');
  assert.equal(none.body.error.instance, 'crane.t.test');
  const wrong = await json(await importJson(bearer(FRESH), { path: ARCHIVE, confirm: 'other.t.test' }));
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.error.code, 'CONFIRM_REQUIRED');

  assert.equal(marker(), 'LIVE', 'a refused import replaced the database');
  assert.deepEqual(audits('config-import-started'), []);
  const refused = audits('config-import-refused');
  assert.equal(refused.length, 2);
  assert.equal(refused[1].confirm, 'other.t.test');
});

test('import: a fresh session naming this instance imports, audited before and after with the archive sha256, and in the restored DB', async () => {
  const want = sha(readFileSync(join(ROOT, 'backups', ARCHIVE)));
  const r = await json(await importJson(bearer(FRESH), { path: ARCHIVE, confirm: ' CRANE.t.test ', restore_env: false }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.audit_in_restored_db, true);
  const restored = new Database(join(ROOT, 'deployhub.db'), { readonly: true });
  assert.equal(restored.prepare("SELECT value FROM settings WHERE key = 'guard_marker'").get()?.value, 'IN-ARCHIVE');

  const started = audits('config-import-started');
  assert.equal(started.length, 1);
  assert.equal(started[0].user_id, ADMIN.id);
  assert.equal(started[0].sha256, want);
  const done = audits('config-import');
  assert.equal(done.length, 1);
  assert.equal(done[0].sha256, want);
  assert.equal(done[0].env_replaced, false);
  assert.equal(done[0].encryption_key_replaced, false);
  assert.equal(done[0].restore_env, false);

  const inRestored = restored.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'config-import'").all();
  assert.equal(inRestored.length, 1);
  assert.equal(inRestored[0].user_id, null);
  const d = JSON.parse(inRestored[0].detail);
  assert.equal(d.sha256, want);
  assert.equal(d.actor.id, ADMIN.id);
  assert.equal(d.instance, 'crane.t.test');
  restored.close();
});

test('import upload: confirm is checked from the query string before the file is read', async () => {
  const fd = () => { const f = new FormData(); f.append('file', new Blob([readFileSync(join(ROOT, 'backups', ARCHIVE))]), 'b.tar.gz'); return f; };
  const no = await json(await fetch(`${BASE}/api/settings/config/import?restore_env=0`, { method: 'POST', headers: bearer(FRESH), body: fd() }));
  assert.equal(no.status, 400);
  assert.equal(no.body.error.code, 'CONFIRM_REQUIRED');
  const yes = await json(await fetch(`${BASE}/api/settings/config/import?restore_env=0&confirm=crane.t.test`, { method: 'POST', headers: bearer(FRESH), body: fd() }));
  assert.equal(yes.status, 200, JSON.stringify(yes.body));
  assert.equal(audits('config-import').length, 2);
});
