import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import express from 'express';

// The settings snapshot (GET/POST /api/config/export|import, v2.147.0): a
// dashboard session with a fresh step-up, never an API key, every call audited,
// and an import naming a protected or route-owned setting is refused whole
// unless include_protected is true, in which case each such key is audited.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-cfg-snap-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { guardedSettingKey } = await import('../server/services/settingsOwnedKeys.js');

const user = (name, role) => {
  const key = generateApiKey('dhk_t');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')").run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id: Number(id), key };
};
const session = (userId, ageMinutes) => {
  const tok = randomBytes(24).toString('base64url');
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, datetime('now','+1 day'), datetime('now', ?))`).run(userId, hashApiKey(tok), `-${ageMinutes} minutes`);
  return tok;
};
const ADMIN = user('sa', 'platform_admin');
const PLAIN = user('su', 'user');
const FRESH = session(ADMIN.id, 0);
const STALE = session(ADMIN.id, 60);
const PLAIN_FRESH = session(PLAIN.id, 0);

const configRoutes = (await import('../server/routes/config.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/config', configRoutes);
api.use(errorHandler);
const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const apiKey = (k) => ({ 'X-API-Key': k });
const sha = (v) => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const audits = (action) => db.prepare('SELECT user_id, detail FROM audit_log WHERE action = ? ORDER BY id').all(action).map((r) => ({ user_id: r.user_id, ...JSON.parse(r.detail) }));
const value = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? null;
const setSetting = (k, v) => db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(k, v);
const json = async (r) => ({ status: r.status, body: await r.json() });
const post = (headers, body) => fetch(`${BASE}/api/config/import`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const snapshot = (settings) => ({ kind: 'appcrane-config', version: 1, settings, regenerate: [] });

test('guardedSettingKey: owned, protected, read-only and generic-writer refusals are all caught; ordinary keys are not', () => {
  for (const k of ['oidc_client_id', 'mcp_oauth_only', 'host_gateway_auto_repair', 'host_gateway_repairs', 'auth_sso_only',
    'image_trust_mode', 'managed_db_mariadb_encryption_key', 'app_isolation_domain', 'platform_anthropic_key_encrypted',
    'auto_approve_rce_fixes', 'event_retention_days', 'step_up_window_minutes', 'host_hardening_auto_apply']) {
    assert.ok(guardedSettingKey(k), `${k} is not guarded`);
  }
  assert.deepEqual(guardedSettingKey('host_gateway_repairs'), { readOnly: true });
  for (const k of ['whats_new_email_enabled', 'catalog_enabled', 'mail_from_name']) assert.equal(guardedSettingKey(k), null, `${k} is guarded`);
});

test('export: API key and plain user refused, stale session must step up, fresh session audited with the sha256 of what it returned', async () => {
  const k = await json(await fetch(`${BASE}/api/config/export`, { headers: apiKey(ADMIN.key) }));
  assert.equal(k.status, 403);
  assert.equal(k.body.error.code, 'SESSION_REQUIRED');
  assert.equal((await fetch(`${BASE}/api/config/export`, { headers: bearer(PLAIN_FRESH) })).status, 403);
  const s = await json(await fetch(`${BASE}/api/config/export`, { headers: bearer(STALE) }));
  assert.equal(s.status, 401);
  assert.equal(s.body.error.code, 'STEP_UP_REQUIRED');
  assert.equal(s.body.error.step_up.action, 'platform_archive');
  assert.equal(audits('config-settings-export').length, 0, 'a refused export was audited as done');
  const ok = await json(await fetch(`${BASE}/api/config/export`, { headers: bearer(FRESH) }));
  assert.equal(ok.status, 200);
  assert.equal(ok.body.kind, 'appcrane-config');
  const rows = audits('config-settings-export');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].user_id, ADMIN.id);
  assert.equal(rows[0].keys, ok.body.settings.length);
  assert.equal(rows[0].sha256, sha(ok.body));
});

test('import: an admin API key cannot write a protected setting (the leaked-key bypass), nor anything else', async () => {
  setSetting('mcp_oauth_only', '1');
  const r = await json(await post(apiKey(ADMIN.key), { config: snapshot([{ key: 'mcp_oauth_only', value: '0', encrypted: false }]) }));
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'SESSION_REQUIRED');
  const s = await json(await post(bearer(STALE), { config: snapshot([{ key: 'ordinary_x', value: '1', encrypted: false }]) }));
  assert.equal(s.status, 401);
  assert.equal(value('mcp_oauth_only'), '1');
  assert.equal(value('ordinary_x'), null);
});

test('import: a snapshot naming protected keys is refused whole and audited; ordinary keys in it are not written', async () => {
  setSetting('mcp_oauth_only', '1');
  setSetting('host_gateway_auto_repair', '1');
  const config = snapshot([
    { key: 'ordinary_y', value: 'v', encrypted: false },
    { key: 'mcp_oauth_only', value: '0', encrypted: false },
    { key: 'host_gateway_auto_repair', value: '0', encrypted: false },
    { key: 'image_trust_mode', value: 'off', encrypted: false },
  ]);
  const r = await json(await post(bearer(FRESH), { config }));
  assert.equal(r.status, 409);
  assert.equal(r.body.error.code, 'PROTECTED_SETTINGS');
  assert.deepEqual(r.body.error.keys, ['mcp_oauth_only', 'host_gateway_auto_repair', 'image_trust_mode']);
  assert.equal(value('ordinary_y'), null, 'part of a refused snapshot was written');
  assert.equal(value('mcp_oauth_only'), '1');
  assert.equal(value('host_gateway_auto_repair'), '1');
  const refused = audits('config-settings-import-refused');
  assert.equal(refused.length, 1);
  assert.deepEqual(refused[0].keys, ['mcp_oauth_only', 'host_gateway_auto_repair', 'image_trust_mode']);
  assert.equal(refused[0].body_sha256, sha(config));
  // include_protected must be the boolean true, not a truthy string.
  assert.equal((await post(bearer(FRESH), { config, include_protected: 'true' })).status, 409);
});

test('import: include_protected=true from a fresh session writes them, and audits each with old and new value, ciphertext redacted', async () => {
  setSetting('mcp_oauth_only', '1');
  const oldKey = 'a'.repeat(64);
  const prevKey = process.env.ENCRYPTION_KEY;
  process.env.ENCRYPTION_KEY = oldKey;
  const blob = encrypt('secret-from-source');
  process.env.ENCRYPTION_KEY = prevKey;
  const config = snapshot([
    { key: 'ordinary_z', value: 'z', encrypted: false },
    { key: 'mcp_oauth_only', value: '0', encrypted: false },
    { key: 'oidc_client_secret_encrypted', value: blob, encrypted: true },
  ]);
  const r = await json(await post(bearer(FRESH), { config, old_key: oldKey, include_protected: true }));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.keys, ['ordinary_z', 'mcp_oauth_only', 'oidc_client_secret_encrypted']);
  assert.equal(value('mcp_oauth_only'), '0');
  const each = audits('config-settings-import-protected');
  assert.deepEqual(each.map((a) => [a.key, a.from, a.to]), [['mcp_oauth_only', '1', '0'], ['oidc_client_secret_encrypted', null, '(encrypted)']]);
  assert.ok(each.every((a) => a.include_protected === true && a.body_sha256 === sha(config) && a.user_id === ADMIN.id));
  assert.ok(!JSON.stringify(each).includes(blob), 'ciphertext reached the audit log');
  const done = audits('config-settings-import');
  assert.equal(done.length, 1);
  assert.deepEqual(done[0].keys_written, ['ordinary_z', 'mcp_oauth_only', 'oidc_client_secret_encrypted']);
});

test('import: a snapshot of ordinary keys only needs no include_protected and is audited with the keys written', async () => {
  const config = snapshot([{ key: 'ordinary_w', value: 'w', encrypted: false }]);
  const r = await json(await post(bearer(FRESH), { config }));
  assert.equal(r.status, 200);
  assert.equal(value('ordinary_w'), 'w');
  const done = audits('config-settings-import').at(-1);
  assert.deepEqual(done.keys_written, ['ordinary_w']);
  assert.equal(done.include_protected, false);
  assert.equal(audits('config-settings-import-protected').length, 2, 'an ordinary key was audited as protected');
});

test('key fingerprint: falls back to the running key with no .env key, and the audit says when the running key is not the .env one', async (t) => {
  const { liveKeyFingerprint, runningKeyFingerprint, keyAuditFields } = await import('../server/services/configArchiveGuard.js');
  const { shortFingerprint, keyFingerprint } = await import('../server/services/backupCrypto.js');
  const running = shortFingerprint(keyFingerprint(process.env.ENCRYPTION_KEY));
  assert.equal(runningKeyFingerprint(), running);
  assert.deepEqual(keyAuditFields(running, running), {
    encryption_key_replaced: false, encryption_key_before: running, encryption_key_after: running, encryption_key_running: running, key_outside_env_file: false,
  });
  const f = keyAuditFields('aaaa', 'bbbb');
  assert.equal(f.encryption_key_replaced, true);
  assert.equal(f.key_outside_env_file, true, 'a .env key that is not the running one was not flagged');
  const { repoRoot } = await import('../server/services/backupFiles.js');
  const { existsSync, readFileSync } = await import('fs');
  const envFile = join(repoRoot, '.env');
  if (existsSync(envFile) && /^\s*ENCRYPTION_KEY\s*=/m.test(readFileSync(envFile, 'utf8'))) return t.skip('this checkout has an ENCRYPTION_KEY in .env');
  assert.equal(liveKeyFingerprint(), running, 'with no key in .env the live fingerprint is not the running key');
});
