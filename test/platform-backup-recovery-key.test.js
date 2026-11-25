import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import express from 'express';

// The backup recovery key route (v2.145.0): platform admin only, a dashboard
// session only (no API key), a fresh step-up, audited, and the status route
// never returns the key.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-recovery-key-'));
const KEY = randomBytes(32).toString('hex');
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = KEY;
process.env.LOG_LEVEL = 'error';

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
const PLAIN = user('pu', 'user');
const FRESH = session(ADMIN.id, 0);
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

const call = async (method, headers) => {
  const r = await fetch(`${BASE}/api/settings/backup/recovery-key`, { method, headers });
  const text = await r.text();
  return { status: r.status, text, body: JSON.parse(text), cache: r.headers.get('cache-control') };
};
const audits = () => db.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'backup-recovery-key-download'").all();
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const fp = createHash('sha256').update(`sha256-appcrane-encryption-key-v1:${KEY}`).digest('hex');

test('refused, unaudited and keyless: a plain user, an admin API key, a stale admin session', async () => {
  const plain = await call('POST', bearer(PLAIN_FRESH));
  assert.equal(plain.status, 403, plain.text);
  const apiKey = await call('POST', { 'X-API-Key': ADMIN.key });
  assert.equal(apiKey.status, 403, apiKey.text);
  assert.equal(apiKey.body.error.code, 'SESSION_REQUIRED');
  const stale = await call('POST', bearer(STALE));
  assert.equal(stale.status, 401, stale.text);
  assert.equal(stale.body.error.code, 'STEP_UP_REQUIRED');
  assert.match(stale.body.error.message, /download the backup recovery key/);
  for (const r of [plain, apiKey, stale]) assert.ok(!r.text.includes(KEY), 'no key in a refusal');
  assert.deepEqual(audits(), []);
});

test('status before any download: fingerprint, never the key, not yet taken off the host', async () => {
  const s = await call('GET', { 'X-API-Key': ADMIN.key });
  assert.equal(s.status, 200, s.text);
  assert.ok(!s.text.includes(KEY));
  assert.equal(s.body.fingerprint, fp.slice(0, 16));
  assert.equal(s.body.downloaded_for_current_key, false);
  assert.match(s.body.warning, /unrestorable/);
  assert.equal((await call('GET', bearer(PLAIN_FRESH))).status, 403);
});

test('a freshly stepped-up admin session gets the key, the download is audited, and status records it', async () => {
  const r = await call('POST', bearer(FRESH));
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.key, KEY);
  assert.equal(r.body.fingerprint, fp);
  assert.match(r.body.file_text, new RegExp(`^ENCRYPTION_KEY=${KEY}$`, 'm'));
  assert.match(r.body.file_name, /^appcrane-recovery-key-.*\.txt$/);
  assert.equal(r.cache, 'no-store');
  const a = audits();
  assert.equal(a.length, 1);
  assert.equal(a[0].user_id, ADMIN.id);
  assert.ok(!a[0].detail.includes(KEY), 'the audit row holds the fingerprint, not the key');
  assert.equal(JSON.parse(a[0].detail).fingerprint, fp.slice(0, 16));
  const s = await call('GET', { 'X-API-Key': ADMIN.key });
  assert.equal(s.body.downloaded_for_current_key, true);
  assert.equal(s.body.downloaded_by, 'pa');
  assert.ok(s.body.downloaded_at);
});
