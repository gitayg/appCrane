import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The onboarding button's MCP key (POST /api/me/mcp-keys { purpose: 'onboarding' },
// services/onboardingMcpKey.js). Each click used to leave another write-capable
// key behind; a new onboarding key now revokes only the caller's earlier
// onboarding keys that were never used. Driven through the real route and
// requireAuth with a session-equivalent user API key.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-onbkey-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { onboardingLabel } = await import('../server/services/onboardingMcpKey.js');

initDb();
const db = getDb();

let seq = 0;
function mkUser(role = 'user') {
  const n = ++seq;
  const apiKey = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`u${n}`, `u${n}@t.test`, role, hashApiKey(apiKey), 'human').lastInsertRowid;
  return { id, apiKey };
}
function mkKey(userId, { label = null, purpose = null, used = false, coder = false } = {}) {
  return db.prepare(`INSERT INTO user_mcp_keys (user_id,key_hash,label,purpose,last_used_at,coder_session_id)
                     VALUES (?,?,?,?,?,?)`)
    .run(userId, hashApiKey(generateApiKey('dhk_mcp')), label, purpose, used ? '2026-01-01 00:00:00' : null, coder ? 'sess-x' : null)
    .lastInsertRowid;
}
const revokedAt = (id) => db.prepare('SELECT revoked_at FROM user_mcp_keys WHERE id = ?').get(id).revoked_at;

const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api', (await import('../server/routes/userMcpKeys.js')).default);
httpApp.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message, code: err.code }));
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

async function issue(user, body) {
  const r = await fetch(`${BASE}/api/me/mcp-keys`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': user.apiKey }, body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
}

test('onboarding revokes the caller\'s unused onboarding keys and nothing else', async () => {
  const me = mkUser();
  const other = mkUser();
  const legacyUnused = mkKey(me.id, { label: 'onboarding-1762500000000' });
  const taggedUnused = mkKey(me.id, { label: 'App onboarding, 1 Nov 2026', purpose: 'onboarding' });
  const legacyUsed = mkKey(me.id, { label: 'onboarding-1762500000001', used: true });
  const taggedUsed = mkKey(me.id, { purpose: 'onboarding', used: true });
  const ordinary = mkKey(me.id, { label: 'laptop' });
  const lookalike = mkKey(me.id, { label: 'onboarding-notes' });
  const coder = mkKey(me.id, { label: 'onboarding-1762500000002', coder: true });
  const othersOnboarding = mkKey(other.id, { label: 'onboarding-1762500000003' });

  const { status, body } = await issue(me, { purpose: 'onboarding', label: 'client label ignored' });
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.revoked_previous, 2);
  assert.ok(revokedAt(legacyUnused), 'legacy unused onboarding key should be revoked');
  assert.ok(revokedAt(taggedUnused), 'purpose=onboarding unused key should be revoked');
  for (const [name, id] of Object.entries({ legacyUsed, taggedUsed, ordinary, lookalike, coder, othersOnboarding })) {
    assert.equal(revokedAt(id), null, `${name} must survive`);
  }
  assert.equal(revokedAt(body.key.id), null, 'the new key is live');
});

test('the new onboarding key has purpose, a readable server label and a 30-day expiry', async () => {
  const me = mkUser();
  const { body } = await issue(me, { purpose: 'onboarding', label: 'onboarding-123' });
  const row = db.prepare('SELECT label, purpose, expires_at, read_only FROM user_mcp_keys WHERE id = ?').get(body.key.id);
  assert.equal(row.purpose, 'onboarding');
  assert.equal(body.key.purpose, 'onboarding');
  assert.equal(row.label, onboardingLabel());
  assert.match(row.label, /^App onboarding, \d{1,2} [A-Z][a-z]{2} \d{4}$/);
  const days = (Date.parse(row.expires_at.replace(' ', 'T') + 'Z') - Date.now()) / 86_400_000;
  assert.ok(days > 29.9 && days <= 30.01, `expiry ${row.expires_at} is ${days} days out`);
  assert.equal(body.key.expires_at, row.expires_at);
  assert.match(body.api_key, /^dhk_mcp_/);
});

test('a shorter platform max age wins over the 30 days', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('api_key_max_age_days', '10') ON CONFLICT(key) DO UPDATE SET value = excluded.value").run();
  try {
    const { body } = await issue(mkUser(), { purpose: 'onboarding' });
    const days = (Date.parse(body.key.expires_at.replace(' ', 'T') + 'Z') - Date.now()) / 86_400_000;
    assert.ok(days > 9.9 && days <= 10.01, `expiry ${body.key.expires_at} is ${days} days out`);
  } finally {
    db.prepare("DELETE FROM settings WHERE key = 'api_key_max_age_days'").run();
  }
});

test('one audit row per replaced key, with the key id and the reason', async () => {
  const me = mkUser();
  const a = mkKey(me.id, { label: 'onboarding-1' });
  const b = mkKey(me.id, { purpose: 'onboarding' });
  await issue(me, { purpose: 'onboarding' });
  const rows = db.prepare("SELECT detail FROM audit_log WHERE user_id = ? AND action = 'user-mcp-key-revoke'").all(me.id)
    .map((r) => JSON.parse(r.detail));
  assert.deepEqual(rows.map((d) => d.key_id).sort((x, y) => x - y), [a, b].sort((x, y) => x - y));
  for (const d of rows) assert.equal(d.reason, 'replaced by a new onboarding key');
});

test('an unknown purpose is refused; no purpose keeps the ordinary behaviour', async () => {
  const me = mkUser();
  const keep = mkKey(me.id, { label: 'onboarding-5' });
  const bad = await issue(me, { purpose: 'admin' });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.code, 'VALIDATION');
  const plain = await issue(me, { label: 'desk' });
  assert.equal(plain.status, 200);
  assert.equal(plain.body.revoked_previous, undefined);
  assert.equal(revokedAt(keep), null, 'an ordinary create must not revoke onboarding keys');
  const row = db.prepare('SELECT label, purpose FROM user_mcp_keys WHERE id = ?').get(plain.body.key.id);
  assert.deepEqual({ ...row }, { label: 'desk', purpose: null });
});
