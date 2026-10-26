import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash, randomBytes } from 'crypto';
import express from 'express';
import Database from 'better-sqlite3';

// API key expiry, rotation and "MCP: OAuth only" (services/apiKeyExpiry.js,
// migration 136, middleware/auth.js, routes/apiKeys.js, routes/mcp.js), driven
// over real HTTP against an ephemeral server.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-keyexp-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const expiry = await import('../server/services/apiKeyExpiry.js');
const oauthStore = await import('../server/services/oauthStore.js');
const { issueCoderMcpKey } = await import('../server/services/coderMcpKey.js');

initDb();
const db = getDb();
db.prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES ('alpha','alpha',931,'managed','local','main')").run();
const ALPHA = db.prepare("SELECT id FROM apps WHERE slug='alpha'").get().id;

function mkUser({ role = 'user' } = {}) {
  const key = generateApiKey(role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  const tag = randomBytes(3).toString('hex');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`u${tag}`, `u${tag}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(ALPHA, id);
  return { id, key };
}
function mkMcpKey(userId) {
  const key = generateApiKey('dhk_mcp');
  const id = db.prepare('INSERT INTO user_mcp_keys (user_id, key_hash, label) VALUES (?, ?, ?)').run(userId, hashApiKey(key), 'k').lastInsertRowid;
  return { id, key };
}

const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api/mcp', (await import('../server/routes/mcp.js')).default);
httpApp.get('/api/apps', requireAuth, (req, res) => res.json({ ok: true }));
httpApp.use('/api', (await import('../server/routes/apiKeys.js')).default);
httpApp.use('/api', (await import('../server/routes/userMcpKeys.js')).default);
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const json = async (res) => { try { return await res.json(); } catch (_) { return null; } };
async function rest(headers) {
  const res = await fetch(`${BASE}/api/apps`, { headers });
  return { status: res.status, body: await json(res) };
}
async function mcp(headers) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
  });
  return { status: res.status, body: await json(res), www: res.headers.get('www-authenticate') };
}
const daysFromNow = (iso) => (Date.parse(iso.replace(' ', 'T') + 'Z') - Date.now()) / 86400_000;
const today = () => new Date().toISOString().slice(0, 10);

test('migration 136 gives every existing live key upgrade time + 90 days, not an instant expiry', () => {
  const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  const old = new Database(':memory:');
  for (const f of files.filter((x) => x < '136')) old.exec(readFileSync(join(dir, f), 'utf8'));
  const uid = old.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind,created_at) VALUES ('old','old@t.test','user','h1',1,'human','2024-01-01 00:00:00')").run().lastInsertRowid;
  const longKey = old.prepare("INSERT INTO user_mcp_keys (user_id,key_hash,label,created_at) VALUES (?,'m1','old','2024-01-01 00:00:00')").run(uid).lastInsertRowid;
  const shortKey = old.prepare("INSERT INTO user_mcp_keys (user_id,key_hash,label,expires_at) VALUES (?,'m2','short',datetime('now','+5 days'))").run(uid).lastInsertRowid;
  const aid = old.prepare("INSERT INTO crew_agents (owner_user_id,name,kind) VALUES (?, 'bot', 'hosted')").run(uid).lastInsertRowid;
  const tok = old.prepare("INSERT INTO crew_agent_tokens (agent_id,token_hash,hint) VALUES (?, 'c1', 'abcdef')").run(aid).lastInsertRowid;

  old.exec(readFileSync(join(dir, files.find((f) => f.startsWith('136-'))), 'utf8'));

  const u = old.prepare('SELECT * FROM users WHERE id = ?').get(uid);
  assert.ok(Math.abs(daysFromNow(u.api_key_expires_at) - 90) < 0.01, `user key expiry ${u.api_key_expires_at}`);
  assert.equal(u.api_key_hash, 'h1');
  assert.ok(Math.abs(daysFromNow(old.prepare('SELECT expires_at FROM user_mcp_keys WHERE id = ?').get(longKey).expires_at) - 90) < 0.01);
  assert.ok(Math.abs(daysFromNow(old.prepare('SELECT expires_at FROM user_mcp_keys WHERE id = ?').get(shortKey).expires_at) - 5) < 0.01, 'a shorter existing expiry is kept');
  assert.ok(Math.abs(daysFromNow(old.prepare('SELECT expires_at FROM crew_agent_tokens WHERE id = ?').get(tok).expires_at) - 90) < 0.01);
  old.close();
});

test('a fresh key works; a key past its expiry gets 401 with the message and an audit row', async () => {
  const u = mkUser();
  assert.equal((await rest({ 'X-API-Key': u.key })).status, 200);
  assert.ok(Math.abs(daysFromNow(db.prepare('SELECT api_key_expires_at FROM users WHERE id = ?').get(u.id).api_key_expires_at) - 90) < 0.01);

  db.prepare("UPDATE users SET api_key_expires_at = datetime('now', '-1 minute') WHERE id = ?").run(u.id);
  expiry._resetAuditThrottleForTests();
  const r = await rest({ 'X-API-Key': u.key });
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'API_KEY_EXPIRED');
  assert.equal(r.body.error.message, `This API key expired on ${today()}. Create a new one in Settings → Account.`);
  const audit = db.prepare("SELECT * FROM audit_log WHERE action = 'api-key.expired-used' AND user_id = ?").all(u.id);
  assert.equal(audit.length, 1);
  assert.equal(JSON.parse(audit[0].detail).kind, 'user');

  const row = db.prepare('SELECT api_key_hash, api_key_expired_hash FROM users WHERE id = ?').get(u.id);
  assert.equal(row.api_key_hash, `expired:${hashApiKey(u.key)}`, 'the hash is moved aside so direct api_key_hash lookups stop matching');
  const again = await rest({ 'X-API-Key': u.key });
  assert.equal(again.status, 401);
  assert.match(again.body.error.message, /^This API key expired on /);
});

test('the sweep expires keys that nobody presents, and an expired personal MCP key gets 401', async () => {
  const u = mkUser();
  db.prepare("UPDATE users SET api_key_expires_at = datetime('now', '-1 minute') WHERE id = ?").run(u.id);
  expiry.runApiKeyExpiry(db);
  assert.equal(db.prepare('SELECT api_key_hash FROM users WHERE id = ?').get(u.id).api_key_hash, `expired:${hashApiKey(u.key)}`);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE api_key_hash = ?').get(hashApiKey(u.key)).n, 0);

  const owner = mkUser();
  const k = mkMcpKey(owner.id);
  assert.equal((await mcp({ 'X-API-Key': k.key })).status, 200);
  db.prepare("UPDATE user_mcp_keys SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(k.id);
  const r = await mcp({ 'X-API-Key': k.key });
  assert.equal(r.status, 401);
  assert.match(r.body.error.message, /^This API key expired on \d{4}-\d{2}-\d{2}\./);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'api-key.expired-used' AND user_id = ?").get(owner.id).n, 1);
});

test('the window is a platform setting, bounded 7..365', async () => {
  const admin = mkUser({ role: 'platform_admin' });
  const put = (body) => fetch(`${BASE}/api/api-key-policy`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-API-Key': admin.key }, body: JSON.stringify(body) });
  assert.equal((await put({ max_age_days: 6 })).status, 400);
  assert.equal((await put({ max_age_days: 366 })).status, 400);
  const ok = await put({ max_age_days: 30 });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).max_age_days, 30);
  const u = mkUser();
  assert.ok(Math.abs(daysFromNow(db.prepare('SELECT api_key_expires_at FROM users WHERE id = ?').get(u.id).api_key_expires_at) - 30) < 0.01);
  const k = mkMcpKey(u.id);
  assert.ok(Math.abs(daysFromNow(db.prepare('SELECT expires_at FROM user_mcp_keys WHERE id = ?').get(k.id).expires_at) - 30) < 0.01);

  db.prepare("UPDATE settings SET value = '5000' WHERE key = 'api_key_max_age_days'").run();
  const clamped = mkUser();
  assert.ok(Math.abs(daysFromNow(db.prepare('SELECT api_key_expires_at FROM users WHERE id = ?').get(clamped.id).api_key_expires_at) - 365) < 0.01, 'a value written around the API is clamped');

  const user = mkUser();
  assert.equal((await fetch(`${BASE}/api/api-key-policy`, { headers: { 'X-API-Key': user.key } })).status, 403);
  assert.equal((await put({ max_age_days: 90 })).status, 200);
});

test('warning e-mails go out at 14 and 3 days before expiry, once each', () => {
  db.prepare("DELETE FROM email_queue WHERE source = 'api-key-expiry'").run();
  const u = mkUser();
  db.prepare("UPDATE users SET api_key_expires_at = datetime('now', '+10 days'), api_key_last_used_at = datetime('now') WHERE id = ?").run(u.id);
  const unused = mkUser();
  db.prepare("UPDATE users SET api_key_expires_at = datetime('now', '+10 days') WHERE id = ?").run(unused.id);
  const k = mkMcpKey(u.id);
  db.prepare("UPDATE user_mcp_keys SET expires_at = datetime('now', '+20 days') WHERE id = ?").run(k.id);

  const rows = () => db.prepare("SELECT to_email, subject, idempotency_key FROM email_queue WHERE source = 'api-key-expiry' ORDER BY id").all();
  expiry.sendExpiryWarnings(db);
  expiry.sendExpiryWarnings(db);
  let sent = rows();
  assert.equal(sent.length, 1, JSON.stringify(sent));
  assert.match(sent[0].idempotency_key, new RegExp(`^api-key-expiry:user:${u.id}:.*:14$`));
  assert.match(sent[0].subject, /expires on \d{4}-\d{2}-\d{2}$/);

  const eightDaysOn = Date.now() + 8 * 86400_000;
  expiry.sendExpiryWarnings(db, eightDaysOn);
  expiry.sendExpiryWarnings(db, eightDaysOn);
  sent = rows();
  assert.equal(sent.length, 2);
  assert.match(sent[1].idempotency_key, new RegExp(`^api-key-expiry:user:${u.id}:.*:3$`));
  assert.ok(!sent.some((r) => r.to_email.startsWith(`u`) && r.idempotency_key.includes(`:user:${unused.id}:`)), 'a never-used user key is not warned about');
});

test('rotate issues a new key once and the old one stops working', async () => {
  const u = mkUser();
  const res = await fetch(`${BASE}/api/me/api-key/rotate`, { method: 'POST', headers: { 'X-API-Key': u.key } });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.match(body.api_key, /^dhk_user_/);
  assert.equal((await rest({ 'X-API-Key': u.key })).status, 401);
  assert.equal((await rest({ 'X-API-Key': body.api_key })).status, 200);

  const k = mkMcpKey(u.id);
  db.prepare("UPDATE user_mcp_keys SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(k.id);
  const sess = generateApiKey('sess');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(u.id, hashApiKey(sess));
  const rot = await fetch(`${BASE}/api/me/mcp-keys/${k.id}/rotate`, { method: 'POST', headers: { Authorization: `Bearer ${sess}` } });
  assert.equal(rot.status, 200);
  const rb = await rot.json();
  assert.ok(Math.abs(daysFromNow(rb.key.expires_at) - 90) < 0.01, 'rotation restarts the window');
  assert.equal((await mcp({ 'X-API-Key': k.key })).status, 401);
  assert.equal((await mcp({ 'X-API-Key': rb.api_key })).status, 200);

  const mcpOnly = await fetch(`${BASE}/api/me/api-key/rotate`, { method: 'POST', headers: { 'X-API-Key': rb.api_key } });
  assert.equal(mcpOnly.status, 403, 'an MCP key cannot rotate the REST key');
});

async function oauthToken(userId) {
  const { client } = oauthStore.registerClient({ client_name: 'T', redirect_uris: ['http://127.0.0.1:1/cb'], grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none' });
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const code = oauthStore.createCode({ clientId: client.client_id, userId, redirectUri: 'http://127.0.0.1:1/cb', codeChallenge: challenge, scope: 'mcp', resource: `${BASE}/api/mcp`, readOnly: false });
  return oauthStore.redeemCode({ code, client, redirectUri: 'http://127.0.0.1:1/cb', verifier, resource: `${BASE}/api/mcp` }).access_token;
}

test('MCP: OAuth only refuses API keys on POST /api/mcp with an OAuth challenge; OAuth, coder keys and REST keep working', async () => {
  const u = mkUser();
  const k = mkMcpKey(u.id);
  const access = await oauthToken(u.id);
  const coder = issueCoderMcpKey({ userId: u.id, appId: ALPHA, sessionId: 'sess-1' });
  const exempt = mkUser();

  for (const h of [{ 'X-API-Key': k.key }, { 'X-API-Key': u.key }, { Authorization: `Bearer ${access}` }, { 'X-API-Key': coder.apiKey }]) {
    assert.equal((await mcp(h)).status, 200, `off: ${Object.keys(h)[0]}`);
  }

  db.prepare("INSERT INTO settings (key, value) VALUES ('mcp_oauth_only', 'true') ON CONFLICT(key) DO UPDATE SET value = 'true'").run();
  db.prepare("INSERT INTO settings (key, value) VALUES ('mcp_oauth_only_exempt_user_ids', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify([exempt.id]));
  try {
    for (const key of [k.key, u.key]) {
      const r = await mcp({ 'X-API-Key': key });
      assert.equal(r.status, 401);
      assert.equal(r.body.error.code, 'MCP_OAUTH_ONLY');
      assert.match(r.www, /^Bearer error="invalid_token"/);
      assert.match(r.www, new RegExp(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/api/mcp"`));
    }
    assert.equal((await mcp({ Authorization: `Bearer ${access}` })).status, 200, 'OAuth token accepted');
    assert.equal((await mcp({ 'X-API-Key': coder.apiKey })).status, 200, 'coder per-turn key accepted');
    assert.equal((await mcp({ 'X-API-Key': exempt.key })).status, 200, 'exempt user accepted');
    assert.equal((await rest({ 'X-API-Key': u.key })).status, 200, 'REST unaffected');
  } finally {
    db.prepare("UPDATE settings SET value = 'false' WHERE key = 'mcp_oauth_only'").run();
  }
  assert.equal((await mcp({ 'X-API-Key': k.key })).status, 200, 'off again: API key accepted');
});

test('a Crew agent token gets the window on issue and stops resolving once expired', async () => {
  const { resolveAgentToken } = await import('../server/services/crewTokens.js');
  const u = mkUser();
  const aid = db.prepare("INSERT INTO crew_agents (owner_user_id, name, kind) VALUES (?, ?, 'hosted')").run(u.id, `bot-${randomBytes(3).toString('hex')}`).lastInsertRowid;
  const token = `dhk_crew_${randomBytes(32).toString('base64url')}`;
  const tid = db.prepare('INSERT INTO crew_agent_tokens (agent_id, token_hash, hint) VALUES (?, ?, ?)').run(aid, hashApiKey(token), 'abcdef').lastInsertRowid;
  assert.ok(Math.abs(daysFromNow(db.prepare('SELECT expires_at FROM crew_agent_tokens WHERE id = ?').get(tid).expires_at) - 90) < 0.01);
  assert.ok(resolveAgentToken(token), 'a fresh token resolves');
  db.prepare("UPDATE crew_agent_tokens SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(tid);
  assert.equal(resolveAgentToken(token), null);
});
