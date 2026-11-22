import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import net from 'net';
import crypto from 'crypto';

// Security settings outside the original step-up list, driven against the real
// server: the generic PUT /api/settings/:key refuses every key a dedicated
// route owns (so it cannot write SCIM, OIDC, MFA, OAuth, approval or egress
// policy around those routes' gates), and the policy, IT-setup, SSO-domain,
// blueprint and connection writes refuse a stale dashboard session.

const REPO = fileURLToPath(new URL('..', import.meta.url));
const ENCRYPTION_KEY = 'b'.repeat(64);
let child, base, dataDir, db, enc, adminId, appId;

async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

before(async () => {
  process.env.ENCRYPTION_KEY = ENCRYPTION_KEY;
  dataDir = mkdtempSync(join(tmpdir(), 'crane-step-up-cov-'));
  process.env.DATA_DIR = dataDir;
  process.env.LOG_LEVEL = 'error';
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/index.js'], {
    cwd: REPO,
    env: { ...process.env, DATA_DIR: dataDir, PORT: String(port), HOST: '127.0.0.1', ENCRYPTION_KEY, CRANE_DOMAIN: 'crane.example.test', LOG_LEVEL: 'error', APPCRANE_PR_POLL_DISABLED: '1', APPCRANE_GH_MCP_DISABLED: '1' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  for (let i = 0; i < 160; i++) {
    try { const r = await fetch(`${base}/api/info`); if (r.ok) break; } catch (_) { /* booting */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  const { initDb, getDb } = await import('../server/db.js');
  initDb();
  db = getDb();
  enc = await import('../server/services/encryption.js');
  adminId = Number(db.prepare("INSERT INTO users (name,email,role,active,kind,api_key_hash,password_hash) VALUES ('admin','admin@t.test','platform_admin',1,'human',?,?)")
    .run(enc.hashApiKey(enc.generateApiKey('dhk_admin')), enc.hashPassword('admin-password-123')).lastInsertRowid);
  appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Shop','shop',1,'managed','main')").run().lastInsertRowid);
});

after(() => {
  try { child?.kill(); } catch (_) {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch (_) {}
});

function session(ageMin) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(adminId, enc.hashApiKey(token));
  db.prepare(`UPDATE identity_sessions SET created_at = datetime('now', '-${ageMin} minutes') WHERE token_hash = ?`).run(enc.hashApiKey(token));
  return token;
}

async function call(token, method, path, body) {
  const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined && { body: JSON.stringify(body) }) });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* not json */ }
  return { status: r.status, body: json };
}

const OWNED_KEYS = [
  'oidc_discovery_url', 'oidc_client_id', 'oidc_enabled', 'saml_idp_sso_url', 'saml_enabled',
  'scim_token_hash', 'scim_enabled', 'mfa_required', 'auth_mfa_required', 'session_admin_idle_minutes',
  'oauth_id_jag_enabled', 'oauth_dcr_mode', 'oauth_cimd_enabled', 'capability_approval_required:headless',
  'egress_mode', 'app_audit_owner_streams_private', 'siem_private_allowlist', 'signin_risk_policy',
  'api_key_max_age_days', 'policy_ban_public_apps', 'github_service_token_enc', 'llm_gateway',
  'classification_policy', 'access_review_policy', 'graph_client_secret_encrypted',
];

test('generic settings route refuses every key a dedicated route owns, even to a fresh admin session', async () => {
  const fresh = session(0);
  for (const key of OWNED_KEYS) {
    const before = db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;
    const r = await call(fresh, 'PUT', `/api/settings/${encodeURIComponent(key)}`, { value: '1' });
    assert.equal(r.status, 403, `${key} was writable through the generic route (${r.status})`);
    assert.equal(r.body?.error?.code, 'FORBIDDEN', key);
    assert.match(r.body?.error?.message || '', /^Use /, key);
    assert.equal(db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null, before, `${key} changed`);
  }
  const ok = await call(fresh, 'PUT', '/api/settings/branding', { value: 'Blue' });
  assert.equal(ok.status, 200, 'an ordinary key stays writable');
});

test('a SCIM token chosen by the caller cannot be planted through the generic route', async () => {
  const mine = 'scim_attacker_chosen_token_1234567890';
  await call(session(30), 'PUT', '/api/settings/scim_token_hash', { value: enc.hashApiKey(mine) });
  await call(session(30), 'PUT', '/api/settings/scim_enabled', { value: '1' });
  const r = await fetch(`${base}/api/scim/v2/Users`, { headers: { Authorization: `Bearer ${mine}` } });
  assert.ok(r.status === 401 || r.status === 403, `SCIM answered ${r.status} to a token planted through /api/settings`);
  assert.equal(db.prepare("SELECT value FROM settings WHERE key = 'scim_token_hash'").get()?.value ?? null, null);
});

const GATED = () => [
  ['PUT', '/api/capability-approvals/policy', { headless: { approval_required: false } }],
  ['PUT', '/api/egress/settings', { mode: 'open' }],
  ['PUT', '/api/apps/shop/egress', { enforced: false }],
  ['PUT', '/api/signin-security/policy', {}],
  ['POST', `/api/signin-security/users/${adminId}/unlock`, {}],
  ['PUT', '/api/oauth/admin/policy', { cimd_enabled: true }],
  ['POST', '/api/oauth/admin/blueprints', { name: 'wide', scopes: ['mcp:read'] }],
  ['PATCH', '/api/oauth/admin/blueprints/1', { scopes: ['mcp:read'] }],
  ['PUT', '/api/oauth/admin/clients/c1/blueprint', { blueprint_id: null }],
  ['PUT', '/api/app-audit/settings', { owner_streams_private: true }],
  ['POST', '/api/connections', { name: 'stripe' }],
  ['PUT', '/api/connections/stripe', {}],
  ['POST', '/api/it-setup-links', { label: 'x', scopes: ['oidc', 'saml', 'scim', 'siem', 'domains'] }],
  ['POST', '/api/it-setup-links/1/rollback', { force: true }],
  ['POST', '/api/sso-domains', { domain: 'corp.example.test' }],
  ['POST', '/api/sso-domains/1/verify', {}],
  ['DELETE', '/api/sso-domains/1'],
];

test('policy, IT setup, SSO domain, blueprint and connection writes refuse a stale admin session', async () => {
  const stale = session(30);
  const linksBefore = db.prepare('SELECT COUNT(*) AS n FROM it_setup_links').get().n;
  for (const [method, path, body] of GATED()) {
    const r = await call(stale, method, path, body);
    assert.equal(r.status, 401, `${method} ${path}: ${r.status} ${JSON.stringify(r.body)}`);
    assert.equal(r.body?.error?.code, 'STEP_UP_REQUIRED', `${method} ${path}`);
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM it_setup_links').get().n, linksBefore, 'a link was created without a step-up');
  assert.equal(db.prepare("SELECT value FROM settings WHERE key = 'egress_mode'").get()?.value ?? null, null);
});

test('the same writes pass the gate for a fresh session', async () => {
  const fresh = session(0);
  for (const [method, path, body] of GATED()) {
    const r = await call(fresh, method, path, body);
    assert.notEqual(r.body?.error?.code, 'STEP_UP_REQUIRED', `${method} ${path}`);
  }
  const link = await call(session(0), 'POST', '/api/it-setup-links', { label: 'ok', scopes: ['oidc'] });
  assert.equal(link.status, 201);
});

// set-password without a current password proves only the credential the
// caller already had: the session it returns must not count as a fresh sign-in.
test('a session from set-password by API key or stale session is not a step-up', async () => {
  const mkOwner = (name) => {
    const key = enc.generateApiKey('dhk_user');
    const id = Number(db.prepare("INSERT INTO users (name,email,role,active,kind,api_key_hash,sso_sub) VALUES (?,?,'user',1,'human',?,?)")
      .run(name, `${name}@t.test`, enc.hashApiKey(key), `${name}-sub`).lastInsertRowid);
    db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, id);
    return { id, key };
  };
  db.prepare("INSERT OR IGNORE INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'production', 'API_TOKEN', ?)").run(appId, enc.encrypt('prod-secret'));
  const reveal = (token) => call(token, 'POST', '/api/apps/shop/env/production/API_TOKEN/reveal', {});

  const byKey = mkOwner('keyonly');
  const r = await fetch(`${base}/api/identity/set-password`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': byKey.key }, body: JSON.stringify({ password: 'a long enough password' }) });
  assert.equal(r.status, 200);
  const { token } = await r.json();
  const out = await reveal(token);
  assert.equal(out.body?.error?.code, 'STEP_UP_REQUIRED', `key -> set-password -> reveal: ${out.status} ${JSON.stringify(out.body)}`);

  const bySession = mkOwner('stalesess');
  const stale = crypto.randomBytes(32).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(bySession.id, enc.hashApiKey(stale));
  db.prepare("UPDATE identity_sessions SET created_at = datetime('now', '-30 minutes') WHERE token_hash = ?").run(enc.hashApiKey(stale));
  const r2 = await call(stale, 'POST', '/api/identity/set-password', { password: 'another long password' });
  assert.equal(r2.status, 200);
  const out2 = await reveal(r2.body.token);
  assert.equal(out2.body?.error?.code, 'STEP_UP_REQUIRED', `stale session -> set-password -> reveal: ${out2.status}`);

  // With the current password typed, the new session is a real sign-in.
  const r3 = await call(r2.body.token, 'POST', '/api/identity/set-password', { current_password: 'another long password', password: 'a third long password' });
  assert.equal(r3.status, 200);
  const out3 = await reveal(r3.body.token);
  assert.equal(out3.status, 200, `current password -> reveal: ${out3.status} ${JSON.stringify(out3.body)}`);
});
