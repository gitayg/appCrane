import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Per-app origins: the platform settings that turn it on
// (app_isolation_domain, app_isolation_tls_cert_file/_key_file). Written only
// through PUT /api/settings/isolation so its checks cannot be skipped: a
// domain that is the platform host, or one under which the platform host
// itself would parse as an app host, would route the dashboard to an app.

const DATA = mkdtempSync(join(tmpdir(), 'crane-iso-settings-'));
process.env.DATA_DIR = DATA;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.example.com';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const ADMIN_KEY = generateApiKey('dhk_admin');
const USER_KEY = generateApiKey('dhk_user');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','admin@example.test','platform_admin',?,1,'human')").run(hashApiKey(ADMIN_KEY));
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('User','user@example.test','user',?,1,'human')").run(hashApiKey(USER_KEY));

// Count reload attempts. Off Linux reloadCaddy() logs the config it would
// write; on Linux (CI) it really runs caddy, which a runner does not have, so
// the attempt shows up as the route's "reload ... failed" warning instead.
const log = (await import('../server/utils/logger.js')).default;
let reloads = 0;
const origInfo = log.info;
const origWarn = log.warn;
log.info = (msg, meta) => { if (String(msg).startsWith('[Caddy mock]')) reloads += 1; else origInfo(msg, meta); };
log.warn = (msg, meta) => { if (String(msg).startsWith('Caddy reload after isolation change')) reloads += 1; else origWarn(msg, meta); };

const settingsRoutes = (await import('../server/routes/settings.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/settings', settingsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { log.info = origInfo; server.closeAllConnections?.(); server.close(); });

async function req(method, path, key, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'X-API-Key': key, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* not json */ }
  return { status: res.status, text, body: json };
}
const stored = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? '';
const waitFor = async (pred) => { for (let i = 0; i < 100 && !pred(); i++) await new Promise((r) => setTimeout(r, 20)); };

test('off by default; the read is platform-admin only', async () => {
  const r = await req('GET', '/api/settings/isolation', ADMIN_KEY);
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.body, { domain: '', tls_cert_file: '', tls_key_file: '', enabled: false, warning: null });
  assert.equal((await req('GET', '/api/settings/isolation', USER_KEY)).status, 403);
  assert.equal((await req('PUT', '/api/settings/isolation', USER_KEY, { domain: 'apps.example.com' })).status, 403);
  assert.equal(stored('app_isolation_domain'), '');
});

test('refuses a malformed domain', async () => {
  for (const domain of ['not a domain', 'localhost']) {
    const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain });
    assert.equal(r.status, 400, `${domain}: ${r.text}`);
  }
  assert.equal(stored('app_isolation_domain'), '');
});

test('refuses a domain under which the platform host would be an app host, and stores nothing', async () => {
  const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: 'example.com' });
  assert.equal(r.status, 400, r.text);
  assert.match(r.body.error.message, /would itself be an app host/);
  assert.equal(stored('app_isolation_domain'), '', 'the refused value was left in the settings table');
});

// Apps directly under the platform host (<slug>.crane.example.com next to
// crane.example.com) are allowed: the platform host is not under itself, so it
// never parses as an app host, and its session cookie is __Host- either way.
test('accepts the platform host itself as the apps domain; the platform host is not an app host', async () => {
  const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: 'CRANE.example.com.' });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.domain, 'crane.example.com');
  assert.equal(r.body.warning, null);
  const { parseAppHost, appHost } = await import('../server/services/appOrigin.js');
  assert.equal(parseAppHost(db, 'crane.example.com'), null);
  assert.equal(appHost(db, 'orders', 'production'), 'orders.crane.example.com');
  assert.deepEqual(parseAppHost(db, 'orders-sandbox.crane.example.com'), { slug: 'orders', env: 'sandbox' });
  const off = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: '' });
  assert.equal(off.status, 200, off.text);
  assert.equal(stored('app_isolation_domain'), '');
});

test('TLS files: both or neither, and they must exist and be readable', async () => {
  const one = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: 'apps.example.com', tls_cert_file: '/etc/x.pem' });
  assert.equal(one.status, 400, one.text);
  const missing = await req('PUT', '/api/settings/isolation', ADMIN_KEY, {
    domain: 'apps.example.com', tls_cert_file: join(DATA, 'nope.crt'), tls_key_file: join(DATA, 'nope.key'),
  });
  assert.equal(missing.status, 400, missing.text);
  assert.match(missing.body.error.message, /does not exist or is not a readable file/);
  const dir = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { tls_cert_file: DATA, tls_key_file: DATA });
  assert.equal(dir.status, 400, dir.text);
  assert.equal(stored('app_isolation_domain'), '');
  assert.equal(stored('app_isolation_tls_cert_file'), '');
});

test('turning it on stores the normalized domain, audits, reloads Caddy, and warns on nothing same-site', async () => {
  const before = reloads;
  const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: 'https://Apps.Example.com/' });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.domain, 'apps.example.com');
  assert.equal(r.body.enabled, true);
  assert.equal(r.body.warning, null);
  assert.equal(stored('app_isolation_domain'), 'apps.example.com');
  await waitFor(() => reloads > before);
  assert.ok(reloads > before, 'Caddy was not reloaded after the change');
  const audit = db.prepare("SELECT detail FROM audit_log WHERE action = 'app-isolation-change' ORDER BY id DESC LIMIT 1").get();
  assert.ok(audit, 'no audit entry');
  assert.deepEqual(JSON.parse(audit.detail).to, { domain: 'apps.example.com', tls_cert_file: '', tls_key_file: '' });
  const read = await req('GET', '/api/settings/isolation', ADMIN_KEY);
  assert.equal(read.body.enabled, true);
});

test('an unchanged PUT neither audits nor reloads', async () => {
  const n = db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'app-isolation-change'").get().n;
  const before = reloads;
  const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: 'apps.example.com' });
  assert.equal(r.status, 200, r.text);
  await new Promise((res) => setTimeout(res, 100));
  assert.equal(reloads, before);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'app-isolation-change'").get().n, n);
});

test('a domain on another registrable domain is accepted with a third-party-cookie warning', async () => {
  const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: 'apps.example.test' });
  assert.equal(r.status, 200, r.text);
  assert.match(r.body.warning, /third-party cookies/);
  assert.match((await req('GET', '/api/settings/isolation', ADMIN_KEY)).body.warning, /third-party cookies/);
});

test('readable TLS files are stored and returned', async () => {
  const cert = join(DATA, 'wild.crt');
  const key = join(DATA, 'wild.key');
  writeFileSync(cert, 'cert');
  writeFileSync(key, 'key');
  const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: 'apps.example.com', tls_cert_file: cert, tls_key_file: key });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.tls_cert_file, cert);
  assert.equal(r.body.tls_key_file, key);
  assert.equal(stored('app_isolation_tls_key_file'), key);
});

test('the generic PUT /:key cannot write the isolation keys', async () => {
  for (const k of ['app_isolation_domain', 'app_isolation_tls_cert_file', 'app_isolation_tls_key_file']) {
    const r = await req('PUT', `/api/settings/${k}`, ADMIN_KEY, { value: 'example.com' });
    assert.equal(r.status, 403, `${k}: ${r.text}`);
  }
  assert.equal(stored('app_isolation_domain'), 'apps.example.com');
});

test('an empty domain turns it off', async () => {
  const r = await req('PUT', '/api/settings/isolation', ADMIN_KEY, { domain: '', tls_cert_file: '', tls_key_file: '' });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.body.enabled, false);
  assert.equal(stored('app_isolation_domain'), '');
});
