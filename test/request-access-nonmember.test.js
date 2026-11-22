import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import express from 'express';

// A signed-in person with no role on a private isolated app is refused at the
// handoff (no code, no app session). The refusal now links to the platform's
// own access-request page for that app (/login?denied=1&app=<slug>&name=<name>,
// the page the shared-host mode already redirects to), and the widget
// manifest offers the same link for <appcrane-request-access> on the app host.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-req-nonmember-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';
after(() => rmSync(process.env.DATA_DIR, { recursive: true, force: true }));

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('app_isolation_domain', 'apps.example.test')").run();
const HUB = db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES ('Hub <b>&</b>','hub',1,'managed','forward_auth','private')").run().lastInsertRowid;
const carol = db.prepare("INSERT INTO users (name,email,role,active) VALUES ('carol','carol@t.test','user',1)").run().lastInsertRowid;
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(carol, hashApiKey('plat-carol'));

const handoff = await import('../server/routes/appHandoff.js');
const identityRouter = (await import('../server/routes/identity.js')).default;
const { widgetsRouter } = await import('../server/routes/widgets.js');
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/__appcrane', widgetsRouter);
api.use('/api/identity', handoff.default);
api.use('/api/identity', identityRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });

function call(path, { host = 'crane.example.test', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: server.address().port, path, headers: { Host: host, ...headers } }, (res) => {
      let t = ''; res.on('data', (c) => { t += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: t }));
    }).on('error', reject);
  });
}

const STATE = hashApiKey('browser-state');
const LINK = 'https://crane.example.test/login?denied=1&app=hub&name=Hub+%3Cb%3E%26%3C%2Fb%3E';

test('handoff refusal for a non-member links to the platform request page for this app, and hands nothing to the app', async () => {
  const r = await call(`/api/identity/handoff?app=hub&env=production&return=%2F&state=${STATE}`, { headers: { Cookie: '__Host-cc_token=plat-carol', Accept: 'text/html' } });
  assert.equal(r.status, 403);
  assert.ok(r.body.includes(`<a href="${LINK.replace(/&/g, '&amp;')}">`), r.body);
  assert.ok(r.body.includes('Request access to Hub &lt;b&gt;&amp;&lt;/b&gt;'), 'the name is escaped');
  assert.equal(r.headers['set-cookie'], undefined);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM app_handoff_codes').get().n, 0, 'no sign-in code issued');
  assert.equal(r.headers.location, undefined, 'no redirect to the app host');

  const j = await call(`/api/identity/handoff?app=hub&env=production&state=${STATE}`, { headers: { Cookie: '__Host-cc_token=plat-carol', Accept: 'application/json' } });
  assert.equal(j.status, 403);
  assert.equal(JSON.parse(j.body).request_access_url, LINK);
});

test('the app host refusal (role removed during a session) carries the same link', async () => {
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at, scope, app_env, parent_token_hash)
    VALUES (?, ?, ?, datetime('now','+1 day'), 'app', 'production', ?)`).run(carol, hashApiKey('app-carol'), HUB, hashApiKey('plat-carol'));
  const r = await call('/api/identity/verify?app=hub&env=production&host=isolated', {
    headers: { Cookie: '__Host-cc_app=app-carol', Accept: 'text/html', 'X-Forwarded-Uri': '/', 'X-Forwarded-Method': 'GET', 'X-Forwarded-Host': 'hub.apps.example.test' },
  });
  assert.equal(r.status, 403);
  assert.ok(r.body.includes(LINK.replace(/&/g, '&amp;')), r.body);
});

test('the widget manifest on the app host offers the request page by slug only', async () => {
  const m = JSON.parse((await call('/__appcrane/widgets/manifest.json', { host: 'hub.apps.example.test' })).body);
  assert.equal(m.request_access, 'https://crane.example.test/login?denied=1&app=hub');
  assert.equal(JSON.stringify(m).includes('Hub'), false, 'the app name is not published');
});
