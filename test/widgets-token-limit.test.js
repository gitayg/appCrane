import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'http';
import express from 'express';

// POST /__appcrane/widgets/token is outside /api, so the global API limiter
// never sees it. It has its own: per app session and per client address
// (routes/widgets.js WIDGET_TOKEN_LIMITS, on services/oauthRateLimit.js).

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-widget-limit-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';
after(() => rmSync(process.env.DATA_DIR, { recursive: true, force: true }));

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO settings (key, value) VALUES ('app_isolation_domain', 'apps.example.test')").run();
const HUB = db.prepare("INSERT INTO apps (name,slug,slot,source_type,visibility) VALUES ('hub','hub',1,'managed','private')").run().lastInsertRowid;
const alice = db.prepare("INSERT INTO users (name,email,role,active) VALUES ('alice','alice@t.test','user',1)").run().lastInsertRowid;
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(HUB, alice);
db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now','+1 day'))").run(alice, hashApiKey('plat'));
let n = 0;
function appSession() {
  const token = `app-${++n}`;
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at, scope, app_env, parent_token_hash)
    VALUES (?, ?, ?, datetime('now','+1 day'), 'app', 'production', ?)`).run(alice, hashApiKey(token), HUB, hashApiKey('plat'));
  return token;
}

const { widgetsRouter, WIDGET_TOKEN_LIMITS } = await import('../server/routes/widgets.js');
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/__appcrane', widgetsRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });

function token(cookie) {
  return new Promise((resolve, reject) => {
    const r = http.request({
      host: '127.0.0.1', port: server.address().port, path: '/__appcrane/widgets/token', method: 'POST',
      headers: { Host: 'hub.apps.example.test', 'Content-Type': 'application/json', 'X-AppCrane-Widget': '1', ...(cookie && { Cookie: `__Host-cc_app=${cookie}` }) },
    }, (res) => { let t = ''; res.on('data', (c) => { t += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: t })); });
    r.on('error', reject);
    r.end('{}');
  });
}

test('per app session: the limit-th request is the last one served; another session is unaffected', async () => {
  const s1 = appSession();
  const max = WIDGET_TOKEN_LIMITS.perSession.max;
  for (let i = 0; i < max; i++) assert.equal((await token(s1)).status, 200, `request ${i + 1}`);
  const over = await token(s1);
  assert.equal(over.status, 429);
  assert.equal(JSON.parse(over.body).error.code, 'RATE_LIMITED');
  assert.ok(Number(over.headers['retry-after']) > 0);
  assert.equal((await token(appSession())).status, 200, 'a second session from the same address still gets one');
});

test('per address: past the limit every request is refused, whatever the cookie', async () => {
  const used = WIDGET_TOKEN_LIMITS.perSession.max + 2;
  let last;
  for (let i = used; i < WIDGET_TOKEN_LIMITS.perIp.max; i++) {
    last = await token(i % 2 ? appSession() : null);
    assert.notEqual(last.status, 429, `request ${i + 1} is within the address limit`);
  }
  assert.equal((await token(appSession())).status, 429);
  assert.equal((await token(null)).status, 429);
});
