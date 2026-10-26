import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The hosted coder's AppCrane MCP key (services/coderMcpKey.js).
//
// The agent can read and send anywhere whatever is in its container, this key
// included, so every claim is driven through the real requireAuth + JSON-RPC
// dispatcher with the plaintext an agent would hold: what the key can call,
// which app it can name, where it authenticates, and when it stops working.
// Each refusal has a positive baseline (the same owner's personal key, or the
// coder key on its own app) so nothing passes because everything is broken.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-codermcp-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

// docker is a no-op shim: get_logs runs `docker logs`, evict() runs stop/rm.
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const coderKeys = await import('../server/services/coderMcpKey.js');
const { issueCoderMcpKey, revokeCoderMcpKey, CODER_MCP_TOOLS } = coderKeys;

initDb();
const db = getDb();

const mkApp = (slug, slot) => db
  .prepare("INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES (?,?,?,'managed','local','main')")
  .run(slug, slug, slot).lastInsertRowid;
const ALPHA = mkApp('alpha', 901);
const BETA = mkApp('beta', 902);

let seq = 0;
function mkUser(role = 'user', ownerOf = [ALPHA, BETA]) {
  const n = ++seq;
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`u${n}`, `u${n}@t.test`, role, hashApiKey(generateApiKey('dhk_user')), 'human').lastInsertRowid;
  for (const appId of ownerOf) {
    db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, id);
  }
  const personal = generateApiKey('dhk_mcp');
  db.prepare('INSERT INTO user_mcp_keys (user_id,key_hash,label) VALUES (?,?,?)').run(id, hashApiKey(personal), `p${n}`);
  return { id, personal };
}
// Owns BOTH apps: the pin to alpha has to come from the key, not from a lack of access.
const owner = mkUser('user');
// A platform admin reaches every app by role; the key still names one.
const admin = mkUser('platform_admin', []);

for (const [appId, env, key, val] of [
  [ALPHA, 'sandbox', 'API_TOKEN', 'sandbox-secret-value-123'],
  [ALPHA, 'production', 'API_TOKEN', 'production-secret-value-456'],
  [BETA, 'sandbox', 'BETA_TOKEN', 'beta-secret'],
]) {
  db.prepare('INSERT INTO env_vars (app_id,env,key,value_encrypted) VALUES (?,?,?,?)').run(appId, env, key, encrypt(val));
}
const depAlpha = db.prepare("INSERT INTO deployments (app_id,env,version,status,log) VALUES (?,'sandbox','1.0.0','live','alpha build log')").run(ALPHA).lastInsertRowid;
const depBeta = db.prepare("INSERT INTO deployments (app_id,env,version,status,log) VALUES (?,'sandbox','1.0.0','live','beta build log')").run(BETA).lastInsertRowid;
db.prepare("INSERT INTO enhancement_requests (app_slug,user_name,message,status) VALUES ('alpha','scan','Upgrade proxy-addr 2.0.7 → 2.0.8 (GHSA-test)','new')").run();
db.prepare("INSERT INTO enhancement_requests (app_slug,user_name,message,status) VALUES ('beta','x','beta-only request','new')").run();
db.prepare(`INSERT INTO app_vuln_scans (app_id,env,source,ecosystem,status,package_count,findings_json)
            VALUES (?,'production','scheduled','npm','findings',3,?)`)
  .run(ALPHA, JSON.stringify([{ name: 'proxy-addr', version: '2.0.7', ecosystem: 'npm', ids: ['GHSA-test'], fixed: '2.0.8' }]));

// --- HTTP surface: the real MCP router, plus requireAuth on REST-shaped paths.
const mcpRouter = (await import('../server/routes/mcp.js')).default;
const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api/mcp', mcpRouter);
httpApp.get('/api/apps/:slug', requireAuth, (req, res) => res.json({ ok: true }));
httpApp.post('/api/files/staged', requireAuth, (req, res) => res.json({ ok: true }));
httpApp.use('/api', (await import('../server/routes/userMcpKeys.js')).default);
httpApp.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message, code: err.code }));
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

let rpcId = 0;
async function rpc(key, method, params, extraHeaders = {}) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': key, ...extraHeaders },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  return { status: res.status, body: await res.json() };
}
const call = async (key, name, args) => (await rpc(key, 'tools/call', { name, arguments: args })).body;
const resultOf = (body) => {
  assert.ok(body.result, `expected a result, got ${JSON.stringify(body.error || body)}`);
  return JSON.parse(body.result.content[0].text);
};
const newKey = (userId = owner.id, appId = ALPHA, sessionId = 'sess-1') => issueCoderMcpKey({ userId, appId, sessionId });

// One valid call per allowlisted tool, all naming alpha.
const ALPHA_CALLS = {
  appcrane_get_app_scan: { slug: 'alpha' },
  appcrane_list_requests: { slug: 'alpha' },
  appcrane_get_app: { slug: 'alpha' },
  appcrane_get_health: { slug: 'alpha' },
  appcrane_list_releases: { slug: 'alpha' },
  appcrane_get_deploy_log: { deployment_id: depAlpha },
  appcrane_get_logs: { slug: 'alpha' },
  appcrane_get_secret: { slug: 'alpha' },
};

test('the allowlist under test is the one the service enforces', () => {
  assert.deepEqual(Object.keys(ALPHA_CALLS).sort(), [...CODER_MCP_TOOLS].sort());
});

test('tools/list for a coder key is exactly the allowlist; the owner\'s personal key sees far more', async () => {
  const k = newKey();
  const listed = resultTools(await rpc(k.apiKey, 'tools/list', {}));
  assert.deepEqual(listed.sort(), [...CODER_MCP_TOOLS].sort());
  const personal = resultTools(await rpc(owner.personal, 'tools/list', {}));
  for (const t of ['appcrane_reveal_secret', 'appcrane_deploy', 'appcrane_set_secret']) {
    assert.ok(personal.includes(t), `baseline: the personal key should list ${t}`);
  }
});
function resultTools({ body }) {
  assert.ok(body.result?.tools, JSON.stringify(body));
  return body.result.tools.map((t) => t.name);
}

test('every allowlisted tool answers for the session\'s own app', async () => {
  const k = newKey();
  for (const [name, args] of Object.entries(ALPHA_CALLS)) {
    const out = resultOf(await call(k.apiKey, name, args));
    assert.ok(out, `${name} returned nothing`);
  }
  const scan = resultOf(await call(k.apiKey, 'appcrane_get_app_scan', { slug: 'alpha' }));
  assert.equal(scan.scans.production.status, 'findings');
  assert.deepEqual(scan.scans.production.findings[0], { name: 'proxy-addr', version: '2.0.7', ecosystem: 'npm', ids: ['GHSA-test'], fixed: '2.0.8' });
  const reqs = resultOf(await call(k.apiKey, 'appcrane_list_requests', {}));
  assert.deepEqual(reqs.requests.map((r) => r.app_slug), ['alpha'], 'list_requests without a slug leaked another app\'s requests');
});

test('another app is refused for every allowlisted tool, even passed explicitly, and even for a platform admin\'s key', async () => {
  for (const userId of [owner.id, admin.id]) {
    const k = newKey(userId);
    for (const name of CODER_MCP_TOOLS) {
      const args = name === 'appcrane_get_deploy_log' ? { deployment_id: depBeta } : { slug: 'beta' };
      const body = await call(k.apiKey, name, args);
      assert.ok(body.error, `${name} answered for beta: ${JSON.stringify(body.result)}`);
      assert.match(body.error.message, /outside this key's MCP scope/, `${name}: ${body.error.message}`);
    }
    // Baseline: the same principal's personal key does reach beta.
    const personalKey = userId === owner.id ? owner.personal : admin.personal;
    const base = await call(personalKey, 'appcrane_get_app', { slug: 'beta' });
    assert.ok(base.result, `baseline: ${JSON.stringify(base.error)}`);
  }
});

test('every non-allowlisted tool is refused, by name and by prefixed name; GitHub passthrough too', async () => {
  const k = newKey();
  const samples = {
    appcrane_reveal_secret: { slug: 'alpha', key: 'API_TOKEN' },
    appcrane_deploy: { slug: 'alpha', env: 'sandbox' },
    appcrane_set_secret: { slug: 'alpha', vars: { X: '1' } },
    appcrane_set_env: { slug: 'alpha', vars: { X: '1' } },
    appcrane_push_to_managed_app: { slug: 'alpha', files: [] },
    appcrane_rename_app: { slug: 'alpha', new_slug: 'gamma' },
    appcrane_set_request_status: { id: 1, status: 'done' },
    appcrane_crew_send: { to: 'x', text: 'y' },
    appcrane_cat: { slug: 'alpha', path: '/data/x' },
    appcrane_list_apps: {},
  };
  for (const [name, args] of Object.entries(samples)) {
    for (const called of [name, `mcp__appcrane__${name}`]) {
      const body = await call(k.apiKey, called, args);
      assert.ok(body.error, `${called} was not refused: ${JSON.stringify(body.result)}`);
      assert.match(body.error.message, /Forbidden/, `${called}: ${body.error.message}`);
    }
  }
  // Baseline: the owner's personal key reveals the same secret.
  assert.equal(resultOf(await call(owner.personal, 'appcrane_reveal_secret', { slug: 'alpha', key: 'API_TOKEN' })).value, 'sandbox-secret-value-123');

  const gh = await rpc(k.apiKey, 'tools/call', { name: 'get_me', arguments: {} }, { 'X-Github-Token': 'ghp_fake' });
  assert.match(gh.body.error?.message || '', /Forbidden: the coder's AppCrane connection has no tool/);
});

test('the key works on POST /api/mcp only: REST, staged files and the other /api/mcp routes refuse it', async () => {
  const k = newKey();
  const headers = { 'X-API-Key': k.apiKey, 'Content-Type': 'application/json' };
  for (const [method, path] of [['GET', '/api/apps/alpha'], ['POST', '/api/files/staged'], ['GET', '/api/mcp/catalog'], ['GET', '/api/mcp/connection']]) {
    const r = await fetch(`${BASE}${path}`, { method, headers, ...(method === 'POST' ? { body: '{}' } : {}) });
    const b = await r.json();
    assert.equal(r.status, 403, `${method} ${path} -> ${r.status} ${JSON.stringify(b)}`);
    assert.equal(b.code, 'KEY_SCOPE_RESTRICTED');
  }
  // Baseline: a personal key passes auth on staged files and /api/mcp/connection.
  for (const [method, path] of [['POST', '/api/files/staged'], ['GET', '/api/mcp/connection']]) {
    const r = await fetch(`${BASE}${path}`, { method, headers: { ...headers, 'X-API-Key': owner.personal }, ...(method === 'POST' ? { body: '{}' } : {}) });
    assert.equal(r.status, 200, `baseline ${method} ${path} -> ${r.status}`);
  }
});

const refused = async (key) => {
  const r = await rpc(key, 'tools/call', { name: 'appcrane_get_app', arguments: { slug: 'alpha' } });
  return r.status === 401;
};

test('a revoked key (turn end) stops working', async () => {
  const k = newKey();
  assert.equal(await refused(k.apiKey), false, 'baseline: a fresh key works');
  assert.equal(revokeCoderMcpKey(k.id), 1);
  assert.equal(await refused(k.apiKey), true, 'a revoked coder key still authenticates');
});

test('an expired key stops working', async () => {
  const k = newKey();
  assert.equal(await refused(k.apiKey), false);
  db.prepare("UPDATE user_mcp_keys SET expires_at = datetime('now', '-1 second') WHERE id = ?").run(k.id);
  assert.equal(await refused(k.apiKey), true, 'an expired coder key still authenticates');
});

test('the lifetime is at most a few hours, whatever is asked for', () => {
  const k = issueCoderMcpKey({ userId: owner.id, appId: ALPHA, sessionId: 's-ttl', ttlSeconds: 999999 });
  const secs = db.prepare("SELECT (julianday(expires_at) - julianday('now')) * 86400 AS s FROM user_mcp_keys WHERE id = ?").get(k.id).s;
  assert.ok(secs <= 3 * 3600 + 5, `a coder key lives ${secs}s`);
  assert.ok(coderKeys.CODER_KEY_TTL_SECONDS <= 3 * 3600);
});

test('evicting the app\'s coder container revokes its keys; startup recovery revokes all', async () => {
  const builder = await import('../server/services/builder/builderSession.js');
  const { evict } = await import('../server/services/builder/appContainer.js');
  const a = newKey(owner.id, ALPHA, 'sess-evict');
  const b = newKey(owner.id, BETA, 'sess-other');
  assert.equal(await refused(a.apiKey), false);
  evict('alpha', 'test');
  assert.equal(await refused(a.apiKey), true, 'the coder key outlived its container');
  const other = await rpc(b.apiKey, 'tools/call', { name: 'appcrane_get_app', arguments: { slug: 'beta' } });
  assert.ok(other.body.result, 'evicting alpha revoked beta\'s key too');
  builder.recoverOrphans();
  assert.equal(await refused(b.apiKey), true, 'a coder key survived an AppCrane restart');
});

test('production secret metadata is fully masked for the coder key; sandbox matches the owner\'s view', async () => {
  const k = newKey();
  const prod = resultOf(await call(k.apiKey, 'appcrane_get_secret', { slug: 'alpha', env: 'production' })).vars[0];
  assert.equal(prod.key, 'API_TOKEN');
  assert.equal(prod.length, undefined, 'production length reached the coder');
  assert.equal(prod.fingerprint, undefined, 'production fingerprint reached the coder');
  assert.ok(!prod.preview.includes('456'), `production preview shows the tail: ${prod.preview}`);
  // Baseline: the owner's personal key gets the production fingerprint.
  const ownerProd = resultOf(await call(owner.personal, 'appcrane_get_secret', { slug: 'alpha', env: 'production' })).vars[0];
  assert.ok(ownerProd.fingerprint, 'baseline: the owner sees a production fingerprint');
  const sand = resultOf(await call(k.apiKey, 'appcrane_get_secret', { slug: 'alpha', env: 'sandbox' })).vars[0];
  const ownerSand = resultOf(await call(owner.personal, 'appcrane_get_secret', { slug: 'alpha', env: 'sandbox' })).vars[0];
  assert.deepEqual(sand, ownerSand);
});

test('runtime logs are sandbox only for the coder key', async () => {
  const k = newKey();
  const body = await call(k.apiKey, 'appcrane_get_logs', { slug: 'alpha', stage: 'production' });
  assert.match(body.error?.message || '', /sandbox runtime logs only/);
  assert.ok((await call(k.apiKey, 'appcrane_get_logs', { slug: 'alpha', env: 'sandbox' })).result);
});

test('an owner whose own MCP scope leaves the app out gets a locked-out coder key', async () => {
  const scoped = mkUser('user');
  db.prepare("UPDATE users SET mcp_app_scope = '[\"beta\"]' WHERE id = ?").run(scoped.id);
  const k = newKey(scoped.id, ALPHA);
  const body = await call(k.apiKey, 'appcrane_get_app', { slug: 'alpha' });
  assert.match(body.error?.message || '', /Forbidden/);
});

test('coder keys are not listed or rotatable as personal keys', async () => {
  const k = newKey();
  const bearer = generateApiKey('cc_token');
  db.prepare("INSERT INTO identity_sessions (user_id,token_hash,expires_at) VALUES (?,?,datetime('now','+1 day'))").run(owner.id, hashApiKey(bearer));
  const auth = { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json' };
  const list = await (await fetch(`${BASE}/api/me/mcp-keys`, { headers: auth })).json();
  assert.ok(list.keys.length > 0, 'baseline: the personal key is listed');
  assert.ok(!list.keys.some((r) => r.id === k.id), 'a coder key is listed among personal keys');
  const rot = await fetch(`${BASE}/api/me/mcp-keys/${k.id}/rotate`, { method: 'POST', headers: auth });
  assert.equal(rot.status, 404, 'a coder key can be rotated into a fresh plaintext');
});
