import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import http from 'http';

// Per-instance GitHub App authentication for CONNECTED repos (v2.75.0).
//
// What is under test is the credential model, so nothing here talks to
// github.com: api.github.com is a real HTTP server on 127.0.0.1 that this file
// starts, reached through APPCRANE_GITHUB_API_BASE, and the App's key is a
// throwaway RSA pair generated per run.
//
// The properties that carry the security claim:
//   - the private key is encrypted at rest and never leaves the API
//   - the App JWT is RS256, backdated 60s, and expires inside GitHub's
//     documented 10-minute ceiling
//   - installation tokens are narrowed to one repository, cached, re-issued
//     before expiry, and written nowhere durable
//   - an app with an installation NEVER falls back to its stored PAT
//   - a manifest `state` is single-use and bound to the admin's session
//   - every per-app route is gated on access to THAT app

const ROOT = mkdtempSync(join(tmpdir(), 'crane-ghapp-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { privateKey: PEM, publicKey: PUB } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const APP_ID = 424242;
const INSTALLATION_ID = 5150;
const PAT = 'ghp_STOREDPAT0123456789abcdefABCDEFxy';

// --- api.github.com, on 127.0.0.1 -----------------------------------------
const api = { calls: [], tokenFails: false, issued: 0, installationStatus: 200 };
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null;
    const call = { method: req.method, path: req.url, auth: req.headers.authorization || null, body };
    api.calls.push(call);
    const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

    let m;
    if (req.method === 'POST' && (m = /^\/app-manifests\/([^/]+)\/conversions$/.exec(req.url))) {
      if (m[1] !== 'good-code') return send(404, { message: 'Not Found' });
      return send(201, {
        id: APP_ID, slug: 'appcrane-test-instance', name: 'AppCrane (test)',
        owner: { login: 'acme' }, html_url: 'https://github.com/apps/appcrane-test-instance',
        client_id: 'Iv1.testclientid', client_secret: 'super-secret-client',
        webhook_secret: 'super-secret-webhook', pem: PEM,
      });
    }
    if (req.method === 'POST' && /^\/app\/installations\/\d+\/access_tokens$/.test(req.url)) {
      if (api.tokenFails) return send(500, { message: 'installation token unavailable' });
      api.issued += 1;
      return send(201, {
        token: `ghs_INSTALLATIONTOKEN_${api.issued}`,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      });
    }
    if (req.method === 'GET' && /^\/repos\/[^/]+\/[^/]+\/installation$/.test(req.url)) {
      if (api.installationStatus !== 200) return send(api.installationStatus, { message: 'Not Found' });
      return send(200, { id: INSTALLATION_ID, account: { login: 'acme' } });
    }
    if (req.method === 'GET' && req.url === '/app') return send(200, { slug: 'appcrane-test-instance' });
    return send(404, { message: `unrouted ${req.method} ${req.url}` });
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
process.env.APPCRANE_GITHUB_API_BASE = `http://127.0.0.1:${server.address().port}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { encrypt, decrypt, hashApiKey } = await import('../server/services/encryption.js');
const ghApp = await import('../server/services/githubApp.js');
const ghCred = await import('../server/services/githubCredential.js');
const express = (await import('express')).default;
const githubAppRoutes = (await import('../server/routes/githubApp.js')).default;
const appGithubAppRoutes = (await import('../server/routes/appGithubApp.js')).default;

after(() => { server.close(); try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

// --- fixtures --------------------------------------------------------------
let seq = 0;
function mkUser(role, key) {
  const n = ++seq;
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`u${n}`, `u${n}@example.com`, role, hashApiKey(key)).lastInsertRowid;
  return { id, role, key };
}
let slot = 900;
function mkApp(slug, { token = PAT, url = `https://github.com/acme/${slug}` } = {}) {
  const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type,github_url,branch,github_token_encrypted) VALUES (?,?,?,'github',?,'main',?)")
    .run(slug, slug, slot++, url, token ? encrypt(token) : null).lastInsertRowid;
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const assign = (appId, userId, role) => {
  db.prepare('INSERT OR IGNORE INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, userId);
  if (role) db.prepare('INSERT OR REPLACE INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, userId, role);
};

const ex = express();
ex.use(express.json());
ex.use('/api/github-app', githubAppRoutes);
ex.use('/api/apps', appGithubAppRoutes);
ex.use((e, _req, res, _next) => res.status(e.statusCode || e.status || 500).json({ error: { code: e.code, message: e.message } }));
const httpSrv = http.createServer(ex);
await new Promise((r) => httpSrv.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${httpSrv.address().port}`;
after(() => httpSrv.close());

async function call(method, path, key, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'X-API-Key': key, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

const admin = mkUser('platform_admin', 'dhk_admin_key');
const admin2 = mkUser('platform_admin', 'dhk_admin_two');
const plain = mkUser('user', 'dhk_plain_key');

// ---------------------------------------------------------------------------
// Manifest flow
// ---------------------------------------------------------------------------

test('the manifest asks for read-only Contents, Metadata and Pull requests — nothing writable', async () => {
  const r = await call('POST', '/api/github-app/manifest', admin.key, {});
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.manifest.default_permissions, { contents: 'read', metadata: 'read', pull_requests: 'read' });
  assert.deepEqual(r.body.manifest.default_events, []);
  assert.equal(r.body.manifest.public, false);
  assert.equal(r.body.manifest.hook_attributes.active, false);
  assert.ok(String(r.body.action).endsWith('/settings/apps/new'), r.body.action);
  assert.ok(r.body.state && r.body.state.length >= 20);
});

test('a platform admin is required to start the flow or exchange a code', async () => {
  assert.equal((await call('POST', '/api/github-app/manifest', plain.key, {})).status, 403);
  assert.equal((await call('POST', '/api/github-app/exchange', plain.key, { code: 'good-code', state: 'x' })).status, 403);
  assert.equal((await call('GET', '/api/github-app', plain.key)).status, 403);
});

test("a state issued to one admin's session is refused for another session", async () => {
  const started = await call('POST', '/api/github-app/manifest', admin.key, {});
  const stolen = await call('POST', '/api/github-app/exchange', admin2.key, { code: 'good-code', state: started.body.state });
  assert.equal(stolen.status, 400);
  assert.equal(stolen.body.error.code, 'BAD_STATE');
  assert.equal(ghApp.getAppConfig(), null, 'the App must not have been registered by the wrong session');
});

test('a state is bound to the credential that started the flow, not merely to the same admin user', async () => {
  // Same platform admin, second credential: a portal identity session instead of
  // the API key the flow was started with. User id matches; the session does not.
  const bearer = 'identity-session-token-for-state-binding';
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))")
    .run(admin.id, hashApiKey(bearer));
  const started = await call('POST', '/api/github-app/manifest', admin.key, {});
  const res = await fetch(`${BASE}/api/github-app/exchange`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: 'good-code', state: started.body.state }),
  });
  const body = await res.json();
  assert.equal(res.status, 400, JSON.stringify(body));
  assert.equal(body.error.code, 'BAD_STATE');
  assert.equal(ghApp.getAppConfig(), null);
});

test('the manifest code is exchanged once: the App is stored, and a replayed state is refused', async () => {
  const started = await call('POST', '/api/github-app/manifest', admin.key, {});
  const ok = await call('POST', '/api/github-app/exchange', admin.key, { code: 'good-code', state: started.body.state });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.github_app_id, APP_ID);
  assert.equal(ok.body.slug, 'appcrane-test-instance');

  const replay = await call('POST', '/api/github-app/exchange', admin.key, { code: 'good-code', state: started.body.state });
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error.code, 'BAD_STATE');
});

test('the private key, webhook secret and client secret are encrypted at rest and never served', async () => {
  const row = db.prepare('SELECT * FROM github_app_config WHERE id = 1').get();
  assert.ok(!row.private_key_enc.includes('PRIVATE KEY'), 'the PEM is stored in clear');
  assert.equal(decrypt(row.private_key_enc), PEM);
  assert.equal(decrypt(row.webhook_secret_enc), 'super-secret-webhook');
  assert.equal(decrypt(row.client_secret_enc), 'super-secret-client');

  const served = JSON.stringify((await call('GET', '/api/github-app', admin.key)).body);
  for (const secret of ['PRIVATE KEY', 'super-secret-webhook', 'super-secret-client']) {
    assert.equal(served.includes(secret), false, `${secret} reached the API response`);
  }
  // And not in the sqlite file as plaintext either.
  const raw = readFileSync(join(ROOT, 'deployhub.db'));
  assert.equal(raw.includes(Buffer.from('BEGIN PRIVATE KEY')), false);
});

// ---------------------------------------------------------------------------
// JWT + installation tokens
// ---------------------------------------------------------------------------

test('the App JWT is RS256, backdated 60s, and expires inside GitHub\'s 10-minute ceiling', () => {
  const now = 1_800_000_000_000;
  const jwt = ghApp.createAppJwt({ nowMs: now });
  const [h, p, sig] = jwt.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const payload = JSON.parse(Buffer.from(p, 'base64url'));
  assert.equal(header.alg, 'RS256');
  assert.equal(payload.iss, String(APP_ID));
  assert.equal(payload.iat, Math.floor(now / 1000) - 60);
  assert.ok(payload.exp > Math.floor(now / 1000), 'already expired');
  assert.ok(payload.exp - Math.floor(now / 1000) <= 600, `exp is ${payload.exp - Math.floor(now / 1000)}s out — GitHub rejects more than 600`);

  const v = crypto.createVerify('RSA-SHA256');
  v.update(`${h}.${p}`);
  v.end();
  assert.ok(v.verify(PUB, Buffer.from(sig, 'base64url')), 'signature does not verify against the App key');
});

test('an installation token is narrowed to one repository, cached, and re-issued before it expires', async () => {
  ghApp.clearTokenCache();
  api.calls.length = 0;
  const issuedFirst = await ghApp.getInstallationToken(INSTALLATION_ID, { repositories: ['widget'] });
  const tokenCalls = api.calls.filter((c) => c.path.endsWith('/access_tokens'));
  assert.equal(tokenCalls.length, 1);
  assert.deepEqual(tokenCalls[0].body, { repositories: ['widget'] });
  assert.match(tokenCalls[0].auth, /^Bearer ey/);

  const cached = await ghApp.getInstallationToken(INSTALLATION_ID, { repositories: ['widget'] });
  assert.equal(cached, issuedFirst);
  assert.equal(api.calls.filter((c) => c.path.endsWith('/access_tokens')).length, 1, 'a cached token was re-requested');

  // 56 minutes on: 4 minutes of life left, inside the 5-minute margin.
  const refreshed = await ghApp.getInstallationToken(INSTALLATION_ID, { repositories: ['widget'], nowMs: Date.now() + 56 * 60_000 });
  assert.notEqual(refreshed, issuedFirst, 'a token inside the refresh margin was reused');
  assert.equal(api.calls.filter((c) => c.path.endsWith('/access_tokens')).length, 2);

  // Never persisted: not in the database file, not in any settings row.
  const raw = readFileSync(join(ROOT, 'deployhub.db'));
  assert.equal(raw.includes(Buffer.from(issuedFirst)), false, 'an installation token reached the database');
  assert.equal(raw.includes(Buffer.from(refreshed)), false, 'an installation token reached the database');
});

// ---------------------------------------------------------------------------
// The resolver
// ---------------------------------------------------------------------------

test('with no installation attached, the app still resolves to its stored PAT', async () => {
  const app = mkApp('pat-only');
  api.calls.length = 0;
  const cred = await ghCred.resolveGitHubCredential(app);
  assert.deepEqual({ source: cred.source, token: cred.token }, { source: 'pat', token: PAT });
  assert.equal(api.calls.length, 0, 'the PAT path must not talk to the GitHub App API at all');
});

test('an undecryptable PAT reads as no token for pollers and throws for the deployer — unchanged', async () => {
  const app = mkApp('pat-broken');
  db.prepare('UPDATE apps SET github_token_encrypted = ? WHERE id = ?').run('zz:zz:zz', app.id);
  const broken = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  assert.equal((await ghCred.resolveGitHubCredential(broken)).token, null);
  await assert.rejects(() => ghCred.resolveGitHubCredential(broken, { patErrors: 'throw' }), /authentication tag/);
});

test('attaching resolves the installation from GitHub, not from any redirect parameter', async () => {
  const app = mkApp('widget');
  api.calls.length = 0;
  const r = await ghCred.attachInstallation(app, admin.id);
  assert.deepEqual(r, { installation_id: INSTALLATION_ID, repo_full_name: 'acme/widget', account: 'acme' });
  const lookup = api.calls.find((c) => c.path === '/repos/acme/widget/installation');
  assert.ok(lookup, 'the installation was not looked up with the App JWT');
  assert.match(lookup.auth, /^Bearer ey/);
});

test('an attached app authenticates with a short-lived installation token, never its PAT', async () => {
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'widget'").get();
  ghApp.clearTokenCache();
  const cred = await ghCred.resolveGitHubCredential(app);
  assert.equal(cred.source, 'installation');
  assert.match(cred.token, /^ghs_INSTALLATIONTOKEN_/);
  assert.notEqual(cred.token, PAT);
  assert.equal(cred.installationId, INSTALLATION_ID);
});

test('when the installation token cannot be issued the operation FAILS — the PAT is not used', async () => {
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'widget'").get();
  assert.ok(app.github_token_encrypted, 'this app must still have a PAT for the test to mean anything');
  ghApp.clearTokenCache();
  api.tokenFails = true;
  try {
    await assert.rejects(
      () => ghCred.resolveGitHubCredential(app),
      (e) => {
        assert.equal(e.message.includes(PAT), false);
        assert.match(e.message, /access_tokens returned 500/);
        return true;
      },
    );
  } finally {
    api.tokenFails = false;
  }
});

test('repointing github_url after attaching fails closed instead of using the old installation', async () => {
  const app = mkApp('moved');
  await ghCred.attachInstallation(app, admin.id);
  db.prepare('UPDATE apps SET github_url = ? WHERE id = ?').run('https://github.com/acme/elsewhere', app.id);
  const moved = db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
  await assert.rejects(() => ghCred.resolveGitHubCredential(moved), /was attached to acme\/moved/);
});

test('with the App deleted, an app that still has an installation refuses to fall back to its PAT', async () => {
  const app = mkApp('orphan');
  await ghCred.attachInstallation(app, admin.id);
  const saved = db.prepare('SELECT * FROM github_app_config WHERE id = 1').get();
  db.prepare('DELETE FROM github_app_config WHERE id = 1').run();
  try {
    await assert.rejects(() => ghCred.resolveGitHubCredential(app), /Refusing to fall back to a stored personal access token/);
  } finally {
    db.prepare(`INSERT INTO github_app_config
      (id, github_app_id, slug, name, owner_login, html_url, client_id, client_secret_enc, webhook_secret_enc, private_key_enc, created_by, created_at)
      VALUES (1,?,?,?,?,?,?,?,?,?,?,?)`).run(
      saved.github_app_id, saved.slug, saved.name, saved.owner_login, saved.html_url, saved.client_id,
      saved.client_secret_enc, saved.webhook_secret_enc, saved.private_key_enc, saved.created_by, saved.created_at);
    ghCred.detachInstallation(app.id);
  }
});

// ---------------------------------------------------------------------------
// Per-app authorization
// ---------------------------------------------------------------------------

test('the per-app routes are gated on access to THAT app, not merely on being signed in', async () => {
  const mine = mkApp('mine');
  const theirs = mkApp('theirs');
  assign(mine.id, plain.id, 'owner');

  assert.equal((await call('GET', '/api/apps/theirs/github-app', plain.key)).status, 403);
  assert.equal((await call('PUT', '/api/apps/theirs/github-app', plain.key, {})).status, 403);
  assert.equal((await call('DELETE', '/api/apps/theirs/github-app', plain.key)).status, 403);
  assert.equal((await call('GET', '/api/apps/mine/github-app', plain.key)).status, 200);
});

test('attaching needs the same role permission as changing the repo URL', async () => {
  const app = mkApp('roles');
  const member = mkUser('user', 'dhk_member_key');
  assign(app.id, member.id);                    // plain assignment, no app role
  assert.equal((await call('GET', '/api/apps/roles/github-app', member.key)).status, 200);
  const denied = await call('PUT', '/api/apps/roles/github-app', member.key, {});
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error.code, 'FORBIDDEN');

  db.prepare('INSERT OR REPLACE INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(app.id, member.id, 'owner');
  const allowed = await call('PUT', '/api/apps/roles/github-app', member.key, {});
  assert.equal(allowed.status, 200, JSON.stringify(allowed.body));
  assert.equal(allowed.body.installation_id, INSTALLATION_ID);
});

test('attaching an app the App is not installed on says so instead of half-attaching it', async () => {
  const app = mkApp('uninstalled');
  api.installationStatus = 404;
  try {
    const r = await call('PUT', '/api/apps/uninstalled/github-app', admin.key, {});
    assert.equal(r.status, 409);
    assert.equal(r.body.error.code, 'NOT_INSTALLED');
    assert.equal(ghCred.getInstallation(app.id), null);
  } finally {
    api.installationStatus = 200;
  }
});

test('deleting the App is refused while apps still use it, and force detaches them', async () => {
  const app = mkApp('attached-one');
  await ghCred.attachInstallation(app, admin.id);
  const refused = await call('DELETE', '/api/github-app', admin.key);
  assert.equal(refused.status, 409);
  assert.equal(refused.body.error.code, 'APPS_ATTACHED');
  assert.ok(ghCred.getInstallation(app.id));

  const forced = await fetch(`${BASE}/api/github-app?force=1`, { method: 'DELETE', headers: { 'X-API-Key': admin.key } });
  assert.equal(forced.status, 200);
  assert.equal(ghCred.getInstallation(app.id), null);
  assert.equal(ghApp.getAppConfig(), null);
});

test('the credential health probe skips when no App is configured', async () => {
  const { PROBES } = await import('../server/services/credentialChecker.js');
  const probe = PROBES.find((p) => p.name === 'GitHub App');
  assert.ok(probe, 'no GitHub App probe registered');
  assert.deepEqual(await probe.run(), { ok: true, skipped: true });
});
