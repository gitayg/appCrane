import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
import http from 'http';

// POST /api/github-app/webhook — deliveries for this instance's GitHub App.
//
// Nothing here talks to GitHub: api.github.com is a server on 127.0.0.1
// (APPCRANE_GITHUB_API_BASE), signatures are real HMAC-SHA256 over the exact
// bytes sent, and deployApp is observed through the service's test seam so no
// build runs. The receiver is mounted in the same order as server/index.js:
// raw body parser, then the global express.json(), then the handler.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-ghhook-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.CRANE_DOMAIN;

const { privateKey: PEM } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const APP_ID = 777001;
const SECRET = 'webhook-secret-under-test-0123456789';

// --- api.github.com on 127.0.0.1 -------------------------------------------
const api = { calls: [] };
const apiServer = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null;
    api.calls.push({ method: req.method, path: req.url, auth: req.headers.authorization || null, body });
    const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (req.method === 'PATCH' && req.url === '/app/hook/config') {
      return send(200, { url: body.url, content_type: body.content_type, insecure_ssl: body.insecure_ssl, secret: '********' });
    }
    if (req.method === 'POST' && /^\/app\/installations\/\d+\/access_tokens$/.test(req.url)) {
      return send(201, { token: 'ghs_TESTTOKEN', expires_at: new Date(Date.now() + 3600_000).toISOString() });
    }
    if (req.method === 'GET' && /^\/repos\/[^/]+\/[^/]+\/installation$/.test(req.url)) {
      return send(200, { id: 9001, account: { login: 'acme' } });
    }
    return send(404, { message: `unrouted ${req.method} ${req.url}` });
  });
});
await new Promise((r) => apiServer.listen(0, '127.0.0.1', r));
process.env.APPCRANE_GITHUB_API_BASE = `http://127.0.0.1:${apiServer.address().port}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { hashApiKey } = await import('../server/services/encryption.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');
const ghApp = await import('../server/services/githubApp.js');
const ghCred = await import('../server/services/githubCredential.js');
const hookSvc = await import('../server/services/githubAppWebhook.js');
const express = (await import('express')).default;
const { default: webhookRouter, rawWebhookBody } = await import('../server/routes/githubAppWebhook.js');
const { default: githubAppRoutes } = await import('../server/routes/githubApp.js');

const deployCalls = [];
hookSvc.setDeployDepsForTests({
  deployApp: (deploymentId, app, env) => { deployCalls.push({ deploymentId, slug: app.slug, env }); return Promise.resolve(); },
  getPortsForSlot: () => ({}),
});

const web = express();
web.use('/api/github-app/webhook', rawWebhookBody);
web.use(express.json({ limit: '50mb' }));
web.use('/api/github-app/webhook', webhookRouter);
web.use('/api/github-app', githubAppRoutes);
web.use((e, _req, res, _next) => res.status(e.statusCode || e.status || 500).json({ error: { code: e.code || e.type, message: e.message } }));
const server = await new Promise((r) => { const s = web.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  server.closeAllConnections?.();
  server.close();
  apiServer.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

ghApp.saveAppConfig({
  id: APP_ID, slug: 'appcrane-hook-test', name: 'AppCrane (test)', owner: { login: 'acme' },
  html_url: 'https://github.com/apps/appcrane-hook-test', client_id: 'Iv1.x', webhook_secret: SECRET, pem: PEM,
});

// --- fixtures --------------------------------------------------------------
let seq = 0;
function mkApp({ repo, installationId = 9001, attachedRepo = repo, cfg = {} }) {
  const slug = `hook-${++seq}`;
  const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES (?, ?, ?, 'github', ?, 'main')")
    .run(slug, slug, getNextSlot(db), `https://github.com/${repo}`).lastInsertRowid;
  db.prepare('INSERT INTO webhook_configs (app_id, token, secret) VALUES (?, ?, ?)')
    .run(appId, crypto.randomBytes(16).toString('hex'), crypto.randomBytes(16).toString('hex'));
  for (const [k, v] of Object.entries(cfg)) db.prepare(`UPDATE webhook_configs SET ${k} = ? WHERE app_id = ?`).run(v, appId);
  db.prepare('INSERT INTO app_github_installations (app_id, slug, installation_id, repo_full_name) VALUES (?, ?, ?, ?)')
    .run(appId, slug, installationId, attachedRepo);
  return { appId, slug, app: () => db.prepare('SELECT * FROM apps WHERE id = ?').get(appId) };
}
const deploysOf = (appId) => db.prepare('SELECT env, status, commit_hash, commit_message, log FROM deployments WHERE app_id = ? ORDER BY id').all(appId).map((r) => ({ ...r }));
const deliveriesOf = (appId) => db.prepare('SELECT event, delivery_id, branch, commit_hash, sig_valid, action_taken FROM webhook_deliveries WHERE app_id = ? ORDER BY id').all(appId).map((r) => ({ ...r }));
const auditsOf = (appId) => db.prepare('SELECT action, detail FROM audit_log WHERE app_id = ? ORDER BY id').all(appId).map((r) => ({ ...r }));

const SHA = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const push = (repo, { ref = 'refs/heads/main', installationId = 9001, ...extra } = {}) => ({
  ref, before: '0'.repeat(40), after: SHA, created: false, deleted: false,
  repository: { full_name: repo }, installation: { id: installationId },
  head_commit: { message: 'ship it' }, ...extra,
});
const sign = (body, secret = SECRET) => `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;

async function deliver(payload, { event = 'push', id = crypto.randomUUID(), raw, sig, secret = SECRET, headers = {} } = {}) {
  const body = raw ?? JSON.stringify(payload);
  const h = {
    'content-type': 'application/json', 'x-github-event': event, 'x-github-delivery': id,
    'x-github-hook-installation-target-type': 'integration', 'x-github-hook-installation-target-id': String(APP_ID),
    ...headers,
  };
  const signature = sig === undefined ? sign(body, secret) : sig;
  if (signature !== null) h['x-hub-signature-256'] = signature;
  const r = await fetch(`${BASE}/api/github-app/webhook`, { method: 'POST', headers: h, body });
  return { status: r.status, body: await r.json().catch(() => null), id };
}

let userSeq = 0;
function mkAdmin() {
  const key = `dhk_hook_admin_${++userSeq}`;
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`a${userSeq}`, `a${userSeq}@example.com`, 'platform_admin', hashApiKey(key));
  return key;
}
async function adminCall(method, path, key, body) {
  const r = await fetch(`${BASE}${path}`, {
    method, headers: { 'X-API-Key': key, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

// ---------------------------------------------------------------------------

test('server/index.js reads the raw body before express.json() and mounts the receiver ahead of the admin-only router', () => {
  const src = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
  const raw = src.indexOf("app.use('/api/github-app/webhook', rawWebhookBody)");
  const json = src.indexOf('app.use(express.json(');
  const receiver = src.indexOf("app.use('/api/github-app/webhook', githubAppWebhookRoutes)");
  const admin = src.indexOf("app.use('/api/github-app', githubAppRoutes)");
  assert.ok(raw > 0 && json > 0 && raw < json, 'raw parser must precede express.json()');
  assert.ok(receiver > 0 && admin > 0 && receiver < admin, 'receiver must precede the platform-admin router');
});

test('the signature compare is constant-time: timingSafeEqual, no string equality on the signature', () => {
  const src = readFileSync(new URL('../server/routes/githubAppWebhook.js', import.meta.url), 'utf8');
  const fn = /export function signatureMatches[\s\S]*?\n}/.exec(src)[0];
  assert.match(fn, /crypto\.timingSafeEqual\(given, expected\)/);
  // The only equality operators allowed are the type guard and the length guard
  // timingSafeEqual needs; anything else compares signature content.
  const rest = fn.replace("typeof header !== 'string'", '').replace('given.length !== expected.length', '');
  assert.doesNotMatch(rest, /[!=]==?/);
});

test('a signed push to the deploy branch starts the deploy; the same delivery again does nothing', async (t) => {
  const a = mkApp({ repo: 'acme/web' });
  const first = await deliver(push('acme/web'));
  t.diagnostic(`first delivery: ${first.status} ${JSON.stringify(first.body)}`);
  assert.equal(first.status, 200);
  assert.equal(first.body.result, 'deploy_triggered');
  const rows = deploysOf(a.appId);
  t.diagnostic(`deployments: ${JSON.stringify(rows)}`);
  assert.deepEqual(rows, [{ env: 'sandbox', status: 'pending', commit_hash: 'a1b2c3d4', commit_message: 'ship it', log: 'Triggered by GitHub App push webhook' }]);
  assert.deepEqual(deliveriesOf(a.appId).map((d) => [d.event, d.delivery_id, d.branch, d.commit_hash, d.sig_valid, d.action_taken]),
    [['github-app-push', first.id, 'main', 'a1b2c3d4', 1, 'deploy_triggered']]);
  assert.deepEqual(auditsOf(a.appId), [{ action: 'github-app-push-deploy', detail: '{"env":"sandbox","commit":"a1b2c3d4"}' }]);
  assert.equal(deployCalls.filter((c) => c.slug === a.slug).length, 1);

  const again = await deliver(push('acme/web'), { id: first.id });
  t.diagnostic(`redelivery: ${again.status} ${JSON.stringify(again.body)}`);
  t.diagnostic(`deployments after redelivery: ${deploysOf(a.appId).length}`);
  assert.equal(again.status, 200);
  assert.equal(again.body.duplicate, true);
  assert.equal(deploysOf(a.appId).length, 1);
  assert.equal(deployCalls.filter((c) => c.slug === a.slug).length, 1);
  assert.equal(auditsOf(a.appId).length, 1);
});

test('auto_deploy_prod and the branch filter are honoured exactly as the per-app webhook honours them', async () => {
  const both = mkApp({ repo: 'acme/both', cfg: { auto_deploy_prod: 1 } });
  const r = await deliver(push('acme/both'));
  assert.deepEqual(r.body.apps[0].triggered.map((x) => x.env), ['sandbox', 'production']);

  const filtered = mkApp({ repo: 'acme/rel', cfg: { branch_filter: 'release' } });
  const onMain = await deliver(push('acme/rel'));
  assert.deepEqual(onMain.body.apps, [{ slug: filtered.slug, action: 'skipped_branch', branch_filter: 'release' }]);
  assert.equal(deploysOf(filtered.appId).length, 0);
  const onRelease = await deliver(push('acme/rel', { ref: 'refs/heads/release' }));
  assert.equal(onRelease.body.result, 'deploy_triggered');

  const off = mkApp({ repo: 'acme/off', cfg: { auto_deploy_sandbox: 0, auto_deploy_prod: 0 } });
  const none = await deliver(push('acme/off'));
  assert.equal(none.body.apps[0].action, 'skipped_no_auto');
  assert.equal(deploysOf(off.appId).length, 0);
});

test('a push to a non-deploy branch deploys nothing', async () => {
  const a = mkApp({ repo: 'acme/branchy' });
  const r = await deliver(push('acme/branchy', { ref: 'refs/heads/feature/x' }));
  assert.equal(r.status, 200);
  assert.equal(r.body.result, 'no_deploy');
  assert.equal(deploysOf(a.appId).length, 0);
  assert.deepEqual(deliveriesOf(a.appId).map((d) => d.action_taken), ['skipped_branch']);
});

test('a tag push is ignored, even a tag named like the deploy branch', async () => {
  const a = mkApp({ repo: 'acme/tags' });
  const r = await deliver(push('acme/tags', { ref: 'refs/tags/main' }));
  assert.equal(r.status, 200);
  assert.equal(r.body.result, 'ignored_non_branch_ref');
  assert.equal(deploysOf(a.appId).length, 0);
});

test('a push that deleted the deploy branch deploys nothing', async () => {
  const a = mkApp({ repo: 'acme/gone' });
  const r = await deliver(push('acme/gone', { deleted: true, after: '0'.repeat(40) }));
  assert.equal(r.status, 200);
  assert.equal(r.body.result, 'ignored_deleted_ref');
  assert.equal(deploysOf(a.appId).length, 0);
});

test('signature: missing, wrong secret, and a wrong signature of the right length are all 401 and deploy nothing', async () => {
  const a = mkApp({ repo: 'acme/sig' });
  const body = JSON.stringify(push('acme/sig'));
  const good = sign(body);
  const flipped = good.slice(0, -1) + (good.endsWith('0') ? '1' : '0');
  assert.equal(flipped.length, good.length);

  for (const [label, sig] of [['missing', null], ['wrong secret', sign(body, 'not-the-secret')], ['same length, one hex digit off', flipped], ['no prefix', good.slice(7)]]) {
    const r = await deliver(null, { raw: body, sig });
    assert.equal(r.status, 401, label);
  }
  assert.equal(deploysOf(a.appId).length, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM github_app_webhook_deliveries').get().n > 0, true);
});

test('the signature is checked against the bytes GitHub sent, not re-serialised JSON', async () => {
  const a = mkApp({ repo: 'acme/ws' });
  const raw = `{\n  "ref" :  "refs/heads/main",\n  "after": "${SHA}",  "deleted": false,\n  "repository": { "full_name": "acme/ws" },\n  "installation": {"id": 9001}\n}\n`;
  assert.notEqual(JSON.stringify(JSON.parse(raw)), raw);
  const r = await deliver(null, { raw });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(deploysOf(a.appId).length, 1);
});

test('apps come from the DB (installation id AND repo), never from the payload alone', async () => {
  const a = mkApp({ repo: 'acme/one', installationId: 9001 });
  const b = mkApp({ repo: 'acme/two', installationId: 9001 });
  const other = mkApp({ repo: 'acme/three', installationId: 4242 });

  const wrongInstallation = await deliver(push('acme/one', { installationId: 4242 }));
  assert.equal(wrongInstallation.body.result, 'ignored_unattached');

  const unknownInstallation = await deliver(push('acme/one', { installationId: 123456 }));
  assert.equal(unknownInstallation.body.result, 'ignored_unattached');

  const unknownRepo = await deliver(push('acme/not-attached', { installationId: 9001 }));
  assert.equal(unknownRepo.body.result, 'ignored_unattached');

  const noInstallation = await deliver({ ...push('acme/one'), installation: undefined });
  assert.equal(noInstallation.body.result, 'ignored_no_installation');

  assert.equal(deploysOf(a.appId).length, 0);
  assert.equal(deploysOf(b.appId).length, 0);
  assert.equal(deploysOf(other.appId).length, 0);

  const onlyB = await deliver(push('ACME/Two'));
  assert.deepEqual(onlyB.body.apps.map((x) => [x.slug, x.action]), [[b.slug, 'deploy_triggered']]);
  assert.equal(deploysOf(a.appId).length, 0);
  assert.equal(deploysOf(b.appId).length, 1);
});

test("an app whose github_url no longer names the attached repo is not deployed", async () => {
  const a = mkApp({ repo: 'acme/moved' });
  db.prepare('UPDATE apps SET github_url = ? WHERE id = ?').run('https://github.com/acme/elsewhere', a.appId);
  const r = await deliver(push('acme/moved'));
  assert.deepEqual(r.body.apps, [{ slug: a.slug, action: 'skipped_repo_mismatch' }]);
  assert.equal(deploysOf(a.appId).length, 0);
});

test('installation suspend / unsuspend / deleted: the app stays attached and fails with the reason, never a token error', async () => {
  const a = mkApp({ repo: 'acme/susp', installationId: 5555 });

  const s = await deliver({ action: 'suspend', installation: { id: 5555 } }, { event: 'installation' });
  assert.equal(s.body.result, 'installation_suspend');
  assert.ok(ghCred.getInstallation(a.appId), 'still attached');
  await assert.rejects(ghCred.resolveGitHubCredential(a.app()), /suspended on GitHub/);
  const blockedPush = await deliver(push('acme/susp', { installationId: 5555 }));
  assert.equal(blockedPush.body.apps[0].action, 'skipped_installation_removed');
  assert.equal(deploysOf(a.appId).length, 0);

  await deliver({ action: 'unsuspend', installation: { id: 5555 } }, { event: 'installation' });
  const cred = await ghCred.resolveGitHubCredential(a.app());
  assert.equal(cred.source, 'installation');

  const d = await deliver({ action: 'deleted', installation: { id: 5555 } }, { event: 'installation' });
  assert.equal(d.body.result, 'installation_deleted');
  assert.ok(ghCred.getInstallation(a.appId), 'marked, not detached: detaching would silently return the app to its PAT');
  await assert.rejects(ghCred.resolveGitHubCredential(a.app()), /uninstalled on GitHub/);
  assert.deepEqual(auditsOf(a.appId).map((x) => x.action), ['github-app-installation-suspend', 'github-app-installation-unsuspend', 'github-app-installation-deleted']);

  // unsuspend does not resurrect an uninstalled installation
  await deliver({ action: 'unsuspend', installation: { id: 5555 } }, { event: 'installation' });
  await assert.rejects(ghCred.resolveGitHubCredential(a.app()), /uninstalled on GitHub/);
});

test('installation_repositories removed marks only the removed repos; added restores them', async () => {
  const keep = mkApp({ repo: 'acme/keep', installationId: 6666 });
  const drop = mkApp({ repo: 'acme/drop', installationId: 6666 });

  const r = await deliver({
    action: 'removed', installation: { id: 6666 }, repository_selection: 'selected',
    repositories_added: [], repositories_removed: [{ id: 1, name: 'drop', full_name: 'acme/drop' }],
  }, { event: 'installation_repositories' });
  assert.deepEqual(r.body.apps, [drop.slug]);

  await assert.rejects(ghCred.resolveGitHubCredential(drop.app()), /was removed from GitHub App installation 6666/);
  assert.equal((await ghCred.resolveGitHubCredential(keep.app())).source, 'installation');
  assert.equal((await deliver(push('acme/keep', { installationId: 6666 }))).body.result, 'deploy_triggered');
  assert.equal((await deliver(push('acme/drop', { installationId: 6666 }))).body.apps[0].action, 'skipped_installation_removed');

  await deliver({
    action: 'added', installation: { id: 6666 }, repository_selection: 'selected',
    repositories_added: [{ id: 1, name: 'drop', full_name: 'acme/drop' }], repositories_removed: [],
  }, { event: 'installation_repositories' });
  assert.equal((await ghCred.resolveGitHubCredential(drop.app())).source, 'installation');
});

test('re-attaching (GitHub confirms the installation) clears an uninstalled mark', async () => {
  const a = mkApp({ repo: 'acme/back', installationId: 9001 });
  await deliver({ action: 'deleted', installation: { id: 9001 } }, { event: 'installation' });
  await assert.rejects(ghCred.resolveGitHubCredential(a.app()), /uninstalled/);
  await ghCred.attachInstallation(a.app());
  assert.equal((await ghCred.resolveGitHubCredential(a.app())).source, 'installation');
});

test('ping is 200; other events are accepted and ignored', async () => {
  const p = await deliver({ zen: 'hi', hook_id: 1 }, { event: 'ping' });
  assert.deepEqual([p.status, p.body.result], [200, 'pong']);
  const o = await deliver({ action: 'opened' }, { event: 'pull_request' });
  assert.deepEqual([o.status, o.body.result], [202, 'ignored_event']);
});

test('malformed deliveries: bad delivery id, another App as target, non-JSON body', async () => {
  assert.equal((await deliver({ zen: 1 }, { event: 'ping', id: 'bad id!' })).status, 400);
  assert.equal((await deliver({ zen: 1 }, { event: 'ping', headers: { 'x-github-hook-installation-target-id': '1' } })).status, 400);
  assert.equal((await deliver(null, { event: 'ping', raw: 'not json' })).status, 400);
});

test('body limit: a 1 MB push is accepted, an 11 MB one is refused with 413', async () => {
  const a = mkApp({ repo: 'acme/big' });
  const big = await deliver(push('acme/big', { padding: 'x'.repeat(1024 * 1024) }));
  assert.equal(big.status, 200, JSON.stringify(big.body));
  assert.equal(deploysOf(a.appId).length, 1);
  const huge = await deliver(push('acme/big', { padding: 'x'.repeat(11 * 1024 * 1024) }));
  assert.equal(huge.status, 413);
  assert.equal(deploysOf(a.appId).length, 1);
});

test('manifest: webhooks active with a push subscription only when CRANE_DOMAIN is set', async () => {
  const key = mkAdmin();
  delete process.env.CRANE_DOMAIN;
  const off = await adminCall('POST', '/api/github-app/manifest', key, {});
  assert.equal(off.body.manifest.hook_attributes.active, false);
  process.env.CRANE_DOMAIN = 'crane.example.com';
  try {
    const on = await adminCall('POST', '/api/github-app/manifest', key, {});
    assert.deepEqual(on.body.manifest.hook_attributes, { url: 'https://crane.example.com/api/github-app/webhook', active: true });
    assert.deepEqual(on.body.manifest.default_events, ['push']);
  } finally {
    delete process.env.CRANE_DOMAIN;
  }
});

test('existing App: status says what to click; webhook-config PATCHes /app/hook/config with the JWT, url, json and the stored secret', async () => {
  const key = mkAdmin();
  db.prepare('DELETE FROM github_app_webhook_deliveries').run();

  const noDomain = await adminCall('GET', '/api/github-app', key);
  assert.equal(noDomain.body.webhook.state, 'unavailable');
  assert.match(noDomain.body.webhook.reason, /CRANE_DOMAIN is not set/);
  assert.equal((await adminCall('POST', '/api/github-app/webhook-config', key, {})).status, 409);
  assert.equal(api.calls.filter((c) => c.path === '/app/hook/config').length, 0);

  process.env.CRANE_DOMAIN = 'crane.example.com';
  try {
    const before = await adminCall('GET', '/api/github-app', key);
    assert.equal(before.body.webhook.state, 'not_configured');
    assert.equal(before.body.webhook.manual_steps.length, 4);
    assert.match(before.body.webhook.manual_steps.join(' '), /tick "Active"/);
    assert.match(before.body.webhook.manual_steps.join(' '), /tick "Push"/);
    assert.equal(JSON.stringify(before.body).includes(SECRET), false, 'status must never carry the secret');

    const r = await adminCall('POST', '/api/github-app/webhook-config', key, {});
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(JSON.stringify(r.body).includes(SECRET), false);
    const patch = api.calls.filter((c) => c.method === 'PATCH' && c.path === '/app/hook/config');
    assert.equal(patch.length, 1);
    assert.deepEqual(patch[0].body, { url: 'https://crane.example.com/api/github-app/webhook', content_type: 'json', secret: SECRET, insecure_ssl: '0' });
    assert.match(patch[0].auth, /^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    assert.equal(r.body.webhook.state, 'configured');
    assert.equal(r.body.webhook.manual_steps.length, 4, 'activation and the Push subscription are still clicks');

    await deliver({ zen: 'hi' }, { event: 'ping' });
    const after = await adminCall('GET', '/api/github-app', key);
    assert.equal(after.body.webhook.state, 'receiving');
    assert.deepEqual(after.body.webhook.manual_steps, []);
  } finally {
    delete process.env.CRANE_DOMAIN;
  }
});

test('no stored webhook secret -> 401; no App configured -> 404', async () => {
  db.prepare('UPDATE github_app_config SET webhook_secret_enc = NULL WHERE id = 1').run();
  assert.equal((await deliver({ zen: 1 }, { event: 'ping' })).status, 401);
  ghApp.deleteAppConfig();
  assert.equal((await deliver({ zen: 1 }, { event: 'ping' })).status, 404);
});
