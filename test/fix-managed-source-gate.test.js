import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// A managed app with no local repo is cloned with the platform's service-account
// token, scoped to whatever github_url the row names. Whoever may pick that URL
// may read anything the token reads, so choosing it is a platform-admin act. The
// same holds for attaching the GitHub App: it issues an installation token for
// whatever repo the app names, on no proof the caller can reach that repo.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-fix-managed-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO role_permissions (permission, role, granted) VALUES ('platform.create_app', 'user', 1) ON CONFLICT(permission, role) DO UPDATE SET granted = 1").run();

function user(name, role) {
  const key = generateApiKey('dhk_admin');
  const id = db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,\'human\')')
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
}
const admin = user('admin', 'platform_admin');
const owner = user('owner', 'user');

function makeApp(slug, { sourceType = 'github', githubUrl = 'https://github.com/example-owner/own-repo', backend = null } = {}) {
  const slot = db.prepare('SELECT COALESCE(MAX(slot), 100) + 1 AS s FROM apps').get().s;
  const id = db.prepare('INSERT INTO apps (name,slug,slot,source_type,github_url,branch,repo_backend) VALUES (?,?,?,?,?,\'main\',?)')
    .run(slug, slug, slot, sourceType, githubUrl, backend).lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, owner.id);
  return id;
}
const row = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const appGithubAppRoutes = (await import('../server/routes/appGithubApp.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use('/api/apps', appGithubAppRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function req(who, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': who.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json() };
}

const VICTIM = 'https://github.com/svc-account/AMC_victim';

test('PUT: an owner cannot turn their app managed and point it at another repo', async () => {
  makeApp('gate-put-both');
  const r = await req(owner, 'PUT', '/api/apps/gate-put-both', { source_type: 'managed', github_url: VICTIM });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  const after_ = row('gate-put-both');
  assert.equal(after_.source_type, 'github');
  assert.equal(after_.github_url, 'https://github.com/example-owner/own-repo');
});

test('PUT: the two-step version is refused at the step that makes it managed', async () => {
  makeApp('gate-put-steps');
  const first = await req(owner, 'PUT', '/api/apps/gate-put-steps', { github_url: VICTIM });
  assert.equal(first.status, 200, 'a github app runs on its own PAT, so its URL stays the owner\'s to change');
  const second = await req(owner, 'PUT', '/api/apps/gate-put-steps', { source_type: 'managed' });
  assert.equal(second.status, 403, JSON.stringify(second.body));
  assert.equal(row('gate-put-steps').source_type, 'github');
});

test('PUT: an owner cannot repoint an app that is already managed', async () => {
  makeApp('gate-put-repoint', { sourceType: 'managed', githubUrl: 'https://github.com/svc-account/AMC_gate-put-repoint' });
  const r = await req(owner, 'PUT', '/api/apps/gate-put-repoint', { github_url: VICTIM });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(row('gate-put-repoint').github_url, 'https://github.com/svc-account/AMC_gate-put-repoint');
});

test('PUT: an owner still edits a managed app, including a form that resends its source unchanged', async () => {
  const url = 'https://github.com/svc-account/AMC_gate-put-edit';
  makeApp('gate-put-edit', { sourceType: 'managed', githubUrl: url });
  const plain = await req(owner, 'PUT', '/api/apps/gate-put-edit', { description: 'edited', branch: 'next' });
  assert.equal(plain.status, 200, JSON.stringify(plain.body));
  assert.equal(row('gate-put-edit').description, 'edited');
  assert.equal(row('gate-put-edit').branch, 'next');
  const resent = await req(owner, 'PUT', '/api/apps/gate-put-edit', { description: 'again', source_type: 'managed', github_url: url });
  assert.equal(resent.status, 200, JSON.stringify(resent.body));
  assert.equal(row('gate-put-edit').description, 'again');
});

test('PUT: an owner may leave managed, and a platform admin may do all of it', async () => {
  makeApp('gate-put-admin');
  const r = await req(admin, 'PUT', '/api/apps/gate-put-admin', { source_type: 'managed', github_url: VICTIM });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(row('gate-put-admin').github_url, VICTIM);
  makeApp('gate-put-leave', { sourceType: 'managed', githubUrl: 'https://github.com/svc-account/AMC_gate-put-leave' });
  const left = await req(owner, 'PUT', '/api/apps/gate-put-leave', { source_type: 'github', github_url: 'https://github.com/example-owner/own-repo' });
  assert.equal(left.status, 200, JSON.stringify(left.body));
});

test('POST: only a platform admin creates a managed app through the API', async () => {
  const refused = await req(owner, 'POST', '/api/apps', { name: 'x', slug: 'gate-post-owner', source_type: 'managed', github_url: VICTIM });
  assert.equal(refused.status, 403, JSON.stringify(refused.body));
  assert.equal(row('gate-post-owner'), undefined);
  const github = await req(owner, 'POST', '/api/apps', { name: 'x', slug: 'gate-post-github', source_type: 'github', github_url: 'https://github.com/example-owner/own-repo' });
  assert.equal(github.status, 201, JSON.stringify(github.body));
  const allowed = await req(admin, 'POST', '/api/apps', { name: 'x', slug: 'gate-post-admin', source_type: 'managed', github_url: VICTIM });
  assert.equal(allowed.status, 201, JSON.stringify(allowed.body));
});

test('MCP appcrane_create_app: the enum in its schema is not enforced, so the handler refuses managed itself', async () => {
  await assert.rejects(
    callTool(owner.row, 'appcrane_create_app', { name: 'x', slug: 'gate-mcp-owner', source_type: 'managed', github_url: VICTIM }),
    /platform admin/i,
  );
  assert.equal(row('gate-mcp-owner'), undefined);
  await callTool(owner.row, 'appcrane_create_app', { name: 'x', slug: 'gate-mcp-github', github_url: 'https://github.com/example-owner/own-repo' });
  assert.equal(row('gate-mcp-github').source_type, 'github');
});

test('MCP appcrane_update_app stays platform-admin only', async () => {
  makeApp('gate-mcp-update');
  await assert.rejects(
    callTool(owner.row, 'appcrane_update_app', { slug: 'gate-mcp-update', source_type: 'managed', github_url: VICTIM }),
    /requires platform admin/,
  );
  assert.equal(row('gate-mcp-update').source_type, 'github');
});

test('PUT /:slug/github-app: an owner is refused before any installation lookup; a platform admin reaches it', async () => {
  makeApp('gate-attach');
  const refused = await req(owner, 'PUT', '/api/apps/gate-attach/github-app', {});
  assert.equal(refused.status, 403, JSON.stringify(refused.body));
  assert.equal(refused.body.error.code, 'FORBIDDEN');
  // No GitHub App on this install, so attach itself fails: the point is it got past the gate.
  const allowed = await req(admin, 'PUT', '/api/apps/gate-attach/github-app', {});
  assert.notEqual(allowed.status, 403, JSON.stringify(allowed.body));
  // Detaching drops a credential, so it stays with the owner.
  const detach = await req(owner, 'DELETE', '/api/apps/gate-attach/github-app');
  assert.equal(detach.status, 200, JSON.stringify(detach.body));
});
