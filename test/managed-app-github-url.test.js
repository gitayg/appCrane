import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Who may set the github_url of a Crane-hosted app (source_type 'managed',
// repo_backend 'local'), measured through the real PUT /api/apps/:slug router
// and the MCP appcrane_update_app handler.
//
// The owner (or a platform admin) may set and clear it, so the GitHub
// comparison can show whether the repo they dual-push to is ahead or behind.
// That is safe only because (1) githubSyncStatus never reads it with the
// platform service-account token and (2) a deploy of that app still clones the
// local repo. Both are pinned below. Every other managed-source change stays
// platform-admin only.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-managed-ghurl-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

// docker fails, so a deploy stops after the clone and SHA check under test.
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, encrypt } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function user(name, role) {
  const key = generateApiKey('dhk_admin');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
}
const admin = user('padmin', 'platform_admin');
const owner = user('owner', 'user');
const appAdmin = user('appadmin', 'user');
const member = user('member', 'user');

function makeApp(slug, { repoBackend = 'local', sourceType = 'managed', githubUrl = null } = {}) {
  const slot = db.prepare('SELECT COALESCE(MAX(slot), 100) + 1 AS s FROM apps').get().s;
  const id = db.prepare('INSERT INTO apps (name,slug,slot,source_type,github_url,branch,repo_backend) VALUES (?,?,?,?,?,\'main\',?)')
    .run(slug, slug, slot, sourceType, githubUrl, repoBackend).lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, owner.id);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'admin')").run(id, appAdmin.id);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(id, member.id);
  return id;
}
const row = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
const audits = (id) => db.prepare("SELECT detail FROM audit_log WHERE app_id = ? AND action = 'app-update'").all(id);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);
const server = await new Promise((resolve) => { const s = api.listen(0, '127.0.0.1', () => resolve(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) { /* best effort */ }
});

async function req(who, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': who.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json() };
}

const OWN = 'https://github.com/example-owner/own-repo';
const MANAGED_REFUSAL = /limited to platform admins/;

test('PUT: an owner sets, changes and clears github_url on a Crane-hosted app; the app stays local; each change is audited', async () => {
  const id = makeApp('ghurl-owner');
  const set = await req(owner, 'PUT', '/api/apps/ghurl-owner', { github_url: OWN });
  assert.equal(set.status, 200, JSON.stringify(set.body));
  assert.equal(row('ghurl-owner').github_url, OWN);
  const changed = await req(owner, 'PUT', '/api/apps/ghurl-owner', { github_url: `${OWN}-2` });
  assert.equal(changed.status, 200, JSON.stringify(changed.body));
  assert.equal(row('ghurl-owner').github_url, `${OWN}-2`);
  const cleared = await req(owner, 'PUT', '/api/apps/ghurl-owner', { github_url: '' });
  assert.equal(cleared.status, 200, JSON.stringify(cleared.body));
  assert.ok(!row('ghurl-owner').github_url);
  assert.equal(row('ghurl-owner').repo_backend, 'local');
  assert.equal(row('ghurl-owner').source_type, 'managed');
  assert.equal(audits(id).length, 3, JSON.stringify(audits(id)));
});

test('PUT: an app admin and a plain member are refused on a Crane-hosted app', async () => {
  makeApp('ghurl-appadmin');
  const a = await req(appAdmin, 'PUT', '/api/apps/ghurl-appadmin', { github_url: OWN });
  assert.equal(a.status, 403, JSON.stringify(a.body));
  const m = await req(member, 'PUT', '/api/apps/ghurl-appadmin', { github_url: OWN });
  assert.equal(m.status, 403, JSON.stringify(m.body));
  assert.equal(row('ghurl-appadmin').github_url, null);
});

test('PUT: an app admin whose role grants code.modify_repo_settings is still refused by the managed gate', async () => {
  makeApp('ghurl-appadmin-rbac');
  db.prepare("INSERT INTO role_permissions (permission, role, granted) VALUES ('code.modify_repo_settings', 'admin', 1) ON CONFLICT(permission, role) DO UPDATE SET granted = 1").run();
  try {
    const a = await req(appAdmin, 'PUT', '/api/apps/ghurl-appadmin-rbac', { github_url: OWN });
    assert.equal(a.status, 403, JSON.stringify(a.body));
    assert.match(a.body.error.message, MANAGED_REFUSAL);
    assert.equal(row('ghurl-appadmin-rbac').github_url, null);
  } finally {
    db.prepare("DELETE FROM role_permissions WHERE permission = 'code.modify_repo_settings' AND role = 'admin'").run();
  }
});

test('PUT: an owner is still refused on a managed app whose repo is on GitHub (repo_backend NULL)', async () => {
  makeApp('ghurl-remote', { repoBackend: null, githubUrl: 'https://github.com/svc-account/AMC_ghurl-remote' });
  const r = await req(owner, 'PUT', '/api/apps/ghurl-remote', { github_url: OWN });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.match(r.body.error.message, MANAGED_REFUSAL);
  assert.equal(row('ghurl-remote').github_url, 'https://github.com/svc-account/AMC_ghurl-remote');
});

test('PUT: an owner is refused (403, not a crash) on a managed app with an unrecognised repo_backend', async () => {
  makeApp('ghurl-oddmarker', { repoBackend: 'bogus' });
  const r = await req(owner, 'PUT', '/api/apps/ghurl-oddmarker', { github_url: OWN });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.match(r.body.error.message, MANAGED_REFUSAL);
  assert.equal(row('ghurl-oddmarker').github_url, null);
});

test('PUT: an owner is still refused any source_type change into managed, with or without a github_url', async () => {
  makeApp('ghurl-st', { sourceType: 'github', repoBackend: null, githubUrl: OWN });
  for (const body of [{ source_type: 'managed' }, { source_type: 'managed', github_url: `${OWN}-x` }]) {
    const r = await req(owner, 'PUT', '/api/apps/ghurl-st', body);
    assert.equal(r.status, 403, `${JSON.stringify(body)}: ${JSON.stringify(r.body)}`);
    assert.match(r.body.error.message, MANAGED_REFUSAL);
  }
  assert.equal(row('ghurl-st').source_type, 'github');
  assert.equal(row('ghurl-st').github_url, OWN);
});

test('MCP appcrane_update_app stays platform-admin only, even for an owner of a Crane-hosted app', async () => {
  makeApp('ghurl-mcp');
  await assert.rejects(
    callTool(owner.row, 'appcrane_update_app', { slug: 'ghurl-mcp', github_url: OWN }),
    /requires platform admin/,
  );
  assert.equal(row('ghurl-mcp').github_url, null);
});

test('PUT: a platform admin sets and clears it on a Crane-hosted app', async () => {
  makeApp('ghurl-padmin');
  const set = await req(admin, 'PUT', '/api/apps/ghurl-padmin', { github_url: OWN });
  assert.equal(set.status, 200, JSON.stringify(set.body));
  assert.equal(row('ghurl-padmin').github_url, OWN);
  const cleared = await req(admin, 'PUT', '/api/apps/ghurl-padmin', { github_url: '' });
  assert.equal(cleared.status, 200, JSON.stringify(cleared.body));
  assert.ok(!row('ghurl-padmin').github_url);
});

test('PUT: neither an owner nor a platform admin can store a URL with credentials, another host or plain http', async () => {
  makeApp('ghurl-bad');
  for (const who of [owner, admin]) {
    for (const bad of ['https://user:pw@github.com/example-owner/own-repo', 'https://gitlab.com/example-owner/own-repo', 'http://github.com/example-owner/own-repo', 'https://github.com/example-owner']) {
      const r = await req(who, 'PUT', '/api/apps/ghurl-bad', { github_url: bad });
      assert.equal(r.status, 400, `${who.row.name} ${bad}: ${JSON.stringify(r.body)}`);
    }
  }
  assert.equal(row('ghurl-bad').github_url, null);
});

test('the sync check never reads an owner-set github_url with the platform service-account token', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('github_service_token_enc', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(encrypt('svc-token-for-test'));
  const { getServiceTokenInternal } = await import('../server/services/githubService.js');
  assert.equal(getServiceTokenInternal(), 'svc-token-for-test', 'precondition: service token configured');
  const { defaultResolveRemote } = await import('../server/services/githubSyncStatus.js');
  makeApp('ghurl-hazard');
  const r = await req(owner, 'PUT', '/api/apps/ghurl-hazard', { github_url: 'https://github.com/svc-account/AMC_someone-else' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const remote = await defaultResolveRemote(row('ghurl-hazard'));
  assert.equal(remote.credential, 'none');
  assert.equal(remote.token, null);
  assert.equal(remote.url, 'https://github.com/svc-account/AMC_someone-else.git');
});

test('deploy: after the owner sets github_url, a Crane-hosted app still builds from the local repo at its tip', async () => {
  const lg = await import('../server/services/localGit.js');
  const { deployApp } = await import('../server/services/deployer.js');
  const { getPortsForSlot } = await import('../server/services/portAllocator.js');
  db.prepare("INSERT INTO settings (key,value) VALUES ('supply_chain_verify_enabled','1') ON CONFLICT(key) DO UPDATE SET value='1'").run();
  await lg.createAppRepo('ghurl-deploy', { description: 'local source' });
  const tip = execFileSync('git', [`--git-dir=${lg.repoPath('ghurl-deploy')}`, 'rev-parse', 'refs/heads/main'],
    { env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } }).toString().trim();
  const id = makeApp('ghurl-deploy');
  const GH = 'https://github.com/example-owner/elsewhere';
  const r = await req(owner, 'PUT', '/api/apps/ghurl-deploy', { github_url: GH });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(row('ghurl-deploy').github_url, GH);

  const depId = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)")
    .run(id, admin.id).lastInsertRowid;
  await deployApp(depId, row('ghurl-deploy'), 'sandbox', getPortsForSlot(row('ghurl-deploy').slot), {}).catch(() => {});
  const log = db.prepare('SELECT log FROM deployments WHERE id = ?').get(depId).log || '';
  assert.match(log, /Cloning managed repo AMC_ghurl-deploy from this host's repository store \(branch: main\)/, log);
  const cloned = /Cloned successfully\. Commit: ([0-9a-f]+)/.exec(log)?.[1];
  assert.ok(cloned && tip.startsWith(cloned), `deployed ${cloned}, local tip ${tip}\n${log}`);
  assert.match(log, new RegExp(`Supply-chain verify: OK \\(HEAD ${tip.slice(0, 12)} matches the local managed repository AMC_ghurl-deploy@main\\)`), log);
  assert.ok(!log.includes('example-owner/elsewhere'), `the github_url reached the deploy:\n${log}`);
});
