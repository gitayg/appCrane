import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  db, mkUser, mkApp, appRow, assign, setSetting, capRows, auditRows, provisioned,
  startServer, stopServer, call, requestCap, approve, grantCap, BASE,
} from './capability-harness.mjs';

// Capability approvals, enforcement: for every gated capability, through the
// real write path, an owner is refused without a grant, allowed after approval
// exactly within the approved scope, and refused outside it. A platform admin
// setting it directly is allowed and leaves an implicit, audited grant.

const { issueServiceToken } = await import('../server/services/appServiceToken.js');
const { ensureManifestDatabase } = await import('../server/services/manifestDatabase.js');
const { callTool } = await import('../server/services/mcpTools.js');

const PA = mkUser({ name: 'Pat Platform', role: 'platform_admin' });

before(startServer);
after(stopServer);

function fresh(slug, cols) {
  const app = mkApp(slug, cols);
  const owner = mkUser({ name: `Owner ${slug}` });
  assign(app, owner, 'owner');
  return { app, owner };
}
const refused = (r) => {
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'CAPABILITY_APPROVAL_REQUIRED');
  assert.match(r.body.error.message, /capability-requests/);
  assert.match(r.body.error.message, /appcrane_request_capability/);
};

test('auth_bypass_paths: refused without a grant, allowed for the approved paths, refused for one more', async () => {
  const { app, owner } = fresh('cap-bypass');
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/hooks'] }));
  assert.equal(appRow(app).auth_bypass_paths, null);

  await grantCap(owner, PA, app, 'auth_bypass_paths', { paths: ['/hooks'] });
  const ok = await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/hooks'] });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.deepEqual(JSON.parse(appRow(app).auth_bypass_paths), ['/hooks']);

  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/hooks', '/extra'] }));
  assert.deepEqual(JSON.parse(appRow(app).auth_bypass_paths), ['/hooks']);
  // The echo of what the app already has is not a new capability.
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/hooks'], description: 'x' })).status, 200);
});

test('headless: refused without a grant, allowed after approval', async () => {
  const { app, owner } = fresh('cap-headless');
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_mode: 'headless' }));
  assert.notEqual(appRow(app).auth_mode, 'headless');
  await grantCap(owner, PA, app, 'headless', {});
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_mode: 'headless' })).status, 200);
  assert.equal(appRow(app).auth_mode, 'headless');
});

test('public visibility: refused without a grant on REST and on MCP set_app_meta, allowed after approval', async () => {
  const { app, owner } = fresh('cap-public');
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { visibility: 'public' }));
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { public_access: true }));
  await assert.rejects(callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, visibility: 'public' }), /needs platform admin approval/);
  assert.equal(appRow(app).visibility, 'private');
  await grantCap(owner, PA, app, 'public_visibility', {});
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { visibility: 'public' })).status, 200);
  assert.equal(appRow(app).visibility, 'public');
});

test('MCP set_app_meta now honours ban_public_apps (it skipped the platform policy before)', async () => {
  const { app, owner } = fresh('cap-ban');
  await grantCap(owner, PA, app, 'public_visibility', {});
  setSetting('policy_ban_public_apps', '1');
  try {
    await assert.rejects(callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, visibility: 'public' }), /ban_public_apps/);
    assert.equal(appRow(app).visibility, 'private');
  } finally { setSetting('policy_ban_public_apps', '0'); }
});

test('headless and bypass paths through MCP set_app_meta: refused, then allowed within the grant', async () => {
  const { app, owner } = fresh('cap-meta');
  await assert.rejects(callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, auth_mode: 'headless' }), /needs platform admin approval/);
  await assert.rejects(callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, auth_bypass_paths: ['/ws'] }), /needs platform admin approval/);
  await grantCap(owner, PA, app, 'auth_bypass_paths', { paths: ['/ws'] });
  await callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, auth_bypass_paths: ['/ws'] });
  assert.deepEqual(JSON.parse(appRow(app).auth_bypass_paths), ['/ws']);
  await assert.rejects(callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, auth_bypass_paths: ['/ws', '/extra'] }), /needs platform admin approval/);
});

test('tcp_ports: an owner applies exactly the approved type and port, nothing else', async () => {
  const { app, owner } = fresh('cap-ports');
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp', public_port: 31501 }));
  const member = mkUser({ name: 'Member ports' });
  assign(app, member, 'user');
  const notOwner = await call(member, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp', public_port: 31501 });
  assert.equal(notOwner.status, 403);
  assert.match(notOwner.body.error.message, /or the app owner publishing within an approved tcp_ports capability grant/);

  const req = await requestCap(owner, app, 'tcp_ports', { ingress_type: 'tcp', public_port: 31501 });
  // Not yet approved: still refused, and the message names the open request.
  const waiting = await call(owner, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp', public_port: 31501 });
  refused(waiting);
  assert.match(waiting.body.error.message, new RegExp(`Request #${req.id} is waiting`));
  await approve(PA, req.id);

  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp', public_port: 31502 }));
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp', public_port: 31501, sandbox_public_port: 31503 }));
  assert.equal(appRow(app).ingress_type ?? 'http', 'http');

  const ok = await call(owner, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp', public_port: 31501 });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(appRow(app).ingress_type, 'tcp');
  assert.equal(appRow(app).public_port, 31501);
});

test('tcp_ports: a platform admin publishing directly records an implicit grant with the allocated port', async () => {
  const { app } = fresh('cap-ports-admin');
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp' }, { as: 'session' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const port = appRow(app).public_port;
  assert.ok(Number.isInteger(port));
  const [g] = capRows(app, 'tcp_ports');
  assert.equal(g.origin, 'implicit');
  assert.equal(g.status, 'approved');
  assert.equal(JSON.parse(g.scope).public_port, port);
  assert.equal(auditRows('capability-implicit-grant', app.id).length, 1);
});

test('outbound e-mail: the app is refused without a grant, may mail the approved domain only', async () => {
  const { app, owner } = fresh('cap-mail');
  const token = issueServiceToken(app.id);
  mkUser({ name: 'Recipient' });
  const recipient = db.prepare("SELECT email FROM users WHERE name = 'Recipient'").get().email;
  const other = db.prepare("INSERT INTO users (name, email, role, active, kind) VALUES ('Elsewhere', 'someone@other.test', 'user', 1, 'human') RETURNING email").get().email;
  const send = (to) => fetch(`${BASE}/api/service/email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-AppCrane-Service-Token': token },
    body: JSON.stringify({ to, subject: 'hi', text: 'hello' }),
  }).then(async (res) => ({ status: res.status, body: await res.json() }));

  refused(await send(recipient));
  await grantCap(owner, PA, app, 'outbound_email', { recipient_domains: ['t.test'] });
  const ok = await send(recipient);
  assert.equal(ok.status, 202, JSON.stringify(ok.body));
  refused(await send(other));
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE app_id = ? AND source = 'app'").get(app.id).n, 1);
});

const DB_POLICY = 'capability_approval_required:managed_database';
const withDbApproval = (fn) => async () => { setSetting(DB_POLICY, '1'); try { await fn(); } finally { db.prepare('DELETE FROM settings WHERE key = ?').run(DB_POLICY); } };

test('managed database: self-service by default, and listed (with its policy) in the capability view', async () => {
  const { app, owner } = fresh('cap-db-default');
  assert.equal((await call(owner, 'POST', `/api/apps/${app.slug}/database`, { engine: 'postgres' })).status, 200);
  const out = await ensureManifestDatabase(app, { engine: 'mariadb' }, { provision: async () => {}, credentialsFor: () => null });
  assert.equal(out.provisioned, true);
  const view = await call(owner, 'GET', `/api/apps/${app.slug}/capabilities`);
  assert.equal(view.body.capabilities.managed_database.approval_required, false);
  assert.equal(view.body.capabilities.managed_database.default_approval_required, false);
  assert.equal(capRows(app, 'managed_database').length, 0, 'no grant recorded while approval is off');
});

test('managed database: with approval switched on, REST and MCP refuse a new engine without a grant; approved engine provisions, another does not', withDbApproval(async () => {
  const { app, owner } = fresh('cap-db');
  refused(await call(owner, 'POST', `/api/apps/${app.slug}/database`, { engine: 'postgres' }));
  await assert.rejects(callTool(owner, 'appcrane_provision_database', { slug: app.slug, engine: 'postgres' }), /needs platform admin approval/);
  assert.equal(provisioned.filter(([id]) => id === app.id).length, 0, 'nothing was provisioned');

  await grantCap(owner, PA, app, 'managed_database', { engines: ['postgres'] });
  assert.equal((await call(owner, 'POST', `/api/apps/${app.slug}/database`, { engine: 'postgres' })).status, 200);
  refused(await call(owner, 'POST', `/api/apps/${app.slug}/database`, { engine: 'mariadb' }));
  await assert.rejects(callTool(owner, 'appcrane_provision_database', { slug: app.slug, engine: 'mongo' }), /needs platform admin approval/);
}));

test('managed database: with approval on, the deploy-time manifest path refuses with the reason, then provisions once approved', withDbApproval(async () => {
  const { app, owner } = fresh('cap-db-manifest');
  const logs = [];
  const calls = [];
  const provision = async (scope, eng) => { calls.push([scope, eng]); };
  await assert.rejects(
    ensureManifestDatabase(app, { engine: 'postgres' }, { appendLog: (m) => logs.push(m), provision, credentialsFor: () => null }),
    (e) => /deployhub\.json declares a postgres database/.test(e.message) && /needs platform admin approval/.test(e.message),
  );
  assert.equal(calls.length, 0, 'never skipped into a silent provision');

  await grantCap(owner, PA, app, 'managed_database', { engines: ['postgres'] });
  const out = await ensureManifestDatabase(app, { engine: 'postgres' }, { appendLog: (m) => logs.push(m), provision, credentialsFor: () => null });
  assert.equal(out.provisioned, true);
  assert.equal(calls.length, 1);
}));

test('managed database: with approval on, an app that already has the engine (grandfathered data) is not stopped at deploy', withDbApproval(async () => {
  const { app } = fresh('cap-db-existing');
  db.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, '', 'postgres', 'd', 'u', 'enc:x')").run(app.id);
  const calls = [];
  const out = await ensureManifestDatabase(app, { engine: 'postgres' }, {
    scope: { appId: app.id, tenant: 'sandbox' }, provision: async (s, e) => { calls.push([s, e]); }, credentialsFor: () => null,
  });
  assert.equal(out.provisioned, true, 'the sandbox database of an engine the app already holds is not a new capability');
}));

test('custom domain: with sign-in on it is self-service; without sign-in it needs a grant for exactly that domain', async () => {
  const { app, owner } = fresh('cap-domain');
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { domain: 'signin.example.test', custom_domain_auth: true })).status, 200);
  assert.equal(appRow(app).domain, 'signin.example.test');
  // Turning sign-in off on the existing domain counts as needing the grant.
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { custom_domain_auth: false }));
  assert.equal(appRow(app).custom_domain_auth, 1);
  await assert.rejects(callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, custom_domain_auth: false }), /needs platform admin approval/);

  await grantCap(owner, PA, app, 'custom_domain_unprotected', { domains: ['open.example.test'] });
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { custom_domain_auth: false }));
  const ok = await call(owner, 'PUT', `/api/apps/${app.slug}`, { domain: 'open.example.test', custom_domain_auth: false });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(appRow(app).custom_domain_auth, 0);
  // The echo of the domain it already serves unprotected is nothing new.
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { domain: 'open.example.test', description: 'edit' })).status, 200);
  // Another domain without sign-in is outside the scope, on REST and on MCP.
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { domain: 'other.example.test' }));
  await assert.rejects(callTool(owner, 'appcrane_set_app_meta', { slug: app.slug, domain: 'other.example.test' }), /needs platform admin approval/);
  assert.equal(appRow(app).domain, 'open.example.test');
  // Moving to another domain WITH sign-in is self-service again.
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { domain: 'other.example.test', custom_domain_auth: true })).status, 200);
});

test('custom domain at create: refused for a non-admin, an implicit grant for a platform admin; MCP update_app records one too', async () => {
  const creator = mkUser({ name: 'Creator', role: 'platform_admin', kind: 'agent' });
  const r = await call(creator, 'POST', '/api/apps', { name: 'Dom create', slug: 'cap-dom-create', domain: 'create.example.test' });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'CAPABILITY_APPROVAL_REQUIRED');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM apps WHERE slug = 'cap-dom-create'").get().n, 0, 'nothing was created');

  const ok = await call(PA, 'POST', '/api/apps', { name: 'Dom create', slug: 'cap-dom-create', domain: 'create.example.test' }, { as: 'session' });
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  const created = db.prepare("SELECT * FROM apps WHERE slug = 'cap-dom-create'").get();
  const [g] = capRows(created, 'custom_domain_unprotected');
  assert.equal(g.origin, 'implicit');
  assert.deepEqual(JSON.parse(g.scope), { domains: ['create.example.test'] });

  const { app } = fresh('cap-dom-update');
  const asSession = { kind: 'session', credentialHash: null, userId: PA.id };
  await callTool(PA, 'appcrane_update_app', { slug: app.slug, domain: 'upd.example.test' }, null, asSession);
  assert.equal(capRows(app, 'custom_domain_unprotected')[0].origin, 'implicit');
  await assert.rejects(callTool(creator, 'appcrane_update_app', { slug: app.slug, domain: 'upd2.example.test' }), /needs platform admin approval/);
  await assert.rejects(callTool(creator, 'appcrane_create_app', { name: 'Mcp dom', slug: 'cap-dom-mcp', github_url: 'https://github.com/example/app', domain: 'mcp.example.test' }), /needs platform admin approval/);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM apps WHERE slug = 'cap-dom-mcp'").get().n, 0);
  await callTool(PA, 'appcrane_create_app', { name: 'Mcp dom', slug: 'cap-dom-mcp', github_url: 'https://github.com/example/app', domain: 'mcp.example.test' }, null, asSession);
  const mcpApp = db.prepare("SELECT * FROM apps WHERE slug = 'cap-dom-mcp'").get();
  assert.equal(capRows(mcpApp, 'custom_domain_unprotected')[0].origin, 'implicit');
});

test('external secret store connection: refused without a grant, allowed for the approved provider only', async () => {
  const { app, owner } = fresh('cap-secrets');
  const body = (name, provider) => ({ name, provider, settings: { address: 'https://vault.example.test' }, credentials: { token: 'x' } });
  refused(await call(owner, 'POST', `/api/apps/${app.slug}/secret-connections`, body('v1', 'vault')));
  await grantCap(owner, PA, app, 'external_secret_connections', { providers: ['vault'] });
  const ok = await call(owner, 'POST', `/api/apps/${app.slug}/secret-connections`, body('v1', 'vault'));
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  refused(await call(owner, 'POST', `/api/apps/${app.slug}/secret-connections`, { name: 'i1', provider: 'infisical', settings: {}, credentials: { client_id: 'a', client_secret: 'b' } }));
});

test('LLM gateway: allowed by default; with approval on, refused until granted', async () => {
  const { app, owner } = fresh('cap-llm');
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}/llm-gateway`, { enabled: true })).status, 200);
  const { app: app2, owner: owner2 } = fresh('cap-llm-2');
  setSetting('capability_approval_required:llm_gateway', '1');
  try {
    refused(await call(owner2, 'PUT', `/api/apps/${app2.slug}/llm-gateway`, { enabled: true }));
    await grantCap(owner2, PA, app2, 'llm_gateway', {});
    assert.equal((await call(owner2, 'PUT', `/api/apps/${app2.slug}/llm-gateway`, { enabled: true })).status, 200);
  } finally { setSetting('capability_approval_required:llm_gateway', '0'); }
});

test('approval off restores the rule from before: owner sets headless freely, ports stay platform-admin only', async () => {
  const { app, owner } = fresh('cap-off');
  setSetting('capability_approval_required:headless', '0');
  setSetting('capability_approval_required:tcp_ports', '0');
  try {
    assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_mode: 'headless' })).status, 200);
    const r = await call(owner, 'PUT', `/api/apps/${app.slug}`, { ingress_type: 'tcp' });
    assert.equal(r.status, 403);
    assert.doesNotMatch(r.body.error.message, /grant/);
    assert.equal(capRows(app, 'headless').length, 0, 'no grant recorded while approval is off');
  } finally {
    setSetting('capability_approval_required:headless', '1');
    setSetting('capability_approval_required:tcp_ports', '1');
  }
});

test('a platform admin acting by API key or MCP key is allowed, but leaves no grant the owner could reuse', async () => {
  const { app, owner } = fresh('cap-implicit-key');
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/status'] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(JSON.parse(appRow(app).auth_bypass_paths), ['/status']);
  assert.equal(capRows(app, 'auth_bypass_paths').length, 0, 'a key-based admin write recorded a durable grant');
  assert.equal(auditRows('capability-admin-direct', app.id).length, 1, 'the direct write is still audited');
  // The owner clears it and tries to put it back: that still needs approval.
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: [] })).status, 200);
  refused(await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/status'] }));

  const { app: viaMcp } = fresh('cap-implicit-mcp');
  await callTool(PA, 'appcrane_update_app', { slug: viaMcp.slug, domain: 'keyed.example.test' });
  assert.equal(capRows(viaMcp, 'custom_domain_unprotected').length, 0, 'an MCP admin write recorded a durable grant');
});

test('platform admin setting bypass paths directly: allowed, implicit grant and audit row', async () => {
  const { app } = fresh('cap-implicit');
  const r = await call(PA, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/status'] }, { as: 'session' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const [g] = capRows(app, 'auth_bypass_paths');
  assert.equal(g.origin, 'implicit');
  assert.deepEqual(JSON.parse(g.scope), { paths: ['/status'] });
  assert.equal(g.decided_by, PA.id);
  assert.equal(auditRows('capability-implicit-grant', app.id).length, 1);
});

test('an agent identity holding platform_admin gets no implicit grant', async () => {
  const { app } = fresh('cap-agent-admin');
  const bot = mkUser({ name: 'Bot', role: 'platform_admin', kind: 'agent' });
  refused(await call(bot, 'PUT', `/api/apps/${app.slug}`, { auth_mode: 'headless' }));
  await assert.rejects(callTool(bot, 'appcrane_set_app_ingress', { slug: app.slug, ingress_type: 'tcp' }), /needs platform admin approval/);
  assert.equal(appRow(app).ingress_type ?? 'http', 'http');
  assert.equal(capRows(app, 'headless').length + capRows(app, 'tcp_ports').length, 0);
});
