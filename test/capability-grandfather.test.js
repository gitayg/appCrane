import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  db as firstDb, mkUser, mkApp, appRow, assign, startServer, stopServer, call, BASE,
} from './capability-harness.mjs';

// Existing apps: migration 200 grandfathers every capability already in use.
// Nothing about those apps changes until a platform admin reviews them, they
// show as unreviewed, confirm keeps the grant, revoke ends it.
//
// The apps are created with migration 200 rolled back, then the real migration
// runs over them through initDb(), the same way an upgrade applies it.

const { initDb, getDb } = await import('../server/db.js');
const { issueServiceToken } = await import('../server/services/appServiceToken.js');

firstDb.exec('DROP TABLE capability_requests');
firstDb.prepare("DELETE FROM _migrations WHERE name IN ('200-capability-approvals.sql', '201-capability-custom-domain.sql')").run();

const PA = mkUser({ name: 'Pat Platform', role: 'platform_admin' });
const owner = mkUser({ name: 'Olive Owner' });
const bypassApp = mkApp('gf-bypass', { auth_bypass_paths: JSON.stringify(['/hooks']) });
const headlessApp = mkApp('gf-headless', { auth_mode: 'headless' });
const publicApp = mkApp('gf-public', { visibility: 'public', public_access: 1 });
const tcpApp = mkApp('gf-tcp', { ingress_type: 'tcp', public_port: 31777 });
const mailApp = mkApp('gf-mail');
const plainApp = mkApp('gf-plain');
const domainApp = mkApp('gf-domain', { domain: 'Legacy.Example.test', custom_domain_auth: 0 });
const signinDomainApp = mkApp('gf-domain-signin', { domain: 'signin.example.test', custom_domain_auth: 1 });
for (const a of [bypassApp, headlessApp, publicApp, tcpApp, mailApp, plainApp, domainApp, signinDomainApp]) assign(a, owner, 'owner');
firstDb.prepare("INSERT INTO app_host_ports (host_port, app_id, env, state) VALUES (31777, ?, 'production', 'pinned')").run(tcpApp.id);
firstDb.prepare("INSERT INTO email_queue (app_id, to_email, subject, body_text, source) VALUES (?, ?, 'old', 'old', 'app')").run(mailApp.id, owner.email);
firstDb.prepare("INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?, '', 'postgres', 'd', 'u', 'enc:x')").run(plainApp.id);

initDb();
const db = getDb();

before(startServer);
after(stopServer);

const rows = (app) => db.prepare('SELECT * FROM capability_requests WHERE app_id = ? ORDER BY capability').all(app.id);

test('the migration grandfathers exactly what is in use, as approved and unreviewed', () => {
  const caps = (app) => rows(app).map((r) => r.capability);
  assert.deepEqual(caps(bypassApp), ['auth_bypass_paths']);
  assert.deepEqual(JSON.parse(rows(bypassApp)[0].scope), { paths: ['/hooks'] });
  assert.deepEqual(caps(headlessApp), ['headless']);
  assert.deepEqual(caps(publicApp), ['public_visibility']);
  assert.deepEqual(caps(tcpApp), ['tcp_ports']);
  assert.equal(JSON.parse(rows(tcpApp)[0].scope).public_port, 31777);
  assert.deepEqual(caps(mailApp), ['outbound_email']);
  assert.deepEqual(caps(plainApp), ['managed_database']);
  assert.deepEqual(caps(domainApp), ['custom_domain_unprotected']);
  assert.deepEqual(JSON.parse(rows(domainApp)[0].scope), { domains: ['legacy.example.test'] });
  assert.deepEqual(caps(signinDomainApp), [], 'a custom domain behind sign-in is not a capability');
  for (const r of db.prepare('SELECT * FROM capability_requests').all()) {
    assert.equal(r.origin, 'grandfathered');
    assert.equal(r.status, 'approved');
    assert.equal(r.reviewed_at, null);
  }
});

test('grandfathered apps keep working untouched: echoes, edits and the e-mail API', async () => {
  assert.equal((await call(owner, 'PUT', `/api/apps/${bypassApp.slug}`, { auth_bypass_paths: ['/hooks'], description: 'edit' })).status, 200);
  assert.equal((await call(owner, 'PUT', `/api/apps/${headlessApp.slug}`, { auth_mode: 'headless', description: 'edit' })).status, 200);
  assert.equal((await call(owner, 'PUT', `/api/apps/${publicApp.slug}`, { visibility: 'public', description: 'edit' })).status, 200);
  assert.equal(appRow(headlessApp).auth_mode, 'headless');
  assert.equal(appRow(publicApp).visibility, 'public');
  const token = issueServiceToken(mailApp.id);
  const res = await fetch(`${BASE}/api/service/email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-AppCrane-Service-Token': token },
    body: JSON.stringify({ to: owner.email, subject: 'still works', text: 'x' }),
  });
  assert.equal(res.status, 202);
  // An app that never sent mail is not grandfathered into sending it.
  const plainToken = issueServiceToken(plainApp.id);
  const refused = await fetch(`${BASE}/api/service/email`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-AppCrane-Service-Token': plainToken },
    body: JSON.stringify({ to: owner.email, subject: 'new', text: 'x' }),
  });
  assert.equal(refused.status, 403);
  // Grandfathered scope is exact: one more path still needs a request.
  assert.equal((await call(owner, 'PUT', `/api/apps/${bypassApp.slug}`, { auth_bypass_paths: ['/hooks', '/more'] })).status, 403);
});

test('the review list shows them; the app view marks them unreviewed', async () => {
  const list = await call(PA, 'GET', '/api/capability-requests?status=unreviewed');
  assert.equal(list.status, 200);
  assert.equal(list.body.requests.length, 7);
  const view = await call(owner, 'GET', `/api/apps/${headlessApp.slug}/capabilities`);
  assert.equal(view.body.capabilities.headless.grants[0].unreviewed, true);
});

test('confirm keeps the grant and clears it from the list; revoke ends it and removes the setting', async () => {
  const [hl] = rows(headlessApp);
  const confirm = await call(PA, 'POST', `/api/capability-requests/${hl.id}/confirm`, { expires_in_days: 30 }, { as: 'session' });
  assert.equal(confirm.status, 200, JSON.stringify(confirm.body));
  assert.ok(confirm.body.request.reviewed_at);
  assert.ok(confirm.body.request.expires_at);
  assert.equal((await call(PA, 'POST', `/api/capability-requests/${hl.id}/confirm`, {}, { as: 'session' })).status, 409);
  assert.equal(appRow(headlessApp).auth_mode, 'headless', 'confirm changes nothing about the app');

  const [pub] = rows(publicApp);
  const revoke = await call(PA, 'POST', `/api/capability-requests/${pub.id}/revoke`, {}, { as: 'session' });
  assert.equal(revoke.status, 200, JSON.stringify(revoke.body));
  assert.equal(appRow(publicApp).visibility, 'private');

  const [tcp] = rows(tcpApp);
  const flag = await call(PA, 'POST', `/api/capability-requests/${tcp.id}/revoke`, {}, { as: 'session' });
  assert.match(flag.body.effect, /flag only/);
  assert.equal(appRow(tcpApp).ingress_type, 'tcp', 'a published port is not closed by a revoke; the admin switches it to http');

  const [dom] = rows(domainApp);
  const domRevoke = await call(PA, 'POST', `/api/capability-requests/${dom.id}/revoke`, {}, { as: 'session' });
  assert.match(domRevoke.body.effect, /flag only/);
  assert.equal(appRow(domainApp).domain, 'Legacy.Example.test', 'the domain is never dropped by a revoke');
  assert.equal(appRow(domainApp).custom_domain_auth, 0, 'sign-in is not forced on by a revoke');
  // ...but with the grant gone, turning sign-in on and off again needs a new one.
  assert.equal((await call(owner, 'PUT', `/api/apps/${domainApp.slug}`, { custom_domain_auth: true })).status, 200);
  assert.equal((await call(owner, 'PUT', `/api/apps/${domainApp.slug}`, { custom_domain_auth: false })).status, 403);

  const left = await call(PA, 'GET', '/api/capability-requests?status=unreviewed');
  assert.equal(left.body.requests.length, 3);
});
