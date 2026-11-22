import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  db, mkUser, mkApp, appRow, assign, capRows, auditRows,
  startServer, stopServer, call, requestCap, approve, grantCap,
} from './capability-harness.mjs';

// Capability approvals, lifecycle: who may request, who may decide (a human
// platform admin on a dashboard session, never the requester, never an agent,
// never over MCP), narrowing and expiry, the sweep, per-app authz on every
// route, the MCP tools and the audit trail.

const { callTool, getToolCatalog } = await import('../server/services/mcpTools.js');
const { sweepCapabilityGrants } = await import('../server/services/capabilities/sweeper.js');

const PA = mkUser({ name: 'Pat Platform', role: 'platform_admin' });
const PA2 = mkUser({ name: 'Quinn Platform', role: 'platform_admin' });

before(startServer);
after(stopServer);

function fresh(slug) {
  const app = mkApp(slug);
  const owner = mkUser({ name: `Owner ${slug}` });
  assign(app, owner, 'owner');
  return { app, owner };
}
const expireNow = (id) => db.prepare("UPDATE capability_requests SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(id);

test('requesters: owner and app admin may; a plain member and an outsider may not; one open request per capability', async () => {
  const { app, owner } = fresh('lc-who');
  const appAdmin = mkUser(); assign(app, appAdmin, 'admin');
  const member = mkUser(); assign(app, member, 'user');
  const outsider = mkUser();

  const body = { capability: 'headless', scope: {}, reason: 'public status page' };
  const first = await call(owner, 'POST', `/api/apps/${app.slug}/capability-requests`, body);
  assert.equal(first.status, 201, JSON.stringify(first.body));
  const again = await call(appAdmin, 'POST', `/api/apps/${app.slug}/capability-requests`, body);
  assert.equal(again.status, 200);
  assert.equal(again.body.request.id, first.body.request.id, 'the open request comes back, no duplicate');
  assert.equal((await call(member, 'POST', `/api/apps/${app.slug}/capability-requests`, body)).status, 403);
  assert.equal((await call(outsider, 'POST', `/api/apps/${app.slug}/capability-requests`, body)).status, 403);
  assert.equal((await call(outsider, 'GET', `/api/apps/${app.slug}/capabilities`)).status, 403);
  assert.equal((await call(null, 'GET', `/api/apps/${app.slug}/capabilities`)).status, 401);
  assert.equal((await call(owner, 'POST', `/api/apps/${app.slug}/capability-requests`, { capability: 'headless', scope: {} })).status, 400, 'reason is required');
  assert.equal((await call(owner, 'POST', `/api/apps/${app.slug}/capability-requests`, { capability: 'ai_annex_iii', reason: 'x' })).status, 400);
  const view = await call(member, 'GET', `/api/apps/${app.slug}/capabilities`);
  assert.equal(view.status, 200);
  assert.equal(view.body.can_request, false);
  assert.equal(view.body.capabilities.headless.pending.id, first.body.request.id);
  assert.ok('ai_annex_iii' in view.body.external);
  // E-mail to the platform admins, not to the requester.
  const mails = db.prepare("SELECT to_email FROM email_queue WHERE source = 'capability-request' AND subject LIKE ?").all(`%${app.name}%`).map((r) => r.to_email);
  assert.deepEqual(mails.sort(), [PA.email, PA2.email].sort());
});

test('deciders: API key, agent identity, non-admin and the requester themself are refused; another admin on a session decides', async () => {
  const { app } = fresh('lc-decide');
  // PA2 is the app's owner AND a platform admin: they may ask, not approve their own ask.
  assign(app, PA2, 'owner');
  const req = await requestCap(PA2, app, 'headless', {});
  const bot = mkUser({ name: 'Admin bot', role: 'platform_admin', kind: 'agent' });
  const someone = mkUser();

  const viaKey = await call(PA, 'POST', `/api/capability-requests/${req.id}/approve`, {});
  assert.equal(viaKey.status, 403); assert.equal(viaKey.body.error.code, 'APPROVAL_REQUIRES_SESSION');
  const viaAgent = await call(bot, 'POST', `/api/capability-requests/${req.id}/approve`, {}, { as: 'session' });
  assert.equal(viaAgent.status, 403); assert.equal(viaAgent.body.error.code, 'AGENT_CANNOT_APPROVE');
  const viaUser = await call(someone, 'POST', `/api/capability-requests/${req.id}/approve`, {}, { as: 'session' });
  assert.equal(viaUser.status, 403);
  const self = await call(PA2, 'POST', `/api/capability-requests/${req.id}/approve`, {}, { as: 'session' });
  assert.equal(self.status, 403); assert.equal(self.body.error.code, 'SELF_APPROVAL');
  assert.equal(capRows(app, 'headless')[0].status, 'pending');

  const ok = await approve(PA, req.id, { note: 'fine' });
  assert.equal(ok.status, 'approved');
  assert.equal(ok.decided_by.id, PA.id);
  assert.equal((await call(PA, 'POST', `/api/capability-requests/${req.id}/approve`, {}, { as: 'session' })).status, 409, 'decided once');
  assert.equal(auditRows('capability-approve', app.id).length, 1);
  const decisionMail = db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE source = 'capability-request' AND to_email = ? AND subject LIKE '%approved%'").get(PA2.email).n;
  assert.equal(decisionMail, 1);
});

test('step-up: approve, deny, confirm and revoke on a dashboard session signed in outside the window are refused until the admin steps up', async () => {
  const { app, owner } = fresh('lc-stepup');
  const stale = mkUser({ name: 'Sam Stale', role: 'platform_admin' });
  db.prepare("UPDATE identity_sessions SET created_at = datetime('now', '-30 minutes') WHERE user_id = ?").run(stale.id);
  const req = await requestCap(owner, app, 'headless', {});
  const other = fresh('lc-stepup-granted');
  const g = await grantCap(other.owner, PA, other.app, 'headless', {});
  for (const [verb, id] of [['approve', req.id], ['deny', req.id], ['confirm', g.id], ['revoke', g.id]]) {
    const r = await call(stale, 'POST', `/api/capability-requests/${id}/${verb}`, {}, { as: 'session' });
    assert.equal(r.status, 401, `${verb}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error.code, 'STEP_UP_REQUIRED', verb);
  }
  assert.equal(capRows(app, 'headless')[0].status, 'pending');
  assert.equal(capRows(other.app, 'headless')[0].status, 'approved');
  db.prepare("UPDATE identity_sessions SET step_up_at = strftime('%Y-%m-%d %H:%M:%SZ', 'now') WHERE user_id = ?").run(stale.id);
  assert.equal((await approve(stale, req.id)).status, 'approved');
});

test('MCP: no tool can approve; an agent may request and is recorded as one; list shows the queue', async () => {
  const names = getToolCatalog().map((t) => t.name);
  assert.ok(names.includes('appcrane_request_capability'));
  assert.ok(names.includes('appcrane_list_capability_requests'));
  assert.equal(names.filter((n) => /capabilit/.test(n) && /approve|deny|confirm|revoke|decide/.test(n)).length, 0);

  const { app } = fresh('lc-mcp');
  const agent = mkUser({ name: 'Coder agent', kind: 'agent' });
  assign(app, agent, 'admin');
  const res = await callTool(agent, 'appcrane_request_capability', { slug: app.slug, capability: 'auth_bypass_paths', scope: { paths: ['/ws'] }, reason: 'websocket runner' });
  const out = JSON.parse(res.content[0].text);
  assert.equal(out.created, true);
  assert.equal(out.request.requested_by_kind, 'agent');
  assert.equal(out.request.requested_via, 'mcp');

  const listed = JSON.parse((await callTool(agent, 'appcrane_list_capability_requests', { slug: app.slug })).content[0].text);
  assert.equal(listed.capabilities.auth_bypass_paths.pending.id, out.request.id);
  const queue = JSON.parse((await callTool(PA, 'appcrane_list_capability_requests', {})).content[0].text);
  assert.ok(queue.requests.some((r) => r.id === out.request.id));
  const outsider = mkUser();
  await assert.rejects(callTool(outsider, 'appcrane_request_capability', { slug: app.slug, capability: 'headless', reason: 'x' }), /Forbidden/);
  await assert.rejects(callTool(outsider, 'appcrane_list_capability_requests', { slug: app.slug }), /Forbidden/);
  const mine = JSON.parse((await callTool(outsider, 'appcrane_list_capability_requests', {})).content[0].text);
  assert.equal(mine.requests.length, 0, 'someone else\'s requests do not leak');
});

test('narrowing: an admin may approve less than asked, never more; deny records the note', async () => {
  const { app, owner } = fresh('lc-narrow');
  const req = await requestCap(owner, app, 'auth_bypass_paths', { paths: ['/a', '/b'] });
  const wide = await call(PA, 'POST', `/api/capability-requests/${req.id}/approve`, { scope: { paths: ['/a', '/c'] } }, { as: 'session' });
  assert.equal(wide.status, 400); assert.equal(wide.body.error.code, 'SCOPE_WIDENED');
  const ok = await approve(PA, req.id, { scope: { paths: ['/a'] } });
  assert.deepEqual(ok.scope, { paths: ['/a'] });
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/a', '/b'] })).status, 403, 'the narrowed-away path stays refused');
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/a'] })).status, 200);

  const r2 = await requestCap(owner, app, 'headless', {});
  const denied = await call(PA, 'POST', `/api/capability-requests/${r2.id}/deny`, { note: 'use a bypass path' }, { as: 'session' });
  assert.equal(denied.status, 200);
  assert.equal(denied.body.request.status, 'denied');
  assert.equal(auditRows('capability-deny', app.id).length, 1);
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_mode: 'headless' })).status, 403);
});

test('cancel: the requester or the owner; another app\'s request id is a 404', async () => {
  const { app, owner } = fresh('lc-cancel');
  const { app: other, owner: otherOwner } = fresh('lc-cancel-other');
  const req = await requestCap(owner, app, 'headless', {});
  assert.equal((await call(otherOwner, 'POST', `/api/apps/${other.slug}/capability-requests/${req.id}/cancel`)).status, 404);
  const ok = await call(owner, 'POST', `/api/apps/${app.slug}/capability-requests/${req.id}/cancel`);
  assert.equal(ok.status, 200); assert.equal(ok.body.request.status, 'cancelled');
});

test('admin routes are platform-admin only', async () => {
  const { owner } = fresh('lc-admin-routes');
  assert.equal((await call(owner, 'GET', '/api/capability-requests')).status, 403);
  assert.equal((await call(owner, 'GET', '/api/capability-approvals/policy')).status, 403);
  assert.equal((await call(owner, 'PUT', '/api/capability-approvals/policy', { headless: { approval_required: false } })).status, 403);
  assert.equal((await call(owner, 'POST', '/api/capability-requests/1/revoke', {}, { as: 'session' })).status, 403);
  const pol = await call(PA, 'GET', '/api/capability-approvals/policy');
  assert.equal(pol.status, 200);
  assert.equal(pol.body.policy.headless.approval_required, true);
  assert.equal(pol.body.policy.llm_gateway.approval_required, false);
  assert.equal(pol.body.policy.managed_database.approval_required, false);
  assert.equal(pol.body.policy.custom_domain_unprotected.approval_required, true);
  const put = await call(PA, 'PUT', '/api/capability-approvals/policy', { llm_gateway: { approval_required: true } });
  assert.equal(put.body.policy.llm_gateway.approval_required, true);
  await call(PA, 'PUT', '/api/capability-approvals/policy', { llm_gateway: { approval_required: false } });
  assert.equal(auditRows('capability-policy').length, 2);
});

test('expiry: the sweep revokes a bypass grant (paths removed) and only flags a database grant (database kept)', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('capability_approval_required:managed_database', '1') ON CONFLICT(key) DO UPDATE SET value = '1'").run();
  const { app, owner } = fresh('lc-expiry');
  const bypass = await grantCap(owner, PA, app, 'auth_bypass_paths', { paths: ['/hooks', '/later'] }, { expires_in_days: 1 });
  assert.ok(bypass.expires_at);
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/hooks'] })).status, 200);
  const dbGrant = await grantCap(owner, PA, app, 'managed_database', { engines: ['postgres'] }, { expires_in_days: 1 });
  assert.equal((await call(owner, 'POST', `/api/apps/${app.slug}/database`, { engine: 'postgres' })).status, 200);

  expireNow(bypass.id); expireNow(dbGrant.id);
  // Past expires_at a grant authorizes nothing, before the sweep has even run.
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/hooks', '/later'] })).status, 403);
  const reloads = [];
  const results = await sweepCapabilityGrants(db, { reloadCaddy: async () => { reloads.push(1); } });
  const byCap = Object.fromEntries(results.map((r) => [r.capability, r]));
  assert.equal(byCap.auth_bypass_paths.action, 'revoked');
  assert.equal(byCap.managed_database.action, 'flagged');
  assert.equal(appRow(app).auth_bypass_paths, null, 'the bypass path is gone');
  assert.equal(reloads.length, 1, 'Caddy reloaded once for the removed path');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM managed_databases WHERE app_id = ?').get(app.id).n, 1, 'the database is never dropped by a timer');
  const flagged = await call(PA, 'GET', '/api/capability-requests?status=flagged');
  assert.ok(flagged.body.requests.some((r) => r.id === dbGrant.id));
  assert.equal(auditRows('capability-expire', app.id).length, 2);

  // An expired grant authorizes nothing new.
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_bypass_paths: ['/hooks'] })).status, 403);
  assert.equal((await call(owner, 'POST', `/api/apps/${app.slug}/database`, { engine: 'mariadb' })).status, 403);
  assert.equal((await sweepCapabilityGrants(db, { reloadCaddy: async () => {} })).length, 0, 'a second sweep does nothing');
  db.prepare("DELETE FROM settings WHERE key = 'capability_approval_required:managed_database'").run();
});

test('revoke: headless goes back to authenticated, e-mail stops, audit and owner mail', async () => {
  const { app, owner } = fresh('lc-revoke');
  const g = await grantCap(owner, PA, app, 'headless', {});
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}`, { auth_mode: 'headless' })).status, 200);
  const viaKey = await call(PA, 'POST', `/api/capability-requests/${g.id}/revoke`, {});
  assert.equal(viaKey.status, 403);
  const r = await call(PA, 'POST', `/api/capability-requests/${g.id}/revoke`, { note: 'no longer needed' }, { as: 'session' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.request.status, 'revoked');
  assert.match(r.body.effect, /authenticated/);
  assert.equal(appRow(app).auth_mode, 'authenticated');
  assert.equal(auditRows('capability-revoke', app.id).length, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM email_queue WHERE source = 'capability-request' AND to_email = ? AND subject LIKE '%revoked%'").get(owner.email).n, 1);
});

test('audit: request, approve, deny, expire, revoke and implicit grants all leave a row', async () => {
  for (const a of ['capability-request', 'capability-approve', 'capability-deny', 'capability-expire', 'capability-revoke']) {
    assert.ok(auditRows(a).length > 0, `${a} audited`);
  }
  const agentRow = db.prepare("SELECT actor_kind FROM audit_log WHERE action = 'capability-request' AND actor_kind = 'agent' LIMIT 1").get();
  assert.ok(agentRow, 'an agent request is attributed to an agent');
});
