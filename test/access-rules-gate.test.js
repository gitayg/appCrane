import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Path role rules at the gate. A pentest of a hosted app found 27 routes with
// no check of their own: the forward_auth gate only asked "may this person
// enter the app". These tests drive /api/identity/verify the way Caddy's
// forward_auth does (X-Forwarded-Method / X-Forwarded-Uri, ?app=&prefix=) and
// the dashboard rules route the way the Manage page does.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-accessrules-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const { parseAccessRules, setRules, canonicalSegments, decideAccess, AccessRulesError } = await import('../server/services/accessRules.js');

const mkApp = (slug, slot) => db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES (?,?,?,'managed','forward_auth','private')"
).run(slug === 'gate-app' ? 'Roadmap' : slug, slug, slot).lastInsertRowid;
const APP = mkApp('gate-app', 1);
const OTHER = mkApp('gate-other', 2);

const mkUser = (name, role = 'user') => {
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@acme.test`, role, hashApiKey(`key-${name}`)).lastInsertRowid;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))")
    .run(id, hashApiKey(`tok-${name}`));
  return id;
};
const seat = (appId, userId, role) => db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, userId, role);

const member = mkUser('member'); seat(APP, member, 'user'); seat(OTHER, member, 'owner');
const admin = mkUser('admin'); seat(APP, admin, 'admin');
const owner = mkUser('owner'); seat(APP, owner, 'owner');
const padmin = mkUser('padmin', 'platform_admin');

setRules(db, APP, 'production', 'manifest', parseAccessRules({ rules: [
  { path: '/admin/*', roles: ['admin'] },
  { path: '/api/settings', methods: ['PUT', 'POST', 'PATCH', 'DELETE'], roles: ['admin'] },
  { path: '/api/users/*/delete', roles: ['owner'] },
] }));
setRules(db, APP, 'sandbox', 'manifest', parseAccessRules({ rules: [
  { path: '/reports/*', roles: ['admin'] },
] }));

const identityRouter = (await import('../server/routes/identity.js')).default;
const accessRulesRouter = (await import('../server/routes/accessRules.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/identity', identityRouter);
api.use('/api/apps', accessRulesRouter);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

/** One forward_auth sub-request, as Caddy sends it (prefix already stripped). */
async function gate(who, method, uri, { env = 'production', accept = 'application/json', slug = 'gate-app' } = {}) {
  const prefix = env === 'sandbox' ? `/${slug}-sandbox` : `/${slug}`;
  const r = await fetch(`${BASE}/api/identity/verify?app=${slug}&prefix=${prefix}`, {
    headers: {
      Cookie: `cc_token=tok-${who}`,
      Accept: accept,
      'X-Forwarded-Method': method,
      'X-Forwarded-Uri': uri,
      'X-Forwarded-Host': 'crane.test.local',
    },
    redirect: 'manual',
  });
  return { status: r.status, body: await r.text(), headers: r.headers };
}

test('a member is refused on a rule-protected path; admin and owner are allowed', async () => {
  const refused = await gate('member', 'GET', '/admin/users');
  assert.equal(refused.status, 403, refused.body);
  const body = JSON.parse(refused.body);
  assert.equal(body.error.code, 'ROLE_REQUIRED');
  assert.equal(body.error.required_role, 'admin');
  assert.match(body.error.message, /You need the admin role or higher on Roadmap for this page/);
  assert.equal(refused.headers.get('x-appcrane-user-id'), null, 'a refused request must not carry identity headers');

  for (const who of ['admin', 'owner', 'padmin']) {
    const ok = await gate(who, 'GET', '/admin/users');
    assert.equal(ok.status, 200, `${who}: ${ok.body}`);
  }
  const ownerOk = await gate('owner', 'GET', '/admin/users');
  assert.equal(ownerOk.headers.get('x-appcrane-app-role'), 'owner');
  assert.ok(ownerOk.headers.get('x-appcrane-identity-sig'), 'an allowed request is still signed');
});

test('a browser gets a readable page, not JSON', async () => {
  const r = await gate('member', 'GET', '/admin', { accept: 'text/html,application/xhtml+xml' });
  assert.equal(r.status, 403);
  assert.match(r.headers.get('content-type'), /text\/html/);
  assert.match(r.body, /You need the admin role or higher on Roadmap for this page/);
});

test('a method-scoped rule: GET allowed, PUT refused, HEAD follows GET', async () => {
  assert.equal((await gate('member', 'GET', '/api/settings')).status, 200);
  assert.equal((await gate('member', 'PUT', '/api/settings')).status, 403);
  assert.equal((await gate('member', 'delete', '/api/settings')).status, 403, 'method compared case-insensitively');
  assert.equal((await gate('admin', 'PUT', '/api/settings')).status, 200);
  const getOnly = [{ path: '/export', methods: ['GET'], roles: ['admin'] }];
  assert.equal(decideAccess(getOnly, { method: 'HEAD', uri: '/export', appRole: 'user' }).ok, false, 'HEAD must follow a GET rule');
  assert.equal(decideAccess(getOnly, { method: 'POST', uri: '/export', appRole: 'user' }).ok, true);
  assert.equal(decideAccess(getOnly, { method: undefined, uri: '/export', appRole: 'user' }).ok, false, 'unknown method: method rules apply');
});

test('a single-segment wildcard and the strictest matching rule', async () => {
  assert.equal((await gate('admin', 'POST', '/api/users/42/delete')).status, 403, 'owner-only rule');
  assert.equal((await gate('owner', 'POST', '/api/users/42/delete')).status, 200);
  assert.equal((await gate('member', 'POST', '/api/users/42/rename')).status, 200);
});

test('an unmatched path behaves as before: anyone with access', async () => {
  for (const uri of ['/', '/dashboard', '/api/items?x=1', '/administrator', '/api/settings/theme']) {
    const r = await gate('member', 'GET', uri);
    assert.equal(r.status, 200, `${uri}: ${r.body}`);
  }
});

test('no access to the app is still refused first, rule or not', async () => {
  const stranger = mkUser('stranger');
  void stranger;
  const r = await gate('stranger', 'GET', '/dashboard');
  assert.equal(r.status, 302, 'no role on the app sends the browser to /login?denied=1 as before');
});

test('normalisation: every bypass attempt on /admin is refused for a member', async () => {
  const attempts = [
    '/ADMIN/users', '/Admin', '/admin', '/admin/', '/admin?x=1', '/admin#x',
    '//admin/users', '/./admin', '/x/../admin', '/x/..%2Fadmin', '/%61dmin', '/%2561dmin',
    '/admin%2Fusers', '/%2e%2e/admin', '/x/%2e%2e/admin/users', '/admin;jsessionid=1',
    '/admin\\users', '/x%5C..%5Cadmin', '/gate-app/admin', '/GATE-APP/admin', '/%67ate-app/admin',
    '/admin/./users', '/admin//users', '/..;/admin',
  ];
  const through = [];
  for (const uri of attempts) {
    const r = await gate('member', 'GET', uri);
    if (r.status !== 403) through.push(`${uri} -> ${r.status}`);
  }
  assert.deepEqual(through, [], `let through: ${through.join(', ')}`);
  for (const uri of ['/%E0%A4%A', '/admin%00', '/a%0d%0ab']) {
    const r = await gate('member', 'GET', uri);
    assert.equal(r.status, 400, `${uri} should be refused as unreadable (${r.status})`);
  }
  assert.equal((await gate('member', 'PUT', '/API/Settings/')).status, 403, 'method rule normalised too');
});

test('canonicalSegments resolves the path the way frameworks may read it', () => {
  assert.deepEqual(canonicalSegments('/A//b/./c/../D;x=1?q'), ['a', 'b', 'd']);
  assert.deepEqual(canonicalSegments('/../../etc'), ['etc']);
  assert.equal(canonicalSegments('/%25252561'), null, 'still encoded after three decodes');
});

test('sandbox uses its own rules', async () => {
  assert.equal((await gate('member', 'GET', '/admin', { env: 'sandbox' })).status, 200, 'production rule leaked into sandbox');
  assert.equal((await gate('member', 'GET', '/reports/q3', { env: 'sandbox' })).status, 403);
  assert.equal((await gate('member', 'GET', '/reports/q3')).status, 200, 'sandbox rule leaked into production');
});

test('another app is unaffected', async () => {
  assert.equal((await gate('member', 'GET', '/admin', { slug: 'gate-other' })).status, 200);
});

test('a direct /verify with no forwarded URI (an API client) is not gated', async () => {
  const r = await fetch(`${BASE}/api/identity/verify?app=gate-app`, { headers: { Authorization: 'Bearer tok-member' } });
  assert.equal(r.status, 200);
});

test('invalid rules are rejected with the field named', () => {
  const cases = [
    [{ rules: 'x' }, /access\.rules: must be an array/],
    [{ rule: [] }, /access\.rule: unknown key/],
    [{ rules: [{ path: 'admin', roles: ['admin'] }] }, /rules\[0\]\.path: must be a string starting with "\/"/],
    [{ rules: [{ path: '/a%2F', roles: ['admin'] }] }, /rules\[0\]\.path: .*not allowed/],
    [{ rules: [{ path: '/a/../b', roles: ['admin'] }] }, /rules\[0\]\.path: .*"\.\." segment/],
    [{ rules: [{ path: '/a*', roles: ['admin'] }] }, /rules\[0\]\.path: .*whole segment/],
    [{ rules: [{ path: '/a/', roles: ['admin'] }] }, /must not end with "\/"/],
    [{ rules: [{ path: '/a//b', roles: ['admin'] }] }, /empty segment/],
    [{ rules: [{ path: '/a', roles: [] }] }, /rules\[0\]\.roles: must be a non-empty array/],
    [{ rules: [{ path: '/a', roles: ['member'] }] }, /unknown role "member"/],
    [{ rules: [{ path: '/a', roles: ['admin'], methods: ['FETCH'] }] }, /unknown method "FETCH"/],
    [{ rules: [{ path: '/a', roles: ['admin'], methods: [] }] }, /rules\[0\]\.methods: must be a non-empty array/],
    [{ rules: [{ path: '/a', roles: ['admin'], when: 'x' }] }, /rules\[0\]\.when: unknown key/],
    [[], /access: must be an object/],
  ];
  for (const [block, re] of cases) {
    assert.throws(() => parseAccessRules(block), (e) => e instanceof AccessRulesError && re.test(e.message), JSON.stringify(block));
  }
  assert.equal(parseAccessRules(undefined), null);
  assert.deepEqual(parseAccessRules({ rules: [{ path: '/a', roles: ['admin'], methods: ['put'] }] }),
    [{ path: '/a', roles: ['admin'], methods: ['PUT'] }]);
});

// --- dashboard rules ------------------------------------------------------

const asUser = (who, path, init = {}) => fetch(`${BASE}${path}`, {
  ...init,
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer tok-${who}`, ...(init.headers || {}) },
});

test('dashboard rules take effect without a redeploy, alongside the manifest ones', async () => {
  assert.equal((await gate('member', 'GET', '/billing')).status, 200);
  const put = await asUser('owner', '/api/apps/gate-app/access-rules/production', {
    method: 'PUT', body: JSON.stringify({ rules: [{ path: '/billing/*', roles: ['admin'] }] }),
  });
  assert.equal(put.status, 200, await put.text());
  assert.equal((await gate('member', 'GET', '/billing/invoices')).status, 403);
  assert.equal((await gate('member', 'GET', '/admin')).status, 403, 'manifest rule still applies');
  assert.equal((await gate('admin', 'GET', '/billing')).status, 200);

  const list = await (await asUser('admin', '/api/apps/gate-app/access-rules')).json();
  assert.deepEqual(list.rules.production.dashboard, [{ path: '/billing/*', roles: ['admin'] }]);
  assert.equal(list.rules.production.manifest.length, 3);

  const clear = await asUser('admin', '/api/apps/gate-app/access-rules/production', { method: 'PUT', body: JSON.stringify({ rules: [] }) });
  assert.equal(clear.status, 200);
  assert.equal((await gate('member', 'GET', '/billing/invoices')).status, 200);
});

test('dashboard rules are per-app authorised', async () => {
  // member owns gate-other, which must not reach gate-app.
  const put = await asUser('member', '/api/apps/gate-app/access-rules/production', {
    method: 'PUT', body: JSON.stringify({ rules: [] }),
  });
  assert.equal(put.status, 403);
  assert.equal((await asUser('member', '/api/apps/gate-app/access-rules')).status, 403);
  assert.equal((await gate('member', 'GET', '/admin')).status, 403, 'a refused write changed nothing');
  const own = await asUser('member', '/api/apps/gate-other/access-rules/sandbox', {
    method: 'PUT', body: JSON.stringify({ rules: [{ path: '/x', roles: ['owner'] }] }),
  });
  assert.equal(own.status, 200, 'an owner edits their own app');
  const padminPut = await asUser('padmin', '/api/apps/gate-app/access-rules/sandbox', {
    method: 'PUT', body: JSON.stringify({ rules: [] }),
  });
  assert.equal(padminPut.status, 200, 'a platform admin may edit');
});

test('dashboard rules are validated', async () => {
  const bad = await asUser('owner', '/api/apps/gate-app/access-rules/production', {
    method: 'PUT', body: JSON.stringify({ rules: [{ path: '/x/../admin', roles: ['admin'] }] }),
  });
  assert.equal(bad.status, 400);
  assert.match((await bad.json()).error.message, /access\.rules\[0\]\.path/);
  const badEnv = await asUser('owner', '/api/apps/gate-app/access-rules/staging', { method: 'PUT', body: JSON.stringify({ rules: [] }) });
  assert.equal(badEnv.status, 400);
});
