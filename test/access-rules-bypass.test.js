import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Path role rules vs. the bypass classes the 2026-10 security review found
// (F-004): a method override carried on a POST, framework path aliases of a
// protected path, and rules that only applied once the new release was
// already serving. Driven through /api/identity/verify the way Caddy's
// forward_auth calls it (its request clone carries the client's headers), plus
// the staging functions the deployer calls around the container swap.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-accessbypass-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const ar = await import('../server/services/accessRules.js');

const APP = db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility) VALUES ('Shop','shop-app',1,'managed','forward_auth','private')").run().lastInsertRowid;
const mkUser = (name, appRole) => {
  const id = db.prepare("INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,'user',1,?)").run(name, `${name}@acme.test`, hashApiKey(`key-${name}`)).lastInsertRowid;
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?,?, datetime('now','+1 day'))").run(id, hashApiKey(`tok-${name}`));
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, id, appRole);
};
mkUser('member', 'user');
mkUser('boss', 'admin');

ar.setRules(db, APP, 'production', 'manifest', ar.parseAccessRules({ rules: [
  { path: '/admin', roles: ['admin'] },
  { path: '/admin/*', roles: ['admin'] },
  { path: '/api/items/*', methods: ['DELETE'], roles: ['admin'] },
  { path: '/reports', roles: ['admin'] },
] }));

const api = express();
api.use(express.json());
api.use('/api/identity', (await import('../server/routes/identity.js')).default);
api.use((await import('../server/utils/errors.js')).errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
after(() => { server.closeAllConnections?.(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

async function gate(who, method, uri, extra = {}) {
  const r = await fetch(`${BASE}/api/identity/verify?app=shop-app&prefix=/shop-app`, {
    headers: { Cookie: `cc_token=tok-${who}`, Accept: 'application/json', 'X-Forwarded-Method': method, 'X-Forwarded-Uri': uri, 'X-Forwarded-Host': 'crane.test.local', ...extra },
    redirect: 'manual',
  });
  return r.status;
}

test('F-004 a method override cannot carry a member past a DELETE-only rule', async () => {
  assert.equal(await gate('member', 'DELETE', '/api/items/5'), 403, 'baseline: DELETE is refused');
  assert.equal(await gate('member', 'POST', '/api/items/5'), 200, 'baseline: a plain POST is allowed');
  const cases = [
    ['X-HTTP-Method-Override', { 'X-HTTP-Method-Override': 'DELETE' }, '/api/items/5'],
    ['X-HTTP-Method', { 'X-HTTP-Method': 'delete' }, '/api/items/5'],
    ['X-Method-Override', { 'X-Method-Override': 'DELETE' }, '/api/items/5'],
    ['header list', { 'X-HTTP-Method-Override': 'PUT, DELETE' }, '/api/items/5'],
    ['_method query', {}, '/api/items/5?_method=DELETE'],
    ['_method query, encoded', {}, '/api/items/5?x=1&%5Fmethod=delete'],
  ];
  for (const [label, headers, uri] of cases) {
    const st = await gate('member', 'POST', uri, headers);
    console.log(`# POST ${uri} ${JSON.stringify(headers)} -> ${st}`);
    assert.equal(st, 403, label);
  }
  assert.equal(await gate('boss', 'POST', '/api/items/5', { 'X-HTTP-Method-Override': 'DELETE' }), 200, 'the role the rule asks for still passes');
  assert.equal(await gate('member', 'POST', '/api/items/5', { 'X-HTTP-Method-Override': 'PATCH' }), 200, 'an override to a method no rule restricts stays allowed');
});

test('F-004 framework aliases of a protected path are refused to a member', async () => {
  const aliases = [
    '/admin.json', '/admin.html', '/ADMIN.JSON', '/admin/', '/admin.json?x=1', '/reports.csv',
    '/_next/data/build-123/admin.json', '/_next/data/build-123/admin/index.json', '/_next/data/b/admin/users.json',
    '/admin/__data.json', '/reports/__data.json', '/reports/_payload.json', '/admin/users.json',
  ];
  for (const uri of aliases) {
    const st = await gate('member', 'GET', uri);
    console.log(`# GET ${uri} -> ${st}`);
    assert.equal(st, 403, uri);
  }
  for (const uri of ['/administrator', '/adminx.json', '/shop', '/_next/data/b/index.json', '/_next/static/chunks/admin.js', '/reportsx']) {
    assert.equal(await gate('member', 'GET', uri), 200, `${uri} is not an alias of a protected path`);
  }
  assert.equal(await gate('boss', 'GET', '/_next/data/b/admin.json'), 200);
});

test('F-004 rules before the swap: the union is enforced while the new release starts, then exactly the new set; a failed deploy reverts', () => {
  const env = 'sandbox';
  ar.storeManifestRules(APP, env, [{ path: '/old-admin', roles: ['admin'] }]);
  const next = [{ path: '/new-admin', roles: ['admin'] }];
  const decide = (uri) => ar.decideAccess(ar.effectiveRules(db, APP, env), { method: 'GET', uri, appRole: 'user' }).ok;
  assert.equal(decide('/new-admin'), true, 'baseline: before staging the new route is open');

  const staged = ar.stageManifestRules(APP, env, next);
  assert.equal(decide('/new-admin'), false, 'the new release\'s rule must hold from its first request');
  assert.equal(decide('/old-admin'), false, 'the old rule must not lapse early');

  ar.storeManifestRules(APP, env, next);
  assert.deepEqual(ar.getRules(db, APP, env, 'manifest').rules, next, 'after go-live: exactly the new release\'s rules');

  ar.storeManifestRules(APP, env, [{ path: '/old-admin', roles: ['admin'] }]);
  const s2 = ar.stageManifestRules(APP, env, next);
  ar.revertStagedManifestRules(s2);
  assert.deepEqual(ar.getRules(db, APP, env, 'manifest').rules, [{ path: '/old-admin', roles: ['admin'] }], 'a failed deploy restores the previous rules exactly');
  assert.equal(decide('/new-admin'), true);

  ar.storeManifestRules(APP, env, []);
  const s3 = ar.stageManifestRules(APP, env, next);
  assert.equal(decide('/new-admin'), false, 'first rules on an app with none are staged too');
  ar.revertStagedManifestRules(s3);
  assert.equal(ar.getRules(db, APP, env, 'manifest'), null);
  assert.ok(staged);
});
