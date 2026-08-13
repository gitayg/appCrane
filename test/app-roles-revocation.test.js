import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// App-defined roles, revocation side (v2.41.0).
//
// A grant is only meaningful while its holder can still enter the app. AppCrane
// is the authority and the hosted app is the enforcer, so a grant AppCrane
// believes it took away but keeps putting on the wire is not a stale row — it is
// a live in-app privilege surviving revocation, and the app has no way to know.
//
// Revocation is spread across three call sites (the Users modal's replace-all,
// the per-user tier route, the MCP revoke tool) and none of them originally
// touched app_role_grants. These tests pin both halves of the fix: every revoke
// path clears the grants, AND the read that feeds the wire refuses a grant whose
// holder is not a member — so a fourth revoke path added later cannot reopen it
// by forgetting one line.
//
// The public-app case is the sharp one. resolveAppRole falls back to 'viewer'
// rather than denying, so /verify returns 200 for a removed person and only the
// membership condition stands between them and the roles they used to hold.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-revoke-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkApp = (name, slug, slot, visibility) => {
  const id = db.prepare(
    `INSERT INTO apps (name,slug,slot,source_type,auth_mode,visibility)
     VALUES (?,?,?,'managed','forward_auth',?)`
  ).run(name, slug, slot, visibility).lastInsertRowid;
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?,'production','live')").run(id);
  return id;
};

const PRIV = mkApp('Priv', 'rv-priv', 1, 'private');
const PUB  = mkApp('Pub',  'rv-pub',  2, 'public');

let seq = 0;
function mkUser(craneRole) {
  const n = ++seq;
  const key = generateApiKey('dhk_user');
  const uid = db.prepare(
    'INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)'
  ).run(`rv${n}`, `rv${n}@t.test`, craneRole, hashApiKey(key)).lastInsertRowid;
  return { uid, key };
}

const seat = (appId, uid, tier) => {
  db.prepare('INSERT OR IGNORE INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, uid);
  db.prepare(`INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)
              ON CONFLICT(app_id,user_id) DO UPDATE SET app_role = excluded.app_role`).run(appId, uid, tier);
};

const OWNER  = mkUser('user');
const VICTIM = mkUser('user');
seat(PRIV, OWNER.uid, 'owner');
seat(PUB,  OWNER.uid, 'owner');
seat(PRIV, VICTIM.uid, 'user');
seat(PUB,  VICTIM.uid, 'user');

const svc = await import('../server/services/appDefinedRoles.js');
for (const appId of [PRIV, PUB]) {
  svc.createRole(appId, { key: 'approver', label: 'Approver' }, OWNER.uid);
  svc.createRole(appId, { key: 'auditor', label: 'Auditor' }, OWNER.uid);
}

const appRolesRouter = (await import('../server/routes/appRoles.js')).default;
const usersRouter    = (await import('../server/routes/users.js')).default;
const appsRouter     = (await import('../server/routes/apps.js')).default;
const identityRouter = (await import('../server/routes/identity.js')).default;
const meRouter       = (await import('../server/routes/me.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appRolesRouter);
api.use('/api/apps', appsRouter);
api.use('/api/apps', usersRouter);
api.use('/api/identity', identityRouter);
api.use('/api', meRouter);
api.use(errorHandler);

const server = await new Promise(r => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const PORT = server.address().port;
const { after } = await import('node:test');
after(() => server.close());

const call = async (who, method, path, body) => {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method,
    headers: { 'X-API-Key': who.key, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: 'manual',
  });
  let json = null;
  try { json = await res.json(); } catch (_) { /* redirect / empty body */ }
  return { status: res.status, body: json, headers: res.headers };
};

const grant = (slug, keys) =>
  call(OWNER, 'PUT', `/api/apps/${slug}/app-roles/members/${VICTIM.uid}`, { keys });
const headerFor = slug =>
  call(VICTIM, 'GET', `/api/identity/verify?app=${slug}`).then(r => r.headers.get('x-appcrane-app-roles'));
const grantRows = () =>
  db.prepare('SELECT COUNT(*) n FROM app_role_grants WHERE user_id = ?').get(VICTIM.uid).n;

// ---------------------------------------------------------------- baseline

test('the fixture actually issues the header before anything is revoked', async () => {
  // Every assertion below is an ABSENCE. Without this, a typo in the fixture
  // would make the whole file pass by never granting anything at all.
  const r = await grant('rv-pub', ['auditor', 'approver']);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.app_roles, ['approver', 'auditor']);
  assert.equal(await headerFor('rv-pub'), 'approver,auditor');
});

// ------------------------------------------------- every revoke path clears

test('PUT /:slug/users (replace the member list) drops the roles of whoever is missing', async () => {
  // The Users modal's save. It replaces app_users wholesale, so the people who
  // lost access are not named anywhere — they are whoever fell off the list.
  assert.equal(grantRows(), 2, 'fixture premise broken');

  const r = await call(OWNER, 'PUT', '/api/apps/rv-pub/users', { user_ids: [OWNER.uid] });
  assert.equal(r.status, 200, JSON.stringify(r.body));

  assert.equal(grantRows(), 0, 'the removed member kept their app_role_grants rows');
  assert.equal(await headerFor('rv-pub'), null,
    'a removed member is still being issued X-AppCrane-App-Roles — on a public app ' +
    'resolveAppRole falls back to viewer, so /verify never denies them');
});

test('re-adding the member does not silently restore roles nobody re-granted', async () => {
  const r = await call(OWNER, 'PUT', '/api/apps/rv-pub/users', { user_ids: [OWNER.uid, VICTIM.uid] });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(await headerFor('rv-pub'), null,
    'restoring access restored the app-defined roles too — a grant must be issued ' +
    'deliberately, and re-adding someone is not a grant');
});

test('PUT /:slug/roles {app_role:"none"} clears them too', async () => {
  seat(PUB, VICTIM.uid, 'user');
  await grant('rv-pub', ['approver']);
  assert.equal(await headerFor('rv-pub'), 'approver', 'fixture premise broken');

  const r = await call(OWNER, 'PUT', '/api/apps/rv-pub/roles', { user_id: VICTIM.uid, app_role: 'none' });
  assert.equal(r.status, 200, JSON.stringify(r.body));

  assert.equal(grantRows(), 0,
    "'none' is how this route removes someone, so it must drop their app-defined roles");
  assert.equal(await headerFor('rv-pub'), null);
});

test('the MCP revoke tool clears them as well', async () => {
  seat(PUB, VICTIM.uid, 'user');
  await grant('rv-pub', ['approver', 'auditor']);
  assert.equal(grantRows(), 2, 'fixture premise broken');

  const { callTool } = await import('../server/services/mcpTools.js');
  const owner = db.prepare('SELECT * FROM users WHERE id = ?').get(OWNER.uid);
  const res = await callTool(owner, 'appcrane_revoke_app_access', { slug: 'rv-pub', user: String(VICTIM.uid) });
  const out = JSON.parse(res.content[0].text);

  assert.equal(out.removed.app_defined_roles, 2,
    'the revoke tool does not report clearing the app-defined roles');
  assert.equal(grantRows(), 0);
  assert.equal(await headerFor('rv-pub'), null);
});

// ------------------------------------------- the read itself requires membership

test('a grant whose holder is not a member is inert on every surface', async () => {
  // Defence in depth for the same rule, at the one read both surfaces share.
  // Written straight to the tables, bypassing the API — which is exactly the
  // shape a future revoke path that forgets one DELETE would leave behind.
  seat(PRIV, VICTIM.uid, 'user');
  await grant('rv-priv', ['approver']);
  assert.equal(await headerFor('rv-priv'), 'approver', 'fixture premise broken');

  db.prepare('DELETE FROM app_users WHERE app_id = ? AND user_id = ?').run(PRIV, VICTIM.uid);
  assert.ok(grantRows() > 0, 'test premise broken: the orphan grant is gone already');

  assert.deepEqual(svc.roleKeysForUser(PRIV, VICTIM.uid), [],
    'roleKeysForUser honours a grant whose holder was removed from the app');
  assert.equal(await headerFor('rv-priv'), null);

  db.prepare('DELETE FROM app_role_grants WHERE user_id = ?').run(VICTIM.uid);
  seat(PRIV, VICTIM.uid, 'user');
});

test('an orphan grant is not counted as a holder', async () => {
  // The delete confirmation exists to state how many people lose the role, and
  // the roster is drawn from app_users. If the count came off the grant rows
  // instead, the two would disagree and the operator would be shown a number
  // nobody on screen accounts for.
  await grant('rv-priv', ['approver']);
  db.prepare('DELETE FROM app_users WHERE app_id = ? AND user_id = ?').run(PRIV, VICTIM.uid);

  const roles = (await call(OWNER, 'GET', '/api/apps/rv-priv/app-roles')).body.roles;
  const approver = roles.find(r => r.key === 'approver');
  assert.equal(approver.member_count, 0,
    'member_count counts grant rows rather than members, so it over-reports holders ' +
    'the Members panel cannot show');

  const members = (await call(OWNER, 'GET', '/api/apps/rv-priv/app-roles/members')).body.members;
  assert.equal(members.filter(m => m.app_roles.includes('approver')).length, approver.member_count,
    'the roster and the count disagree about who holds the role');

  db.prepare('DELETE FROM app_role_grants WHERE user_id = ?').run(VICTIM.uid);
  seat(PRIV, VICTIM.uid, 'user');
});

// -------------------------------------------- /api/me agrees with the header

test('/api/me withholds app_roles from someone the platform denies', async () => {
  // The two surfaces are one wire contract and apps are told they may read
  // either, so a person AppCrane denies must not learn their old keys by
  // picking the other one. identity.js emits the header only after its
  // appRole === 'none' denial; /api/me has to gate at the same point.
  await grant('rv-priv', ['approver', 'auditor']);
  const before = await call(VICTIM, 'GET', '/api/me?app=rv-priv');
  assert.deepEqual(before.body.app_roles, ['approver', 'auditor'], 'fixture premise broken');

  const r = await call(OWNER, 'PUT', '/api/apps/rv-priv/roles', { user_id: VICTIM.uid, app_role: 'none' });
  assert.equal(r.status, 200, JSON.stringify(r.body));

  const me = await call(VICTIM, 'GET', '/api/me?app=rv-priv');
  assert.equal(me.body.app_role, 'none', 'test premise broken: the tier was not revoked');
  assert.deepEqual(me.body.app_roles, [],
    '/api/me hands a denied user the roles they used to hold, while /verify correctly ' +
    'withholds them — an app following the documented browser pattern would keep trusting them');

  const v = await call(VICTIM, 'GET', '/api/identity/verify?app=rv-priv');
  assert.ok(v.status === 403 || v.status === 302, `expected /verify to deny, got ${v.status}`);
  assert.equal(v.headers.get('x-appcrane-app-roles'), null);
});
