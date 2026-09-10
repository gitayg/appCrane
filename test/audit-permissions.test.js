import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Runtime logs and the audit trail behind the RBAC matrix (v2.66.0).
//
// Before this, all three routes in server/routes/logs.js were gated by
// requireAppAccess (per-app) or requireAdmin (platform-wide). requireAppAccess
// is satisfied by ANY assignment — a plain 'user' with no role row included —
// and container logs are unredacted application output: bearer tokens, e-mail
// addresses, request paths. So "assigned to the app" was the wrong bar for
// logs, and only barely the right one for audit.
//
// Everything below goes over a real socket into the REAL router with real API
// keys, because the properties at issue are properties of the wiring:
//
//   1. THE MATRIX HAS NO DEFAULTS FALLBACK. userHasAppPermission() ends in
//      `row?.granted === 1` against role_permissions — there is no read of the
//      DEFAULTS map in resetToDefaults(). A permission key declared only in
//      permissions.js therefore denies EVERY per-app tier, so migration
//      087 is not bookkeeping: without its rows an upgrade silently takes logs
//      and audit away from every app owner who has them today. That is asserted
//      twice here — once directly against role_permissions, and once through
//      the owner's 200s, which are what an operator would actually notice.
//
//   2. THE SPLIT IS THE POINT. A per-app admin gets the audit trail and NOT the
//      logs. A test that only checked "owner yes, user no" would pass with both
//      keys wired to the same default and lose the distinction that was asked
//      for.
//
//   3. /api/audit IS SCOPED IN SQL, NOT IN JS. It paginates. Filtering a
//      fetched page in JS gives a `total` that counts rows the caller may not
//      read and offers pages that come back short or empty. So the assertions
//      are over `total` and `by_actor` as well as `entries`.
//
//   4. NULL app_id IS PLATFORM-LEVEL. Sign-ins, user management, settings
//      changes. `app_id IN (subquery)` is NULL for those rows — not true — so
//      they drop out for a non-admin without a special case. Asserted, because
//      a later rewrite to `OR al.app_id IS NULL` would leak the lot.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-auditperm-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

// A `docker` that always has logs, so "the owner can read logs" asserts over
// real content instead of over the empty array getAppLogs() returns when the
// daemon is absent — and so this test never touches a developer's real
// containers or waits on a real daemon.
const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(
  join(SHIM_DIR, 'docker'),
  '#!/bin/sh\nprintf \'%s\\n\' "GET /health 200" "token=SECRET-abc user=someone@example.com"\n',
  { mode: 0o755 },
);
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, name };
}

let slot = 9000;
function mkApp(slug) {
  return db.prepare(
    'INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)'
  ).run(slug, slug, ++slot).lastInsertRowid;
}

function assign(appId, user, appRole) {
  db.prepare('INSERT OR IGNORE INTO app_users (app_id, user_id) VALUES (?, ?)').run(appId, user.id);
  if (appRole) {
    db.prepare(
      'INSERT OR REPLACE INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)'
    ).run(appId, user.id, appRole);
  }
}

const platformAdmin = mkUser('apadmin', 'platform_admin');
const owner = mkUser('apowner', 'user');
const appAdmin = mkUser('apappadmin', 'user');
const plainUser = mkUser('apuser', 'user');
const outsider = mkUser('apoutsider', 'user');

// APP_A: everyone above except the outsider is on it, at three different tiers.
// APP_B: the owner is nowhere near it — it is what proves /api/audit scopes.
const APP_A = 'auditperm-a';
const APP_B = 'auditperm-b';
const appAId = mkApp(APP_A);
const appBId = mkApp(APP_B);

assign(appAId, owner, 'owner');
assign(appAId, appAdmin, 'admin');
assign(appAId, plainUser, null);          // bare membership — roleForUserOnApp → 'user'
assign(appBId, outsider, 'owner');

db.prepare('INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?,?,?,?)')
  .run(owner.id, appAId, 'deploy-production', 'app A deploy');
db.prepare('INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?,?,?,?)')
  .run(owner.id, appAId, 'env-write', 'app A env');
db.prepare('INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?,?,?,?)')
  .run(outsider.id, appBId, 'deploy-production', 'app B deploy');
// Platform-level: no app_id. Admins only, forever.
db.prepare('INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?,?,?,?)')
  .run(platformAdmin.id, null, 'user-create', 'PLATFORM-ONLY-ROW');

const logsRoutes = (await import('../server/routes/logs.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
// The one and only mount in server/index.js is `app.use('/api', logsRoutes)`,
// so the per-app paths are /api/:slug/... — NOT /api/apps/:slug/... Mounting it
// anywhere else here would test a URL space that does not exist.
api.use('/api', logsRoutes);
api.use(errorHandler);

const server = await new Promise((resolve) => {
  const s = api.listen(0, '127.0.0.1', () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;

after(() => {
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function get(as, path) {
  const res = await fetch(`${BASE}${path}`, { headers: { 'X-API-Key': as.key } });
  return { status: res.status, body: await res.json() };
}

const logsPath = (slug) => `/api/${slug}/logs/production`;
const auditPath = (slug) => `/api/${slug}/audit`;

// ---------------------------------------------------------------------------
// The migration — the row that everything else stands on
// ---------------------------------------------------------------------------

test('migration 087 seeded both keys for all four role tiers', () => {
  const rows = db.prepare(
    "SELECT permission, role, granted FROM role_permissions "
    + "WHERE permission IN ('app.logs.view','app.audit.view') ORDER BY permission, role"
  ).all();

  // userHasAppPermission() is `row?.granted === 1` with NO fallback to the
  // DEFAULTS map, so a MISSING row and an explicit 0 are the same answer —
  // deny. All eight must physically exist.
  assert.deepEqual(rows, [
    { permission: 'app.audit.view', role: 'admin',          granted: 1 },
    { permission: 'app.audit.view', role: 'owner',          granted: 1 },
    { permission: 'app.audit.view', role: 'platform_admin', granted: 1 },
    { permission: 'app.audit.view', role: 'user',           granted: 0 },
    { permission: 'app.logs.view',  role: 'admin',          granted: 0 },
    { permission: 'app.logs.view',  role: 'owner',          granted: 1 },
    { permission: 'app.logs.view',  role: 'platform_admin', granted: 1 },
    { permission: 'app.logs.view',  role: 'user',           granted: 0 },
  ]);
});

// ---------------------------------------------------------------------------
// Per-app: logs
// ---------------------------------------------------------------------------

test('an app owner reads runtime logs', async () => {
  const r = await get(owner, logsPath(APP_A));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.logs.some(l => l.includes('GET /health 200')),
    'a 200 with an empty array would pass a status-only assertion while the owner saw nothing');
});

test('a plain assigned user is refused runtime logs', async () => {
  const r = await get(plainUser, logsPath(APP_A));
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'FORBIDDEN');
  assert.doesNotMatch(JSON.stringify(r.body), /SECRET-abc|someone@example\.com/,
    'the refusal must not carry the log content it is refusing');
});

test('a per-app admin is refused runtime logs — the split that was asked for', async () => {
  const r = await get(appAdmin, logsPath(APP_A));
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.match(r.body.error.message, /runtime logs/i,
    'the message has to name what was refused; "Forbidden" sends the reader to the wrong setting');
});

test('a platform admin reads runtime logs', async () => {
  const r = await get(platformAdmin, logsPath(APP_A));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.logs.some(l => l.includes('GET /health 200')));
});

test('someone not on the app at all still gets the membership 403, not a permission 403', async () => {
  const r = await get(outsider, logsPath(APP_A));
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.match(r.body.error.message, /not assigned/i,
    'requireAppAccess must still run first — the permission check is on top of membership, not instead of it');
});

// ---------------------------------------------------------------------------
// Per-app: audit
// ---------------------------------------------------------------------------

test('an app owner reads the per-app audit trail', async () => {
  const r = await get(owner, auditPath(APP_A));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.entries.length, 2);
});

test('a per-app admin reads the per-app audit trail', async () => {
  const r = await get(appAdmin, auditPath(APP_A));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.entries.length, 2,
    'admin gets audit and not logs — if this is a 403 the two keys have been wired to the same default');
});

test('a plain assigned user is refused the per-app audit trail', async () => {
  const r = await get(plainUser, auditPath(APP_A));
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'FORBIDDEN');
  assert.doesNotMatch(JSON.stringify(r.body), /app A deploy/);
});

test('a platform admin reads the per-app audit trail', async () => {
  const r = await get(platformAdmin, auditPath(APP_A));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.entries.length, 2);
});

// ---------------------------------------------------------------------------
// Platform-wide /api/audit — permission-scoped, in SQL
// ---------------------------------------------------------------------------

test('an admin sees every entry on /api/audit, including the platform-level one', async () => {
  const r = await get(platformAdmin, '/api/audit');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.total, 4);
  assert.ok(r.body.entries.some(e => e.detail === 'PLATFORM-ONLY-ROW'));
  assert.ok(r.body.entries.some(e => e.detail === 'app B deploy'));
});

test('/api/audit is no longer admin-only — an owner gets a 200, not a 403', async () => {
  const r = await get(owner, '/api/audit');
  assert.equal(r.status, 200, JSON.stringify(r.body));
});

test('a non-admin sees only entries for the apps they may audit', async () => {
  const r = await get(owner, '/api/audit');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.entries.map(e => e.detail).sort(), ['app A deploy', 'app A env']);
  assert.equal(r.body.total, 2,
    '`total` drives the pager — counting rows the caller cannot read offers pages that come back empty');
});

test('a NULL app_id entry never reaches a non-admin', async () => {
  for (const who of [owner, appAdmin, plainUser, outsider]) {
    const r = await get(who, '/api/audit');
    assert.equal(r.status, 200, `${who.name}: ${JSON.stringify(r.body)}`);
    assert.doesNotMatch(JSON.stringify(r.body.entries), /PLATFORM-ONLY-ROW/,
      `${who.name} was shown a platform-level audit row`);
  }
});

test('a per-app admin is scoped the same way — they hold app.audit.view on app A only', async () => {
  const r = await get(appAdmin, '/api/audit');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.entries.map(e => e.detail).sort(), ['app A deploy', 'app A env']);
});

test('a plain user holds app.audit.view nowhere, so /api/audit is empty rather than forbidden', async () => {
  const r = await get(plainUser, '/api/audit');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.entries, []);
  assert.equal(r.body.total, 0);
});

test("the outsider sees their own app's entries and nothing from app A", async () => {
  const r = await get(outsider, '/api/audit');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.entries.map(e => e.detail), ['app B deploy']);
});

test('by_actor is scoped too — an unscoped breakdown is a count of unreadable rows', async () => {
  const mine = await get(owner, '/api/audit');
  const total = mine.body.by_actor.reduce((n, r) => n + r.n, 0);
  assert.equal(total, 2, `by_actor summed to ${total}; the caller may read 2 rows`);

  const all = await get(platformAdmin, '/api/audit');
  assert.equal(all.body.by_actor.reduce((n, r) => n + r.n, 0), 4);
});

test('the ?app= filter narrows within the scope and cannot escape it', async () => {
  const r = await get(owner, `/api/audit?app=${APP_B}`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.entries, [],
    'naming an app you cannot audit must return nothing, not that app\'s trail');
  assert.equal(r.body.total, 0);
});

test('an anonymous caller gets 401, not an unscoped page', async () => {
  const res = await fetch(`${BASE}/api/audit`);
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------------------
// resetToDefaults — LAST on purpose
// ---------------------------------------------------------------------------
//
// This test WRITES to role_permissions. Run earlier, it re-seeds the very rows
// migration 087 is supposed to have written, and every route assertion above
// would then pass on a build whose migration seeds nothing — which is exactly
// the silent lockout this file exists to catch. Measured: with this test second
// in the file, deleting the migration's INSERT reddened one assertion instead
// of eight.

test('the two keys are declared in PERMISSIONS, so the Settings matrix can render them', async () => {
  const { PERMISSIONS, resetToDefaults } = await import('../server/services/permissions.js');
  const keys = PERMISSIONS.map(p => p.key);
  assert.ok(keys.includes('app.logs.view'), 'a key checked by a route but absent here throws on check');
  assert.ok(keys.includes('app.audit.view'));

  // resetToDefaults() must agree with the migration, or "Reset to defaults" in
  // the UI silently rewrites the grants to something else.
  //
  // PERTURB FIRST. Measured: without this, dropping a key from the DEFAULTS map
  // makes resetToDefaults() skip it entirely — the migration's rows survive
  // untouched and the assertion below passes on a build where "Reset to
  // defaults" is a no-op for that permission.
  const { setMatrix } = await import('../server/services/permissions.js');
  setMatrix({
    'app.logs.view':  { user: 1, admin: 1, owner: 0, platform_admin: 0 },
    'app.audit.view': { user: 1, admin: 0, owner: 0, platform_admin: 0 },
  });
  resetToDefaults(['app.logs.view', 'app.audit.view']);
  const after = db.prepare(
    "SELECT permission, role, granted FROM role_permissions "
    + "WHERE permission IN ('app.logs.view','app.audit.view') ORDER BY permission, role"
  ).all();
  assert.deepEqual(after.map(r => `${r.permission}:${r.role}=${r.granted}`), [
    'app.audit.view:admin=1', 'app.audit.view:owner=1',
    'app.audit.view:platform_admin=1', 'app.audit.view:user=0',
    'app.logs.view:admin=0', 'app.logs.view:owner=1',
    'app.logs.view:platform_admin=1', 'app.logs.view:user=0',
  ]);
});
