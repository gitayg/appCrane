import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';
import Database from 'better-sqlite3';

// Platform policy — the two levers that let a platform admin constrain what
// every app owner on the box may do (v2.52.0).
//
// Everything here is driven through the REAL routes rather than by calling the
// service, because the thing being tested is not "does assertVisibilityAllowed
// throw" — it is "can a request reach the visibility column without passing
// it". A policy enforced on PUT and not on POST is not a policy, so both write
// paths are exercised, and both of the two fields that resolve to
// visibility='public' (`visibility` and the older `public_access`) are tried.
//
// Two properties matter as much as the refusal itself:
//   1. Defaults OFF. An upgrade that writes no settings rows must behave
//      exactly as before, so the same public write is proved to SUCCEED first.
//   2. Not retroactive. Turning the lever on refuses the next write and
//      REPORTS what is already public; it must not rewrite a row behind an
//      owner's back, because that breaks a live URL with no warning.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-policy-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const {
  POLICY_KEYS, getPolicy, setPolicy, assertVisibilityAllowed, policyViolations,
} = await import('../server/services/platformPolicy.js');

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, role };
}

const platformAdmin = mkUser('policyplatformadmin', 'platform_admin');
// The interesting near-miss: a tier-2 global admin passes requireAppAccess and
// isAdmin(), so only the platform_admin check itself keeps them off the lever.
const globalAdmin = mkUser('policyglobaladmin', 'admin');
const owner = mkUser('policyowner', 'user');

let nextSlot = 0;
function mkApp(slug, visibility = 'private') {
  const id = db.prepare(
    'INSERT INTO apps (name,slug,slot,source_type,visibility,public_access) VALUES (?,?,?,?,?,?)'
  ).run(slug, slug, ++nextSlot, 'managed', visibility, visibility === 'public' ? 1 : 0).lastInsertRowid;
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(id, owner.id);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')")
    .run(id, owner.id);
  return id;
}

const APP_PRIVATE = mkApp('pol-private');       // the app the ban must protect
const APP_LEGACY_PUBLIC = mkApp('pol-legacy-public', 'public'); // already public when the lever goes on
const APP_ACCESS = mkApp('pol-access');         // public_access route around the named field

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);

const server = await new Promise((resolve) => {
  const s = api.listen(0, () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;

// Same undici keep-alive trap as test/tcp-ingress-schema.test.js: server.close()
// waits on pooled sockets that never go away, and POST /api/apps schedules
// health-check intervals that hold the loop open on their own.
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function req(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': as.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json() };
}

const visOf = (id) => db.prepare('SELECT visibility, public_access FROM apps WHERE id = ?').get(id);
const setVis = (id, v) => db.prepare('UPDATE apps SET visibility = ?, public_access = ? WHERE id = ?')
  .run(v, v === 'public' ? 1 : 0, id);
const clearPolicy = () => db.prepare('DELETE FROM settings WHERE key IN (?, ?)')
  .run(POLICY_KEYS.banPublicApps, POLICY_KEYS.mandateScans);

// ---------------------------------------------------------------------------
// Defaults off — an upgrade that has never written a policy row changes nothing
// ---------------------------------------------------------------------------

test('both levers default to false with no settings rows at all', () => {
  clearPolicy();
  const rows = db.prepare('SELECT COUNT(*) AS n FROM settings WHERE key LIKE ?').get('policy_%').n;
  assert.equal(rows, 0, 'the test started with policy rows already written');
  assert.deepEqual(getPolicy(db), { ban_public_apps: false, mandate_security_scans: false });
});

test('with the lever off, assertVisibilityAllowed permits public', () => {
  clearPolicy();
  assert.doesNotThrow(() => assertVisibilityAllowed(db, 'public'));
});

test('with the lever off, an owner can still make an app public through PUT', async () => {
  clearPolicy();
  setVis(APP_PRIVATE, 'private');
  const r = await req(owner, 'PUT', '/api/apps/pol-private', { visibility: 'public' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(visOf(APP_PRIVATE), { visibility: 'public', public_access: 1 },
    'default-off must leave the pre-existing behaviour exactly as it was');
  setVis(APP_PRIVATE, 'private');
});

test('with the lever off, policyViolations reports nothing even though a public app exists', () => {
  clearPolicy();
  assert.equal(visOf(APP_LEGACY_PUBLIC).visibility, 'public');
  assert.deepEqual(policyViolations(db), [],
    'a lever that is off must report no violations — there is no policy to violate');
});

// ---------------------------------------------------------------------------
// ban_public_apps — the refusal, on BOTH write paths and BOTH fields
// ---------------------------------------------------------------------------

test('PUT visibility=public is refused, names the policy, and does not write the row', async () => {
  clearPolicy();
  setVis(APP_PRIVATE, 'private');
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  const r = await req(owner, 'PUT', '/api/apps/pol-private', { visibility: 'public' });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'POLICY_BAN_PUBLIC_APPS');
  assert.match(r.body.error.message, /ban_public_apps/,
    'the refusal must name the policy — an owner cannot read the settings table to find out why');
  assert.deepEqual(visOf(APP_PRIVATE), { visibility: 'private', public_access: 0 },
    'the refused request still wrote the column');
  clearPolicy();
});

test('public_access=true is refused too — it is the second door onto the same column', async () => {
  clearPolicy();
  setVis(APP_ACCESS, 'private');
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  const r = await req(owner, 'PUT', '/api/apps/pol-access', { public_access: true });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'POLICY_BAN_PUBLIC_APPS');
  assert.deepEqual(visOf(APP_ACCESS), { visibility: 'private', public_access: 0 },
    'the older public_access field walked straight past the ban');
  clearPolicy();
});

test('a platform admin is refused as well — this lever binds the whole platform', async () => {
  clearPolicy();
  setVis(APP_PRIVATE, 'private');
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  const r = await req(platformAdmin, 'PUT', '/api/apps/pol-private', { visibility: 'public' });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'POLICY_BAN_PUBLIC_APPS');
  clearPolicy();
});

test('non-public visibilities are untouched by the ban', async () => {
  clearPolicy();
  setVis(APP_PRIVATE, 'private');
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);
  for (const v of ['hidden', 'private']) {
    const r = await req(owner, 'PUT', '/api/apps/pol-private', { visibility: v });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(visOf(APP_PRIVATE).visibility, v);
  }
  setVis(APP_PRIVATE, 'private');
  clearPolicy();
});

test('POST /api/apps asking for a public app is refused and creates nothing', async () => {
  clearPolicy();
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  const r = await req(platformAdmin, 'POST', '/api/apps',
    { name: 'pol new public', slug: 'pol-new-public', visibility: 'public' });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'POLICY_BAN_PUBLIC_APPS');
  assert.match(r.body.error.message, /ban_public_apps/);
  assert.equal(db.prepare('SELECT id FROM apps WHERE slug = ?').get('pol-new-public'), undefined,
    'the app was created despite the refusal');
  clearPolicy();
});

test('POST /api/apps with public_access is refused on the same terms', async () => {
  clearPolicy();
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  const r = await req(platformAdmin, 'POST', '/api/apps',
    { name: 'pol new access', slug: 'pol-new-access', public_access: true });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'POLICY_BAN_PUBLIC_APPS');
  assert.equal(db.prepare('SELECT id FROM apps WHERE slug = ?').get('pol-new-access'), undefined);
  clearPolicy();
});

test('POST /api/apps that asks for nothing public still works under the ban', async () => {
  clearPolicy();
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  const r = await req(platformAdmin, 'POST', '/api/apps',
    { name: 'pol new quiet', slug: 'pol-new-quiet' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  const row = db.prepare('SELECT visibility FROM apps WHERE slug = ?').get('pol-new-quiet');
  assert.equal(row.visibility, 'private',
    'the ban must not change what an ordinary create does');
  clearPolicy();
});

test('POST with an unparseable visibility behaves exactly as it did before the policy', async () => {
  // This route never persisted visibility and never validated it. A lever that
  // is OFF must not turn that silent ignore into a 400.
  clearPolicy();
  const r = await req(platformAdmin, 'POST', '/api/apps',
    { name: 'pol new bogus', slug: 'pol-new-bogus', visibility: 'bogus' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(db.prepare('SELECT visibility FROM apps WHERE slug = ?').get('pol-new-bogus').visibility,
    'private');
});

// ---------------------------------------------------------------------------
// Not retroactive
// ---------------------------------------------------------------------------

test('turning the lever on leaves an already-public app public, and reports it', () => {
  clearPolicy();
  setVis(APP_LEGACY_PUBLIC, 'public');
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  assert.deepEqual(visOf(APP_LEGACY_PUBLIC), { visibility: 'public', public_access: 1 },
    'the policy rewrote a row behind the owner\'s back — that breaks a live URL with no warning');

  const v = policyViolations(db).filter(x => x.policy === 'ban_public_apps');
  const mine = v.find(x => x.app_id === APP_LEGACY_PUBLIC);
  assert.ok(mine, 'the app already in violation was not reported');
  assert.equal(mine.slug, 'pol-legacy-public');
  assert.match(mine.detail, /public/);
  clearPolicy();
});

test('an owner echoing back the value they were handed is not refused', async () => {
  clearPolicy();
  setVis(APP_LEGACY_PUBLIC, 'public');
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  // A read-modify-write client editing a description resends the whole app.
  // Refusing that would make the ban retroactive by the back door: the owner
  // could no longer touch any field on an app that was public before the lever.
  const r = await req(owner, 'PUT', '/api/apps/pol-legacy-public',
    { visibility: 'public', description: 'edited under the ban' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(visOf(APP_LEGACY_PUBLIC).visibility, 'public');
  clearPolicy();
});

test('converting an app OUT of public is allowed, and clears the violation', async () => {
  clearPolicy();
  setVis(APP_LEGACY_PUBLIC, 'public');
  setPolicy(db, { ban_public_apps: true }, platformAdmin.id);

  const r = await req(owner, 'PUT', '/api/apps/pol-legacy-public', { visibility: 'private' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(
    policyViolations(db).filter(x => x.policy === 'ban_public_apps' && x.app_id === APP_LEGACY_PUBLIC).length,
    0, 'the app was converted but is still reported as violating');
  setVis(APP_LEGACY_PUBLIC, 'public');
  clearPolicy();
});

// ---------------------------------------------------------------------------
// mandate_security_scans — reported, never enforced by refusal
// ---------------------------------------------------------------------------

const hasScanTable = !!db.prepare(
  "SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_vuln_scans'"
).get();

test('with the mandate on, an app with no scan at all is reported', { skip: !hasScanTable && 'app_vuln_scans not migrated yet' }, () => {
  clearPolicy();
  db.prepare('DELETE FROM app_vuln_scans').run();
  setPolicy(db, { mandate_security_scans: true }, platformAdmin.id);

  const v = policyViolations(db).filter(x => x.policy === 'mandate_security_scans');
  assert.ok(v.length >= 3, 'no unscanned app was reported');
  assert.ok(v.every(x => x.detail === 'never scanned successfully'));
  clearPolicy();
});

test('a fresh completed scan clears the app; a stale one does not', { skip: !hasScanTable && 'app_vuln_scans not migrated yet' }, () => {
  clearPolicy();
  db.prepare('DELETE FROM app_vuln_scans').run();
  const ins = db.prepare(`INSERT INTO app_vuln_scans (app_id, env, scanned_at, source, status)
    VALUES (?, 'production', datetime('now', ?), 'scheduled', ?)`);
  ins.run(APP_PRIVATE, '-1 hours', 'ok');
  ins.run(APP_LEGACY_PUBLIC, '-10 days', 'findings');
  setPolicy(db, { mandate_security_scans: true }, platformAdmin.id);

  const byApp = new Map(policyViolations(db)
    .filter(x => x.policy === 'mandate_security_scans').map(x => [x.app_id, x]));
  assert.equal(byApp.has(APP_PRIVATE), false, 'an app scanned an hour ago was reported as unscanned');
  assert.ok(byApp.has(APP_LEGACY_PUBLIC), 'a scan ten days old counted as recent');
  assert.match(byApp.get(APP_LEGACY_PUBLIC).detail, /older than/);
  db.prepare('DELETE FROM app_vuln_scans').run();
  clearPolicy();
});

test("a failed scan is not a scan — status 'error' does not satisfy the mandate", { skip: !hasScanTable && 'app_vuln_scans not migrated yet' }, () => {
  clearPolicy();
  db.prepare('DELETE FROM app_vuln_scans').run();
  // The whole point of the four-valued status: a reporting control that counts
  // "could not check" as "checked" reports a clean fleet loudest at the moment
  // it has stopped working.
  db.prepare(`INSERT INTO app_vuln_scans (app_id, env, scanned_at, source, status, error)
    VALUES (?, 'production', datetime('now'), 'scheduled', 'error', 'OSV unreachable')`).run(APP_PRIVATE);
  setPolicy(db, { mandate_security_scans: true }, platformAdmin.id);

  const mine = policyViolations(db)
    .find(x => x.policy === 'mandate_security_scans' && x.app_id === APP_PRIVATE);
  assert.ok(mine, "an 'error' row was counted as a successful scan");
  assert.equal(mine.detail, 'never scanned successfully');
  db.prepare('DELETE FROM app_vuln_scans').run();
  clearPolicy();
});

test('the mandate never refuses a write — it is report-only', async () => {
  clearPolicy();
  setVis(APP_PRIVATE, 'private');
  setPolicy(db, { mandate_security_scans: true }, platformAdmin.id);
  const r = await req(owner, 'PUT', '/api/apps/pol-private', { description: 'still writable' });
  assert.equal(r.status, 200, 'the scan mandate blocked a write — it must only report');
  clearPolicy();
});

test('policyViolations survives a database with no app_vuln_scans table', () => {
  // The lever can be turned on before the scanner migration reaches a box. A
  // missing table must not take the policy page down, and must not read as
  // "everything is scanned". Driven on a scratch database rather than by
  // dropping the real one, so this stays true whichever order the two features
  // land in.
  const scratch = new Database(':memory:');
  scratch.exec(`
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT, updated_by INTEGER);
    CREATE TABLE apps (id INTEGER PRIMARY KEY, slug TEXT, name TEXT,
                       visibility TEXT NOT NULL DEFAULT 'private', public_access INTEGER DEFAULT 0);
    INSERT INTO apps (id, slug, name) VALUES (1, 'scratch-app', 'scratch app');
  `);
  assert.equal(
    scratch.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_vuln_scans'").get(),
    undefined, 'the scratch database is meant to be missing the scans table');

  setPolicy(scratch, { mandate_security_scans: true }, null);
  const v = policyViolations(scratch);
  assert.equal(v.length, 1);
  assert.equal(v[0].policy, 'mandate_security_scans');
  assert.equal(v[0].detail, 'never scanned successfully',
    'a missing scans table reported as "scanned" — the silent all-clear this feature exists to prevent');
  scratch.close();
});

// ---------------------------------------------------------------------------
// The routes
// ---------------------------------------------------------------------------

test('GET /api/apps/platform-policy is platform-admin only', async () => {
  clearPolicy();
  for (const as of [globalAdmin, owner]) {
    const r = await req(as, 'GET', '/api/apps/platform-policy');
    assert.equal(r.status, 403, `${as.role} read the platform policy: ${JSON.stringify(r.body)}`);
  }
  const ok = await req(platformAdmin, 'GET', '/api/apps/platform-policy');
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.deepEqual(ok.body.policy, { ban_public_apps: false, mandate_security_scans: false });
  assert.ok(Array.isArray(ok.body.violations));
});

test('the policy route is not swallowed by GET /api/apps/:slug', async () => {
  // /:slug is registered in the same router and matches this path exactly. If
  // the ordering ever changes, a platform admin gets 404/403 from
  // requireAppAccess instead of the policy, which reads as "the feature is
  // gone" rather than "the routes are in the wrong order".
  const r = await req(platformAdmin, 'GET', '/api/apps/platform-policy');
  assert.equal(r.status, 200);
  assert.ok(r.body.policy, 'the app-detail route answered instead of the policy route');
  assert.equal(r.body.app, undefined);
});

test('PUT /api/apps/platform-policy is platform-admin only and does not write on refusal', async () => {
  clearPolicy();
  for (const as of [globalAdmin, owner]) {
    const r = await req(as, 'PUT', '/api/apps/platform-policy', { ban_public_apps: true });
    assert.equal(r.status, 403, `${as.role} changed the platform policy`);
  }
  assert.equal(getPolicy(db).ban_public_apps, false, 'a refused PUT still wrote the setting');
});

test('PUT flips a lever, records the change, and reports what now violates it', async () => {
  clearPolicy();
  setVis(APP_LEGACY_PUBLIC, 'public');
  const r = await req(platformAdmin, 'PUT', '/api/apps/platform-policy', { ban_public_apps: true });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.policy, { ban_public_apps: true, mandate_security_scans: false });
  assert.ok(r.body.violations.some(v => v.app_id === APP_LEGACY_PUBLIC),
    'the response must show the apps the switch did NOT convert');

  const audit = db.prepare(
    "SELECT detail FROM audit_log WHERE action = 'platform-policy-change' ORDER BY id DESC LIMIT 1").get();
  assert.ok(audit, 'flipping a platform-wide lever was not audited');
  const d = JSON.parse(audit.detail);
  assert.equal(d.from.ban_public_apps, false);
  assert.equal(d.to.ban_public_apps, true);
  clearPolicy();
});

test('PUT is a partial patch — an unnamed lever is left alone', async () => {
  clearPolicy();
  setPolicy(db, { mandate_security_scans: true }, platformAdmin.id);
  const r = await req(platformAdmin, 'PUT', '/api/apps/platform-policy', { ban_public_apps: true });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.policy, { ban_public_apps: true, mandate_security_scans: true },
    'setting one lever cleared the other');
  clearPolicy();
});

test('PUT with no recognised field is a 400, not a silent no-op', async () => {
  clearPolicy();
  const r = await req(platformAdmin, 'PUT', '/api/apps/platform-policy', { nonsense: true });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'VALIDATION');
});

test('a lever can be turned back off, and the refusal stops immediately', async () => {
  clearPolicy();
  setVis(APP_PRIVATE, 'private');
  await req(platformAdmin, 'PUT', '/api/apps/platform-policy', { ban_public_apps: true });
  const banned = await req(owner, 'PUT', '/api/apps/pol-private', { visibility: 'public' });
  assert.equal(banned.status, 403);

  await req(platformAdmin, 'PUT', '/api/apps/platform-policy', { ban_public_apps: false });
  const allowed = await req(owner, 'PUT', '/api/apps/pol-private', { visibility: 'public' });
  assert.equal(allowed.status, 200, JSON.stringify(allowed.body));
  assert.equal(visOf(APP_PRIVATE).visibility, 'public');
  setVis(APP_PRIVATE, 'private');
  clearPolicy();
});
