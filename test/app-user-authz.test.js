import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// requireAppUser: assignment is authoritative for every role (v2.39.0).
//
// This gate covers the app's own data and secrets — env vars (including the
// ?reveal=true plaintext dump), backup/restore/copy-data, health config,
// notifications and webhooks — as distinct from platform administration.
//
// platform_admin used to return early with no assignment check at all. Combined
// with the session cookie reaching app containers, one lifted admin session read
// the DECRYPTED env vars of every app on the box. It also contradicted the rule
// envVars.js states at the top of its own file: "assigned app users only —
// admins are explicitly NOT granted access to env-var values".
//
// Second bug fixed here: the `admin` branch used to sit BEFORE the assignment
// lookup, so an admin who did exactly what the error message said — assign
// themselves — remained blocked. The advice was unreachable.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-authz-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const appId = db.prepare(
  'INSERT INTO apps (name,slug,slot,source_type,auth_mode,branch) VALUES (?,?,?,?,?,?)'
).run('Secrets', 'secrets', 1, 'managed', 'forward_auth', 'main').lastInsertRowid;

let seq = 0;
function mkUser(role) {
  const n = ++seq;
  return db.prepare(
    'INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)'
  ).run(`u${n}`, `u${n}@t.test`, role, `hash${n}`).lastInsertRowid;
}
const assign = (uid) =>
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, uid);

const { requireAppUser } = await import('../server/middleware/auth.js');

/** Run the middleware and report what it did: 'allowed' or the error code. */
function attempt(userId, role) {
  const req = { params: { slug: 'secrets' }, user: { id: userId, role } };
  let outcome = null;
  requireAppUser(req, {}, (err) => { outcome = err ? (err.code || err.message) : 'allowed'; });
  return outcome;
}

test('an UNASSIGNED platform_admin is blocked from app data and secrets', () => {
  // The regression that matters: this returned 'allowed' before v2.39.0, which
  // is what turned a lifted admin session into every app's plaintext env vars.
  const uid = mkUser('platform_admin');
  assert.equal(attempt(uid, 'platform_admin'), 'ADMIN_BLOCKED');
});

test('an ASSIGNED platform_admin is allowed — the guardrail is not a lockout', () => {
  // Access stays reachable, but only by an explicit, admin-gated, auditable
  // membership change rather than silently by virtue of the role.
  const uid = mkUser('platform_admin');
  assign(uid);
  assert.equal(attempt(uid, 'platform_admin'), 'allowed');
});

test('an UNASSIGNED admin is blocked', () => {
  const uid = mkUser('admin');
  assert.equal(attempt(uid, 'admin'), 'ADMIN_BLOCKED');
});

test("an ASSIGNED admin is allowed — the error's own advice now works", () => {
  // Pre-v2.39.0 the admin branch preceded the assignment lookup, so this
  // returned ADMIN_BLOCKED and the message telling them to self-assign was a
  // dead end. Assignment is checked first now, so following the advice works.
  const uid = mkUser('admin');
  assign(uid);
  assert.equal(attempt(uid, 'admin'), 'allowed');
});

test('an unassigned ordinary user is refused, and told so plainly', () => {
  const uid = mkUser('user');
  assert.equal(attempt(uid, 'user'), 'FORBIDDEN');
});

test('an assigned ordinary user is allowed', () => {
  const uid = mkUser('user');
  assign(uid);
  assert.equal(attempt(uid, 'user'), 'allowed');
});

test('no role short-circuits ahead of the assignment lookup', () => {
  // Guards the SHAPE of the fix, not just its outcomes. If someone reinstates an
  // early `if (role === 'platform_admin') return next()`, the outcome tests above
  // still catch it — but this states the invariant directly: every role reaches
  // the same app_users query, and only membership decides.
  const src = requireAppUser.toString();
  const lookup = src.indexOf('app_users');
  const roleChecks = [...src.matchAll(/role === '(admin|platform_admin)'/g)].map(m => m.index);
  assert.ok(lookup > 0, 'requireAppUser no longer queries app_users');
  for (const idx of roleChecks) {
    assert.ok(idx > lookup,
      'a role check runs BEFORE the assignment lookup — an assigned user of that ' +
      'role would be blocked, and the "assign yourself" advice becomes unreachable');
  }
});

test('an unknown app still 404s rather than leaking through the gate', () => {
  const uid = mkUser('platform_admin');
  const req = { params: { slug: 'does-not-exist' }, user: { id: uid, role: 'platform_admin' } };
  let code = null;
  requireAppUser(req, {}, (err) => { code = err?.code ?? 'allowed'; });
  assert.equal(code, 'NOT_FOUND');
});
