import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// 'none' must REMOVE access, not grant it (v2.42.1).
//
// PUT /api/apps/:slug/roles with app_role='none' — how the admin UI removes
// someone — used to write a 'none' row AND insert an app_users membership row.
// requireAppUser checks app_users, so the "removed" person gained access they
// had never had: GET /:slug/env/:env?reveal=true returns DECRYPTED production
// secrets, and backup/restore/copy-data open up with it.
//
// What made it survive is that every human-visible signal disagreed with the one
// path that mattered. The dashboard showed 'none'. /api/me reported 'none'.
// Caddy's forward_auth denied them at /<slug>, because resolveAppRole reads
// app_user_roles and correctly refuses 'none'. Only requireAppUser — reading
// app_users — said yes, and that is the gate in front of the plaintext.
//
// So the invariant worth pinning is not one endpoint's status code: it is that
// the checks AGREE. They cannot disagree about a row that does not exist, which
// is why 'none' now deletes from both tables instead of writing to either.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-none-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const mkUser = (name, role) => db.prepare(
  'INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)'
).run(name, `${name}@t.test`, role, `hash-${name}`).lastInsertRowid;

const OWNER = mkUser('owner', 'user');
const TARGET = mkUser('target', 'user');

const APP = db.prepare(
  "INSERT INTO apps (name,slug,slot,source_type,auth_mode,branch) VALUES (?,?,?,'managed','forward_auth','main')"
).run('Legal', 'legal', 1).lastInsertRowid;

db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(APP, OWNER);
db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(APP, OWNER, 'owner');

const { roleForUserOnApp } = await import('../server/services/permissions.js');
const { requireAppUser, requireAppAccess } = await import('../server/middleware/auth.js');

/** Run a middleware and report 'allowed' or its error code. */
function gate(mw, userId, role) {
  const req = { params: { slug: 'legal' }, user: { id: userId, role } };
  let out = null;
  mw(req, {}, (err) => { out = err ? (err.code || err.message) : 'allowed'; });
  return out;
}

/** Put the target in the state the admin UI's "remove" produces. */
function setRole(app_role) {
  // Mirrors PUT /api/apps/:slug/roles. Kept in step with the route by the shape
  // assertion at the bottom, which fails if the route stops deleting.
  if (app_role === 'none') {
    db.prepare('DELETE FROM app_user_roles WHERE app_id = ? AND user_id = ?').run(APP, TARGET);
    db.prepare('DELETE FROM app_users WHERE app_id = ? AND user_id = ?').run(APP, TARGET);
  } else {
    db.prepare(`INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)
                ON CONFLICT(app_id,user_id) DO UPDATE SET app_role = excluded.app_role`)
      .run(APP, TARGET, app_role);
    db.prepare('INSERT OR IGNORE INTO app_users (app_id,user_id) VALUES (?,?)').run(APP, TARGET);
  }
}

test('baseline: a real member is allowed, so the assertions below can fail', () => {
  setRole('user');
  assert.equal(gate(requireAppUser, TARGET, 'user'), 'allowed');
  assert.equal(gate(requireAppAccess, TARGET, 'user'), 'allowed');
  assert.equal(roleForUserOnApp({ id: TARGET, role: 'user' }, { id: APP }), 'user');
});

test("'none' leaves no row in either table", () => {
  setRole('none');
  const m = db.prepare('SELECT COUNT(*) c FROM app_users WHERE app_id=? AND user_id=?').get(APP, TARGET).c;
  const r = db.prepare('SELECT COUNT(*) c FROM app_user_roles WHERE app_id=? AND user_id=?').get(APP, TARGET).c;
  assert.equal(m, 0, 'membership row survived removal — this is the row that granted secret access');
  assert.equal(r, 0, "a stored app_role='none' row survived; absence must be the only representation");
});

test("every gate agrees after 'none' — the disagreement WAS the bug", () => {
  setRole('none');
  // requireAppUser guards ?reveal=true (decrypted production env vars) and
  // backup/restore/copy-data. It is the one that used to say 'allowed'.
  assert.equal(gate(requireAppUser, TARGET, 'user'), 'FORBIDDEN');
  assert.equal(gate(requireAppAccess, TARGET, 'user'), 'FORBIDDEN');
  assert.notEqual(roleForUserOnApp({ id: TARGET, role: 'user' }, { id: APP }), 'user');
});

test("re-adding after 'none' works — removal is not a tombstone", () => {
  setRole('none');
  setRole('admin');
  assert.equal(gate(requireAppUser, TARGET, 'user'), 'allowed');
  assert.equal(roleForUserOnApp({ id: TARGET, role: 'user' }, { id: APP }), 'admin');
});

test("the route deletes on 'none' rather than writing a row", () => {
  // Shape guard. The behavioural tests above drive a local mirror of the route,
  // so this pins the route itself: reinstate the unconditional membership insert
  // and this fails, naming the line that granted the access.
  const users = readFileSync('server/routes/users.js', 'utf8');
  const at = users.indexOf("if (app_role === 'none')");
  assert.ok(at > 0, "the 'none' branch is gone from PUT /:slug/roles");
  assert.match(users.slice(at, at + 600), /DELETE FROM app_users/,
    "PUT /:slug/roles no longer deletes the membership row on 'none' — a removed " +
    'user regains access to decrypted production secrets');
});
