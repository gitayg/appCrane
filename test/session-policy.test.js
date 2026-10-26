import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import express from 'express';

// Session lifetime policy (migration 145 trigger, services/sessionPolicy.js,
// the Bearer branch of middleware/auth.js): absolute lifetime + idle timeout,
// stricter for platform admins. Time is moved by shifting a row's timestamps
// into the past (what the clock would have done), never by sleeping.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-sesspol-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const sp = await import('../server/services/sessionPolicy.js');

initDb();
const db = getDb();

const httpApp = express();
httpApp.get('/api/ping', requireAuth, (req, res) => res.json({ id: req.user.id }));
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const MIN = 60_000;
const ping = async (token) => (await fetch(`${BASE}/api/ping`, { headers: { Authorization: `Bearer ${token}` } })).status;

function mkUser(role) {
  const tag = randomBytes(4).toString('hex');
  return db.prepare("INSERT INTO users (name, email, role, api_key_hash, active, kind) VALUES (?, ?, ?, ?, 1, 'human')")
    .run(`s${tag}`, `s${tag}@t.test`, role, hashApiKey(tag)).lastInsertRowid;
}
// Inserted the way identity.js / oidc.js / saml.js do: a 24h ISO expiry.
function issue(userId) {
  const token = randomBytes(24).toString('base64url');
  db.prepare('INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at) VALUES (?, ?, ?, ?)')
    .run(userId, hashApiKey(token), null, new Date(Date.now() + 24 * 3600_000).toISOString());
  return token;
}
const row = (token) => db.prepare('SELECT * FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(token));
const ms = (s) => sp.parseUtc(s);
function shiftBack(token, minutes) {
  const r = row(token);
  db.prepare('UPDATE identity_sessions SET last_seen_at = ?, expires_at = ?, absolute_expires_at = ? WHERE id = ?').run(
    sp.sqlUtc(ms(r.last_seen_at) - minutes * MIN), sp.sqlUtc(ms(r.expires_at) - minutes * MIN),
    sp.sqlUtc(ms(r.absolute_expires_at) - minutes * MIN), r.id);
}
const near = (a, b, tolMs = 5000) => Math.abs(a - b) <= tolMs;

test('every new session gets the role policy: admin 8h absolute / 30 min idle, user 24h / 8h', () => {
  assert.deepEqual(sp.DEFAULTS, { admin: { absolute: 480, idle: 30 }, user: { absolute: 1440, idle: 480 } });
  const now = Date.now();
  const a = row(issue(mkUser('platform_admin')));
  assert.ok(near(ms(a.absolute_expires_at), now + 480 * MIN), a.absolute_expires_at);
  assert.ok(near(ms(a.expires_at), now + 30 * MIN), a.expires_at);
  assert.ok(near(ms(a.last_seen_at), now));
  const u = row(issue(mkUser('user')));
  assert.ok(near(ms(u.absolute_expires_at), now + 1440 * MIN), u.absolute_expires_at);
  assert.ok(near(ms(u.expires_at), now + 480 * MIN), u.expires_at);
  assert.match(u.expires_at, /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ$/, 'stored so text comparison with datetime(\'now\') is correct');
});

test('the trigger honours the settings and matches policyFor(); a shorter requested expiry is never extended', () => {
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('session_admin_idle_minutes', '10'), ('session_user_absolute_minutes', '60')").run();
  try {
    const now = Date.now();
    const adminId = mkUser('platform_admin');
    const a = row(issue(adminId));
    assert.equal(sp.policyFor({ role: 'platform_admin' }, db).idle, 10);
    assert.ok(near(ms(a.expires_at), now + 10 * MIN), a.expires_at);
    const u = row(issue(mkUser('user')));
    assert.ok(near(ms(u.absolute_expires_at), now + 60 * MIN));
    assert.ok(near(ms(u.expires_at), now + 60 * MIN), 'idle (480) longer than absolute (60) is capped at absolute');

    const t = randomBytes(8).toString('hex');
    db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '-1 minute'))").run(adminId, hashApiKey(t));
    assert.ok(ms(row(t).expires_at) < Date.now(), 'an already-expired insert stays expired');
  } finally {
    db.prepare("DELETE FROM settings WHERE key IN ('session_admin_idle_minutes', 'session_user_absolute_minutes')").run();
  }
});

test('idle timeout is enforced: 31 idle minutes signs an admin out but not a user', async () => {
  const admin = issue(mkUser('platform_admin'));
  const user = issue(mkUser('user'));
  assert.equal(await ping(admin), 200);
  assert.equal(await ping(user), 200);
  shiftBack(admin, 31);
  shiftBack(user, 31);
  assert.equal(await ping(admin), 401, 'admin idle 30 min');
  assert.equal(await ping(user), 200, 'user idle 8h');
});

test('activity slides the idle deadline, but never past the absolute lifetime', async () => {
  const admin = issue(mkUser('platform_admin'));
  shiftBack(admin, 25);
  assert.equal(await ping(admin), 200);
  const slid = row(admin);
  assert.ok(near(ms(slid.expires_at), Date.now() + 30 * MIN), `slid to now + 30 min: ${slid.expires_at}`);
  assert.ok(near(ms(slid.last_seen_at), Date.now()));

  const r = row(admin);
  db.prepare('UPDATE identity_sessions SET absolute_expires_at = ?, last_seen_at = ? WHERE id = ?')
    .run(sp.sqlUtc(Date.now() + 2 * MIN), sp.sqlUtc(Date.now() - 2 * MIN), r.id);
  assert.equal(await ping(admin), 200);
  assert.ok(near(ms(row(admin).expires_at), Date.now() + 2 * MIN), 'capped at the absolute deadline');
});

test('absolute lifetime is enforced even for a session in constant use', async () => {
  const user = issue(mkUser('user'));
  const r = row(user);
  db.prepare('UPDATE identity_sessions SET absolute_expires_at = ?, expires_at = ?, last_seen_at = ? WHERE id = ?')
    .run(sp.sqlUtc(Date.now() - MIN), sp.sqlUtc(Date.now() - MIN), sp.sqlUtc(Date.now() - 2 * MIN), r.id);
  assert.equal(await ping(user), 401);
});

test('last_seen_at is written at most once a minute', async () => {
  const user = issue(mkUser('user'));
  const first = row(user).last_seen_at;
  for (let i = 0; i < 5; i++) assert.equal(await ping(user), 200);
  assert.equal(row(user).last_seen_at, first, 'five requests inside a minute: no write');

  const r = row(user);
  assert.equal(sp.touchSession(db, r, { role: 'user' }, ms(r.last_seen_at) + 59_000), false);
  assert.equal(sp.touchSession(db, r, { role: 'user' }, ms(r.last_seen_at) + 61_000), true);
  assert.notEqual(row(user).last_seen_at, first);
});

test('a session issued before migration 145 (no absolute_expires_at) is left alone', async () => {
  const id = mkUser('platform_admin');
  const t = randomBytes(8).toString('hex');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(t));
  db.prepare('UPDATE identity_sessions SET absolute_expires_at = NULL, last_seen_at = NULL WHERE token_hash = ?').run(hashApiKey(t));
  const before = row(t).expires_at;
  assert.equal(await ping(t), 200);
  assert.equal(row(t).expires_at, before);
});

test('a legacy ISO expiry ("...T...Z") that passed earlier today is refused (text comparison would wave it through)', async () => {
  const id = mkUser('user');
  const t = randomBytes(8).toString('hex');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(t));
  const past = new Date(Date.now() - 2000).toISOString();
  db.prepare('UPDATE identity_sessions SET expires_at = ?, absolute_expires_at = NULL WHERE token_hash = ?').run(past, hashApiKey(t));
  assert.equal(db.prepare("SELECT ? > datetime('now') AS live").get(past).live, 1, 'precondition: the old text comparison calls it live');
  assert.equal(await ping(t), 401);
});

test('issueSession returns the expiry the row really has', () => {
  const id = mkUser('platform_admin');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const s = sp.issueSession(db, null, null, user);
  assert.equal(row(s.token).expires_at, s.expires_at);
  assert.ok(near(ms(s.expires_at), Date.now() + 30 * MIN));
});

test('the stored format parses as UTC in JavaScript and compares correctly in SQLite', () => {
  const t = Date.UTC(2030, 0, 2, 3, 4, 5);
  const s = sp.sqlUtc(t);
  assert.equal(s, '2030-01-02 03:04:05Z');
  assert.equal(new Date(s).getTime(), t, 'new Date() (identity.js /verify) reads it as UTC');
  assert.equal(db.prepare("SELECT ? > '2030-01-02 03:04:04' AS a, ? > '2030-01-02 03:04:06' AS b, datetime(?) AS c").get(s, s, s).a, 1);
  assert.equal(db.prepare("SELECT ? > '2030-01-02 03:04:06' AS b").get(s).b, 0);
  assert.equal(db.prepare('SELECT datetime(?) AS c').get(s).c, '2030-01-02 03:04:05');
});
