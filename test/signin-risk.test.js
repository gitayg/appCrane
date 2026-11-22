import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import express from 'express';

// Sign-in risk signals end to end over HTTP: device recognition and the
// new-device e-mail, per-account lockout with backoff and its break-glass
// paths, admin unlock, the credential-stuffing signal, stale accounts, and
// the "not you?" link.

const DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-signin-risk-'));
process.env.DATA_DIR = DATA_DIR;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { hashPassword, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const config = await import('../server/services/signinRisk/config.js');
const lockout = await import('../server/services/signinRisk/lockout.js');
const stuffing = await import('../server/services/signinRisk/stuffing.js');
const stale = await import('../server/services/signinRisk/stale.js');
const { issueSsoHandoff } = await import('../server/routes/oidc.js');
initDb();
const db = getDb();

const httpApp = express();
httpApp.set('trust proxy', true);
httpApp.use(express.json());
httpApp.use('/api/identity/mfa', (await import('../server/routes/mfa.js')).default);
httpApp.use('/api/identity', (await import('../server/routes/identity.js')).default);
httpApp.use('/api/auth/oidc', (await import('../server/routes/oidc.js')).default);
httpApp.use('/api/signin-security', (await import('../server/routes/signinSecurity.js')).default);
httpApp.use('/oauth', (await import('../server/routes/oauth.js')).default);
httpApp.get('/api/probe', requireAuth, (req, res) => res.json({ ok: true }));
httpApp.use(errorHandler);
const server = await new Promise((r) => { const s = httpApp.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); rmSync(DATA_DIR, { recursive: true, force: true }); });

const PASSWORD = 'a long enough password';
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
let ipSeq = 0;
// Every request its own address unless a test pins one: the per-IP 5/min
// login limiter must not be what a lockout test measures.
const nextIp = () => `10.${20 + Math.floor(ipSeq / 60000)}.${Math.floor((++ipSeq % 60000) / 250)}.${ipSeq % 250}`;

function mkUser({ role = 'user', kind = 'human', lastLogin = "datetime('now')" } = {}) {
  const tag = randomBytes(4).toString('hex');
  const id = db.prepare(`INSERT INTO users (name, email, username, role, password_hash, api_key_hash, active, kind, last_login_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ${lastLogin})`)
    .run(`t${tag}`, `t${tag}@t.test`, `t${tag}`, role, hashPassword(PASSWORD), hashApiKey(`key-${tag}`), kind).lastInsertRowid;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
function sessionFor(id) {
  const token = randomBytes(24).toString('base64url');
  db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 day'))").run(id, hashApiKey(token));
  return token;
}
async function call(method, path, body, headers = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    redirect: 'manual',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp(), 'X-Forwarded-Proto': 'https', 'User-Agent': UA, ...headers },
    body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const text = await res.text();
  let json = {};
  try { json = JSON.parse(text); } catch (_) {}
  return { status: res.status, body: json, text, cookies: res.headers.getSetCookie(), headers: res.headers };
}
const login = (u, { password = PASSWORD, cookie, ip } = {}) =>
  call('POST', '/api/identity/login', { login: u.username, password }, { ...(cookie && { Cookie: cookie }), ...(ip && { 'X-Forwarded-For': ip }) });
const deviceSetCookie = (cookies) => cookies.find((c) => /^__Secure-cc_device=/.test(c)) || null;
const pair = (setCookie) => setCookie.split(';')[0];
const mails = (u, like) => db.prepare('SELECT * FROM email_queue WHERE to_email = ? AND subject LIKE ?').all(u.email, like);
const events = (kind, userId) => db.prepare('SELECT * FROM events WHERE kind = ? AND subject_user_id IS ?').all(kind, userId ?? null);
const setPolicy = (p) => config.writePolicy(db, p, null);

beforeEach(() => {
  stuffing._resetStuffingForTests();
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auth_mfa_required', 'off')").run();
  db.prepare('DELETE FROM settings WHERE key = ?').run(config.POLICY_KEY);
  setPolicy({ lockout_threshold: 3, stuffing_accounts: 1000 });
});

// Baseline sign-in: the first device an account is ever seen on. Returns the device cookie pair.
async function baseline(u) {
  const r = await login(u);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const c = deviceSetCookie(r.cookies);
  assert.ok(c, 'device cookie issued');
  return pair(c);
}

test('new-device e-mail: none for the baseline device, one for a new device, never again for that device', async () => {
  const u = mkUser();
  const home = await baseline(u);
  assert.equal(mails(u, '%New sign-in%').length, 0, 'first device is the baseline');

  const again = await login(u, { cookie: home });
  assert.equal(again.status, 200);
  assert.equal(deviceSetCookie(again.cookies), null, 'a known device is not issued a new cookie');
  assert.equal(mails(u, '%New sign-in%').length, 0, 'known device: no e-mail');

  const fresh = await login(u);
  assert.equal(fresh.status, 200);
  const other = pair(deviceSetCookie(fresh.cookies));
  const sent = mails(u, '%New sign-in%');
  assert.equal(sent.length, 1, 'new device: one e-mail');
  assert.match(sent[0].body_text, /Chrome on macOS/);
  assert.match(sent[0].body_text, /\/api\/signin-security\/not-me\?t=[A-Za-z0-9_-]{43}/);
  assert.equal(sent[0].source, 'signin-risk');
  assert.equal(events('login.risk.new_device', u.id).length, 1);

  for (let i = 0; i < 3; i++) assert.equal((await login(u, { cookie: other })).status, 200);
  assert.equal(mails(u, '%New sign-in%').length, 1, 'at most one e-mail per device');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM signin_devices WHERE user_id = ?').get(u.id).n, 2);
});

test('device cookie: httpOnly, Secure, SameSite=Lax, Path=/, and only its SHA-256 is stored', async () => {
  const u = mkUser();
  const r = await login(u);
  const c = deviceSetCookie(r.cookies);
  assert.match(c, /HttpOnly/i);
  assert.match(c, /;\s*Secure/i);
  assert.match(c, /SameSite=Lax/i);
  assert.match(c, /Path=\//);
  const raw = decodeURIComponent(pair(c).split('=')[1]);
  assert.ok(raw.length >= 43);
  const row = db.prepare('SELECT * FROM signin_devices WHERE user_id = ?').get(u.id);
  assert.equal(row.token_hash, createHash('sha256').update(raw).digest('hex'));
  for (const v of Object.values(row)) assert.ok(!String(v).includes(raw), 'raw token not stored in any column');
  assert.equal(row.ua_family, 'Chrome on macOS');
});

test('SAML: the device check runs on the same-origin handoff redeem', async () => {
  const u = mkUser();
  const home = await baseline(u);
  const token = sessionFor(u.id);
  const bind = randomBytes(24).toString('base64url');
  const code = issueSsoHandoff(token, 'cc_test_bind', bind, null, { userId: u.id, method: 'saml' });
  const r = await call('POST', '/api/auth/oidc/handoff', { code }, { Cookie: `cc_test_bind=${bind}` });
  assert.equal(r.status, 200);
  assert.equal(r.body.token, token);
  assert.ok(deviceSetCookie(r.cookies), 'new device cookie on the handoff');
  assert.equal(mails(u, '%New sign-in%').length, 1);
  assert.match(mails(u, '%New sign-in%')[0].body_text, /Method: saml/);

  const code2 = issueSsoHandoff(token, 'cc_test_bind', bind, null, { userId: u.id, method: 'saml' });
  await call('POST', '/api/auth/oidc/handoff', { code: code2 }, { Cookie: `cc_test_bind=${bind}; ${home}` });
  assert.equal(mails(u, '%New sign-in%').length, 1, 'known device through SAML: no e-mail');
});

test('lockout is per account: failures from different IPs lock it, even a correct password is refused', async () => {
  const u = mkUser();
  for (let i = 0; i < 2; i++) assert.equal((await login(u, { password: 'wrong' })).status, 401);
  const third = await login(u, { password: 'wrong' });
  assert.equal(third.status, 401);
  const locked = await login(u);
  assert.equal(locked.status, 429);
  assert.equal(locked.body.error.code, 'SIGNIN_LOCKED');
  assert.ok(Number(locked.headers.get('retry-after')) > 200);
  assert.equal(mails(u, '%paused%').length, 1, 'owner e-mailed');
  assert.equal(events('login.risk.locked', u.id).length, 1);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE action = 'signin-locked'").get().n >= 1, true);
});

test('a name that matches no account locks the same way (no enumeration)', async () => {
  const ghost = { username: `nobody-${randomBytes(4).toString('hex')}` };
  for (let i = 0; i < 3; i++) assert.equal((await login(ghost, { password: 'wrong' })).status, 401);
  const r = await login(ghost, { password: 'wrong' });
  assert.equal(r.status, 429);
  assert.equal(r.body.error.code, 'SIGNIN_LOCKED');
  assert.equal(r.body.error.message, (await import('../server/services/signinRisk/index.js')).LOCKED_MESSAGE);
});

test('backoff: each lock in a row doubles, capped at the max', async () => {
  setPolicy({ lockout_threshold: 3, lockout_base_minutes: 5, lockout_max_minutes: 15 });
  const u = mkUser();
  const until = () => Date.parse(db.prepare('SELECT locked_until FROM signin_lockouts WHERE subject_key = ?').get(`u:${u.id}`).locked_until.replace(' ', 'T'));
  const expire = () => db.prepare("UPDATE signin_lockouts SET locked_until = datetime('now', '-1 second') WHERE subject_key = ?").run(`u:${u.id}`);
  const lockOnce = async () => { for (let i = 0; i < 3; i++) await login(u, { password: 'wrong' }); return (until() - Date.now()) / 60_000; };
  const m1 = await lockOnce();
  assert.ok(m1 > 4.5 && m1 <= 5.01, `first lock ~5 min, got ${m1}`);
  expire();
  const m2 = await lockOnce();
  assert.ok(m2 > 9.5 && m2 <= 10.01, `second lock ~10 min, got ${m2}`);
  expire();
  const m3 = await lockOnce();
  assert.ok(m3 > 14.5 && m3 <= 15.01, `third lock capped at 15, got ${m3}`);
  assert.equal(lockout.lockMinutes(config.readPolicy(db), 1), 5);
  assert.equal(lockout.lockMinutes(config.readPolicy(db), 2), 10);
});

test('break-glass: a browser the account signed in from before is not locked out, and existing sessions keep working', async () => {
  const u = mkUser();
  const home = await baseline(u);
  const token = sessionFor(u.id);
  for (let i = 0; i < 3; i++) await login(u, { password: 'wrong' });
  assert.equal((await login(u)).status, 429, 'locked for unknown browsers');

  const fromHome = await login(u, { cookie: home });
  assert.equal(fromHome.status, 200, 'known device signs in through the account lock');
  const me = await call('GET', '/api/identity/me', undefined, { Authorization: `Bearer ${token}` });
  assert.equal(me.status, 200, 'existing session unaffected');

  // The known device has its own counter: guessing from it locks only it.
  for (let i = 0; i < 3; i++) await login(u, { password: 'wrong', cookie: home });
  const r = await login(u, { cookie: home });
  assert.equal(r.status, 429);
  assert.ok(db.prepare("SELECT 1 FROM signin_lockouts WHERE subject_key LIKE 'd:%' AND user_id = ?").get(u.id));
});

test('platform admin unlock: lifts the lock, is audited, and is refused to non-admins', async () => {
  const u = mkUser();
  const adminUser = mkUser({ role: 'platform_admin' });
  const nobody = mkUser();
  for (let i = 0; i < 3; i++) await login(u, { password: 'wrong' });
  assert.equal((await login(u)).status, 429);

  const overview = await call('GET', '/api/signin-security', undefined, { Authorization: `Bearer ${sessionFor(adminUser.id)}` });
  assert.equal(overview.status, 200);
  assert.ok(overview.body.locked.some((l) => l.user_id === u.id));

  const denied = await call('POST', `/api/signin-security/users/${u.id}/unlock`, {}, { Authorization: `Bearer ${sessionFor(nobody.id)}` });
  assert.equal(denied.status, 403);
  assert.equal((await login(u)).status, 429, 'still locked after a refused unlock');

  const ok = await call('POST', `/api/signin-security/users/${u.id}/unlock`, {}, { Authorization: `Bearer ${sessionFor(adminUser.id)}` });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.cleared >= 1);
  const audit = db.prepare("SELECT * FROM audit_log WHERE action = 'signin-unlock' ORDER BY id DESC").get();
  assert.equal(audit.user_id, adminUser.id);
  assert.equal(JSON.parse(audit.detail).target_user_id, u.id);
  assert.equal(events('login.risk.unlocked', u.id).length, 1);
  assert.equal((await login(u)).status, 200, 'unlocked');
});

test('credential stuffing: many accounts failing from one /24 raises the throttle and emits a critical event', async () => {
  setPolicy({ lockout_threshold: 50, stuffing_accounts: 4, stuffing_logins_per_minute: 1 });
  const users = [mkUser(), mkUser(), mkUser(), mkUser()];
  for (let i = 0; i < 3; i++) await login(users[i], { password: 'wrong', ip: `10.77.1.${i + 1}` });
  assert.equal(db.prepare("SELECT COUNT(*) n FROM events WHERE kind = 'login.risk.stuffing'").get().n, 0, 'below threshold');
  await login(users[3], { password: 'wrong', ip: '10.77.1.4' });
  const ev = db.prepare("SELECT * FROM events WHERE kind = 'login.risk.stuffing' ORDER BY id DESC").get();
  assert.ok(ev, 'stuffing event');
  assert.equal(ev.severity, 'critical');
  assert.equal(JSON.parse(ev.data).network, '10.77.1.0/24');

  const fresh = mkUser();
  assert.equal((await login(fresh, { ip: '10.77.1.200' })).status, 200, 'one attempt a minute still allowed');
  const second = await login(fresh, { ip: '10.77.1.200' });
  assert.equal(second.status, 429);
  assert.equal(second.body.error.code, 'RATE_LIMITED');
  assert.equal((await login(fresh, { ip: '10.78.1.200' })).status, 200, 'another network is unaffected');
  assert.equal((await login(fresh, { ip: '10.78.1.200' })).status, 200);
});

test('credential stuffing: distinct invalid API keys from one network are a signal too', async () => {
  setPolicy({ stuffing_accounts: 5 });
  for (let i = 0; i < 5; i++) {
    const r = await call('GET', '/api/probe', undefined, { 'X-API-Key': `dhk_bogus_${i}_${randomBytes(6).toString('hex')}`, 'X-Forwarded-For': `10.88.3.${i + 1}` });
    assert.equal(r.status, 401);
  }
  const ev = db.prepare("SELECT * FROM events WHERE kind = 'login.risk.stuffing' ORDER BY id DESC").get();
  assert.ok(ev);
  assert.equal(JSON.parse(ev.data).network, '10.88.3.0/24');
  assert.equal(JSON.parse(ev.data).method, 'api_key');
});

test('stale accounts: listed after stale_days, agents excluded, never-signed-in counted from creation', async () => {
  setPolicy({ stale_days: 90 });
  const old = mkUser({ lastLogin: "datetime('now', '-200 days')" });
  const recent = mkUser({ lastLogin: "datetime('now', '-5 days')" });
  const agent = mkUser({ kind: 'agent', lastLogin: "datetime('now', '-400 days')" });
  const never = mkUser({ lastLogin: 'NULL' });
  db.prepare("UPDATE users SET created_at = datetime('now', '-120 days') WHERE id = ?").run(never.id);
  const ids = stale.listStale(db).map((r) => r.id);
  assert.ok(ids.includes(old.id));
  assert.ok(ids.includes(never.id));
  assert.ok(!ids.includes(recent.id));
  assert.ok(!ids.includes(agent.id));
  assert.equal(stale.listStale(db).find((r) => r.id === never.id).never_signed_in, true);
});

test('auto-deactivate: off by default; when on it deactivates, but never the last active platform admin', async () => {
  const old = mkUser({ lastLogin: "datetime('now', '-400 days')" });
  assert.equal(config.readPolicy(db).stale_deactivate_days, 0, 'off by default');
  assert.deepEqual(stale.runStaleSweep(db).deactivated, []);
  assert.equal(db.prepare('SELECT active FROM users WHERE id = ?').get(old.id).active, 1);

  // Every platform admin is stale; exactly one must survive the sweep.
  mkUser({ role: 'platform_admin', lastLogin: "datetime('now', '-400 days')" });
  db.prepare("UPDATE users SET last_login_at = datetime('now', '-400 days') WHERE role = 'platform_admin'").run();
  setPolicy({ stale_days: 90, stale_deactivate_days: 180 });
  const sessionTok = sessionFor(old.id);
  const out = stale.runStaleSweep(db);
  assert.ok(out.deactivated.includes(old.id));
  assert.equal(db.prepare('SELECT active FROM users WHERE id = ?').get(old.id).active, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE token_hash = ?').get(hashApiKey(sessionTok)).n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM users WHERE role = 'platform_admin' AND active = 1").get().n, 1, 'last admin kept');
  assert.equal(out.skipped_last_admin.length, 1);
  assert.ok(events('login.risk.stale_deactivated', old.id).length === 1);
  db.prepare("UPDATE users SET active = 1, last_login_at = datetime('now') WHERE role = 'platform_admin'").run();
});

test('policy: stale_deactivate_days must exceed stale_days; route validates and is admin only', async () => {
  assert.throws(() => setPolicy({ stale_days: 90, stale_deactivate_days: 30 }), /stale_deactivate_days/);
  const adminUser = mkUser({ role: 'platform_admin' });
  const bad = await call('PUT', '/api/signin-security/policy', { lockout_threshold: 1 }, { Authorization: `Bearer ${sessionFor(adminUser.id)}` });
  assert.equal(bad.status, 400);
  const good = await call('PUT', '/api/signin-security/policy', { lockout_threshold: 7 }, { Authorization: `Bearer ${sessionFor(adminUser.id)}` });
  assert.equal(good.status, 200);
  assert.equal(config.readPolicy(db).lockout_threshold, 7);
  const user = mkUser();
  assert.equal((await call('PUT', '/api/signin-security/policy', { lockout_threshold: 9 }, { Authorization: `Bearer ${sessionFor(user.id)}` })).status, 403);
});

test('"not you?" link: GET changes nothing, POST revokes every session once', async () => {
  const u = mkUser();
  await baseline(u);
  await login(u);
  const link = mails(u, '%New sign-in%')[0].body_text.match(/not-me\?t=([A-Za-z0-9_-]+)/)[1];
  const s1 = sessionFor(u.id);
  const view = await call('GET', `/api/signin-security/not-me?t=${link}`);
  assert.equal(view.status, 200);
  assert.match(view.text, /<form method="post"/);
  assert.ok(db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?').get(u.id).n >= 1, 'GET did not revoke');

  // Credentials an intruder could have made while signed in: none may survive.
  const appId = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')")
    .run(`NotMe${u.id}`, `notme-${u.id}`, 9000 + u.id).lastInsertRowid);
  const mcpKey = db.prepare('INSERT INTO user_mcp_keys (user_id, key_hash, label) VALUES (?, ?, ?)').run(u.id, `h-mcp-${u.id}`, 'intruder').lastInsertRowid;
  const appKey = db.prepare('INSERT INTO user_app_keys (user_id, app_id, key_hash, label) VALUES (?, ?, ?, ?)').run(u.id, appId, `h-app-${u.id}`, 'intruder').lastInsertRowid;
  const grant = db.prepare("INSERT INTO step_up_grants (user_id, action, expires_at) VALUES (?, 'manage_api_keys', strftime('%Y-%m-%d %H:%M:%SZ', 'now', '+10 minutes'))").run(u.id).lastInsertRowid;

  const form = { 'Content-Type': 'application/x-www-form-urlencoded' };
  const done = await call('POST', '/api/signin-security/not-me', `t=${link}`, form);
  assert.equal(done.status, 200);
  assert.ok(db.prepare('SELECT revoked_at FROM user_mcp_keys WHERE id = ?').get(mcpKey).revoked_at, 'an MCP key survived');
  assert.ok(db.prepare('SELECT revoked_at FROM user_app_keys WHERE id = ?').get(appKey).revoked_at, 'an app key survived');
  assert.ok(db.prepare('SELECT revoked_at FROM step_up_grants WHERE id = ?').get(grant).revoked_at, 'a step-up grant survived');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM identity_sessions WHERE user_id = ?').get(u.id).n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM signin_devices WHERE user_id = ?').get(u.id).n, 0);
  assert.equal(events('login.risk.reported', u.id).length, 1);
  assert.equal(events('login.risk.reported', u.id)[0].severity, 'critical');
  assert.equal((await call('GET', '/api/identity/me', undefined, { Authorization: `Bearer ${s1}` })).status, 401);
  assert.equal((await call('POST', '/api/signin-security/not-me', `t=${link}`, form)).status, 410, 'single use');
  assert.equal((await call('GET', `/api/signin-security/not-me?t=${'x'.repeat(43)}`)).status, 410);
});

test('credential stuffing: OAuth client-authentication failures on /oauth/token and /oauth/revoke count too', async () => {
  setPolicy({ stuffing_accounts: 4 });
  for (let i = 0; i < 2; i++) {
    const r = await call('POST', '/oauth/token', { grant_type: 'authorization_code', client_id: `ghost-${i}-${randomBytes(4).toString('hex')}` }, { 'X-Forwarded-For': `10.99.4.${i + 1}` });
    assert.equal(r.status, 401);
    assert.equal(r.body.error, 'invalid_client');
  }
  for (let i = 2; i < 4; i++) {
    const r = await call('POST', '/oauth/revoke', { token: 'x', client_id: `ghost-${i}-${randomBytes(4).toString('hex')}` }, { 'X-Forwarded-For': `10.99.4.${i + 1}` });
    assert.equal(r.status, 401);
  }
  const ev = db.prepare("SELECT * FROM events WHERE kind = 'login.risk.stuffing' ORDER BY id DESC").get();
  assert.ok(ev, 'stuffing event');
  assert.equal(JSON.parse(ev.data).network, '10.99.4.0/24');
  assert.equal(JSON.parse(ev.data).method, 'oauth_client');
});

test('access reviews: each item says whether the account is stale, read live under stale_days', async () => {
  const { createCampaign } = await import('../server/services/accessReviews/campaigns.js');
  const { reviewsForUser } = await import('../server/services/accessReviews/queries.js');
  setPolicy({ stale_days: 90 });
  const idle = mkUser({ role: 'platform_admin', lastLogin: "datetime('now', '-200 days')" });
  const fresh = mkUser({ role: 'platform_admin' });
  createCampaign(db, { notify: false });
  const review = reviewsForUser(db, fresh).find((r) => r.kind === 'platform');
  assert.ok(review);
  const item = (id) => review.items.find((i) => i.user_id === id);
  assert.equal(item(idle.id).account_stale, true);
  assert.equal(item(fresh.id).account_stale, false);
  assert.ok(item(idle.id).account_last_sign_in_at);
  db.prepare("UPDATE access_review_campaigns SET status = 'closed' WHERE status = 'open'").run();
});
