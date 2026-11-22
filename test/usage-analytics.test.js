import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Usage analytics on an injected clock: DAU/WAU/MAU/stickiness from seeded
// user-days (MAU is a union, not a sum), new vs returning weeks, the adoption
// funnel against app_user_roles, coverage flags, the 400-day retention bound,
// per-app authz, the member rule, aggregates-only, and the platform view's
// inactivity forecast.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-usage-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const activity = await import('../server/services/envActivity.js');
const usage = await import('../server/services/usageAnalytics.js');
const policy = await import('../server/services/sleepPolicy.js');

const DAY = 86_400_000;
const NOW = Date.parse('2026-11-20T12:00:00Z'); // a Friday
const at = (day, h = 10) => Date.parse(`${day}T${String(h).padStart(2, '0')}:00:00Z`);
const sql = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
const range = (from, to) => { const out = []; for (let t = Date.parse(from); t <= Date.parse(to); t += DAY) out.push(new Date(t).toISOString().slice(0, 10)); return out; };
usage._setUsageClockForTests(() => NOW);

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid);
  return { id, key, role, email: `${name}@t.test` };
}
let slot = 400;
function mkApp(slug, extra = {}) {
  const id = Number(db.prepare(`INSERT INTO apps (name,slug,slot,source_type,auth_mode,auth_bypass_paths,domain,custom_domain_auth)
    VALUES (?,?,?,'managed',?,?,?,?)`).run(slug, slug, ++slot, extra.authMode || 'authenticated',
    extra.bypass ? JSON.stringify(extra.bypass) : null, extra.domain || null, extra.customDomainAuth ? 1 : 0).lastInsertRowid);
  for (const env of ['sandbox', 'production']) {
    db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, ?, 'live', ?, ?)")
      .run(id, env, sql(Date.parse('2026-09-01T00:00:00Z')), sql(Date.parse('2026-09-01T00:00:00Z')));
    if (extra.track !== false) activity.ensureTracking(db, id, env, extra.trackFrom ?? Date.parse('2026-09-01T00:00:00Z'));
  }
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const grant = (app, u, r) => db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(app.id, u.id, r);
function hit(app, env, u, days, perDay = 1) {
  for (const d of days) {
    for (let i = 0; i < perDay; i++) activity.noteRequest(app.id, env, u.id, at(d, 10 + i));
    activity.flushActivity(db, at(d, 23));
  }
}

// ── seed ────────────────────────────────────────────────────────────────────
const admin = mkUser('ua-platadmin', 'platform_admin');
const u1 = mkUser('ua-owner');      // every day 11-01..11-20, 2 requests a day
const u2 = mkUser('ua-appadmin');   // 11-10, 11-11, 11-12
const u3 = mkUser('ua-member');     // 10-25
const u4 = mkUser('ua-old');        // 10-01 (outside the 30 days ending 11-20)
const u6 = mkUser('ua-visitor');    // app_visits only
const u7 = mkUser('ua-never');      // granted, nothing
const u8 = mkUser('ua-sandboxer');  // sandbox only, 11-19, not granted
const u9 = mkUser('ua-norole');     // app_role 'none', active 11-20: not granted
const outsider = mkUser('ua-outsider');

const app = mkApp('ua-app');
for (const [u, r] of [[u1, 'owner'], [u2, 'admin'], [u3, 'user'], [u4, 'user'], [u6, 'user'], [u7, 'user'], [u9, 'none']]) grant(app, u, r);
hit(app, 'production', u4, ['2026-10-01']);
hit(app, 'production', u3, ['2026-10-25']);
hit(app, 'production', u1, range('2026-11-01', '2026-11-20'), 2);
hit(app, 'production', u2, ['2026-11-10', '2026-11-11', '2026-11-12']);
hit(app, 'production', admin, ['2026-11-20']);
hit(app, 'production', u9, ['2026-11-20']);
hit(app, 'sandbox', u1, ['2026-11-20']);
hit(app, 'sandbox', u8, ['2026-11-19']);
db.prepare('INSERT INTO app_visits (user_id, app_id, day) VALUES (?, ?, ?)').run(u6.id, app.id, '2026-08-01');

const q = (params) => usage.parseUsageQuery(params, NOW);
const run = (params, perUser = true) => usage.appUsage(db, app, { ...q(params), perUser, now: NOW });

after(() => { activity._resetActivityForTests(); usage._setUsageClockForTests(null); });

// ── metrics ─────────────────────────────────────────────────────────────────

test('DAU, WAU, MAU and stickiness are exact; MAU is a union of users, not a sum of DAUs', () => {
  const r = run({ from: '2026-11-14', to: '2026-11-20' });
  assert.deepEqual(r.summary, { requests: 14 + 1 + 1, dau: 3, wau: 3, mau: 5, stickiness: 0.1733 });
  const userDays = db.prepare(`SELECT COUNT(*) AS n FROM (SELECT DISTINCT day, user_id FROM env_activity_users
    WHERE app_id = ? AND env = 'production' AND day BETWEEN '2026-10-22' AND '2026-11-20')`).get(app.id).n;
  assert.equal(userDays, 26, 'the summed DAUs MAU must not equal');
  const d = Object.fromEntries(r.daily.map(x => [x.day, x]));
  assert.deepEqual(d['2026-11-20'], { day: '2026-11-20', requests: 4, dau: 3, wau: 3, mau: 5, stickiness: 0.6 });
  assert.deepEqual(d['2026-11-14'], { day: '2026-11-14', requests: 2, dau: 1, wau: 2, mau: 3, stickiness: 0.3333 });
  assert.equal(r.daily.length, 7);
  const edge = run({ from: '2026-10-30', to: '2026-11-01' }).daily;
  assert.deepEqual(edge.map(x => [x.day, x.wau, x.mau]), [['2026-10-30', 1, 2], ['2026-10-31', 1, 1], ['2026-11-01', 1, 2]],
    'the 7- and 30-day windows include exactly d-6 and d-29');
});

test('env=all counts a user active in both environments once a day', () => {
  const r = run({ env: 'all', from: '2026-11-19', to: '2026-11-20' });
  const d = Object.fromEntries(r.daily.map(x => [x.day, x]));
  assert.equal(d['2026-11-20'].dau, 3, 'u1 in sandbox and production counted twice');
  assert.equal(d['2026-11-20'].requests, 5);
  assert.equal(d['2026-11-19'].dau, 2);
  assert.equal(d['2026-11-20'].mau, 6);
  assert.equal(run({ env: 'sandbox', from: '2026-11-19', to: '2026-11-20' }).summary.mau, 2);
});

test('new vs returning per Monday week', () => {
  const r = run({ from: '2026-11-02', to: '2026-11-20' });
  assert.deepEqual(r.weeks.map(w => [w.week_start, w.active, w.new, w.returning, w.partial_week]), [
    ['2026-11-02', 1, 0, 1, false],
    ['2026-11-09', 2, 1, 1, false],
    ['2026-11-16', 3, 2, 1, true],
  ]);
});

test('adoption funnel: granted -> signed in -> 3 days in 30 -> this week, each a subset', () => {
  const r = run({ from: '2026-11-14', to: '2026-11-20' });
  assert.deepEqual(r.funnel, { granted: 6, signed_in: 5, active_3_days_in_30: 2, active_this_week: 1, active_without_grant: 2 });
  const earlier = run({ from: '2026-11-05', to: '2026-11-11' }).funnel;
  assert.deepEqual(earlier, { granted: 6, signed_in: 5, active_3_days_in_30: 1, active_this_week: 1, active_without_grant: 0 },
    'two active days in 30 counted as engaged, or later use leaked into an earlier funnel');
  assert.equal(run({ from: '2026-10-01', to: '2026-10-01' }).funnel.signed_in, 2, 'use after `to` counted as signed in');
});

test('top users carry requests, active days and last seen; perUser false hides them', () => {
  const r = run({ from: '2026-11-14', to: '2026-11-20' });
  assert.deepEqual(r.top_users.map(t => [t.email, t.requests, t.active_days, t.last_seen]), [
    [u1.email, 14, 7, '2026-11-20'],
    [admin.email, 1, 1, '2026-11-20'],
    [u9.email, 1, 1, '2026-11-20'],
  ]);
  const c = mkApp('ua-counts');
  for (let i = 0; i < 2; i++) { activity.noteRequest(c.id, 'production', u1.id, at('2026-11-20', 9 + i)); activity.flushActivity(db, at('2026-11-20', 9 + i)); }
  assert.equal(db.prepare('SELECT requests FROM env_activity_users WHERE app_id = ?').get(c.id).requests, 2, 'a second flush in a day replaced the count');
  const h = run({ from: '2026-11-14', to: '2026-11-20' }, false);
  assert.equal(h.top_users, null);
  assert.equal(h.per_user_hidden, 'aggregates_only');
  assert.equal(h.summary.mau, 5);
});

// ── coverage ────────────────────────────────────────────────────────────────

test('coverage: full, tracking started in range, headless, bypass, custom domain, not tracked', () => {
  assert.equal(run({ from: '2026-11-14', to: '2026-11-20' }).coverage, 'full');
  const early = run({ from: '2026-08-01', to: '2026-11-20' });
  assert.equal(early.coverage, 'partial');
  assert.deepEqual(early.coverage_reasons.map(r => [r.code, r.tracking_since]), [['tracking_started', '2026-09-01']]);

  const cov = (a, env = 'production') => usage.appUsage(db, a, { ...q({ env, from: '2026-11-14' }), perUser: false, now: NOW });
  const headless = cov(mkApp('ua-headless', { authMode: 'headless' }));
  assert.equal(headless.coverage, 'none');
  assert.deepEqual(headless.coverage_reasons.map(r => r.code), ['headless']);
  assert.equal(cov(mkApp('ua-bypass', { bypass: ['/hooks'] })).coverage, 'partial');
  const dom = mkApp('ua-domain', { domain: 'ua.example.test' });
  assert.deepEqual(cov(dom).coverage_reasons.map(r => r.code), ['custom_domain']);
  assert.equal(cov(dom, 'sandbox').coverage, 'full');
  assert.equal(cov(mkApp('ua-domain-auth', { domain: 'ua2.example.test', customDomainAuth: true })).coverage, 'full');
  assert.equal(cov(mkApp('ua-untracked', { track: false })).coverage, 'none');
});

// ── retention ───────────────────────────────────────────────────────────────

test('retention: the flush path deletes user-days and daily rows older than 400 days, and only those', () => {
  const r = mkApp('ua-retention');
  const cutoff = new Date(NOW - activity.RETENTION_DAYS * DAY).toISOString().slice(0, 10);
  const before = new Date(Date.parse(cutoff) - DAY).toISOString().slice(0, 10);
  for (const day of [before, cutoff]) {
    db.prepare("INSERT INTO env_activity_users (app_id, env, day, user_id, requests) VALUES (?, 'production', ?, ?, 1)").run(r.id, day, u1.id);
    db.prepare("INSERT INTO env_activity_daily (app_id, env, day, requests) VALUES (?, 'production', ?, 1)").run(r.id, day);
  }
  activity._resetActivityForTests();
  activity.flushActivity(db, NOW);
  assert.deepEqual(db.prepare('SELECT day FROM env_activity_users WHERE app_id = ? ORDER BY day').all(r.id).map(x => x.day), [cutoff]);
  assert.deepEqual(db.prepare('SELECT day FROM env_activity_daily WHERE app_id = ? ORDER BY day').all(r.id).map(x => x.day), [cutoff]);
  assert.ok(db.prepare('SELECT COUNT(*) AS n FROM env_activity_users WHERE app_id = ?').get(app.id).n > 20, 'recent rows were pruned');
});

test('query validation: env, dates, range bound, and a from older than retention is clamped', () => {
  assert.throws(() => q({ env: 'staging' }), /env must be/);
  assert.throws(() => q({ from: '2026-13-01' }), /YYYY-MM-DD/);
  assert.throws(() => q({ from: '2026-11-20', to: '2026-11-01' }), /after/);
  assert.throws(() => q({ from: '2025-01-01', to: '2026-11-20' }), /at most/);
  const c = q({ from: '2025-10-01', to: '2025-12-01' });
  assert.equal(c.clamped, true);
  assert.equal(c.from, '2025-11-15');
  assert.deepEqual(q({}), { env: 'production', envs: ['production'], from: '2026-08-23', to: '2026-11-20', clamped: false });
});

// ── HTTP: authz, member rule, aggregates-only, platform view ────────────────

const usageRoutes = (await import('../server/routes/usage.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api', usageRoutes);
api.use(errorHandler);
const server = await new Promise(r => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); });

async function call(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(as ? { 'X-API-Key': as.key } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, body: json };
}

const path = `/api/apps/${app.slug}/usage?from=2026-11-14&to=2026-11-20`;

test('per-app authz: owner, app admin and platform admin read; member and outsider 403; anonymous 401', async () => {
  for (const u of [u1, u2, admin]) {
    const r = await call(u, 'GET', path);
    assert.equal(r.status, 200, `${u.email}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.summary.mau, 5);
    assert.equal(r.body.top_users[0].email, u1.email);
  }
  for (const u of [u3, u7, outsider]) {
    const r = await call(u, 'GET', path);
    assert.equal(r.status, 403, u.email);
    assert.equal(r.body.top_users, undefined);
    assert.equal(r.body.summary, undefined);
  }
  assert.equal((await call(null, 'GET', path)).status, 401);
  assert.equal((await call(u1, 'GET', `/api/apps/${app.slug}/usage?env=nope`)).status, 400);
});

test('aggregates-only: only readers set it, it is audited, and it hides per-user rows from everyone', async () => {
  const s = `/api/apps/${app.slug}/usage/settings`;
  assert.equal((await call(u3, 'PUT', s, { aggregates_only: true })).status, 403);
  assert.equal((await call(u1, 'PUT', s, { aggregates_only: 'yes' })).status, 400);
  assert.equal((await call(u1, 'PUT', s, { aggregates_only: true })).status, 200);
  const audits = db.prepare("SELECT user_id FROM audit_log WHERE app_id = ? AND action = 'usage-settings-update'").all(app.id);
  assert.deepEqual(audits.map(a => a.user_id), [u1.id]);
  for (const u of [u1, admin]) {
    const r = await call(u, 'GET', path);
    assert.equal(r.status, 200);
    assert.equal(r.body.top_users, null);
    assert.equal(r.body.aggregates_only, true);
    assert.equal(r.body.funnel.granted, 6);
    assert.ok(!JSON.stringify(r.body).includes(u1.email), 'an email reached an aggregates-only response');
  }
  assert.equal((await call(u2, 'PUT', s, { aggregates_only: false })).status, 200);
  assert.equal((await call(u1, 'GET', path)).body.top_users.length, 3);
});

test('platform view: platform admin only, least used first, and the inactivity forecast', async () => {
  assert.equal((await call(u1, 'GET', '/api/usage/apps')).status, 403);
  policy.setAppPolicy(db, app.id, { inactive_days: 30 }, admin.id);
  const headlessId = db.prepare("SELECT id FROM apps WHERE slug = 'ua-headless'").get().id;
  policy.setAppPolicy(db, headlessId, { inactive_days: 30 }, admin.id);
  const r = await call(admin, 'GET', '/api/usage/apps');
  assert.equal(r.status, 200);
  const slugs = r.body.apps.map(a => a.slug);
  assert.equal(slugs.at(-1), app.slug, 'the most used app is not last');
  const me = r.body.apps.find(a => a.slug === app.slug);
  assert.equal(me.active_users_30d, 6);
  assert.equal(me.last_use_at, new Date(at('2026-11-20', 11)).toISOString());
  const prod = me.envs.find(e => e.env === 'production');
  assert.equal(prod.inactive_days, 30);
  assert.equal(prod.sleeps_at, new Date(at('2026-11-20', 11) + 30 * DAY).toISOString());
  assert.equal(prod.due, false);
  const headless = r.body.apps.find(a => a.slug === 'ua-headless');
  assert.equal(headless.coverage, 'none');
  assert.equal(headless.inactive_days, 30);
  assert.equal(headless.envs.every(e => e.inactive_days === 30 && e.sleeps_at === null && e.not_eligible.length > 0), true);
  const untracked = r.body.apps.find(a => a.slug === 'ua-untracked');
  assert.equal(untracked.last_use_at, null);
});
