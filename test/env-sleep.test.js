import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Environment sleep without Docker: the policy, the sleeper's decisions on an
// injected clock, what must not react to a sleeping env, the activity count at
// forward_auth, one wake for concurrent callers, and per-app authz on the
// settings routes. Docker is a recorded fake here; env-sleep-live.test.js runs
// the same paths against real containers and a real Caddy.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-env-sleep-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const policy = await import('../server/services/sleepPolicy.js');
const activity = await import('../server/services/envActivity.js');
const sleeper = await import('../server/services/envSleeper.js');
const wake = await import('../server/services/envWake.js');
const { sleepRow } = await import('../server/services/envSleepState.js');

const MIN = 60_000, DAY = 24 * 60 * MIN;
const T0 = Date.parse('2026-11-16T09:00:00Z'); // a Monday
const sql = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid);
  return { id, key, role, email: `${name}@t.test` };
}
let slot = 300;
function mkApp(slug, { authMode = 'authenticated', deployedAt = T0 - 30 * DAY } = {}) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,auth_mode) VALUES (?,?,?,'managed',?)")
    .run(slug, slug, ++slot, authMode).lastInsertRowid);
  for (const env of ['sandbox', 'production']) {
    db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, ?, 'live', ?, ?)")
      .run(id, env, sql(deployedAt), sql(deployedAt));
  }
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

const calls = [];
const running = new Map();
const fakeDeps = {
  docker: async (args) => {
    calls.push(args.join(' '));
    if (args[0] === 'stop') running.set(args[1], 'exited');
    if (args[0] === 'start') { await new Promise(r => setTimeout(r, 30)); running.set(args[1], 'running'); }
    return '';
  },
  probe: async () => true,
  admit: async () => {},
  invalidate: async () => {},
  recoverSoon: async () => {},
  sleep: (ms) => new Promise(r => setTimeout(r, Math.min(ms, 5))),
};
wake._setWakeDepsForTests(fakeDeps);
const listContainers = async () => running;
const run = (now) => sleeper.runSleeper({ now: () => now, listContainers, processStart: 0 });
const up = (app) => { for (const e of ['sandbox', 'production']) running.set(`appcrane-${app.slug}-${e}`, 'running'); };
const stops = (name) => calls.filter(c => c === `stop ${name}`).length;
const starts = (name) => calls.filter(c => c === `start ${name}`).length;

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
});

// ── policy ──────────────────────────────────────────────────────────────────

test('schedule: validated, and the window is read in its own time zone', () => {
  assert.throws(() => policy.parseSchedule({ days: [], start: '08:00', end: '19:00', tz: 'UTC' }), /days/);
  assert.throws(() => policy.parseSchedule({ days: [1], start: '8:00', end: '19:00', tz: 'UTC' }), /HH:MM/);
  assert.throws(() => policy.parseSchedule({ days: [1], start: '08:00', end: '19:00', tz: 'Mars/Base' }), /time zone/);
  const s = policy.parseSchedule({ days: ['mon', 'tue', 'wed', 'thu', 'fri'], start: '08:00', end: '19:00', tz: 'America/New_York' });
  assert.deepEqual(s.days, [1, 2, 3, 4, 5]);
  // New York is UTC-5 in November: 08:00 local = 13:00Z, 19:00 local = 00:00Z next day.
  assert.equal(policy.inSchedule(s, Date.parse('2026-11-16T12:59:00Z')), false);
  assert.equal(policy.inSchedule(s, Date.parse('2026-11-16T13:00:00Z')), true);
  assert.equal(policy.inSchedule(s, Date.parse('2026-11-16T23:59:00Z')), true);
  assert.equal(policy.inSchedule(s, Date.parse('2026-11-17T00:00:00Z')), false);
  assert.equal(policy.inSchedule(s, Date.parse('2026-11-21T15:00:00Z')), false, 'Saturday');
});

test('bounds: idle 10-1440 minutes and inactive 7-365 days, 0 is off', () => {
  assert.throws(() => policy.parsePolicyBody({ sandbox_idle_minutes: 5 }, { allowNull: true }), /10 to 1440/);
  assert.throws(() => policy.parsePolicyBody({ sandbox_idle_minutes: 1441 }, { allowNull: true }), /10 to 1440/);
  assert.throws(() => policy.parsePolicyBody({ inactive_days: 3 }, { allowNull: true }), /7 to 365/);
  assert.deepEqual(policy.parsePolicyBody({ sandbox_idle_minutes: 0, inactive_days: 365 }, { allowNull: true }), { sandbox_idle_minutes: 0, inactive_days: 365 });
  assert.throws(() => policy.parsePolicyBody({ inactive_days: null }, { allowNull: false }), /cannot be null/);
});

// ── sleeper decisions ───────────────────────────────────────────────────────

test('sandbox sleeps after its idle minutes; production never takes the minutes rule', async () => {
  const app = mkApp('idle-a');
  up(app);
  policy.setAppPolicy(db, app.id, { sandbox_idle_minutes: 15 }, null);
  activity.noteRequest(app.id, 'sandbox', null, T0);
  activity.noteRequest(app.id, 'production', null, T0);
  await run(T0 + 14 * MIN);
  assert.equal(stops(`appcrane-${app.slug}-sandbox`), 0, 'slept before its idle minutes');
  await run(T0 + 16 * MIN);
  assert.equal(stops(`appcrane-${app.slug}-sandbox`), 1, 'sandbox not put to sleep after 16 idle minutes');
  assert.equal(sleepRow(db, app.id, 'sandbox').state, 'sleeping');
  assert.equal(sleepRow(db, app.id, 'sandbox').reason, 'idle');
  await run(T0 + 300 * DAY);
  assert.equal(stops(`appcrane-${app.slug}-production`), 0, 'production was put to sleep by the sandbox idle setting');
  const audit = db.prepare("SELECT detail FROM audit_log WHERE app_id = ? AND action = 'env-sleep'").all(app.id);
  assert.equal(audit.length, 1);
  assert.match(audit[0].detail, /"reason":"idle"/);
});

test('a request inside the idle window keeps the sandbox awake', async () => {
  const app = mkApp('idle-b');
  up(app);
  policy.setAppPolicy(db, app.id, { sandbox_idle_minutes: 15 }, null);
  await run(T0 - MIN); // AppCrane starts tracking the env before the requests
  activity.noteRequest(app.id, 'sandbox', null, T0);
  activity.noteRequest(app.id, 'sandbox', 7, T0 + 10 * MIN);
  await run(T0 + 16 * MIN);
  assert.equal(stops(`appcrane-${app.slug}-sandbox`), 0);
  await run(T0 + 26 * MIN);
  assert.equal(stops(`appcrane-${app.slug}-sandbox`), 1);
});

test('a headless app is never put to sleep: AppCrane cannot see its requests', async () => {
  const app = mkApp('idle-headless', { authMode: 'headless' });
  up(app);
  policy.setAppPolicy(db, app.id, { sandbox_idle_minutes: 10, inactive_days: 7 }, null);
  await run(T0);
  await run(T0 + 400 * DAY);
  assert.equal(stops(`appcrane-${app.slug}-sandbox`), 0);
  assert.equal(stops(`appcrane-${app.slug}-production`), 0);
});

test('production sleeps only after N days with no request and no deploy, and owners are e-mailed once', async () => {
  const owner = mkUser('prod-owner');
  const app = mkApp('quiet-prod');
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(app.id, owner.id);
  up(app);
  policy.setAppPolicy(db, app.id, { inactive_days: 7 }, null);
  activity.noteRequest(app.id, 'production', owner.id, T0);
  await run(T0 + 7 * DAY - MIN);
  assert.equal(stops(`appcrane-${app.slug}-production`), 0, 'slept before 7 days');
  await run(T0 + 7 * DAY + MIN);
  assert.equal(stops(`appcrane-${app.slug}-production`), 1, 'production not asleep after 7 idle days');
  assert.equal(sleepRow(db, app.id, 'production').reason, 'inactive');
  await run(T0 + 8 * DAY);
  await run(T0 + 9 * DAY);
  const mails = db.prepare("SELECT to_email, subject FROM email_queue WHERE app_id = ? AND env = 'production'").all(app.id);
  assert.equal(mails.length, 1, `expected one owner mail, got ${mails.length}`);
  assert.equal(mails[0].to_email, owner.email);
  assert.match(mails[0].subject, /asleep after 7 days/);
});

test('a deploy resets the inactivity clock', async () => {
  const app = mkApp('redeployed');
  up(app);
  policy.setAppPolicy(db, app.id, { inactive_days: 7 }, null);
  activity.noteRequest(app.id, 'production', null, T0 - 10 * DAY);
  db.prepare("INSERT INTO deployments (app_id, env, status, started_at, finished_at) VALUES (?, 'production', 'live', ?, ?)")
    .run(app.id, sql(T0 - DAY), sql(T0 - DAY));
  await run(T0);
  await run(T0 + 5 * DAY);
  assert.equal(stops(`appcrane-${app.slug}-production`), 0, 'slept although it was deployed 1 day ago');
  await run(T0 + 6 * DAY + MIN);
  assert.equal(stops(`appcrane-${app.slug}-production`), 1, 'not asleep 7 days after the deploy');
});

test('schedule: stopped at the window end, started at the window start', async () => {
  const app = mkApp('office-hours');
  up(app);
  policy.setAppPolicy(db, app.id, { sandbox_schedule: { days: [1, 2, 3, 4, 5], start: '08:00', end: '19:00', tz: 'UTC' } }, null);
  const name = `appcrane-${app.slug}-sandbox`;
  activity.noteRequest(app.id, 'sandbox', null, Date.parse('2026-11-16T17:00:00Z'));
  await run(Date.parse('2026-11-16T18:59:00Z'));
  assert.equal(stops(name), 0, 'stopped inside the window');
  await run(Date.parse('2026-11-16T19:00:00Z'));
  assert.equal(stops(name), 1, 'not stopped at 19:00');
  assert.equal(sleepRow(db, app.id, 'sandbox').reason, 'schedule');
  await run(Date.parse('2026-11-17T07:59:00Z'));
  assert.equal(starts(name), 0, 'started before 08:00');
  await run(Date.parse('2026-11-17T08:00:00Z'));
  assert.equal(starts(name), 1, 'not started at 08:00');
  assert.equal(sleepRow(db, app.id, 'sandbox').state, 'awake');
  assert.equal(stops(`appcrane-${app.slug}-production`), 0, 'the sandbox schedule stopped production');
});

test('concurrent wakes share one docker start', async () => {
  const app = mkApp('herd');
  running.set(`appcrane-${app.slug}-sandbox`, 'running');
  const s = await wake.sleepEnv(app, 'sandbox', 'idle');
  assert.equal(s.ok, true);
  const results = await Promise.all(Array.from({ length: 12 }, () => wake.wakeEnv(app, 'sandbox')));
  assert.ok(results.every(r => r.ok), JSON.stringify(results));
  assert.equal(starts(`appcrane-${app.slug}-sandbox`), 1);
});

// ── what must not react to a sleeping env ───────────────────────────────────

test('container recovery leaves a sleeping env alone', async () => {
  const { findMissing } = await import('../server/services/containerRecovery.js');
  const { envIsSleeping } = await import('../server/services/envSleepState.js');
  const app = mkApp('rec');
  running.set(`appcrane-${app.slug}-sandbox`, 'running');
  await wake.sleepEnv(app, 'sandbox', 'idle');
  const out = findMissing({
    targets: [{ app_id: app.id, env: 'sandbox', slug: app.slug }],
    containers: new Map([[`appcrane-${app.slug}-sandbox`, 'exited']]),
    restoring: () => false, attemptState: new Map(), now: Date.now(), sleeping: envIsSleeping,
  });
  assert.equal(out.missing.length, 0, 'recovery would re-run the release of a sleeping env');
  assert.equal(out.skipped[0].why, 'asleep');
});

test('a scheduled cron run skips a sleeping env without waking it or reporting it down', async () => {
  const { runCronJob } = await import('../server/services/cronScheduler.js');
  const app = mkApp('cronny');
  running.set(`appcrane-${app.slug}-sandbox`, 'running');
  await wake.sleepEnv(app, 'sandbox', 'idle');
  const id = db.prepare("INSERT INTO app_cron_jobs (app_id, env, name, schedule, command, enabled) VALUES (?, 'sandbox', 'tick', '* * * * *', 'true', 1)").run(app.id).lastInsertRowid;
  const job = db.prepare('SELECT * FROM app_cron_jobs WHERE id = ?').get(id);
  const r = await runCronJob(job);
  assert.equal(r.skipped, true);
  assert.match(r.reason, /asleep/);
  assert.equal(starts(`appcrane-${app.slug}-sandbox`), 0);
});

test('the health checker does not probe, count or page a sleeping env', async () => {
  const { refreshAppChecks } = await import('../server/services/healthChecker.js');
  const app = mkApp('hc');
  running.set(`appcrane-${app.slug}-sandbox`, 'running');
  db.prepare("INSERT INTO health_configs (app_id, env, interval_sec, fail_threshold, down_threshold) VALUES (?, 'sandbox', 1, 1, 1)").run(app.id);
  db.prepare("INSERT INTO health_state (app_id, env) VALUES (?, 'sandbox')").run(app.id);
  await wake.sleepEnv(app, 'sandbox', 'idle');
  refreshAppChecks(app.id);
  await new Promise(r => setTimeout(r, 3500));
  const h = db.prepare("SELECT consecutive_fails, is_down, last_check_at FROM health_state WHERE app_id = ? AND env = 'sandbox'").get(app.id);
  assert.equal(h.last_check_at, null, `a sleeping env was probed (fails=${h.consecutive_fails}, down=${h.is_down})`);
  assert.equal(h.is_down, 0);
});

// ── HTTP: activity at forward_auth, app list, settings authz ─────────────────

const identityRoutes = (await import('../server/routes/identity.js')).default;
const appsRoutes = (await import('../server/routes/apps.js')).default;
const sleepRoutes = (await import('../server/routes/sleep.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api/identity', identityRoutes);
api.use('/api/apps', appsRoutes);
api.use('/api', sleepRoutes);
api.use(errorHandler);
const server = await new Promise(r => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); });

async function call(as, method, path, body, headers = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(as ? { 'X-API-Key': as.key } : {}), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, body: json };
}

const admin = mkUser('platadmin', 'platform_admin');
const owner = mkUser('owner1');
const appAdmin = mkUser('appadmin1');
const member = mkUser('member1');
const outsider = mkUser('outsider1');
const authzApp = mkApp('authz-app');
for (const [u, r] of [[owner, 'owner'], [appAdmin, 'admin'], [member, 'user']]) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(authzApp.id, u.id, r);
}

test('forward_auth counts a request; a direct verify call (no X-Forwarded-Uri) does not', async () => {
  activity._resetActivityForTests();
  const before = activity.activityOf(db, authzApp.id, 'sandbox').lastRequestAt;
  const direct = await call(member, 'GET', `/api/identity/verify?app=${authzApp.slug}&prefix=/${authzApp.slug}-sandbox`);
  assert.equal(direct.status, 200, JSON.stringify(direct.body));
  assert.equal(activity.activityOf(db, authzApp.id, 'sandbox').lastRequestAt, before, 'a direct verify call counted as use');
  const proxied = await call(member, 'GET', `/api/identity/verify?app=${authzApp.slug}&prefix=/${authzApp.slug}-sandbox`, undefined,
    { 'X-Forwarded-Uri': `/${authzApp.slug}-sandbox/`, 'X-Forwarded-Method': 'GET' });
  assert.equal(proxied.status, 200);
  assert.ok(activity.activityOf(db, authzApp.id, 'sandbox').lastRequestAt > (before || 0), 'a forward_auth request was not counted');
  assert.equal(activity.activityOf(db, authzApp.id, 'production').lastRequestAt, null, 'a sandbox request counted for production');
  activity.flushActivity(db);
  const day = new Date().toISOString().slice(0, 10);
  assert.equal(db.prepare("SELECT requests FROM env_activity_daily WHERE app_id = ? AND env = 'sandbox' AND day = ?").get(authzApp.id, day).requests, 1);
  assert.deepEqual(db.prepare("SELECT user_id FROM env_activity_users WHERE app_id = ? AND env = 'sandbox' AND day = ?").all(authzApp.id, day).map(r => r.user_id), [member.id]);
});

test('settings: owners, app admins and platform admins may change them; members and outsiders may not', async () => {
  const path = `/api/apps/${authzApp.slug}/sleep`;
  assert.equal((await call(outsider, 'GET', path)).status, 403, 'an outsider read the settings');
  const seen = await call(member, 'GET', path);
  assert.equal(seen.status, 200);
  assert.equal(seen.body.can_edit, false);
  assert.equal((await call(member, 'PUT', path, { sandbox_idle_minutes: 30 })).status, 403, 'a member changed the settings');
  assert.equal((await call(outsider, 'PUT', path, { sandbox_idle_minutes: 30 })).status, 403, 'an outsider changed the settings');
  assert.equal(policy.getAppPolicy(db, authzApp.id).sandbox_idle_minutes, null);
  const o = await call(owner, 'PUT', path, { sandbox_idle_minutes: 30 });
  assert.equal(o.status, 200, JSON.stringify(o.body));
  assert.equal(o.body.effective.sandbox_idle_minutes, 30);
  assert.equal((await call(appAdmin, 'PUT', path, { inactive_days: 14 })).status, 200);
  assert.equal((await call(admin, 'PUT', path, { sandbox_schedule: { days: [1], start: '09:00', end: '17:00', tz: 'UTC' } })).status, 200);
  assert.equal((await call(owner, 'PUT', path, { sandbox_idle_minutes: 3 })).status, 400);
  const p = policy.getAppPolicy(db, authzApp.id);
  assert.equal(p.sandbox_idle_minutes, 30);
  assert.equal(p.inactive_days, 14);
  const audits = db.prepare("SELECT user_id FROM audit_log WHERE app_id = ? AND action = 'sleep-settings-update' ORDER BY id").all(authzApp.id);
  assert.deepEqual(audits.map(a => a.user_id), [owner.id, appAdmin.id, admin.id]);
});

test('platform defaults: platform admins only', async () => {
  assert.equal((await call(owner, 'PUT', '/api/sleep/defaults', { sandbox_idle_minutes: 60 })).status, 403);
  assert.equal((await call(owner, 'GET', '/api/sleep/defaults')).status, 403);
  const r = await call(admin, 'PUT', '/api/sleep/defaults', { sandbox_idle_minutes: 60 });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.defaults.sandbox_idle_minutes, 60);
  assert.equal(policy.effectivePolicy(db, authzApp.id).sandbox_idle_minutes, 30, 'the app override lost to the default');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'sleep-defaults-update'").get().n, 1);
  await call(admin, 'PUT', '/api/sleep/defaults', { sandbox_idle_minutes: 0 });
});

test('a sleeping env is listed as sleeping, not down', async () => {
  running.set(`appcrane-${authzApp.slug}-sandbox`, 'running');
  db.prepare("INSERT OR IGNORE INTO health_state (app_id, env, is_down, consecutive_fails) VALUES (?, 'sandbox', 1, 9)").run(authzApp.id);
  await wake.sleepEnv(authzApp, 'sandbox', 'idle');
  const h = db.prepare("SELECT is_down, consecutive_fails FROM health_state WHERE app_id = ? AND env = 'sandbox'").get(authzApp.id);
  assert.deepEqual({ ...h }, { is_down: 0, consecutive_fails: 0 });
  const list = await call(owner, 'GET', '/api/apps');
  const row = list.body.apps.find(a => a.slug === authzApp.slug);
  assert.equal(row.sandbox.health.status, 'sleeping');
  const s = await call(member, 'GET', `/api/apps/${authzApp.slug}/sleep`);
  assert.equal(s.body.envs.sandbox.state, 'sleeping');
});

test('a request to /api/_crashed without the Caddy token does not wake anything', async () => {
  const { handleSleepingRequest } = await import('../server/services/sleepWakeHandler.js');
  const crash = express();
  crash.all('/api/_crashed/*splat', async (req, res) => { if (!(await handleSleepingRequest(req, res))) res.status(599).end(); });
  const srv = await new Promise(r => { const s = crash.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const before = starts(`appcrane-${authzApp.slug}-sandbox`);
    const r = await fetch(`http://127.0.0.1:${srv.address().port}/api/_crashed/${authzApp.slug}-sandbox/`, { headers: { 'X-AppCrane-Wake': 'guessed', Accept: 'text/html' } });
    assert.equal(r.status, 503);
    assert.match(await r.text(), /is asleep/);
    assert.equal(starts(`appcrane-${authzApp.slug}-sandbox`), before, 'a forged token woke the sandbox');
    assert.equal(sleepRow(db, authzApp.id, 'sandbox').state, 'sleeping');
  } finally {
    srv.close();
  }
});

test('past the bounded wait: 503 + Retry-After for an API call, a self-reloading page for a browser', async () => {
  const { handleSleepingRequest, _setWaitsForTests } = await import('../server/services/sleepWakeHandler.js');
  const app = mkApp('slowpoke');
  running.set(`appcrane-${app.slug}-sandbox`, 'running');
  await wake.sleepEnv(app, 'sandbox', 'idle');
  let release;
  const gate = new Promise(r => { release = r; });
  wake._setWakeDepsForTests({ ...fakeDeps, probe: async () => { await gate; return true; } });
  _setWaitsForTests({ api: 100, browser: 100 });
  const crash = express();
  crash.all('/api/_crashed/*splat', async (req, res) => { if (!(await handleSleepingRequest(req, res))) res.status(599).end(); });
  const srv = await new Promise(r => { const s = crash.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const url = `http://127.0.0.1:${srv.address().port}/api/_crashed/${app.slug}-sandbox/api/x`;
    const token = policy.wakeToken(db);
    const apiRes = await fetch(url, { headers: { 'X-AppCrane-Wake': token } });
    assert.equal(apiRes.status, 503);
    assert.equal(apiRes.headers.get('retry-after'), '5');
    assert.equal((await apiRes.json()).error.code, 'WAKING');
    const page = await fetch(url, { headers: { 'X-AppCrane-Wake': token, Accept: 'text/html' } });
    assert.equal(page.status, 503);
    const html = await page.text();
    assert.match(html, /Waking up/);
    assert.match(html, /http-equiv="refresh" content="2"/);
    assert.equal(starts(`appcrane-${app.slug}-sandbox`), 1, 'the two requests did not share one wake');
    release();
    for (let i = 0; i < 100 && sleepRow(db, app.id, 'sandbox').state !== 'awake'; i++) await new Promise(r => setTimeout(r, 10));
    assert.equal(sleepRow(db, app.id, 'sandbox').state, 'awake', 'the wake the timed-out requests started did not finish');
  } finally {
    srv.close();
    wake._setWakeDepsForTests(fakeDeps);
    _setWaitsForTests({ api: 25_000, browser: 5_000 });
  }
});

test('Caddyfile: the wake token rides every crash rewrite while sleep is on, and nothing changes while it is off', async () => {
  const { generateCaddyfile, setAccessLogDirCheck } = await import('../server/services/caddy.js');
  const { originalTarget } = await import('../server/services/sleepWakeHandler.js');
  setAccessLogDirCheck(() => true);
  const setting = (k, v) => db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
  db.prepare('DELETE FROM app_sleep_policy').run();
  policy.setPlatformPolicy(db, { sandbox_idle_minutes: 0, inactive_days: 0, sandbox_schedule: 'off' }, null);
  assert.doesNotMatch(generateCaddyfile(), /X-AppCrane-Wake/i, 'the wake header is emitted with sleep off everywhere');
  policy.setPlatformPolicy(db, { sandbox_idle_minutes: 30 }, null);
  const token = policy.wakeToken(db);
  assert.match(generateCaddyfile(), new RegExp(`rewrite \\* /api/_crashed\\{uri\\}\\n {12}request_header X-AppCrane-Wake "${token}"\\n {12}reverse_proxy 127\\.0\\.0\\.1:5001`));
  const slug = authzApp.slug;
  setting('app_isolation_domain', 'apps.test.local');
  try {
    assert.match(generateCaddyfile(), new RegExp(`rewrite \\* /api/_crashed/${slug}-sandbox\\{uri\\}\\n {12}request_header X-AppCrane-Wake "${token}"`), 'an app host crash rewrite has no wake token');
    const target = (url, host) => originalTarget(db, { originalUrl: url, headers: { host } }, slug, 'sandbox', `${slug}-sandbox`);
    assert.equal(target(`/api/_crashed/${slug}-sandbox/a/b?c=1`, `${slug}-sandbox.apps.test.local`), '/a/b?c=1');
    assert.equal(target(`/api/_crashed/${slug}-sandbox/${slug}-sandbox/a`, `${slug}-sandbox.apps.test.local`), `/${slug}-sandbox/a`);
    assert.equal(target(`/api/_crashed/${slug}-sandbox/a`, 'crane.test.local'), `/${slug}-sandbox/a`);
    assert.equal(target('/api/_crashed//evil.example/x', 'crane.test.local'), '/evil.example/x', 'a protocol-relative Location escaped');
  } finally {
    setting('app_isolation_domain', '');
    policy.setPlatformPolicy(db, { sandbox_idle_minutes: 0 }, null);
  }
});
