import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Platform notices (v2.40.0).
//
// The channel exists because v2.39.0 stopped forwarding the visitor's cc_token
// cookie into app containers — a correct security fix that shipped silently, so
// the app relying on that cookie learned about it as an outage. A notice is only
// worth anything if it actually REACHES someone, which makes three properties
// load-bearing and all three are pinned below:
//
//   1. The global read path answers with NO credentials. An app author whose
//      container just started 401-ing is inside that container with no platform
//      key; gating this endpoint reproduces exactly the silence it exists to fix.
//   2. It is not swallowed. Several routers here are mounted at the bare '/api'
//      with a pathless `router.use(requireAuth)`, so they 401 every /api/*
//      request that merely reaches them. That has already broken two anonymous
//      endpoints in this codebase (GET /api/settings/auth_sso_only twice over).
//      A public notice channel that 401s is a silent notice channel.
//   3. Scoping filters. A notice scoped to a subset must not reach apps outside
//      it — otherwise "your app is headless" arrives at every app owner and the
//      channel trains people to ignore it.
//
// The app-scoped route is the mirror image: it states a fact about someone's
// deployment configuration, and answering at all distinguishes a real slug from
// a 404, so it must stay authenticated AND per-app authorized.

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const INDEX_SRC = readFileSync(join(ROOT, 'server/index.js'), 'utf8');

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-notices-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { NOTICES, matchesApp, globalNotices, noticesForApp } =
  await import('../server/services/platformNotices.js');

const noticesRoutes = (await import('../server/routes/notices.js')).default;
const appsRoutes = (await import('../server/routes/apps.js')).default;
const logsRoutes = (await import('../server/routes/logs.js')).default;
const monitoringRoutes = (await import('../server/routes/monitoring.js')).default;

initDb();
const db = getDb();

// Two apps, differing only in auth_mode. Two is the minimum that lets a scoping
// test genuinely fail: with one app, a `match` that is ignored entirely and a
// `match` that works are indistinguishable.
const mkApp = (name, slug, slot, authMode) => db.prepare(
  'INSERT INTO apps (name,slug,slot,source_type,auth_mode,branch) VALUES (?,?,?,?,?,?)'
).run(name, slug, slot, 'managed', authMode, 'main').lastInsertRowid;

const HEADLESS_ID = mkApp('Headless App', 'headless-app', 91, 'headless');
const VERIFIED_ID = mkApp('Verified App', 'verified-app', 92, 'forward_auth');

const KEY_ADMIN = 'dhk_user_notices_admin';
const KEY_MEMBER = 'dhk_user_notices_member';
const KEY_OUTSIDER = 'dhk_user_notices_outsider';

const mkUser = (name, email, role, key) => db.prepare(
  'INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)'
).run(name, email, role, hashApiKey(key)).lastInsertRowid;

mkUser('Notices Admin', 'notices-admin@example.test', 'platform_admin', KEY_ADMIN);
const MEMBER_ID = mkUser('Notices Member', 'notices-member@example.test', 'user', KEY_MEMBER);
mkUser('Notices Outsider', 'notices-outsider@example.test', 'user', KEY_OUTSIDER);

// The member is assigned to both apps, so a difference in what they get back is
// a difference in SCOPING, never a difference in access.
for (const appId of [HEADLESS_ID, VERIFIED_ID]) {
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(appId, MEMBER_ID);
}

// ── The harness reproduces the mount ORDER from server/index.js ─────────────
//
// Not just noticesRoutes on its own. The failure this file exists to catch is
// positional: routers that 401 anything reaching them sit under the same '/api'
// prefix, and appsRoutes owns '/api/apps'. Mounting the notice router alone
// would make every assertion below pass no matter where index.js actually puts
// it. (The mount order in index.js itself is asserted separately, at the end.)
const api = express();
api.use(express.json());
api.use('/api', noticesRoutes);
api.use('/api/apps', appsRoutes);
api.use('/api', logsRoutes);
api.use('/api', monitoringRoutes);
api.use(errorHandler);

const server = await new Promise((res) => { const s = api.listen(0, () => res(s)); });
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

async function get(path, apiKey) {
  const r = await fetch(`${BASE}${path}`, { headers: apiKey ? { 'X-API-Key': apiKey } : {} });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) {}
  return { status: r.status, body: text, json };
}

const ids = (list) => list.map(n => n.id).sort();

// A notice scoped to a strict subset of the fleet. Pushed onto the live NOTICES
// array for the tests that need it and popped afterwards, rather than asserting
// on hypothetical data — the point is to exercise the real filter through the
// real route.
const HEADLESS_ONLY = {
  id: 'test-scoped-headless-only',
  severity: 'warning',
  version: '2.40.0',
  published_at: '2026-08-11',
  title: 'Headless apps receive no identity headers',
  body: 'Your app runs in headless auth mode, so no X-AppCrane-* headers arrive.',
  match: { auth_mode: 'headless' },
};

function withScopedNotice(fn) {
  NOTICES.push(HEADLESS_ONLY);
  try { return fn(); } finally { NOTICES.splice(NOTICES.indexOf(HEADLESS_ONLY), 1); }
}

async function withScopedNoticeAsync(fn) {
  NOTICES.push(HEADLESS_ONLY);
  try { return await fn(); } finally { NOTICES.splice(NOTICES.indexOf(HEADLESS_ONLY), 1); }
}

// ── Shape ──────────────────────────────────────────────────────────────────

test('every shipped notice carries the full wire contract', () => {
  // Consumers are app authors reading this out of a container, and a missing
  // field there is a crash in someone else's code, not a warning here.
  assert.ok(NOTICES.length > 0, 'no notices ship at all — the channel is inert');
  const seen = new Set();
  for (const n of NOTICES) {
    for (const field of ['id', 'severity', 'version', 'published_at', 'title', 'body']) {
      assert.equal(typeof n[field], 'string', `notice ${n.id}: ${field} is not a string`);
      assert.ok(n[field].length > 0, `notice ${n.id}: ${field} is empty`);
    }
    assert.ok(['breaking', 'warning', 'info'].includes(n.severity),
      `notice ${n.id}: severity '${n.severity}' is outside the documented enum`);
    assert.match(n.version, /^\d+\.\d+\.\d+$/, `notice ${n.id}: version is not a semver`);
    assert.match(n.published_at, /^\d{4}-\d{2}-\d{2}$/, `notice ${n.id}: published_at is not a date`);
    assert.ok('match' in n, `notice ${n.id}: match is absent — scope must be stated, not inferred`);
    assert.ok(!seen.has(n.id), `duplicate notice id ${n.id} — ids are the dedupe key for consumers`);
    seen.add(n.id);
  }
});

test('the v2.39.0 cc_token notice ships, and names the release that broke apps', () => {
  // The notice this whole channel was built to deliver. If it is dropped or
  // renumbered, the one app that lost its identity source gets no explanation.
  const n = NOTICES.find(x => x.id === 'cc-token-not-forwarded-2.39.0');
  assert.ok(n, 'the seeded cc_token notice is gone');
  assert.equal(n.version, '2.39.0', 'the notice points at the wrong release');
  assert.equal(n.severity, 'breaking', 'an app that changes nothing stops working — that is breaking');
  assert.match(n.body, /cc_token/, 'the body never names the cookie that was removed');
  assert.equal(n.match, null,
    'the cookie strip is emitted unconditionally in the Caddyfile and the platform has no signal ' +
    'for which apps read the cookie — narrowing this scope silently excludes the affected app');

  // It has to say what to do instead, or it is an outage report rather than a
  // migration path. These are the long-standing header names an app can rely on.
  for (const header of ['X-AppCrane-User-Email', 'X-AppCrane-App-Role']) {
    assert.ok(n.body.includes(header), `the body offers no replacement: ${header} is not mentioned`);
  }
});

test('the notice carries the two facts the week of debugging actually turned on', () => {
  // Both cost a separate debugging session. The role ORDER, because an app
  // comparing `role === 'admin'` denies owners — the highest tier. And headless,
  // because "no headers" otherwise looks identical to a broken proxy.
  const body = NOTICES.find(x => x.id === 'cc-token-not-forwarded-2.39.0').body;
  assert.match(body, /none\s*<\s*viewer\s*<\s*user\s*<\s*admin\s*<\s*owner/,
    'the App-Role tier order is not stated, so `role === "admin"` still looks correct');
  assert.match(body, /headless/i,
    'headless mode is not mentioned, so an app that receives no headers by design ' +
    'is indistinguishable from a broken forward_auth');
});

// ── The global read path ───────────────────────────────────────────────────

test('GET /api/notices answers an anonymous caller', async () => {
  // The single most important assertion in this file. A 401 here — from this
  // route or from any router mounted ahead of it — is the whole channel going
  // dark for the exact person it was built for.
  const r = await get('/api/notices');
  assert.equal(r.status, 200,
    `anonymous GET /api/notices returned ${r.status}; the channel requires credentials the ` +
    'reader does not have');
  assert.ok(Array.isArray(r.json?.notices), 'response is not { notices: [...] }');
  assert.deepEqual(ids(r.json.notices), ids(globalNotices()));
  assert.ok(r.json.notices.some(n => n.id === 'cc-token-not-forwarded-2.39.0'));
});

test('the public payload is the wire shape, field for field', async () => {
  const n = (await get('/api/notices')).json.notices.find(x => x.id === 'cc-token-not-forwarded-2.39.0');
  assert.deepEqual(
    Object.keys(n).sort(),
    ['body', 'id', 'match', 'published_at', 'severity', 'title', 'version'],
    'the notice wire shape changed — consumers parse these keys by name',
  );
  assert.equal(n.severity, 'breaking');
  assert.equal(n.version, '2.39.0');
});

test('the anonymous route serves ONLY global notices', async () => {
  // A scoped notice states a fact about one app's configuration. Leaking it
  // here would publish someone's deployment posture to any unauthenticated
  // caller — and the route cannot know which app is asking, so there is no
  // version of "just filter it" that is correct.
  await withScopedNoticeAsync(async () => {
    const r = await get('/api/notices');
    assert.equal(r.status, 200);
    assert.ok(!r.json.notices.some(n => n.id === HEADLESS_ONLY.id),
      'an app-scoped notice is served on the unauthenticated global endpoint');
    for (const n of r.json.notices) {
      assert.equal(n.match, null, `notice ${n.id} has a scope but is served globally`);
    }
  });
});

// ── Scoping actually filters ───────────────────────────────────────────────

test('matchesApp filters on the app row rather than matching everything', () => {
  const headless = db.prepare('SELECT * FROM apps WHERE slug = ?').get('headless-app');
  const verified = db.prepare('SELECT * FROM apps WHERE slug = ?').get('verified-app');

  assert.equal(matchesApp(HEADLESS_ONLY, headless), true);
  assert.equal(matchesApp(HEADLESS_ONLY, verified), false,
    'a notice scoped to headless apps matches a forward_auth app — scoping is inert');

  // A null scope is every app, which is what makes globalNotices() coherent.
  assert.equal(matchesApp({ match: null }, verified), true);

  // Multiple columns are ANDed: one mismatch is enough to exclude.
  assert.equal(matchesApp({ match: { auth_mode: 'headless', slug: 'headless-app' } }, headless), true);
  assert.equal(matchesApp({ match: { auth_mode: 'headless', slug: 'verified-app' } }, headless), false);

  // An array is a set of accepted values, not a value.
  assert.equal(matchesApp({ match: { auth_mode: ['headless', 'forward_auth'] } }, verified), true);
  assert.equal(matchesApp({ match: { auth_mode: ['headless', 'sso'] } }, verified), false);
});

test('a scope naming a column that does not exist matches nothing', () => {
  // Documented quiet failure mode, pinned so it stays quiet in the SAFE
  // direction. A typo'd column must under-deliver a notice, never broadcast one
  // to the whole fleet by accident.
  const headless = db.prepare('SELECT * FROM apps WHERE slug = ?').get('headless-app');
  assert.equal(matchesApp({ match: { auth_moed: 'headless' } }, headless), false);
});

test('noticesForApp returns global plus scoped, and never the other app\'s scoped notice', () => {
  withScopedNotice(() => {
    const headless = db.prepare('SELECT * FROM apps WHERE slug = ?').get('headless-app');
    const verified = db.prepare('SELECT * FROM apps WHERE slug = ?').get('verified-app');

    assert.deepEqual(ids(noticesForApp(headless)), ids([...globalNotices(), HEADLESS_ONLY]));
    assert.deepEqual(ids(noticesForApp(verified)), ids(globalNotices()));
  });
});

test('the app-scoped route serves a scoped notice to the app it targets, and not to the other', async () => {
  // The same filter, but through the HTTP path, because a correct predicate
  // behind a handler that calls globalNotices() would pass every test above.
  await withScopedNoticeAsync(async () => {
    const headless = await get('/api/apps/headless-app/notices', KEY_MEMBER);
    assert.equal(headless.status, 200);
    assert.equal(headless.json.slug, 'headless-app');
    assert.ok(headless.json.notices.some(n => n.id === HEADLESS_ONLY.id),
      'the app the notice targets never receives it');
    assert.ok(headless.json.notices.some(n => n.id === 'cc-token-not-forwarded-2.39.0'),
      'the app-scoped route dropped the global notices');

    const verified = await get('/api/apps/verified-app/notices', KEY_MEMBER);
    assert.equal(verified.status, 200);
    assert.equal(verified.json.slug, 'verified-app');
    assert.ok(!verified.json.notices.some(n => n.id === HEADLESS_ONLY.id),
      'a notice scoped to headless apps reached a forward_auth app');
    assert.deepEqual(ids(verified.json.notices), ids(globalNotices()));
  });
});

// ── Authorization on the app-scoped route ──────────────────────────────────

test('the app-scoped route refuses an anonymous caller', async () => {
  const r = await get('/api/apps/headless-app/notices');
  assert.equal(r.status, 401,
    'the configuration posture of a named app is readable without credentials');
  assert.ok(!r.body.includes('auth_mode'), 'the rejection still echoes app configuration');
});

test('an authenticated user not assigned to the app is refused', async () => {
  // requireAppAccess, not bare requireAuth: otherwise any account on the box
  // walks the fleet one slug at a time and reads each app's posture.
  const r = await get('/api/apps/headless-app/notices', KEY_OUTSIDER);
  assert.equal(r.status, 403,
    'any authenticated user can read the notices — and therefore the configuration ' +
    'posture — of an app they have nothing to do with');
  assert.equal(r.json?.error?.code ?? r.json?.code, 'FORBIDDEN');
});

test('an unknown slug 404s rather than answering', async () => {
  const r = await get('/api/apps/no-such-app/notices', KEY_ADMIN);
  assert.equal(r.status, 404);
});

test('an assigned member and a platform admin both get the app payload', async () => {
  for (const key of [KEY_MEMBER, KEY_ADMIN]) {
    const r = await get('/api/apps/verified-app/notices', key);
    assert.equal(r.status, 200);
    assert.equal(r.json.slug, 'verified-app');
    assert.ok(Array.isArray(r.json.notices));
  }
});

// ── Reachability: not swallowed, and not swallowing ─────────────────────────

test('the routers that 401 everything under /api do not reach the notice route first', async () => {
  // logsRoutes and monitoringRoutes both do a pathless `router.use(requireAuth)`
  // at the bare '/api' mount, so from their position down they 401 any /api/*
  // request that reaches them at all — path irrelevant. That is precisely how
  // the anonymous settings read broke, twice. This asserts the live outcome; the
  // test below asserts the ordering in server/index.js that produces it.
  //
  // Proven by contrast: a path those routers do NOT define still 401s, which is
  // what a swallowed /api/notices would have looked like.
  const swallowed = await get('/api/definitely-not-a-route');
  assert.equal(swallowed.status, 401,
    'the harness no longer reproduces the swallowing routers, so the assertion below proves nothing');

  const notices = await get('/api/notices');
  assert.equal(notices.status, 200,
    'GET /api/notices is being answered by a blanket requireAuth instead of the notice router');
});

test('the notice router does not swallow the routes mounted after it', async () => {
  // It is mounted at the bare '/api' and matches two paths. Anything else has to
  // fall straight through — a `router.use()` added to notices.js later would
  // silently take over every /api route registered below it.
  const appRoute = await get('/api/apps/verified-app', KEY_MEMBER);
  assert.equal(appRoute.status, 200, 'GET /api/apps/:slug no longer reaches appsRoutes');
  assert.equal(appRoute.json?.app?.slug ?? appRoute.json?.slug, 'verified-app');

  const audit = await get('/api/audit', KEY_ADMIN);
  assert.equal(audit.status, 200, 'GET /api/audit no longer reaches logsRoutes');

  const health = await get('/api/server/health');
  assert.notEqual(health.status, 404, 'GET /api/server/health no longer reaches monitoringRoutes');
});

// ── Wiring in the real server/index.js ─────────────────────────────────────

test('nothing mounted at the broader /api swallows the anonymous notice route', () => {
  // Same check the settings visibility suite makes, for the same trap: a router
  // mounted at bare '/api' with a pathless requireAuth authenticates EVERY
  // request under /api, including ones bound for a router mounted later.
  const imports = new Map(
    [...INDEX_SRC.matchAll(/^import\s+(\w+)\s+from\s+'(\.\/routes\/[\w.]+\.js)';/gm)].map(m => [m[1], m[2]])
  );
  const mounts = [...INDEX_SRC.matchAll(/^app\.use\('(\/api[^']*)',\s*(\w+)\)/gm)]
    .map(m => ({ path: m[1], router: m[2] }));

  const noticesAt = mounts.findIndex(m => imports.get(m.router)?.endsWith('/notices.js'));
  assert.ok(noticesAt > -1, 'the notices router is not mounted in server/index.js at all');
  assert.equal(mounts[noticesAt].path, '/api',
    'the notices router must be mounted at the bare /api — it serves both /api/notices and ' +
    '/api/apps/:slug/notices');

  const blanket = (file) =>
    /^router\.use\(requireAuth\);/m.test(readFileSync(join(ROOT, 'server', file.slice(2)), 'utf8'));

  const swallowers = mounts.slice(0, noticesAt)
    .filter(m => m.path === '/api' && imports.has(m.router) && blanket(imports.get(m.router)))
    .map(m => `${m.router} (${imports.get(m.router)})`);
  assert.deepEqual(swallowers, [],
    'these are mounted at bare /api ahead of the notices router and authenticate every request ' +
    `under it, so anonymous GET /api/notices 401s:\n  ${swallowers.join('\n  ')}`);

  // appsRoutes owns '/api/apps' and installs its own blanket requireAuth, so
  // /api/apps/:slug/notices would be 401'd before requireAppAccess ever ran —
  // an assigned member would be told they are unauthenticated.
  const appsAt = mounts.findIndex(m => m.path === '/api/apps' && imports.get(m.router)?.endsWith('/apps.js'));
  assert.ok(appsAt > -1, 'could not locate the /api/apps mount');
  assert.ok(noticesAt < appsAt,
    'the notices router is mounted after /api/apps, so /api/apps/:slug/notices is answered by ' +
    "appsRoutes' blanket auth (401) or its 404 instead of by its own requireAppAccess");
});

test('the setup guard and the app-proxy passthrough both let /api/notices through', () => {
  // Two more places the endpoint can go dark without any handler changing.
  // PUBLIC_PATHS: a breaking-change channel that is unreachable on a box nobody
  // has initialized yet is useless exactly when someone is deciding whether to
  // deploy to it. APPCRANE_PASSTHROUGH: without it an app's own frontend fetch
  // is 307'd back into its own /{slug} prefix and never reaches the platform.
  const listOf = (name) => {
    const raw = INDEX_SRC.match(new RegExp(`const ${name} = \\[([\\s\\S]*?)\\];`))?.[1];
    assert.ok(raw, `could not locate ${name} in server/index.js`);
    return [...raw.matchAll(/'([^']+)'/g)].map(m => m[1]);
  };
  assert.ok(listOf('PUBLIC_PATHS').includes('/api/notices'),
    '/api/notices is blocked by the not-yet-initialized guard');
  assert.ok(listOf('APPCRANE_PASSTHROUGH').includes('/api/notices'),
    '/api/notices is redirected into the app prefix when fetched from inside a hosted app');

  // The app-scoped route must NOT be public: it is authenticated by design.
  assert.ok(!listOf('PUBLIC_PATHS').some(p => p.includes('/notices') && p.includes('apps')),
    'the app-scoped notice route was added to PUBLIC_PATHS');
});

test('/api/info advertises the channel without inlining the bodies', () => {
  // /api/info is the universal poll — installer readiness probe, crane doctor,
  // the health endpoint, the SPA sidebar, the 30-minute version check. A count
  // is what makes a new notice discoverable to a poller that never knew to look
  // for the endpoint; the multi-paragraph bodies must not ride on that traffic.
  const info = INDEX_SRC.match(/notices:\s*\{[^}]*\}/)?.[0];
  assert.ok(info, '/api/info no longer reports notices, so a new notice is undiscoverable');
  assert.match(info, /url:\s*'\/api\/notices'/, '/api/info does not point at the notice endpoint');
  assert.match(info, /count:/, '/api/info carries no count, so a poller sees no change');
  assert.ok(!/body/.test(info), '/api/info inlines notice bodies onto the universal poll');
  assert.equal(globalNotices().length, NOTICES.filter(n => !n.match).length);
});
