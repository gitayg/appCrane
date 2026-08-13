import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// auth_mode must be READABLE wherever an operator or an agent inspects an app
// (v2.40.0).
//
// Four separate identity debugging sessions traced back to the same blind spot:
// `auth_mode` is settable but was effectively unreadable, so "my app receives no
// X-AppCrane-* headers" could not be told apart from "this app is headless and
// by design never gets them". headless is the one mode where forward_auth is
// skipped entirely (caddy.js: `app.auth_mode === 'headless'`), so it has to be
// the first thing a triage step can rule out.
//
// The invariant these tests pin: every payload that carries auth_mode reports
// the EFFECTIVE mode — the same verdict caddy.js reaches — as a plain string,
// on every serializer, never absent and never a raw value that contradicts what
// the proxy does.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-authmode-'));
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
// reloadCaddy() logs the whole generated Caddyfile at info on non-Linux (mock
// mode), and POST/PUT below both call it. Quieter output, same code path.
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const KEY = generateApiKey('dhk_admin');
const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','admin@t.test','platform_admin',?,1,'human')"
).run(hashApiKey(KEY)).lastInsertRowid;
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);

// The four shapes an app's stored auth_mode can actually take.
//   stored: null  → the column was never written (the overwhelmingly common
//                   case — migration 056 defaults it, nobody toggles it)
//   'forward_auth' → a value that is neither of the two the API accepts. No
//                   CHECK constraint guards this column, and test fixtures in
//                   this very repo already write it. caddy.js bypasses ONLY on
//                   the literal 'headless', so anything else is authenticated
//                   on the wire and must be reported that way.
const APPS = [
  { slug: 'am-headless', stored: 'headless',      expected: 'headless' },
  { slug: 'am-authed',   stored: 'authenticated', expected: 'authenticated' },
  { slug: 'am-default',  stored: null,            expected: 'authenticated' },
  { slug: 'am-legacy',   stored: 'forward_auth',  expected: 'authenticated' },
];

let slot = 0;
for (const a of APPS) {
  a.id = a.stored === null
    ? db.prepare('INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,?)')
        .run(a.slug, a.slug, ++slot, 'managed').lastInsertRowid
    : db.prepare('INSERT INTO apps (name,slug,slot,source_type,auth_mode) VALUES (?,?,?,?,?)')
        .run(a.slug, a.slug, ++slot, 'managed', a.stored).lastInsertRowid;
  // A live production deployment, so generateCaddyfile emits a real proxy block
  // for the app instead of the "Not deployed" stub.
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(a.id);
}

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);

const server = await new Promise((resolve) => {
  const s = api.listen(0, () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;
// Same undici keep-alive trap as test/mcp-protocol.test.js: server.close() waits
// for pooled sockets that never go away on their own, and node --test hangs with
// every test already green. POST /api/apps also schedules health-check intervals
// for the app it creates, which hold the loop open on their own.
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': KEY },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json() };
}

/** The one thing every caller needs: a usable string, not a guess. */
function assertLegible(value, where) {
  assert.equal(typeof value, 'string', `${where}: auth_mode must be a string, got ${JSON.stringify(value)}`);
  assert.ok(['authenticated', 'headless'].includes(value),
    `${where}: auth_mode must be 'authenticated' or 'headless', got ${JSON.stringify(value)}`);
}

test('the app list reports an effective auth_mode for every app', async () => {
  const r = await req('GET', '/api/apps');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  for (const a of APPS) {
    const row = r.body.apps.find(x => x.slug === a.slug);
    assert.ok(row, `${a.slug} missing from the list`);
    assertLegible(row.auth_mode, `GET /api/apps (${a.slug})`);
    assert.equal(row.auth_mode, a.expected, `GET /api/apps (${a.slug}, stored=${JSON.stringify(a.stored)})`);
  }
});

test('the app detail view agrees with the list, app for app', async () => {
  // The half-fix this catches: normalizing the detail payload but leaving the
  // list raw (or vice versa) gives the dashboard and the API two different
  // answers for the same app — which is how "no identity headers" stayed
  // unexplained for four sessions.
  const list = (await req('GET', '/api/apps')).body.apps;
  for (const a of APPS) {
    const r = await req('GET', `/api/apps/${a.slug}`);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assertLegible(r.body.app.auth_mode, `GET /api/apps/${a.slug}`);
    assert.equal(r.body.app.auth_mode, a.expected);
    assert.equal(r.body.app.auth_mode, list.find(x => x.slug === a.slug).auth_mode,
      `${a.slug}: detail and list disagree about auth_mode`);
  }
});

test('a freshly created app reports authenticated, not an absent field', async () => {
  const r = await req('POST', '/api/apps', { name: 'AM New', slug: 'am-new', source_type: 'managed' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assertLegible(r.body.app.auth_mode, 'POST /api/apps');
  assert.equal(r.body.app.auth_mode, 'authenticated',
    'a new app is SSO-gated; the create response must say so rather than leave the caller to infer it');
});

test('flipping auth_mode through PUT reports the mode that now applies', async () => {
  const on = await req('PUT', '/api/apps/am-authed', { auth_mode: 'headless' });
  assert.equal(on.status, 200, JSON.stringify(on.body));
  assert.equal(on.body.app.auth_mode, 'headless');
  // Confirm the write landed and is visible on the read path too — the flip is
  // exactly the moment an app stops receiving identity headers.
  assert.equal((await req('GET', '/api/apps/am-authed')).body.app.auth_mode, 'headless');

  const off = await req('PUT', '/api/apps/am-authed', { auth_mode: 'authenticated' });
  assert.equal(off.body.app.auth_mode, 'authenticated');
  assert.equal((await req('GET', '/api/apps/am-authed')).body.app.auth_mode, 'authenticated');
});

test('a PUT that changes nothing reports the same auth_mode as a GET', async () => {
  // Same route, same `app` key — a caller cannot be expected to know that the
  // no-op branch returns a different shape from the one that did work.
  for (const a of APPS) {
    const put = await req('PUT', `/api/apps/${a.slug}`, {});
    assert.equal(put.status, 200, JSON.stringify(put.body));
    assert.equal(put.body.message, 'No changes', `${a.slug}: expected the no-op branch`);
    assertLegible(put.body.app.auth_mode, `PUT /api/apps/${a.slug} (no changes)`);
    assert.equal(put.body.app.auth_mode, a.expected,
      `${a.slug}: the no-op PUT response disagrees with every other serializer`);
  }
});

test('appcrane_get_app surfaces config.auth_mode — the case that failed triage', async () => {
  for (const a of APPS) {
    const res = await callTool(admin, 'appcrane_get_app', { slug: a.slug });
    const out = JSON.parse(res.content[0].text);
    assert.ok('auth_mode' in out.config,
      `${a.slug}: appcrane_get_app config has no auth_mode key — an agent debugging ` +
      'missing identity headers cannot rule out headless');
    assertLegible(out.config.auth_mode, `appcrane_get_app(${a.slug})`);
    assert.equal(out.config.auth_mode, a.expected);
  }
});

test('appcrane_set_app_meta echoes the effective mode even when it patched something else', async () => {
  // A meta write that never touched auth_mode used to echo back the raw column,
  // so the agent's own confirmation payload was the least trustworthy reading of
  // it available.
  for (const a of APPS) {
    const res = await callTool(admin, 'appcrane_set_app_meta', { slug: a.slug, category: 'triage' });
    const out = JSON.parse(res.content[0].text);
    assert.deepEqual(out.updated_fields, ['category'], `${a.slug}: expected only category to change`);
    assertLegible(out.auth_mode, `appcrane_set_app_meta(${a.slug})`);
    assert.equal(out.auth_mode, a.expected);
  }
});

test('appcrane_update_app returns the same auth_mode as appcrane_get_app', async () => {
  // Its own comment promises "the same shape as appcrane_get_app", and an agent
  // that verifies a write from this payload must not read a different mode.
  for (const a of APPS) {
    const upd = JSON.parse((await callTool(admin, 'appcrane_update_app', { slug: a.slug, description: 'x' })).content[0].text);
    const get = JSON.parse((await callTool(admin, 'appcrane_get_app', { slug: a.slug })).content[0].text);
    assertLegible(upd.config.auth_mode, `appcrane_update_app(${a.slug})`);
    assert.equal(upd.config.auth_mode, get.config.auth_mode, `${a.slug}: update_app and get_app disagree`);
    assert.equal(upd.config.auth_mode, a.expected);
  }
});

test('the reported mode matches what Caddy actually does with the app', async () => {
  // The whole point of reporting auth_mode is to answer "will this app receive
  // X-AppCrane-* headers". That answer is only worth anything if it tracks the
  // generated proxy config: forward_auth is emitted for the app iff the app is
  // not headless, and the per-app verify URI carries the slug.
  const { generateCaddyfile } = await import('../server/services/caddy.js');
  const cf = generateCaddyfile();
  const detail = {};
  for (const a of APPS) detail[a.slug] = (await req('GET', `/api/apps/${a.slug}`)).body.app.auth_mode;

  for (const a of APPS) {
    const verified = cf.includes(`/api/identity/verify?app=${a.slug}&`);
    assert.equal(verified, detail[a.slug] === 'authenticated',
      `${a.slug}: API reports ${detail[a.slug]} but the Caddyfile ` +
      `${verified ? 'does' : 'does not'} run forward_auth for it`);
  }
});

test('the column itself can never be NULL, so "never set" is not a third state', async () => {
  // Migration 056 declares `auth_mode TEXT NOT NULL DEFAULT 'authenticated'`.
  // Worth pinning: if a later table rebuild drops the NOT NULL, every payload
  // above would start emitting a normalized value over a NULL row, and the
  // stored truth and the reported truth would silently diverge.
  const col = db.prepare('PRAGMA table_info(apps)').all().find(c => c.name === 'auth_mode');
  assert.equal(col.notnull, 1, 'auth_mode lost its NOT NULL constraint');
  assert.equal(col.dflt_value, "'authenticated'");
  assert.equal(db.prepare('SELECT auth_mode FROM apps WHERE slug = ?').get('am-default').auth_mode,
    'authenticated', 'an app that never toggled auth_mode stores the default, not NULL');
});
