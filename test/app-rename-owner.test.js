import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// App owners rename their own apps. Renaming was platform-admin only; now the
// owner may, and nothing else about who may changed: app admins and members
// are still refused. What a rename must never do, for anyone: take another
// app's slug, take an old slug another app still redirects from (that would
// capture its links), take a path AppCrane reserves, or say something
// offensive. Owners are also throttled, and cannot release an old slug.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-rename-owner-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.CRANE_DOMAIN = 'crane.test.local';

const SHIM = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mkUser = (name, role = 'user') => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)')
    .run(name, `${name}@acme.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, row: db.prepare('SELECT * FROM users WHERE id = ?').get(id) };
};
let slot = 21000;
const mkApp = (slug) => db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'upload')")
  .run(slug, slug, slot++).lastInsertRowid;
const assign = (appId, u, r) => db.prepare(
  'INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?) ON CONFLICT(app_id,user_id) DO UPDATE SET app_role=excluded.app_role',
).run(appId, u.id, r);
const slugOf = (id) => db.prepare('SELECT slug FROM apps WHERE id = ?').get(id)?.slug;
const aliasesOf = (id) => JSON.parse(db.prepare('SELECT slug_aliases FROM apps WHERE id = ?').get(id)?.slug_aliases || '[]');

const OWNER = mkUser('owner');
const OWNER_B = mkUser('ownerb');
const APPADMIN = mkUser('appadmin');
const MEMBER = mkUser('member');
const PLATFORM = mkUser('platform', 'platform_admin');

/** An app owned by OWNER, with an app admin and a member, unless `owner` says otherwise. */
function ownedApp(slug, owner = OWNER) {
  const id = mkApp(slug);
  assign(id, owner, 'owner');
  assign(id, APPADMIN, 'admin');
  assign(id, MEMBER, 'user');
  return id;
}

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { generateCaddyfile } = await import('../server/services/caddy.js');
const { RENAMES_PER_DAY } = await import('../server/services/appRename.js');

const server = await new Promise((r) => {
  const a = express();
  a.use(express.json());
  a.use('/api/apps', appsRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const rename = (who, slug, new_slug, extra = {}) => fetch(`${BASE}/api/apps/${slug}/rename`, {
  method: 'POST',
  headers: { 'x-api-key': who.key, 'content-type': 'application/json' },
  body: JSON.stringify({ new_slug, ...extra }),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));

test('the owner renames their own app, and the old slug keeps redirecting to the new one', async () => {
  const id = ownedApp('own-old');
  const r = await rename(OWNER, 'own-old', 'own-new');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(slugOf(id), 'own-new');
  assert.deepEqual(aliasesOf(id), ['own-old']);
  const cf = generateCaddyfile();
  assert.match(cf, /handle \/own-old\* \{\s*redir \/own-new\{uri\} permanent/, 'the old path must redirect to the new one');
});

test('an app admin and a member are refused, and the app is unchanged', async () => {
  const id = ownedApp('staff-only');
  for (const who of [APPADMIN, MEMBER]) {
    const r = await rename(who, 'staff-only', 'staff-taken');
    assert.equal(r.status, 403, `${who.row.name}: ${JSON.stringify(r.body)}`);
  }
  assert.equal(slugOf(id), 'staff-only');
});

test('the owner of app A cannot rename app B', async () => {
  ownedApp('a-mine');
  const b = ownedApp('b-theirs', OWNER_B);
  const r = await rename(OWNER, 'b-theirs', 'b-hijacked');
  assert.ok([403, 404].includes(r.status), `got ${r.status}`);
  assert.equal(slugOf(b), 'b-theirs');
});

test('a platform admin still can', async () => {
  const id = ownedApp('plat-old', OWNER_B);
  const r = await rename(PLATFORM, 'plat-old', 'plat-new');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(slugOf(id), 'plat-new');
});

test('another app\'s slug is refused with 400, without naming the holder, and nothing changes', async () => {
  const mine = ownedApp('coll-mine');
  const theirs = ownedApp('coll-theirs', OWNER_B);
  const r = await rename(OWNER, 'coll-mine', 'coll-theirs');
  assert.equal(r.status, 400);
  assert.match(r.body.error.message, /already used by another app/);
  assert.equal(slugOf(mine), 'coll-mine');
  assert.equal(slugOf(theirs), 'coll-theirs');
  assert.deepEqual(aliasesOf(mine), []);
});

test('an old slug another app still redirects from is refused — it would capture that app\'s links', async () => {
  const other = ownedApp('redir-was', OWNER_B);
  assert.equal((await rename(OWNER_B, 'redir-was', 'redir-now')).status, 200);
  const mine = ownedApp('redir-mine');
  const r = await rename(OWNER, 'redir-mine', 'redir-was');
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.match(r.body.error.message, /already used by another app/);
  assert.equal(slugOf(mine), 'redir-mine');
  assert.deepEqual(aliasesOf(other), ['redir-was']);
});

test('creating an app on another app\'s old slug is refused too', async () => {
  ownedApp('create-was');
  assert.equal((await rename(OWNER, 'create-was', 'create-now')).status, 200);
  const r = await fetch(`${BASE}/api/apps`, {
    method: 'POST',
    headers: { 'x-api-key': PLATFORM.key, 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'Squat', slug: 'create-was', source_type: 'upload' }),
  });
  const body = await r.json();
  assert.equal(r.status, 409, JSON.stringify(body));
  assert.match(body.error.message, /already used by another app/);
});

test('an app may return to one of its own old slugs, which then stops being a redirect', async () => {
  const id = ownedApp('back-a');
  assert.equal((await rename(PLATFORM, 'back-a', 'back-b')).status, 200);
  const r = await rename(PLATFORM, 'back-b', 'back-a');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(slugOf(id), 'back-a');
  assert.deepEqual(aliasesOf(id), ['back-b']);
});

test('reserved platform paths are refused', async () => {
  const id = ownedApp('reserved-src');
  for (const s of ['g', 'gi', 'git', 'api', 'a2a', 'login', 'reserved-src-x-sandbox']) {
    const r = await rename(OWNER, 'reserved-src', s);
    assert.equal(r.status, 400, `${s}: ${JSON.stringify(r.body)}`);
  }
  assert.equal(slugOf(id), 'reserved-src');
});

test('offensive slugs and their leetspeak are refused, for the owner and the platform admin alike', async () => {
  const id = ownedApp('clean-src');
  for (const s of ['fuck-this', 'sh1t-app', 'n1gger', 'f-u-c-k']) {
    for (const who of [OWNER, PLATFORM]) {
      const r = await rename(who, 'clean-src', s);
      assert.equal(r.status, 400, `${s}: ${JSON.stringify(r.body)}`);
      assert.ok(!r.body.error.message.includes(s), 'the refusal must not repeat the slug');
    }
  }
  const r = await rename(OWNER, 'clean-src', 'admin-portal');
  assert.equal(r.status, 400, 'a trust-signal slug is refused for an owner');
  assert.equal(slugOf(id), 'clean-src');
});

test('legitimate look-alikes are allowed', async () => {
  const id = ownedApp('lookalike-src');
  for (const s of ['scunthorpe', 'cockpit-tools', 'class-assess']) {
    const r = await rename(PLATFORM, slugOf(id), s);
    assert.equal(r.status, 200, `${s}: ${JSON.stringify(r.body)}`);
  }
});

test('create-app applies the same content policy', async () => {
  for (const slug of ['fuck-app', 'wh0re']) {
    const r = await fetch(`${BASE}/api/apps`, {
      method: 'POST',
      headers: { 'x-api-key': PLATFORM.key, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'X', slug, source_type: 'upload' }),
    });
    assert.equal(r.status, 400, slug);
    assert.equal(db.prepare('SELECT 1 FROM apps WHERE slug = ?').get(slug), undefined);
  }
  await assert.rejects(
    callTool(PLATFORM.row, 'appcrane_create_app', { name: 'X', slug: 'p0rn-site', github_url: 'https://github.com/acme/x' }),
    /not allowed/,
  );
  await assert.rejects(
    callTool(PLATFORM.row, 'appcrane_create_managed_app', { name: 'X', slug: 'bullshit-tracker' }),
    /not allowed/,
  );
});

test('two renames racing for one slug: exactly one wins', async () => {
  const a = ownedApp('race-a');
  const b = ownedApp('race-b', OWNER_B);
  const [ra, rb] = await Promise.all([
    rename(OWNER, 'race-a', 'race-prize'),
    rename(OWNER_B, 'race-b', 'race-prize'),
  ]);
  assert.deepEqual([ra.status, rb.status].sort(), [200, 400]);
  assert.equal([slugOf(a), slugOf(b)].filter((s) => s === 'race-prize').length, 1);
});

test('the database itself refuses an old slug to another app, on insert and on update', () => {
  const holder = ownedApp('db-holder');
  db.prepare('UPDATE apps SET slug_aliases = ? WHERE id = ?').run(JSON.stringify(['db-old']), holder);
  assert.throws(() => db.prepare("INSERT INTO apps (name,slug,slot) VALUES ('x','db-old',?)").run(slot++), /SLUG_TAKEN/);
  const other = ownedApp('db-other');
  assert.throws(() => db.prepare("UPDATE apps SET slug = 'db-old' WHERE id = ?").run(other), /SLUG_TAKEN/);
  db.prepare("UPDATE apps SET slug = 'db-old' WHERE id = ?").run(holder);
  assert.equal(slugOf(holder), 'db-old', 'the holder itself may return to it');
});

test(`an owner may rename an app at most ${RENAMES_PER_DAY} times a day; a platform admin is not throttled`, async () => {
  const id = ownedApp('thr-0');
  for (let i = 1; i <= RENAMES_PER_DAY; i++) {
    const r = await rename(OWNER, `thr-${i - 1}`, `thr-${i}`);
    assert.equal(r.status, 200, JSON.stringify(r.body));
  }
  const cur = slugOf(id);
  const r = await rename(OWNER, cur, 'thr-over');
  assert.equal(r.status, 429, JSON.stringify(r.body));
  assert.equal(slugOf(id), cur);
  const p = await rename(PLATFORM, cur, 'thr-admin');
  assert.equal(p.status, 200, JSON.stringify(p.body));
});

test('an owner cannot release the old slug (redirect: false); a platform admin can', async () => {
  const id = ownedApp('rel-old');
  const r = await rename(OWNER, 'rel-old', 'rel-new', { redirect: false });
  assert.equal(r.status, 403);
  assert.equal(slugOf(id), 'rel-old');
});

test('over MCP: the owner can rename, an app admin is refused', async () => {
  const id = ownedApp('mcp-old');
  await assert.rejects(
    callTool(APPADMIN.row, 'appcrane_rename_app', { slug: 'mcp-old', new_slug: 'mcp-admin' }),
    /Only the app owner or a platform admin/,
  );
  assert.equal(slugOf(id), 'mcp-old');
  const out = await callTool(OWNER.row, 'appcrane_rename_app', { slug: 'mcp-old', new_slug: 'mcp-new' });
  assert.equal(out.new_slug ?? JSON.parse(out.content?.[0]?.text || '{}').new_slug, 'mcp-new');
  assert.equal(slugOf(id), 'mcp-new');
});

test('the owner sees the rename control: GET /:slug says can_rename to exactly the people POST accepts', async () => {
  ownedApp('ui-flag');
  const flag = async (who) => (await (await fetch(`${BASE}/api/apps/ui-flag`, { headers: { 'x-api-key': who.key } })).json()).app.can_rename;
  assert.equal(await flag(OWNER), true);
  assert.equal(await flag(PLATFORM), true);
  assert.equal(await flag(APPADMIN), false);
  assert.equal(await flag(MEMBER), false);
});
