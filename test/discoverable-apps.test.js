import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Apps a caller has no role on are listed only so they can request access:
// name, icon, category and owner name — never health, versions, URLs or ports.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-discoverable-'));
process.env.ENCRYPTION_KEY = '2'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.example.test';
const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey, hashPassword, generateSessionToken } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const mk = (name, role) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,username,role,active,api_key_hash,password_hash) VALUES (?,?,?,?,1,?,?)')
    .run(name, `${name}@t.test`, name, role, hashApiKey(key), hashPassword('pw-' + name)).lastInsertRowid;
  return { id, key, name };
};
const PLATFORM = mk('platform', 'platform_admin');
const OWNER = mk('owner', 'user');
const MEMBER = mk('member', 'user');

let slot = 1;
const mkApp = (slug, visibility, category = null) => {
  const id = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch,visibility,category,domain) VALUES (?,?,?,'managed','main',?,?,?)")
    .run(slug.toUpperCase(), slug, slot++, visibility, category, `${slug}.custom.test`).lastInsertRowid;
  db.prepare("INSERT INTO deployments (app_id,env,version,status,started_at,finished_at) VALUES (?, 'production', '9.9.9', 'live', datetime('now'), datetime('now'))").run(id);
  db.prepare("INSERT INTO health_state (app_id,env,last_status,is_down,last_check_at) VALUES (?, 'production', 200, 0, datetime('now'))").run(id);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, OWNER.id);
  return id;
};
const MINE = mkApp('mine', 'private', 'Tools');
const SECRET = mkApp('secret', 'private', 'Finance');
mkApp('pub', 'public');
mkApp('ghost', 'hidden');
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'user')").run(MINE, MEMBER.id);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const identityRoutes = (await import('../server/routes/identity.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json());
  a.use('/api/apps', appsRoutes);
  a.use('/api/identity', identityRoutes);
  a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(async () => {
  server.closeAllConnections?.(); server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker?.();
});
const base = () => `http://127.0.0.1:${server.address().port}`;
const list = async (who) => {
  const r = await fetch(`${base()}/api/apps`, { headers: { 'x-api-key': who.key } });
  assert.equal(r.status, 200);
  return Object.fromEntries((await r.json()).apps.map(a => [a.slug, a]));
};

const SENSITIVE = ['production', 'sandbox', 'urls', 'domain', 'domain_aliases', 'ports', 'base_path',
  'users', 'resource_limits', 'description', 'github_url', 'slot', 'public_port', 'sandbox_visible'];
const MINIMAL_KEYS = ['access_requested', 'app_role', 'category', 'has_icon', 'id', 'name', 'owner', 'owners', 'slug', 'visibility'];

test('a member gets the full shape for apps they can open', async () => {
  const apps = await list(MEMBER);
  for (const slug of ['mine', 'pub']) {
    const a = apps[slug];
    assert.ok(a, slug);
    assert.notEqual(a.app_role, 'none', slug);
    assert.equal(a.production.deploy.version, '9.9.9', slug);
    assert.equal(a.production.health.status, 'healthy', slug);
    assert.ok(a.urls?.production, slug);
  }
});

test('a member gets only name, icon, category and owner name for an app they have no role on', async () => {
  const a = (await list(MEMBER)).secret;
  assert.ok(a, 'discoverable app is still listed');
  assert.equal(a.app_role, 'none');
  for (const k of SENSITIVE) assert.equal(k in a, false, `${k} must not be sent for a no-access app`);
  assert.deepEqual(Object.keys(a).sort(), MINIMAL_KEYS);
  assert.equal(a.category, 'Finance');
  assert.deepEqual(a.owners, [{ name: 'owner' }]);
  assert.deepEqual(a.owner, { name: 'owner' });
  assert.equal(a.access_requested, false);
  assert.equal(JSON.stringify(a).includes('@t.test'), false, 'no owner e-mail');
});

test('a pending access request is reported, a done one is not', async () => {
  const ins = db.prepare("INSERT INTO enhancement_requests (app_slug,user_id,user_name,message,status) VALUES ('secret',?,'member',?,?)");
  const other = ins.run(MEMBER.id, 'Please add dark mode', 'new').lastInsertRowid;
  assert.equal((await list(MEMBER)).secret.access_requested, false, 'a feature request is not an access request');
  const done = ins.run(MEMBER.id, 'Access request for app “SECRET”', 'done').lastInsertRowid;
  assert.equal((await list(MEMBER)).secret.access_requested, false, 'a closed request is not pending');
  const pending = ins.run(MEMBER.id, 'Access request for app “SECRET”', 'new').lastInsertRowid;
  assert.equal((await list(MEMBER)).secret.access_requested, true);
  db.prepare('DELETE FROM enhancement_requests WHERE id IN (?,?,?)').run(other, done, pending);
});

test('hidden apps stay absent for non-admins', async () => {
  assert.equal('ghost' in (await list(MEMBER)), false);
});

test('a platform admin still gets the full shape for every app', async () => {
  const apps = await list(PLATFORM);
  for (const slug of ['mine', 'secret', 'pub', 'ghost']) {
    assert.equal(apps[slug]?.app_role, 'admin', slug);
    assert.equal(apps[slug].production.deploy.version, '9.9.9', slug);
    assert.ok(apps[slug].ports, slug);
    assert.ok(apps[slug].owners[0].email, slug);
  }
});

const PORTAL_SENSITIVE = ['domain', 'description', 'prod_version', 'sand_version', 'prod_status', 'prod_down',
  'sand_status', 'sand_down', 'has_github', 'public_access'];

test('sign-in portal login strips no-access apps to the minimal row', async () => {
  const r = await fetch(`${base()}/api/identity/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ login: 'member', password: 'pw-member' }),
  });
  assert.equal(r.status, 200);
  const apps = Object.fromEntries((await r.json()).apps.map(a => [a.slug, a]));
  assert.equal(apps.secret.app_role, 'none');
  for (const k of PORTAL_SENSITIVE) assert.equal(k in apps.secret, false, `login: ${k}`);
  assert.equal(apps.mine.prod_version, '9.9.9');
  assert.equal(apps.mine.domain, 'mine.custom.test');
  assert.equal('ghost' in apps, false);
});

test('sign-in portal /me strips no-access apps to the minimal row; platform admin keeps everything', async () => {
  const session = (u) => {
    const token = generateSessionToken();
    db.prepare("INSERT INTO identity_sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))").run(u.id, hashApiKey(token));
    return token;
  };
  const me = async (u) => {
    const r = await fetch(`${base()}/api/identity/me`, { headers: { authorization: `Bearer ${session(u)}` } });
    assert.equal(r.status, 200);
    return Object.fromEntries((await r.json()).apps.map(a => [a.slug, a]));
  };
  const m = await me(MEMBER);
  assert.equal(m.secret.role, 'none');
  for (const k of PORTAL_SENSITIVE) assert.equal(k in m.secret, false, `me: ${k}`);
  assert.equal(m.mine.prod_version, '9.9.9');
  const p = await me(PLATFORM);
  assert.equal(p.secret.role, 'admin');
  assert.equal(p.secret.prod_version, '9.9.9');
});

const pickerSrc = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'studio-web/src/components/AppPicker.tsx'), 'utf8');

test('the Launch picker lists owned apps, then your apps, then Request access', () => {
  const owned = pickerSrc.indexOf("renderSection('owned', 'Apps you own'");
  const yours = pickerSrc.indexOf("renderSection('yours', 'Your apps'");
  const request = pickerSrc.indexOf("renderSection('request', 'Request access'");
  assert.ok(owned > 0 && yours > owned && request > yours, 'section order: owned, yours, request');
  assert.match(pickerSrc, /renderSection\('owned', 'Apps you own', owned, renderTile\)/);
  assert.match(pickerSrc, /renderSection\('yours', 'Your apps', others, renderTile\)/);
  assert.match(pickerSrc, /renderSection\('request', 'Request access', visibleRequestable, renderRequestTile\)/);
});

test('owned apps are not repeated under Your apps', () => {
  assert.match(pickerSrc, /const owned = visibleOpenable\.filter\(isOwned\)/);
  assert.match(pickerSrc, /const others = visibleOpenable\.filter\(a => !isOwned\(a\)\)/);
});

test('no-access apps are never openable and the count covers only openable apps', () => {
  assert.match(pickerSrc, /const canOpen = \(a: PickerApp\) => a\.app_role !== 'none'/);
  assert.match(pickerSrc, /const openable = apps\.filter\(a => canOpen\(a\) && isLive\(a\)\)/);
  assert.match(pickerSrc, /const requestable = apps\.filter\(a => !canOpen\(a\)\)/);
  assert.match(pickerSrc, /`\$\{openable\.length\} app\$\{openable\.length === 1 \? '' : 's'\} available/);
  const tile = pickerSrc.slice(pickerSrc.indexOf('const renderRequestTile'), pickerSrc.indexOf('const renderSection'));
  assert.ok(tile.length > 0);
  assert.equal(/onOpen|href=/.test(tile), false, 'a request tile must not open the app');
  assert.match(tile, /'Request access'/);
  assert.match(tile, /'Requested'/);
  assert.match(tile, /onClick=\{\(\) => requestAccess\(a\)\}/);
  assert.match(pickerSrc, /adminApi\.post\('\/api\/enhancements'/);
  assert.match(pickerSrc, /Access request for app/);
});
