import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';

// Per-app "Show Sandbox to users" (migration 104). Only the owner or a platform
// admin may change it; with it off, the API tells a member's client that
// Sandbox is not offered, and still tells the owner / app admin / platform
// admin that it is. Visibility only: nothing here touches routing.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-sandvis-'));
process.env.ENCRYPTION_KEY = '1'.repeat(64);
const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const mk = (name, role) => {
  const key = generateApiKey('dhk_user');
  const id = db.prepare('INSERT INTO users (name,email,role,active,api_key_hash) VALUES (?,?,?,1,?)').run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, name };
};
const PLATFORM = mk('platform', 'platform_admin');
// A former global admin: that tier was retired (migration 105) and its holders
// became 'user', keeping only explicit app roles — here a plain member role.
const EX_ADMIN = mk('globaladmin', 'user');
const OWNER = mk('owner', 'user');
const APP_ADMIN = mk('appadmin', 'user');
const MEMBER = mk('member', 'user');
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('S','sandvis',1,'managed','main')").run().lastInsertRowid;
for (const [u, r] of [[OWNER, 'owner'], [APP_ADMIN, 'admin'], [MEMBER, 'user'], [EX_ADMIN, 'user']]) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, u.id, r);
}

const apps = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');
const server = await new Promise((r) => {
  const a = express(); a.use(express.json()); a.use('/api/apps', apps); a.use(errorHandler);
  const s = a.listen(0, '127.0.0.1', () => r(s));
});
after(() => { server.closeAllConnections?.(); server.close(); });
const base = () => `http://127.0.0.1:${server.address().port}/api/apps`;
const put = (who, body) => fetch(`${base()}/sandvis`, {
  method: 'PUT', headers: { 'content-type': 'application/json', 'x-api-key': who.key }, body: JSON.stringify(body),
});
const listed = async (who) => {
  const r = await fetch(base(), { headers: { 'x-api-key': who.key } });
  assert.equal(r.status, 200);
  return (await r.json()).apps.find(a => a.slug === 'sandvis');
};
const detail = async (who) => {
  const r = await fetch(`${base()}/sandvis`, { headers: { 'x-api-key': who.key } });
  assert.equal(r.status, 200);
  return (await r.json()).app;
};
const stored = () => db.prepare('SELECT show_sandbox FROM app_settings WHERE app_id = ?').get(appId)?.show_sandbox;

test('default is shown, with no row written', async () => {
  assert.equal(stored(), undefined);
  for (const who of [MEMBER, OWNER, PLATFORM]) {
    const a = await listed(who);
    assert.equal(a.show_sandbox, true, who.name);
    assert.equal(a.sandbox_visible, true, who.name);
  }
  assert.equal((await detail(MEMBER)).sandbox_visible, true);
});

test('app admin, member and former global admin are refused with 403, and nothing changes', async () => {
  for (const who of [APP_ADMIN, MEMBER, EX_ADMIN]) {
    const r = await put(who, { show_sandbox: false });
    assert.equal(r.status, 403, `${who.name} should be refused`);
    assert.match((await r.json()).error?.message ?? '', /owner or a platform admin/, who.name);
  }
  assert.equal(stored(), undefined);
});

test('only the owner and platform admin are told they can change it', async () => {
  assert.equal((await detail(OWNER)).can_change_show_sandbox, true);
  assert.equal((await detail(PLATFORM)).can_change_show_sandbox, true);
  for (const who of [APP_ADMIN, MEMBER, EX_ADMIN]) {
    assert.equal((await detail(who)).can_change_show_sandbox, false, who.name);
  }
});

test('a non-boolean is a 400, not a silent coercion', async () => {
  assert.equal((await put(OWNER, { show_sandbox: 'no' })).status, 400);
  assert.equal(stored(), undefined);
});

test('the owner can turn it off; a member then is not offered sandbox, owner / app admin / admins are', async () => {
  const r = await put(OWNER, { show_sandbox: false });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).app.show_sandbox, false);
  assert.equal(stored(), 0);

  const m = await listed(MEMBER);
  assert.equal(m.show_sandbox, false);
  assert.equal(m.sandbox_visible, false, 'member must not be offered sandbox in the list');
  assert.equal((await detail(MEMBER)).sandbox_visible, false, 'member must not be offered sandbox in the detail');

  for (const who of [OWNER, APP_ADMIN, PLATFORM]) {
    assert.equal((await listed(who)).sandbox_visible, true, `${who.name} (list)`);
    assert.equal((await detail(who)).sandbox_visible, true, `${who.name} (detail)`);
  }
  // A former global admin is now just a member here, and is treated as one.
  assert.equal((await listed(EX_ADMIN)).sandbox_visible, false, 'former global admin (list)');
  assert.equal((await detail(EX_ADMIN)).sandbox_visible, false, 'former global admin (detail)');
});

test('the platform admin can turn it back on, which restores it for the member', async () => {
  const r = await put(PLATFORM, { show_sandbox: true });
  assert.equal(r.status, 200);
  assert.equal(stored(), 1);
  assert.equal((await listed(MEMBER)).sandbox_visible, true);
  assert.equal((await detail(MEMBER)).sandbox_visible, true);
});

test('the platform admin can turn it off too', async () => {
  assert.equal((await put(PLATFORM, { show_sandbox: false })).status, 200);
  assert.equal((await listed(MEMBER)).sandbox_visible, false);
  assert.equal((await put(OWNER, { show_sandbox: true })).status, 200);
});

test('the MCP update tool enforces the same gate', async () => {
  const { callTool, getToolCatalog } = await import('../server/services/mcpTools.js');
  const tool = getToolCatalog().find(t => t.name === 'appcrane_update_app');
  assert.equal(tool.inputSchema.properties.show_sandbox?.type, 'boolean', 'schema exposes show_sandbox');
  const asUser = (u) => db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);
  // A global admin used to pass the tool's requiredRole gate and reach the
  // handler's own check. That tier is retired, so a former holder now stops at
  // the role gate; only platform admins (allowed) reach the handler.
  await assert.rejects(callTool(asUser(EX_ADMIN), 'appcrane_update_app', { slug: 'sandvis', show_sandbox: false }), /requires platform admin/);
  assert.equal(stored(), 1);
  const out = await callTool(asUser(PLATFORM), 'appcrane_update_app', { slug: 'sandvis', show_sandbox: false });
  const body = out?.content ? JSON.parse(out.content[0].text) : out;
  assert.equal(body.config.show_sandbox, false);
  assert.equal(stored(), 0);
  await callTool(asUser(PLATFORM), 'appcrane_update_app', { slug: 'sandvis', show_sandbox: true });
});

test('the row goes with the app', () => {
  const id = db.prepare("INSERT INTO apps (name,slug,slot) VALUES ('G','sandvis-gone',2)").run().lastInsertRowid;
  db.prepare('INSERT INTO app_settings (app_id, show_sandbox) VALUES (?, 0)').run(id);
  db.prepare('DELETE FROM apps WHERE id = ?').run(id);
  assert.equal(db.prepare('SELECT 1 FROM app_settings WHERE app_id = ?').get(id), undefined);
});

test('the launch surfaces honour sandbox_visible', () => {
  const src = (p) => readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'studio-web/src', p), 'utf8');

  const frame = src('pages/AppFrame.tsx');
  const build = frame.slice(frame.indexOf('function buildStage'), frame.indexOf('interface Props'));
  assert.match(build, /sandbox_visible !== false/);
  assert.match(build, /const sandUrl = sandboxOffered \? appOpenUrl\(app, 'sandbox'\) : ''/, 'member gets no sandbox URL, so no env switch');
  assert.match(build, /const sandLive = sandboxOffered &&/, 'a sandbox-only app must not open sandbox for a member');
  assert.match(frame, /'sand-hidden': ''/);

  const picker = src('components/AppPicker.tsx');
  assert.match(picker, /sandbox_visible !== false/);
  assert.match(picker, /prodLive \|\| !sandboxOffered\(a\) \? 'production' : 'sandbox'/);

  const appsPage = src('pages/Applications.tsx');
  const open = appsPage.slice(appsPage.indexOf('function openAppFrame'), appsPage.indexOf('async function uploadIcon'));
  assert.match(open, /sandbox_visible !== false/);
  assert.match(open, /const sandUrl = sandboxOffered \?/);
  assert.match(appsPage, /env === 'sandbox' && app\.sandbox_visible === false/, 'Sandbox column has no launch link for a member');

  // The bar's switch exists only with both URLs; an empty sand-url removes it.
  const bar = src('topbar-element/CraneAppTopbar.ts');
  assert.match(bar, /const showSwitch {2}= !!\(prodUrl && sandUrl\)/);
  assert.match(bar, /'sand-hidden'/);
  assert.match(bar, /the sandbox URL still works for anyone with access/);

  const manager = src('pages/AppManager.tsx');
  assert.match(manager, /can_change_show_sandbox/);
  assert.match(manager, /show_sandbox: next/);
});
