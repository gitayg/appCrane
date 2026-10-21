import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// appcrane_delete_app and appcrane_get_audit, driven through their handlers
// with the same user shapes callTool hands them (a personal key arrives as
// user._mcpUserKey). Once the tools are registered in TOOLS, the last test
// also drives them through callTool.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-mcpdel-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getNextSlot } = await import('../server/services/portAllocator.js');
const { deleteAppTool } = await import('../server/services/mcpGaps/deleteAppTool.js');
const { getAuditTool } = await import('../server/services/mcpGaps/getAuditTool.js');
const { logAudit } = await import('../server/middleware/audit.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

let n = 0;
function mkUser(role = 'user') {
  n++;
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(`u${n}`, `u${n}@example.test`, role, `h${n}`).lastInsertRowid;
  return { id, role, name: `u${n}`, kind: 'human' };
}
function mkApp(slug, roles = []) {
  db.prepare("INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)").run(slug, slug, getNextSlot(db));
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  for (const [user, role] of roles) {
    db.prepare('INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)').run(app.id, user.id, role);
  }
  return app;
}
const exists = (slug) => !!db.prepare('SELECT 1 FROM apps WHERE slug = ?').get(slug);
const del = (user, args) => deleteAppTool.handler(user, args);
const audit = (user, args) => getAuditTool.handler(user, args);

const owner = mkUser();
const appAdmin = mkUser();
const member = mkUser();
const stranger = mkUser();
const padmin = mkUser('platform_admin');

test('delete: refused without confirm_slug or with a different one; nothing deleted', async () => {
  mkApp('del-confirm', [[owner, 'owner']]);
  await assert.rejects(del(owner, { slug: 'del-confirm' }), /CONFIRMATION_REQUIRED/);
  await assert.rejects(del(owner, { slug: 'del-confirm', confirm_slug: 'del-confirmx' }), /CONFIRMATION_REQUIRED/);
  assert.equal(exists('del-confirm'), true);
});

test('delete: refused for an app admin, a plain member and a stranger', async () => {
  mkApp('del-nonowner', [[owner, 'owner'], [appAdmin, 'admin'], [member, 'user']]);
  for (const u of [appAdmin, member, stranger]) {
    await assert.rejects(del(u, { slug: 'del-nonowner', confirm_slug: 'del-nonowner' }), /Forbidden/);
  }
  assert.equal(exists('del-nonowner'), true);
});

test('delete: refused for a read-only key and for the coder key, even for the owner', async () => {
  mkApp('del-keys', [[owner, 'owner']]);
  const ro = { ...owner, mcp_read_only: true, _mcpUserKey: { id: 1, read_only: true } };
  await assert.rejects(del(ro, { slug: 'del-keys', confirm_slug: 'del-keys' }), /read-only/);
  const roKeyOnly = { ...owner, _mcpUserKey: { id: 1, read_only: true } };
  await assert.rejects(del(roKeyOnly, { slug: 'del-keys', confirm_slug: 'del-keys' }), /read-only/);
  const coder = { ...owner, coder_key: { slug: 'del-keys' }, _mcpUserKey: { id: 2, coder: { slug: 'del-keys' } } };
  await assert.rejects(del(coder, { slug: 'del-keys', confirm_slug: 'del-keys' }), /coder/);
  assert.equal(exists('del-keys'), true);
});

test('delete: refused outside the MCP app scope, even for a platform admin', async () => {
  mkApp('del-scope', [[owner, 'owner']]);
  const scoped = { ...padmin, mcp_app_scope: '["something-else"]' };
  await assert.rejects(del(scoped, { slug: 'del-scope', confirm_slug: 'del-scope' }), /outside this key's MCP scope/);
  const scopedOwner = { ...owner, mcp_app_scope: '["something-else"]', _mcpUserKey: { id: 3 } };
  await assert.rejects(del(scopedOwner, { slug: 'del-scope', confirm_slug: 'del-scope' }), /outside this key's MCP scope/);
  assert.equal(exists('del-scope'), true);
});

test('delete: refused for the owner when the role matrix withdraws app.delete', async () => {
  mkApp('del-matrix', [[owner, 'owner']]);
  db.prepare("UPDATE role_permissions SET granted = 0 WHERE permission = 'app.delete' AND role = 'owner'").run();
  try {
    await assert.rejects(del(owner, { slug: 'del-matrix', confirm_slug: 'del-matrix' }), /Forbidden/);
  } finally {
    db.prepare("UPDATE role_permissions SET granted = 1 WHERE permission = 'app.delete' AND role = 'owner'").run();
  }
  assert.equal(exists('del-matrix'), true);
});

test('delete: the owner (personal key) deletes; rows go, the deletion is audited', async () => {
  const app = mkApp('del-ok', [[owner, 'owner']]);
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'sandbox', 'K', 'x')").run(app.id);
  const out = await del({ ...owner, _mcpUserKey: { id: 4 } }, { slug: 'del-ok', confirm_slug: 'del-ok' });
  assert.equal(out.deleted, true);
  assert.equal(exists('del-ok'), false);
  assert.equal(db.prepare('SELECT COUNT(*) c FROM env_vars WHERE app_id = ?').get(app.id).c, 0);
  const row = db.prepare("SELECT * FROM audit_log WHERE action = 'app-delete' AND user_id = ? ORDER BY id DESC LIMIT 1").get(owner.id);
  assert.ok(row, 'an app-delete audit row was written');
  assert.deepEqual(JSON.parse(row.detail), { via: 'mcp', slug: 'del-ok' });
});

test('delete: a platform admin deletes; a Crane-hosted repo is kept and reported', async () => {
  const lg = await import('../server/services/localGit.js');
  await lg.createAppRepo('del-local');
  db.prepare("INSERT INTO apps (name, slug, slot, source_type, repo_backend, branch) VALUES ('del-local', 'del-local', ?, 'managed', 'local', 'main')").run(getNextSlot(db));
  const out = await del(padmin, { slug: 'del-local', confirm_slug: 'del-local' });
  assert.equal(out.deleted, true);
  assert.equal(out.local_repo_kept, 'repos/del-local.git');
  assert.equal(existsSync(lg.repoPath('del-local')), true);
});

// ---- appcrane_get_audit ----

const auditApp = mkApp('aud', [[owner, 'owner'], [appAdmin, 'admin'], [member, 'user']]);
const otherApp = mkApp('aud-other', [[stranger, 'owner']]);
for (let i = 1; i <= 7; i++) logAudit(owner.id, auditApp.id, `deploy-${i}`, { step: i });
logAudit(owner.id, auditApp.id, 'mcp.appcrane_set_secret', { tool: 'appcrane_set_secret', args: { key: 'API', value: 'sup3r-s3cret-value' } });
db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail) VALUES (?, ?, 'legacy-token-row', ?)")
  .run(owner.id, auditApp.id, JSON.stringify({ github_token: 'ghp_legacyplaintexttoken0000', note: 'kept' }));
logAudit(stranger.id, otherApp.id, 'deploy-other', { x: 1 });

test('get_audit: owner and app admin may read; a plain member and another app\'s owner may not', async () => {
  assert.ok((await audit(owner, { slug: 'aud' })).entries.length > 0);
  assert.ok((await audit(appAdmin, { slug: 'aud' })).entries.length > 0);
  assert.ok((await audit(padmin, { slug: 'aud' })).entries.length > 0);
  await assert.rejects(audit(member, { slug: 'aud' }), /app\.audit\.view/);
  await assert.rejects(audit(stranger, { slug: 'aud' }), /Forbidden/);
  await assert.rejects(audit({ ...appAdmin, _mcpUserKey: { id: 9 } }, { slug: 'aud' }), /only covers apps you own/);
  await assert.rejects(audit({ ...owner, mcp_app_scope: '["aud-other"]' }, { slug: 'aud' }), /outside this key's MCP scope/);
});

test('get_audit: only this app\'s rows; credential fields are redacted on the way out', async () => {
  const { entries } = await audit(owner, { slug: 'aud', limit: 200 });
  assert.ok(entries.every((e) => !e.action.includes('other')));
  const text = JSON.stringify(entries);
  assert.ok(!text.includes('sup3r-s3cret-value'), 'set_secret value is not returned');
  assert.ok(!text.includes('ghp_legacyplaintexttoken0000'), 'legacy plaintext token is not returned');
  const legacy = entries.find((e) => e.action === 'legacy-token-row');
  assert.equal(legacy.detail.note, 'kept');
});

test('get_audit: before/next_before paginate without gaps or repeats; limit capped; action filter', async () => {
  const seen = [];
  let before;
  for (;;) {
    const page = await audit(owner, { slug: 'aud', limit: 3, ...(before ? { before } : {}) });
    assert.ok(page.entries.length <= 3);
    seen.push(...page.entries.map((e) => e.id));
    if (page.next_before == null) break;
    before = page.next_before;
  }
  const all = db.prepare('SELECT id FROM audit_log WHERE app_id = ? ORDER BY id DESC').all(auditApp.id).map((r) => r.id);
  assert.deepEqual(seen, all);
  assert.equal((await audit(owner, { slug: 'aud', limit: 5000 })).limit, 200);
  const filtered = await audit(owner, { slug: 'aud', action: 'deploy-' });
  assert.equal(filtered.entries.length, 7);
  assert.equal((await audit(owner, { slug: 'aud', action: '%' })).entries.length, 0);
});

test('registered tools pass through callTool gates (skipped until registered in TOOLS)', async (t) => {
  const { getToolCatalog, callTool } = await import('../server/services/mcpTools.js');
  const names = getToolCatalog().map((x) => x.name);
  if (!names.includes('appcrane_delete_app') || !names.includes('appcrane_get_audit')) {
    t.skip('appcrane_delete_app / appcrane_get_audit not registered yet');
    return;
  }
  mkApp('del-gate', [[owner, 'owner']]);
  await assert.rejects(callTool(owner, 'appcrane_delete_app', { slug: 'del-gate', confirm_slug: 'del-gate' }, { id: 5, read_only: true }), /read-only/);
  await assert.rejects(callTool({ ...owner, coder_key: { slug: 'del-gate' } }, 'appcrane_delete_app', { slug: 'del-gate', confirm_slug: 'del-gate' }, { id: 6, coder: { slug: 'del-gate' } }), /Forbidden/);
  assert.equal(exists('del-gate'), true);
  const r = await callTool(owner, 'appcrane_get_audit', { slug: 'aud', limit: 2 }, { id: 7, read_only: true });
  assert.equal(JSON.parse(r.content[0].text).entries.length, 2);
});
