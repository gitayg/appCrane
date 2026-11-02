import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Deploy advice through the real MCP handlers: a local managed app, real git,
// and a docker shim that reports every container as absent (so appcrane_cp
// takes the host path and no deploy builds anything).

const ROOT = mkdtempSync(join(tmpdir(), 'crane-advice-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), `#!/bin/sh
if [ "$1" = inspect ]; then echo "Error: No such object: $4" >&2; exit 1; fi
echo "no docker" >&2; exit 1
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { _resetDeployAdvice } = await import('../server/services/deployAdvice.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

global.fetch = async () => ({ ok: true, status: 200, headers: new Headers(), text: async () => '{}', json: async () => ({}) });

const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('advadmin','adv@x.test','platform_admin','h',1,'human')",
).run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'advadmin' };

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}

const ctxPath = (slug) => join(ROOT, 'apps', slug, 'agent-context.md');
const MARKER = '<!-- appcrane-advice:single-file-pushes -->';
const count = (s, sub) => s.split(sub).length - 1;

await tool('appcrane_create_managed_app', { name: 'Advice One', slug: 'adv-one', description: 'advice' });

test('push: no advice for two single-file pushes, single-file-pushes advice on the third, context note once', async () => {
  _resetDeployAdvice();
  const p1 = await tool('appcrane_push_to_managed_app', { slug: 'adv-one', files: [{ path: 'a.js', content: '1' }] });
  const p2 = await tool('appcrane_push_to_managed_app', { slug: 'adv-one', files: [{ path: 'b.js', content: '2' }] });
  assert.equal('advice' in p1, false, 'a first push must carry no advice field');
  assert.equal('advice' in p2, false);
  assert.equal(existsSync(ctxPath('adv-one')) && readFileSync(ctxPath('adv-one'), 'utf8').includes(MARKER), false);

  const p3 = await tool('appcrane_push_to_managed_app', { slug: 'adv-one', files: [{ path: 'c.js', content: '3' }] });
  assert.ok(Array.isArray(p3.advice), `third push has no advice: ${JSON.stringify(p3)}`);
  assert.equal(p3.advice.length, 1);
  assert.equal(p3.advice[0].rule, 'single-file-pushes');
  assert.equal(p3.advice[0].evidence.pushes, 3);
  assert.equal(count(readFileSync(ctxPath('adv-one'), 'utf8'), MARKER), 1);

  // Still inside the window: keeps showing, and the note is not written again.
  const p4 = await tool('appcrane_managed_patch', {
    slug: 'adv-one', path: 'a.js', unified_diff: '--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-1\n+11',
  });
  assert.equal(p4.advice?.[0]?.rule, 'single-file-pushes');
  assert.equal(p4.advice[0].evidence.pushes, 4);
  assert.equal(count(readFileSync(ctxPath('adv-one'), 'utf8'), MARKER), 1);

  const app = await tool('appcrane_get_app', { slug: 'adv-one' });
  assert.equal(app.advice?.[0]?.rule, 'single-file-pushes');
});

test('push: one batched push carries no single-file advice; a >64 KB inline file gets large-inline-file', async () => {
  _resetDeployAdvice();
  const big = 'x'.repeat(64 * 1024 + 1);
  const res = await tool('appcrane_push_to_managed_app', {
    slug: 'adv-one', files: [{ path: 'big.js', content: big }, { path: 'd.js', content: 'd' }, { path: 'e.js', content: 'e' }],
  });
  assert.deepEqual(res.advice.map((a) => a.rule), ['large-inline-file']);
  assert.deepEqual(res.advice[0].evidence.files, [{ path: 'big.js', bytes: 64 * 1024 + 1 }]);
});

test('get_deploy_log / wait_deploy: a failed build on a missing export with another push nearby gets half-pushed-build', async () => {
  _resetDeployAdvice();
  const appId = db.prepare("SELECT id FROM apps WHERE slug = 'adv-one'").get().id;
  const push = await tool('appcrane_push_to_managed_app', { slug: 'adv-one', files: [{ path: 'f.js', content: 'f' }] });
  const dep = db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, log, finished_at, started_at)
    VALUES (?, 'sandbox', 'failed', 'deadbeef', ?, datetime('now'), datetime('now', '-1 minute'))`)
    .run(appId, 'vite build\n[MISSING_EXPORT] "x" is not exported by "src/f.js"\n').lastInsertRowid;
  assert.ok(push.commit.sha);

  const logRes = await tool('appcrane_get_deploy_log', { deployment_id: Number(dep) });
  assert.deepEqual(logRes.advice.map((a) => a.rule), ['half-pushed-build']);
  assert.equal(logRes.advice[0].evidence.deployment_id, Number(dep));

  const waitRes = await tool('appcrane_wait_deploy', { deployment_id: Number(dep) });
  assert.equal(waitRes.advice?.[0]?.rule, 'half-pushed-build');
  assert.match(readFileSync(ctxPath('adv-one'), 'utf8'), /<!-- appcrane-advice:half-pushed-build -->/);

  // A restart forgets the in-memory ring; the managed-push delivery log still
  // carries the pushes, so the advice survives it.
  _resetDeployAdvice();
  assert.ok(db.prepare("SELECT COUNT(*) AS n FROM webhook_deliveries WHERE app_id = ? AND event = 'managed-push'").get(appId).n > 0);
  const afterRestart = await tool('appcrane_get_deploy_log', { deployment_id: Number(dep) });
  assert.equal(afterRestart.advice?.[0]?.rule, 'half-pushed-build');

  // Same failure, but the only push is the deployment's own commit: no advice.
  _resetDeployAdvice();
  db.prepare('DELETE FROM webhook_deliveries WHERE app_id = ?').run(appId);
  const own = db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, log, finished_at)
    VALUES (?, 'sandbox', 'failed', ?, 'Cannot find module ./g', datetime('now'))`).run(appId, push.commit.sha.slice(0, 8)).lastInsertRowid;
  const { recordPush } = await import('../server/services/deployAdvice.js');
  recordPush('adv-one', { files: 1, commit: push.commit.sha });
  const ownRes = await tool('appcrane_get_deploy_log', { deployment_id: Number(own) });
  assert.equal('advice' in ownRes, false, JSON.stringify(ownRes.advice));
});

test('cp: writing into a /data folder that did not exist gets upload-created-state-dir; an existing one does not', async () => {
  const first = await tool('appcrane_cp', { slug: 'adv-one', path: 'state/db.json', content: '{}' });
  assert.equal(first.written_via, 'host');
  assert.deepEqual(first.advice?.map((a) => a.rule), ['upload-created-state-dir']);
  assert.deepEqual(first.advice[0].evidence.created_dirs, ['/data/state']);
  const second = await tool('appcrane_cp', { slug: 'adv-one', path: 'state/other.json', content: '{}' });
  assert.equal('advice' in second, false);
  const top = await tool('appcrane_cp', { slug: 'adv-one', path: 'top.json', content: '{}' });
  assert.equal('advice' in top, false);
});

test('context note never fails the push: an agent context at the size cap is left alone and the push still succeeds', async () => {
  _resetDeployAdvice();
  await tool('appcrane_create_managed_app', { name: 'Advice Two', slug: 'adv-two', description: 'cap' });
  mkdirSync(join(ROOT, 'apps', 'adv-two'), { recursive: true });
  const full = 'x'.repeat(256 * 1024 - 10);
  writeFileSync(ctxPath('adv-two'), full);
  let last;
  for (const f of ['a', 'b', 'c']) last = await tool('appcrane_push_to_managed_app', { slug: 'adv-two', files: [{ path: `${f}.js`, content: f }] });
  assert.ok(last.commit.sha);
  assert.equal(last.advice?.[0]?.rule, 'single-file-pushes');
  assert.equal(readFileSync(ctxPath('adv-two'), 'utf8'), full, 'over-cap note must be skipped, not written');
});

test('a read-only caller sees half-pushed-build advice but does not get the note written into the agent context', async () => {
  _resetDeployAdvice();
  await tool('appcrane_create_managed_app', { name: 'Advice Viewer', slug: 'adv-viewer', description: 'advice' });
  const appId = db.prepare("SELECT id FROM apps WHERE slug = 'adv-viewer'").get().id;
  await tool('appcrane_push_to_managed_app', { slug: 'adv-viewer', files: [{ path: 'h.js', content: 'h' }] });
  const dep = db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, log, finished_at, started_at)
    VALUES (?, 'sandbox', 'failed', 'cafebabe', 'Cannot find module ./h2', datetime('now'), datetime('now', '-1 minute'))`)
    .run(appId).lastInsertRowid;
  const viewerId = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('advviewer','view@x.test','user','h2',1,'human')",
  ).run().lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'user')").run(appId, viewerId);
  const viewer = { id: viewerId, role: 'user', name: 'advviewer' };
  const before = existsSync(ctxPath('adv-viewer')) ? readFileSync(ctxPath('adv-viewer'), 'utf8') : '';

  const r = await callTool(viewer, 'appcrane_get_deploy_log', { deployment_id: Number(dep) });
  const res = JSON.parse(r.content[0].text);
  assert.ok(!r.isError, r.content[0].text);
  assert.equal(res.advice?.[0]?.rule, 'half-pushed-build');
  const now = existsSync(ctxPath('adv-viewer')) ? readFileSync(ctxPath('adv-viewer'), 'utf8') : '';
  assert.equal(now, before);
});
