import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Deploy on push is for LOCAL managed repos only. A GitHub-backed managed app
// (repo_backend NULL — every managed app that predates migration 090) must get
// the push response it always got: no auto_deploy key, the same `next`, and no
// deployment, delivery or audit row — even with deploy-on-push switched on for
// both environments in its webhook_configs row.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-dopgh-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = '8'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { setServiceConfig } = await import('../server/services/githubService.js');
const { callTool } = await import('../server/services/mcpTools.js');
const { getNextSlot } = await import('../server/services/portAllocator.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const OWNER = 'svc-owner';
const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('g','g@x.test','platform_admin','h',1,'human')").run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'g' };
setServiceConfig({ owner: OWNER, token: 'ghp_SHIM0123456789abcdefABCDEF0123', visibility: 'private', enabled: true }, adminId);

const json = (status, body) => ({ ok: status < 300, status, statusText: String(status), headers: new Headers(), text: async () => JSON.stringify(body), json: async () => body });
global.fetch = async (url, init = {}) => {
  const method = (init.method || 'GET').toUpperCase();
  const p = /^https:\/\/api\.github\.com(\/[^?]*)/.exec(String(url))?.[1] || '';
  if (method === 'GET' && /^\/repos\/svc-owner\/AMC_[a-z0-9-]+$/.test(p)) return json(200, { default_branch: 'main' });
  if (method === 'GET' && /\/git\/ref\/heads\/main$/.test(p)) return json(200, { object: { sha: '1'.repeat(40) } });
  if (method === 'GET' && /\/git\/commits\/1{40}$/.test(p)) return json(200, { tree: { sha: '2'.repeat(40) } });
  if (method === 'POST' && /\/git\/blobs$/.test(p)) return json(201, { sha: '3'.repeat(40) });
  if (method === 'POST' && /\/git\/trees$/.test(p)) return json(201, { sha: '4'.repeat(40) });
  if (method === 'POST' && /\/git\/commits$/.test(p)) return json(201, { sha: '5'.repeat(40) });
  if (method === 'PATCH' && /\/git\/refs\/heads\/main$/.test(p)) return json(200, { object: { sha: '5'.repeat(40) } });
  if (method === 'GET' && /\/contents\/p\.txt$/.test(p)) return json(200, { type: 'file', encoding: 'base64', content: Buffer.from('one\n').toString('base64'), sha: '6'.repeat(40) });
  return json(599, { message: `unrouted ${method} ${p}` });
};

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}

const slug = 'dopgh-app';
const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES (?, ?, ?, 'managed', ?, 'main')")
  .run(slug, slug, getNextSlot(db), `https://github.com/${OWNER}/AMC_${slug}`).lastInsertRowid;
db.prepare("INSERT INTO webhook_configs (app_id, token, secret, auto_deploy_sandbox, auto_deploy_prod) VALUES (?, 'tok-dopgh', 'sec', 1, 1)").run(appId);
const count = (table) => db.prepare(`SELECT COUNT(*) n FROM ${table} WHERE app_id = ?`).get(appId).n;

test('push, assemble and patch to a NULL-marker managed app: unchanged response, no deploy on push', async () => {
  const push = await tool('appcrane_push_to_managed_app', { slug, files: [{ path: 'p.txt', content: 'one\n' }] });
  assert.equal('auto_deploy' in push, false);
  assert.equal(push.next, `Files pushed. Next: appcrane_deploy slug="${slug}" stage="sandbox" to ship.`);
  assert.deepEqual(Object.keys(push), ['app', 'commit', 'branch', 'files', 'message', 'next']);

  await tool('appcrane_managed_push_chunk', { slug, path: 'b.txt', session: 'dopgh-s', part: 1, of: 1, content: 'x' });
  const asm = await tool('appcrane_managed_assemble', { slug, session: 'dopgh-s', path: 'b.txt' });
  assert.equal('auto_deploy' in asm, false);
  assert.equal(asm.next, `File committed. Next: appcrane_deploy slug="${slug}" stage="sandbox" to ship.`);
  assert.deepEqual(Object.keys(asm), ['app', 'commit', 'branch', 'file', 'next']);

  const patch = await tool('appcrane_managed_patch', { slug, path: 'p.txt', unified_diff: '@@ -1 +1 @@\n-one\n+two' });
  assert.equal('auto_deploy' in patch, false);
  assert.equal(patch.next, `Patch committed. Next: appcrane_deploy slug="${slug}" stage="sandbox" to ship.`);
  assert.deepEqual(Object.keys(patch), ['app', 'commit', 'branch', 'file', 'next']);

  assert.equal(count('deployments'), 0, 'a GitHub-backed push deployed');
  assert.equal(count('webhook_deliveries'), 0);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE app_id = ? AND action LIKE '%deploy%'").get(appId).n, 0);
});
