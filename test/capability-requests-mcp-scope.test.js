import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// appcrane_list_capability_requests without a slug: a platform admin's key
// whose MCP app scope (or blueprint) covers only some apps lists only those
// apps' requests, the same ceiling every per-app tool applies.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-capreq-scope-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';
after(() => rmSync(process.env.DATA_DIR, { recursive: true, force: true }));

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const store = await import('../server/services/capabilities/store.js');
const { callTool } = await import('../server/services/mcpTools.js');

const mkUser = (n, role) => db.prepare("INSERT INTO users (name,username,email,role,active,kind) VALUES (?,?,?,?,1,'human')").run(n, n, `${n}@t.test`, role).lastInsertRowid;
const mkApp = (s, slot) => db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(s, s, slot).lastInsertRowid;
const admin = mkUser('adm', 'platform_admin');
const owner = mkUser('own', 'user');
const alpha = mkApp('alpha', 1);
const beta = mkApp('beta', 2);
for (const a of [alpha, beta]) db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(a, owner);
const ownerRow = db.prepare('SELECT * FROM users WHERE id = ?').get(owner);
for (const [id, why] of [[alpha, 'alpha needs it'], [beta, 'secret beta plan']]) {
  store.createRequest(db, { app: db.prepare('SELECT * FROM apps WHERE id = ?').get(id), user: ownerRow, capability: 'headless', scope: {}, reason: why, via: 'api' });
}
const tool = async (...a) => JSON.parse((await callTool(...a)).content[0].text);
const adminRow = () => db.prepare('SELECT * FROM users WHERE id = ?').get(admin);

test('an admin key scoped to alpha lists only alpha requests', async () => {
  const scoped = { ...adminRow(), mcp_app_scope: JSON.stringify(['alpha']) };
  const r = await tool(scoped, 'appcrane_list_capability_requests', {}, { id: 1, label: 'k', read_only: false });
  const slugs = r.requests.map((q) => q.app_slug ?? q.slug ?? q.app?.slug);
  assert.ok(r.requests.length >= 1, JSON.stringify(r));
  assert.ok(!JSON.stringify(r).includes('secret beta plan'), `beta leaked: ${JSON.stringify(slugs)}`);
});

test('an unscoped admin still sees the platform-wide queue', async () => {
  const r = await tool(adminRow(), 'appcrane_list_capability_requests', {});
  assert.equal(r.requests.length, 2);
});
