import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// users.mcp_app_scope — the per-user MCP ceiling from migration 040 — was
// silently inert on the one key type that actually exists in the wild.
//
// requireAuth builds req.user for `dhk_mcp_*` keys from a hand-picked column
// list rather than `SELECT *`, and mcp_app_scope was not in it. mcpTools.js
// reads `user.mcp_app_scope`, got undefined, and treated every scoped key as
// unrestricted. The other two credential paths (X-API-Key against
// users.api_key_hash, and Bearer against identity_sessions) both select the
// whole users row, so they always carried the value — which is exactly why the
// bug survived: an operator testing the restriction from the dashboard saw it
// work and concluded the feature was fine.
//
// This file pins the field onto all three auth paths, then drives the real
// JSON-RPC surface to prove the ceiling is enforced on a CALL and not merely
// applied to a listing. Every refusal assertion is paired with a baseline
// assertion in the same fixture, so none of them can pass vacuously by the
// fixture simply being broken.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mcpscope-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { requireAuth } = await import('../server/middleware/auth.js');

initDb();
const db = getDb();

const IN_SCOPE = 'alpha';
const OUT_OF_SCOPE = 'beta';

const appIds = {};
for (const [i, slug] of [IN_SCOPE, OUT_OF_SCOPE].entries()) {
  appIds[slug] = db
    .prepare('INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,?,?)')
    .run(slug, slug, i + 1, 'managed', 'main').lastInsertRowid;
}

let seq = 0;
/**
 * Seed a user with BOTH credential kinds pointing at the same identity, plus a
 * portal session — the three ways requireAuth can build req.user. Owner on both
 * apps, so nothing in these tests is ever refused for lack of a role: the only
 * thing that can refuse is the MCP scope.
 */
function mkUser({ role = 'user', scope = null } = {}) {
  const n = ++seq;
  const apiKey = generateApiKey('dhk_user');
  const uid = db
    .prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind,mcp_app_scope) VALUES (?,?,?,?,1,?,?)')
    .run(`u${n}`, `u${n}@t.test`, role, hashApiKey(apiKey), 'human', scope).lastInsertRowid;

  const mcpKey = generateApiKey('dhk_mcp');
  db.prepare('INSERT INTO user_mcp_keys (user_id,key_hash,label) VALUES (?,?,?)')
    .run(uid, hashApiKey(mcpKey), `k${n}`);

  const bearer = generateApiKey('cc_token');
  db.prepare("INSERT INTO identity_sessions (user_id,token_hash,expires_at) VALUES (?,?,datetime('now','+1 day'))")
    .run(uid, hashApiKey(bearer));

  for (const slug of [IN_SCOPE, OUT_OF_SCOPE]) {
    db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appIds[slug], uid);
  }
  return { id: uid, apiKey, mcpKey, bearer };
}

const scoped      = mkUser({ scope: JSON.stringify([IN_SCOPE]) });
const unscoped    = mkUser({ scope: null });
const lockedOut   = mkUser({ scope: '[]' });
const scopedAdmin = mkUser({ role: 'admin', scope: JSON.stringify([IN_SCOPE]) });

// --- HTTP surface -----------------------------------------------------------
// Mount the MCP router alone. Booting server/index.js would start the email
// worker, health checker and credential checker, which hold the event loop open
// and have nothing to do with authorization.

const mcpRouter = (await import('../server/routes/mcp.js')).default;
const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api/mcp', mcpRouter);
// requireAuth rejects via next(err); without a handler express answers 500 HTML
// and the assertion below would read a stack trace instead of the reason.
httpApp.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message, code: err.code }));

const server = await new Promise((resolve) => {
  const s = httpApp.listen(0, () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;

// undici pools keep-alive sockets and server.close() only stops NEW connections
// — idle pooled sockets would hold the listener open and hang `node --test`
// with every test already passed.
after(() => {
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function rpc(headers, method, params) {
  const res = await fetch(`${BASE}/api/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return res.json();
}

const withMcpKey = (u) => ({ 'X-API-Key': u.mcpKey });
const withApiKey = (u) => ({ 'X-API-Key': u.apiKey });

/** Call appcrane_get_app and report 'ok' or the error text the agent would see. */
async function getApp(headers, slug) {
  const body = await rpc(headers, 'tools/call', { name: 'appcrane_get_app', arguments: { slug } });
  if (body.error) return body.error.message;
  // Prove the success case really returned the app rather than an empty result.
  assert.equal(JSON.parse(body.result.content[0].text).slug, slug);
  return 'ok';
}

async function listedSlugs(headers) {
  const body = await rpc(headers, 'tools/call', { name: 'appcrane_list_apps', arguments: {} });
  assert.equal(body.error, undefined, JSON.stringify(body.error));
  return JSON.parse(body.result.content[0].text).apps.map((a) => a.slug).sort();
}

/** Run requireAuth with the given credential header and hand back req.user. */
function authenticate(headers) {
  const req = { headers, baseUrl: '/api/mcp', path: '/', originalUrl: '/api/mcp' };
  let err = null;
  requireAuth(req, {}, (e) => { err = e || null; });
  assert.equal(err, null, `requireAuth rejected the fixture credential: ${err?.message}`);
  return req.user;
}

// --- 1. the field reaches req.user on every auth path -----------------------

test('a dhk_mcp_* key carries mcp_app_scope onto req.user', () => {
  // The fix. Before it, the hand-picked SELECT omitted the column and this read
  // undefined, so mcpScope() saw nothing to enforce.
  const user = authenticate({ 'x-api-key': scoped.mcpKey });
  assert.equal(user.mcp_app_scope, JSON.stringify([IN_SCOPE]));
});

test('a dhk_mcp_* key for an unscoped user reports null, not undefined', () => {
  // Distinguishes "column selected, value is NULL" from "column never selected".
  // Both are falsy, so only the strict comparison catches a regression that
  // drops the column again while leaving the unscoped tests passing.
  const user = authenticate({ 'x-api-key': unscoped.mcpKey });
  assert.equal(user.mcp_app_scope, null);
});

test('the X-API-Key path carries mcp_app_scope', () => {
  // Never broken — it selects the whole users row. Asserted so the three paths
  // are pinned as consistent: an inconsistency between them is the same bug in
  // a different costume.
  const user = authenticate({ 'x-api-key': scoped.apiKey });
  assert.equal(user.mcp_app_scope, JSON.stringify([IN_SCOPE]));
});

test('the Bearer/identity-session path carries mcp_app_scope', () => {
  const user = authenticate({ authorization: `Bearer ${scoped.bearer}` });
  assert.equal(user.mcp_app_scope, JSON.stringify([IN_SCOPE]));
});

// --- 2. the scope is enforced on a CALL, not just a listing -----------------

test('BASELINE: a scoped key reaches the app named in its scope', async () => {
  // Without this, every refusal below could pass because the fixture is broken.
  assert.equal(await getApp(withApiKey(scoped), IN_SCOPE), 'ok');
});

test('a scoped key is REFUSED on an app outside its scope', async () => {
  const msg = await getApp(withApiKey(scoped), OUT_OF_SCOPE);
  assert.match(msg, /outside this key's MCP scope/,
    'the out-of-scope app was reachable — mcp_app_scope is not being enforced on the call');
});

test('the scope is a ceiling over role: a scoped ADMIN is refused too', async () => {
  // migration 040's whole point — carry full dashboard privileges while using a
  // tightly scoped MCP token. If role could win, the feature is decorative.
  assert.equal(await getApp(withApiKey(scopedAdmin), IN_SCOPE), 'ok');
  assert.match(await getApp(withApiKey(scopedAdmin), OUT_OF_SCOPE), /outside this key's MCP scope/);
});

test('a scoped key also sees only the scoped app in appcrane_list_apps', async () => {
  // Secondary to the refusal above: omission from a listing is discovery, not
  // authorization. Both must hold.
  assert.deepEqual(await listedSlugs(withApiKey(scoped)), [IN_SCOPE]);
});

// --- 3. no regression for the common case (no scope set) -------------------

test('a key with NO scope still reaches every app its role allows', async () => {
  assert.equal(await getApp(withApiKey(unscoped), IN_SCOPE), 'ok');
  assert.equal(await getApp(withApiKey(unscoped), OUT_OF_SCOPE), 'ok');
  assert.deepEqual(await listedSlugs(withApiKey(unscoped)), [IN_SCOPE, OUT_OF_SCOPE].sort());
});

test('an unscoped dhk_mcp_* key still reaches the apps it owns', async () => {
  // Every user on an existing box is in this state, so this is the blast-radius
  // test for the auth.js change: adding the column must not narrow anything.
  assert.equal(await getApp(withMcpKey(unscoped), IN_SCOPE), 'ok');
  assert.equal(await getApp(withMcpKey(unscoped), OUT_OF_SCOPE), 'ok');
});

// --- 4. the empty-scope lockout ---------------------------------------------

test("mcp_app_scope '[]' locks a dhk_mcp_* key out of every tool", async () => {
  // The lockout callTool() has always implemented, reachable for the first time
  // now that the column survives requireAuth. Before the fix this returned the
  // full app payload.
  assert.match(await getApp(withMcpKey(lockedOut), IN_SCOPE), /empty MCP scope/);
  const list = await rpc(withMcpKey(lockedOut), 'tools/call', { name: 'appcrane_list_apps', arguments: {} });
  assert.match(list.error.message, /empty MCP scope/,
    'the lockout must cover every tool, not only the app-addressed ones');
});

test("mcp_app_scope '[]' locks the X-API-Key path out identically", async () => {
  assert.match(await getApp(withApiKey(lockedOut), IN_SCOPE), /empty MCP scope/);
});

// --- 5. the ceiling on the key type that exists ------------------------------

test('a NON-EMPTY scope is enforced on a dhk_mcp_* key', async () => {
  // The contract mcpTools.js states at its own definition of mcpScope: "MCP is
  // restricted to those slugs regardless of role". It did not hold for
  // dhk_mcp_* keys: accessibleSlugsForUser and getAppForUser both returned early
  // on `user._mcpUserKey` — a branch added with user_mcp_keys (migration 043)
  // that never learned about the scope from migration 040 — so the ceiling was
  // skipped and only the owner check ran. Both now consult the scope first.
  //
  // Baseline first: the in-scope app must stay reachable, so a failure below is
  // the ceiling missing rather than the key being broken.
  assert.equal(await getApp(withMcpKey(scoped), IN_SCOPE), 'ok');
  assert.match(await getApp(withMcpKey(scoped), OUT_OF_SCOPE), /outside this key's MCP scope/,
    'a dhk_mcp_* key reached an app outside its mcp_app_scope');
  assert.deepEqual(await listedSlugs(withMcpKey(scoped)), [IN_SCOPE]);
});

// --- 6. the ceiling holds for WRITES, not only reads -------------------------

/** appcrane_update_app on `slug`; 'ok' or the error text the agent would see. */
async function updateApp(headers, slug, args) {
  const body = await rpc(headers, 'tools/call',
    { name: 'appcrane_update_app', arguments: { slug, ...args } });
  return body.error ? body.error.message : 'ok';
}

test('a scoped key cannot MUTATE an app it cannot read', async () => {
  // The dangerous half of the same question. appcrane_update_app looks the app
  // row up itself instead of going through getAppForUser, so hardening that
  // helper left the write path wide open: a key correctly refused READ access to
  // `beta` could still set auth_bypass_paths on it (disabling SSO forward_auth
  // for those prefixes), flip it to public, or rotate its GitHub PAT. That is
  // migration 040's headline persona — a full admin holding a tightly-scoped
  // token — so the scope has to be a ceiling over writes too.
  //
  // Baseline: the same call against the in-scope app must succeed, or the
  // refusal below could be the tool simply not working.
  assert.equal(await updateApp(withMcpKey(scopedAdmin), IN_SCOPE, { description: 'in scope' }), 'ok');

  assert.match(
    await updateApp(withMcpKey(scopedAdmin), OUT_OF_SCOPE,
      { auth_bypass_paths: ['/pwn'], visibility: 'public' }),
    /outside this key's MCP scope/);
  const after = db.prepare('SELECT auth_bypass_paths, visibility FROM apps WHERE slug = ?').get(OUT_OF_SCOPE);
  assert.equal(after.auth_bypass_paths, null, 'the out-of-scope app was mutated anyway');
  assert.notEqual(after.visibility, 'public');
});

// --- 7. the lockout covers every MCP surface ---------------------------------

test("mcp_app_scope '[]' empties the tool catalogue too", async () => {
  // The lockout lived only in callTool, so a key the operator believed dead was
  // refused every call while still being handed the full tools/list catalogue.
  const locked = await rpc(withMcpKey(lockedOut), 'tools/list', {});
  assert.equal(locked.result.tools.length, 0);
  // Control: the same listing for an unscoped key is not empty, so the
  // assertion above cannot pass because tools/list is broken for everyone.
  const open = await rpc(withMcpKey(unscoped), 'tools/list', {});
  assert.ok(open.result.tools.length > 0);
});

test("mcp_app_scope '[]' blocks the GitHub MCP passthrough as well", async () => {
  // Non-`appcrane_*` tool names are proxied to a per-user github-mcp-server
  // container, on a branch that never enters callTool — so a locked-out key
  // could still make AppCrane `docker run` that image on the host. Refused
  // before the spawn now; the test would otherwise sit through the 15s
  // container init timeout.
  const body = await rpc(
    { ...withMcpKey(lockedOut), 'X-Github-Token': 'ghp_not_a_real_token' },
    'tools/call', { name: 'get_me', arguments: {} });
  assert.match(body.error.message, /empty MCP scope/);
});

test('a scoped admin does not read access requests for the whole platform', async () => {
  // appcrane_list_access_requests resolved an admin to "every app" and never
  // consulted the scope, leaking pending requests (with requester names) for
  // apps outside it.
  db.prepare(
    "INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status) VALUES (?,?,?,?,'open')"
  ).run(OUT_OF_SCOPE, scoped.id, 'someone', `Access request for app ${OUT_OF_SCOPE}`);
  db.prepare(
    "INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status) VALUES (?,?,?,?,'open')"
  ).run(IN_SCOPE, scoped.id, 'someone', `Access request for app ${IN_SCOPE}`);

  const body = await rpc(withMcpKey(scopedAdmin), 'tools/call',
    { name: 'appcrane_list_access_requests', arguments: {} });
  const slugs = JSON.parse(body.result.content[0].text).requests.map(r => r.app_slug);
  // In-scope must still be visible, or an empty list would satisfy this test
  // for the wrong reason.
  assert.deepEqual([...new Set(slugs)], [IN_SCOPE]);
});
