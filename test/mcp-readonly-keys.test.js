import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// v2.44.0 read-only personal MCP keys (user_mcp_keys.read_only, migration 074).
//
// A personal MCP key authenticates AS its issuer, so handing one to a triage or
// monitoring agent handed that agent deploy, secret-write, role-grant and
// delete. `read_only` is the "look but don't touch" half of the capability
// split, enforced once in the MCP dispatcher against a per-tool `readOnly: true`
// opt-in.
//
// The failure this file exists to prevent is NOT "the flag is wrong" — it is
// "the flag never arrives". users.mcp_app_scope shipped inert for four releases
// because requireAuth builds req.user for `dhk_mcp_*` keys from a hand-picked
// column list and the column was missing from it (fixed in v2.42.1, pinned by
// test/mcp-app-scope.test.js). read_only travels that exact path. So the first
// assertions here are about the column reaching req.user, and every enforcement
// assertion is driven through the real JSON-RPC dispatcher rather than read off
// the source, with a paired positive baseline so nothing can pass vacuously.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mcpro-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);

// Re-export the private TOOLS registry so the "unclassified tool" test can add a
// genuinely new tool — the only way to test the fail-closed DEFAULT rather than
// re-testing the 24 tools that happen to be write-classified today. The hook
// must be installed before mcpTools.js is first imported; every importer then
// shares the one patched instance, so a tool pushed here is reachable over the
// real HTTP surface. module.registerHooks landed in Node 22.15; if it is
// missing the two synthetic-tool tests skip and the rest of the file still runs.
let TOOLS = null;
try {
  const { registerHooks } = await import('node:module');
  if (typeof registerHooks === 'function') {
    registerHooks({
      load(url, context, nextLoad) {
        const result = nextLoad(url, context);
        if (url.endsWith('/server/services/mcpTools.js')) {
          result.source = `${result.source.toString()}\nexport { TOOLS as __TOOLS_FOR_TEST };\n`;
        }
        return result;
      },
    });
  }
} catch (_) { /* older runtime: synthetic-tool tests skip below */ }

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { requireAuth } = await import('../server/middleware/auth.js');
const mcpTools = await import('../server/services/mcpTools.js');
const { callTool, getToolCatalog } = mcpTools;
TOOLS = mcpTools.__TOOLS_FOR_TEST ?? null;

initDb();
const db = getDb();

const SLUG = 'alpha';
const appId = db
  .prepare('INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,?,?)')
  .run(SLUG, SLUG, 1, 'managed', 'main').lastInsertRowid;

let seq = 0;

/**
 * Seed a user who owns the app, plus a portal session. `keys` describes the
 * personal MCP keys to issue: `readOnly` uses the current INSERT, `legacy` uses
 * the EXACT pre-v2.44.0 column list (no read_only named) so the DEFAULT 0
 * backfill is exercised the way every key already in the field was written.
 */
function mkUser({ role = 'user' } = {}) {
  const n = ++seq;
  const uid = db
    .prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(`u${n}`, `u${n}@t.test`, role, hashApiKey(generateApiKey('dhk_user')), 'human').lastInsertRowid;
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(appId, uid);

  const bearer = generateApiKey('cc_token');
  db.prepare("INSERT INTO identity_sessions (user_id,token_hash,expires_at) VALUES (?,?,datetime('now','+1 day'))")
    .run(uid, hashApiKey(bearer));

  const issue = (readOnly) => {
    const key = generateApiKey('dhk_mcp');
    const id = db
      .prepare('INSERT INTO user_mcp_keys (user_id,key_hash,label,read_only) VALUES (?,?,?,?)')
      .run(uid, hashApiKey(key), `k${n}-${readOnly ? 'ro' : 'full'}`, readOnly ? 1 : 0).lastInsertRowid;
    return { key, id };
  };
  const legacy = () => {
    const key = generateApiKey('dhk_mcp');
    const id = db
      .prepare('INSERT INTO user_mcp_keys (user_id,key_hash,label) VALUES (?,?,?)')
      .run(uid, hashApiKey(key), `k${n}-legacy`).lastInsertRowid;
    return { key, id };
  };

  return { id: uid, bearer, ro: issue(true), full: issue(false), legacy: legacy() };
}

const admin = mkUser({ role: 'admin' });
const plain = mkUser({ role: 'user' });

// --- HTTP surface -----------------------------------------------------------
// Mount the two routers alone. Booting server/index.js would start the email
// worker, health checker and credential checker, which hold the event loop open
// and have nothing to do with authorization.

const mcpRouter = (await import('../server/routes/mcp.js')).default;
const keysRouter = (await import('../server/routes/userMcpKeys.js')).default;
const httpApp = express();
httpApp.use(express.json());
httpApp.use('/api/mcp', mcpRouter);
httpApp.use('/api', keysRouter);
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

const hdr = (k) => ({ 'X-API-Key': k.key });

/** Run requireAuth with the given credential header and hand back the whole req. */
function authenticate(headers) {
  const req = { headers, baseUrl: '/api/mcp', path: '/', originalUrl: '/api/mcp' };
  let err = null;
  requireAuth(req, {}, (e) => { err = e || null; });
  assert.equal(err, null, `requireAuth rejected the fixture credential: ${err?.message}`);
  return req;
}

/** appcrane_update_app on the fixture app; 'ok' or the error text an agent sees. */
async function setDescription(headers, description) {
  const body = await rpc(headers, 'tools/call',
    { name: 'appcrane_update_app', arguments: { slug: SLUG, description } });
  return body.error ? body.error.message : 'ok';
}

const descriptionNow = () => db.prepare('SELECT description FROM apps WHERE slug = ?').get(SLUG).description;

const RO_REFUSAL = /changes state and this MCP key is read-only/;

// --- 1. the flag reaches req.user -------------------------------------------

test('a read-only dhk_mcp_* key carries read_only onto req.user', () => {
  // The whole feature hangs on this one line of requireAuth's hand-picked
  // SELECT. Drop `umk.read_only` from it and row.read_only is undefined, `!!`
  // makes it false, and every read-only key in the fleet silently becomes
  // full-access — the mcp_app_scope bug of v2.42.1, one release later.
  const req = authenticate({ 'x-api-key': admin.ro.key });
  assert.equal(req.user.mcp_read_only, true);
  assert.equal(req.user_mcp_key.read_only, true,
    'the key view lost the flag; callTool receives this object as its 4th argument');
});

test('a full-access dhk_mcp_* key reports read_only false on both views', () => {
  // Control for the assertion above: it must be reading the row, not a constant.
  const req = authenticate({ 'x-api-key': admin.full.key });
  assert.equal(req.user.mcp_read_only, false);
  assert.equal(req.user_mcp_key.read_only, false);
});

test('the DB really stores 1 for the read-only key and 0 for the full one', () => {
  // Pins the fixture itself: if both rows were 0, every refusal test below would
  // be asserting against a key that is not actually read-only.
  const rows = db.prepare('SELECT id, read_only FROM user_mcp_keys WHERE id IN (?,?,?)')
    .all(admin.ro.id, admin.full.id, admin.legacy.id);
  const byId = Object.fromEntries(rows.map((r) => [r.id, r.read_only]));
  assert.equal(byId[admin.ro.id], 1);
  assert.equal(byId[admin.full.id], 0);
  assert.equal(byId[admin.legacy.id], 0, 'the pre-v2.44.0 INSERT must land on the DEFAULT');
});

// --- 2. a write is refused, and nothing is written ---------------------------

test('BASELINE: a full-access key can write through the real dispatcher', async () => {
  // Without this the refusal below could pass because the tool, the fixture or
  // the app row is broken rather than because the key is read-only.
  assert.equal(await setDescription(hdr(admin.full), 'written-by-full-key'), 'ok');
  assert.equal(descriptionNow(), 'written-by-full-key');
});

test('a read-only key is REFUSED on a write tool and the row is unchanged', async () => {
  const before = descriptionNow();
  const msg = await setDescription(hdr(admin.ro), 'written-by-read-only-key');
  assert.match(msg, RO_REFUSAL, 'a read-only key mutated an app through MCP');
  assert.match(msg, /appcrane_update_app/, 'the refusal must name the tool the agent called');
  assert.equal(descriptionNow(), before, 'refused, yet the write landed anyway');
});

test('the refusal is written to the audit log with ok:false', async () => {
  // A silently-refused agent call is an operator support ticket; the trail is
  // how it gets diagnosed.
  const row = db.prepare(
    "SELECT detail FROM audit_log WHERE action = 'mcp.appcrane_update_app' AND user_id = ? ORDER BY id DESC LIMIT 1"
  ).get(admin.id);
  const detail = JSON.parse(row.detail);
  assert.equal(detail.ok, false);
  assert.match(detail.error, RO_REFUSAL);
});

test('the read-only gate runs BEFORE the role gate', async () => {
  // appcrane_update_app is requiredRole 'admin' and `plain` is not an admin, so
  // both gates would refuse. The credential's own restriction has to be the
  // reason reported, otherwise an admin's read-only key (which passes the role
  // gate) and a normal user's would be explained by different rules.
  const msg = await setDescription(hdr(plain.ro), 'nope');
  assert.match(msg, RO_REFUSAL);
  assert.doesNotMatch(msg, /requires admin/);
});

// --- 3. reads still work -----------------------------------------------------

test('a read-only key still reaches the read tools', async () => {
  const body = await rpc(hdr(admin.ro), 'tools/call', { name: 'appcrane_get_app', arguments: { slug: SLUG } });
  assert.equal(body.error, undefined, JSON.stringify(body.error));
  assert.equal(JSON.parse(body.result.content[0].text).slug, SLUG);

  const list = await rpc(hdr(admin.ro), 'tools/call', { name: 'appcrane_list_apps', arguments: {} });
  assert.equal(list.error, undefined, JSON.stringify(list.error));
  assert.ok(JSON.parse(list.result.content[0].text).apps.some((a) => a.slug === SLUG));
});

// --- 4. no regression for keys that already exist ----------------------------

test('a key issued by the PRE-v2.44.0 INSERT keeps full access', async () => {
  // Every personal MCP key on every existing box is this row shape: written
  // before the column existed and backfilled by ADD COLUMN ... DEFAULT 0. If
  // this fails, the release breaks every agent in the fleet at once.
  const req = authenticate({ 'x-api-key': admin.legacy.key });
  assert.equal(req.user.mcp_read_only, false);
  assert.equal(await setDescription(hdr(admin.legacy), 'written-by-legacy-key'), 'ok');
  assert.equal(descriptionNow(), 'written-by-legacy-key');
});

test('the column is NOT NULL DEFAULT 0 and no existing row is null', () => {
  // The backfill guarantee behind the test above, asserted at the schema level
  // so a future table rebuild that drops the default is caught here rather than
  // by a key that mysteriously stops working.
  const col = db.prepare("PRAGMA table_info(user_mcp_keys)").all().find((c) => c.name === 'read_only');
  assert.ok(col, 'migration 074 did not run');
  assert.equal(col.notnull, 1);
  assert.equal(String(col.dflt_value), '0');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM user_mcp_keys WHERE read_only IS NULL').get().n, 0);
});

test('a NULL read_only means full access, not read-only', async () => {
  // NOT NULL keeps NULL out of this table today, but the enforcement is a
  // truthiness test rather than `=== 1` precisely so any other path producing a
  // null-ish value fails OPEN on capability instead of bricking a working key.
  // Driven straight at the dispatcher because the DB will not hold the value.
  const req = authenticate({ 'x-api-key': admin.full.key });
  const user = { ...req.user, mcp_read_only: null };
  const result = await callTool(user, 'appcrane_update_app',
    { slug: SLUG, description: 'written-with-null-flag' }, { id: admin.full.id, read_only: null });
  assert.ok(result.content[0].text.includes(SLUG));
  assert.equal(descriptionNow(), 'written-with-null-flag');
});

// --- 5. the classification drives the gate, uniformly ------------------------

test('EVERY write-classified tool is refused to a read-only key', async () => {
  // Proves the gate reads the per-tool flag rather than a curated list of names
  // that drifts as tools are added. The refusal happens before the handler, so
  // none of these calls touch anything.
  const req = authenticate({ 'x-api-key': admin.ro.key });
  const writeTools = getToolCatalog().filter((t) => !t.readOnly);
  assert.ok(writeTools.length > 10, `expected a substantial write surface, saw ${writeTools.length}`);
  for (const t of writeTools) {
    await assert.rejects(
      () => callTool(req.user, t.name, {}, req.user_mcp_key),
      RO_REFUSAL,
      `${t.name} is write-classified but was not refused to a read-only key`,
    );
  }
});

test('tools/list advertises exactly the read tools to a read-only key', async () => {
  // Secondary to the refusal above — omission from a catalogue is discovery, not
  // authorization — but an agent shown a tool it can never call burns turns on it.
  const readOnlyNames = new Set(getToolCatalog().filter((t) => t.readOnly).map((t) => t.name));
  const ro = await rpc(hdr(admin.ro), 'tools/list', {});
  const full = await rpc(hdr(admin.full), 'tools/list', {});
  const roNames = ro.result.tools.map((t) => t.name);

  assert.ok(roNames.length > 0, 'a read-only key was shown no tools at all');
  assert.ok(roNames.length < full.result.tools.length,
    'the read-only catalogue is not narrower than the full one');
  for (const name of roNames) {
    assert.ok(readOnlyNames.has(name), `${name} is write-classified but was advertised to a read-only key`);
  }
});

// --- 6. the fail-closed default, on a tool that did not exist yet ------------

const SYNTHETIC_UNCLASSIFIED = 'appcrane_zz_test_unclassified';
const SYNTHETIC_READONLY = 'appcrane_zz_test_readonly';
let syntheticRan = false;

function pushSynthetic(name, extra) {
  TOOLS.push({
    name,
    description: 'test-only tool registered at runtime',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    requiredRole: 'any',
    ...extra,
    handler: async () => { syntheticRan = true; return { ran: true }; },
  });
}

after(() => {
  if (!TOOLS) return;
  for (let i = TOOLS.length - 1; i >= 0; i--) {
    if (TOOLS[i].name.startsWith('appcrane_zz_test_')) TOOLS.splice(i, 1);
  }
});

test('tool #45: a tool with NO readOnly marker is refused to a read-only key',
  { skip: TOOLS ? false : 'needs module.registerHooks (Node >= 22.15) to reach the tool registry' },
  async () => {
    // The safe default is the actual protection here: the classification is an
    // opt-IN, so the next author to add a tool and never read the comment
    // produces a blocked read tool (a support ticket) rather than a new mutation
    // handed silently to every read-only key already in the field.
    pushSynthetic(SYNTHETIC_UNCLASSIFIED, {});

    // Baseline: the tool really is wired into the live dispatcher, so the
    // refusal below cannot be "unknown tool" wearing a different hat.
    syntheticRan = false;
    const okBody = await rpc(hdr(admin.full), 'tools/call', { name: SYNTHETIC_UNCLASSIFIED, arguments: {} });
    assert.equal(okBody.error, undefined, JSON.stringify(okBody.error));
    assert.equal(syntheticRan, true);

    syntheticRan = false;
    const roBody = await rpc(hdr(admin.ro), 'tools/call', { name: SYNTHETIC_UNCLASSIFIED, arguments: {} });
    assert.match(roBody.error.message, RO_REFUSAL);
    assert.equal(syntheticRan, false, 'the handler ran despite the refusal');
  });

test('a new tool that DOES declare readOnly is allowed through',
  { skip: TOOLS ? false : 'needs module.registerHooks (Node >= 22.15) to reach the tool registry' },
  async () => {
    // Pairs with the test above: proves the refusal came from the missing marker
    // and not merely from the tool being unfamiliar to the gate.
    pushSynthetic(SYNTHETIC_READONLY, { readOnly: true });
    syntheticRan = false;
    const body = await rpc(hdr(admin.ro), 'tools/call', { name: SYNTHETIC_READONLY, arguments: {} });
    assert.equal(body.error, undefined, JSON.stringify(body.error));
    assert.equal(syntheticRan, true);
  });

// --- 7. rotation cannot widen a read-only key --------------------------------

test('rotating a read-only key returns a key that is still read-only', async () => {
  // Rotation replaces the secret, not the capability. If it reset the flag,
  // "rotate the key I pasted into that agent" would quietly hand that agent
  // deploy and secret-write rights — and rotation is the one operation an
  // operator performs on a key they already believe is safe.
  const res = await fetch(`${BASE}/api/me/mcp-keys/${admin.ro.id}/rotate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${admin.bearer}` },
    body: JSON.stringify({ read_only: false }),
  });
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.ok(body.api_key.startsWith('dhk_mcp_'));

  const rotated = { key: body.api_key };
  assert.equal(authenticate({ 'x-api-key': rotated.key }).user.mcp_read_only, true);
  const before = descriptionNow();
  assert.match(await setDescription(hdr(rotated), 'widened-by-rotation'), RO_REFUSAL);
  assert.equal(descriptionNow(), before);
});
