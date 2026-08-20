import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The fleet memory budget, on the two surfaces an operator actually uses
// (v2.49.0).
//
// August 2026: a container was OOM-killed on a host with ZERO swap while its
// configuration said --memory=512m --memory-swap=1g, i.e. a 512 MB swap budget
// the host could never deliver. The fleet-scale version of the same defect is
// ~25 GB of per-container ceilings committed against a 7.6 GB host. Both are one
// thing: a number that reads as a guarantee and is not one.
//
// So the properties worth pinning are the ones that decide whether the new
// numbers are themselves honest:
//
//   1. A 'warn' does NOT block the update. This is the design decision, not an
//      oversight. The fleet is already ~3x over, so a gate would refuse every
//      ordinary edit from the day it shipped — including edits that REDUCE the
//      total — and a control that has to be disabled to get work done is not a
//      control. The route reports and applies.
//   2. Reporting did not widen the gate. Answering the question is new; who may
//      change a limit is not.
//   3. The MCP tool says, in its description AND in its summary, that these are
//      CONFIGURED ceilings and not measured usage. An agent that reads "25 GB
//      committed on a 7.6 GB host" and relays "the host is using 25 GB" has
//      invented an outage out of a headroom report. That sentence is the tool.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-membudget-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { callTool, getToolCatalog } = await import('../server/services/mcpTools.js');
const { hostMemoryMb } = await import('../server/services/memoryBudget.js');

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}

const platformAdmin = mkUser('platformadmin', 'platform_admin');
// The near-miss: requireAppAccess lets a global admin through, so the
// platform-tier check inside the limit block is the only thing between them and
// the fleet's memory ceilings.
const globalAdmin = mkUser('globaladmin', 'admin');
const plainUser = mkUser('plainuser', 'user');

let nextSlot = 0;
function mkApp(slug, ramMb) {
  const id = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type,resource_limits) VALUES (?,?,?,'managed',?)"
  ).run(slug, slug, ++nextSlot, JSON.stringify({ max_ram_mb: ramMb, max_cpu_percent: 50 })).lastInsertRowid;
  // Both stages get a live deployment. A post-reboot cold start brings both up
  // at once, which is the scenario the committed total describes.
  for (const env of ['production', 'sandbox']) {
    db.prepare("INSERT INTO deployments (app_id,env,status,version) VALUES (?,?,'live','1')").run(id, env);
  }
  return id;
}

const SUBJECT = mkApp('mem-subject', 512);
mkApp('mem-neighbour-a', 512);
mkApp('mem-neighbour-b', 512);
mkApp('mem-neighbour-c', 512);

const appsRoutes = (await import('../server/routes/apps.js')).default;
const { errorHandler } = await import('../server/utils/errors.js');

const api = express();
api.use(express.json());
api.use('/api/apps', appsRoutes);
api.use(errorHandler);

const server = await new Promise((resolve) => {
  const s = api.listen(0, () => resolve(s));
});
const BASE = `http://127.0.0.1:${server.address().port}`;

// Same undici keep-alive trap as test/tcp-ingress-schema.test.js: server.close()
// waits on pooled sockets that never go away.
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.unref();
  server.close();
});

async function req(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': as.key },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: await res.json() };
}

const ramOf = (id) =>
  JSON.parse(db.prepare('SELECT resource_limits FROM apps WHERE id = ?').get(id).resource_limits).max_ram_mb;

const unwrap = (r) => (r?.content ? JSON.parse(r.content[0].text) : r);
const budgetTool = async (u = platformAdmin) => unwrap(await callTool(u, 'appcrane_memory_budget', {}));

// ---------------------------------------------------------------------------
// The MCP tool: registration, gate, and the sentence that is the whole point
// ---------------------------------------------------------------------------

test('appcrane_memory_budget is registered admin-only and read-only', () => {
  const t = getToolCatalog().find((x) => x.name === 'appcrane_memory_budget');
  assert.ok(t, 'appcrane_memory_budget is not registered in the tool catalog');
  assert.equal(t.requiredRole, 'admin',
    'the fleet-wide memory picture is a platform-level read, not an app-scoped one');
  assert.equal(t.readOnly, true,
    'a tool that sums existing rows and changes nothing must be usable by a read-only key');
  assert.equal(t.inputSchema.additionalProperties, false,
    'the schema accepts unknown properties, so a mistyped argument passes silently');
});

test('the description states these are CONFIGURED ceilings, not measured usage', () => {
  const { description } = getToolCatalog().find((x) => x.name === 'appcrane_memory_budget');
  assert.match(description, /configured/i,
    'the description never says the numbers are configured limits');
  assert.match(description, /not measured usage/i,
    'the description does not deny that these are measurements — that is the one misreading which ' +
    'turns a headroom report into a phantom outage');
  assert.match(description, /does NOT mean the host is using/,
    'the description does not spell out the wrong conclusion an agent will otherwise reach from ' +
    '"25 GB committed on a 7.6 GB host"');
});

test('an ordinary user is refused the fleet memory picture by the dispatcher', async () => {
  await assert.rejects(() => callTool(plainUser, 'appcrane_memory_budget', {}), /Forbidden/i,
    "a non-admin could read every app's configured memory ceiling and the host's total RAM");
});

test('a fleet that fits reports it, and still refuses to be read as usage', async () => {
  const b = await budgetTool();
  assert.equal(b.host_mb, hostMemoryMb(), 'the tool is not reporting this host');
  assert.equal(b.over_committed, false,
    `4 apps at 512 MB should fit in ${hostMemoryMb()} MB of host RAM`);
  assert.ok(b.committed_mb > 0, 'nothing was counted at all');
  assert.match(b.summary, /sum of LIMITS, not a measurement/,
    'the summary reports a total with no statement that it is configured rather than observed');
  assert.match(b.does_not_measure, /actual memory usage/);
});

// ---------------------------------------------------------------------------
// The REST surface
// ---------------------------------------------------------------------------

test('changing max_ram_mb answers with memory_budget on the 200', async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/mem-subject', { max_ram_mb: 1024 });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.memory_budget, 'the response carries no memory_budget — the change was silent');
  assert.equal(r.body.memory_budget.level, 'ok',
    'a 1 GB app on a fleet that fits was not reported as ok');
  assert.equal(typeof r.body.memory_budget.message, 'string');
  assert.equal(r.body.memory_budget.budget.host_mb, hostMemoryMb());
  assert.equal(ramOf(SUBJECT), 1024, 'the limit was reported on but not applied');
});

test('an edit that does not touch the limits carries no memory_budget', async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/mem-subject', { description: 'unrelated' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.memory_budget, undefined,
    'every app edit now sums the whole fleet and reports a budget move that did not happen');
});

test('reporting did not widen the gate: a global admin still cannot change a limit', async () => {
  const r = await req(globalAdmin, 'PUT', '/api/apps/mem-subject', { max_ram_mb: 2048 });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  assert.equal(ramOf(SUBJECT), 1024, 'the refused change was applied anyway');
});

// ---------------------------------------------------------------------------
// Over-committed: the state the fleet is ALREADY in
// ---------------------------------------------------------------------------

test('seed a fleet whose configured ceilings exceed any host', () => {
  const insert = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type,resource_limits) VALUES (?,?,?,'managed',?)"
  );
  const dep = db.prepare("INSERT INTO deployments (app_id,env,status,version) VALUES (?,?,'live','1')");
  const limits = JSON.stringify({ max_ram_mb: 16384, max_cpu_percent: 50 });
  db.transaction(() => {
    for (let i = 0; i < 200; i++) {
      const id = insert.run(`bloat-${i}`, `bloat-${i}`, ++nextSlot, limits).lastInsertRowid;
      dep.run(id, 'production');
      dep.run(id, 'sandbox');
    }
  })();
  assert.ok(200 * 16384 > hostMemoryMb(),
    'the seeded fleet does not exceed this host, so nothing below tests over-commitment');
});

test('the tool calls over-commitment by name and denies it is a usage figure', async () => {
  const b = await budgetTool();
  assert.equal(b.over_committed, true,
    'a fleet committing over 3 TB of ceilings on this host did not read as over-committed');
  assert.ok(b.committed_mb > b.host_mb);
  assert.match(b.summary, /OVER-COMMITTED/,
    'the headline state is missing from the line an operator reads first');
  assert.match(b.summary, /sum of LIMITS, not a measurement/,
    'the over-committed summary reports a huge number without saying it is not memory in use — ' +
    'exactly the reading that manufactures an outage');
  assert.match(b.summary, /OOM/,
    'the summary never names what over-commitment actually costs');
});

test("a 'warn' REPORTS and does NOT block — the change is applied", async () => {
  assert.equal(ramOf(SUBJECT), 1024, 'precondition: the subject has not already been raised');

  const r = await req(platformAdmin, 'PUT', '/api/apps/mem-subject', { max_ram_mb: 16384 });

  assert.equal(r.status, 200,
    `an over-committed fleet blocked an ordinary limit change: ${JSON.stringify(r.body)}`);
  assert.equal(r.body.memory_budget.level, 'warn',
    'a 1 GB -> 16 GB increase on a fleet already committed past host RAM was not warned about');
  assert.equal(ramOf(SUBJECT), 16384,
    'the warning ate the update. Reporting is the decision here: the fleet is ALREADY over-committed, ' +
    'so a gate would refuse every ordinary edit — including the ones that reduce the total.');
  assert.equal(r.body.app.resource_limits.max_ram_mb, 16384,
    'the response body does not reflect the change that was applied');
});

test('reducing a limit on an over-committed fleet is a notice, and also applies', async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/mem-subject', { max_ram_mb: 64 });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.memory_budget.level, 'notice',
    'a change that IMPROVES an over-committed fleet was warned about as though it made things worse — ' +
    'that is how a report becomes noise operators learn to ignore');
  assert.equal(ramOf(SUBJECT), 64, 'the reduction was not applied');
});

test('the budget on the response is the same picture the MCP tool reports', async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/mem-subject', { max_cpu_percent: 60 });
  const tool = await budgetTool();
  assert.equal(r.body.memory_budget.budget.host_mb, tool.host_mb);
  assert.equal(r.body.memory_budget.budget.committed_mb, tool.committed_mb,
    'the two surfaces disagree about the same fleet, so one of them is lying to an operator');
});
