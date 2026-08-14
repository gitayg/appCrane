import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// TCP (layer-4) ingress — schema, allocator, and the gate that keeps a host
// port off the internet (v2.42.0).
//
// An app with ingress_type='tcp' has its container port published at
// 0.0.0.0:<public_port> with Caddy entirely out of the path. That second door
// has NONE of what v2.35-v2.41 built into the first one: no forward_auth, no
// identity headers, no per-request audit, no rate limiting, no security
// headers, no TLS from AppCrane. Every one of those controls assumes Caddy is
// the only way in.
//
// So two invariants carry the whole feature and both are pinned here:
//   1. Two apps can never hold one host port — enforced by a partial UNIQUE
//      index, not merely by the allocator's read-then-write.
//   2. Only a PLATFORM admin may open that door. An app owner setting their own
//      auth_mode is one thing; publishing a port on the host is a platform-tier
//      decision. The authz tests below drive the REAL route rather than reading
//      the source, because that gate is the control.
//
// AppCrane publishes the port; it deliberately does NOT open the firewall.
// Nothing here asserts otherwise — that stays a separate operator step so a
// mis-click in the dashboard cannot put an app on the internet.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-tcping-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.CRANE_DOMAIN = 'crane.test.local';
// PUT calls reloadCaddy(), which logs the whole generated Caddyfile at info in
// mock mode. Same code path, quieter output.
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const {
  PUBLIC_PORT_MIN, PUBLIC_PORT_MAX, INGRESS_TYPES,
  effectiveIngressType, validateIngressType, isTcpApp, publicPortForApp,
  getIngressForApp, slotPortConflict, assertPublicPortAssignable,
  allocatePublicPort, assignPublicPort, releasePublicPort,
} = await import('../server/services/tcpIngress.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const { isPortSafe } = await import('../server/services/blockedPorts.js');

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

function mkUser(name, role) {
  const key = generateApiKey('dhk_user');
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')"
  ).run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key, role };
}

const platformAdmin = mkUser('platformadmin', 'platform_admin');
// A global admin is the interesting near-miss: requireAppAccess lets this tier
// through, so only the ingress gate itself stands between them and an open port.
const globalAdmin = mkUser('globaladmin', 'admin');
const owner = mkUser('appowner', 'user');
const member = mkUser('appmember', 'user');
const outsider = mkUser('outsider', 'user');

let nextSlot = 0;
function mkApp(slug) {
  return db.prepare('INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,?)')
    .run(slug, slug, ++nextSlot, 'managed').lastInsertRowid;
}

const APP_GATE = mkApp('tcp-gate');     // the authz subject
const APP_FLIP = mkApp('tcp-flip');     // flipped tcp -> http by a platform admin
const APP_LEGACY = mkApp('tcp-legacy'); // never touched; stands in for every pre-072 row
const APP_A = mkApp('tcp-alloc-a');
const APP_B = mkApp('tcp-alloc-b');
const APP_C = mkApp('tcp-alloc-c');

for (const uid of [owner.id, member.id]) {
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(APP_GATE, uid);
  db.prepare('INSERT INTO app_users (app_id,user_id) VALUES (?,?)').run(APP_FLIP, uid);
}
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')")
  .run(APP_GATE, owner.id);
db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')")
  .run(APP_FLIP, owner.id);

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

// Same undici keep-alive trap as test/app-auth-mode-visibility.test.js:
// server.close() waits on pooled sockets that never go away, and POST /api/apps
// schedules health-check intervals that hold the loop open on their own.
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

const rowOf = (id) => db.prepare('SELECT ingress_type, public_port, description FROM apps WHERE id = ?').get(id);
/** Everything back to http/unallocated, so a test can assert an exact port. */
const clearAllPorts = () => db.prepare('UPDATE apps SET public_port = NULL').run();

// ---------------------------------------------------------------------------
// Migration 072 — the columns and the index that make double-booking impossible
// ---------------------------------------------------------------------------

test('072 adds ingress_type NOT NULL DEFAULT http and a nullable public_port', () => {
  const cols = db.prepare('PRAGMA table_info(apps)').all();
  const ingress = cols.find(c => c.name === 'ingress_type');
  const port = cols.find(c => c.name === 'public_port');

  assert.ok(ingress, 'migration 072 did not add apps.ingress_type');
  assert.equal(ingress.type, 'TEXT');
  assert.equal(ingress.notnull, 1,
    'ingress_type must be NOT NULL — "never set" cannot be a third state alongside http and tcp');
  assert.equal(ingress.dflt_value, "'http'",
    'the default must be http: a row that predates 072 has to mean "Caddy fronts this", not "publish a port"');

  assert.ok(port, 'migration 072 did not add apps.public_port');
  assert.equal(port.type, 'INTEGER');
  assert.equal(port.notnull, 0, 'public_port must be nullable — an http app holds no port');
  assert.equal(port.dflt_value, null, 'public_port must default to NULL, never to a real port');
});

test('the enum is validated in code, not by a CHECK constraint', () => {
  // The auth_mode precedent: SQLite cannot ALTER a CHECK, so a constraint here
  // would force a full table rebuild the next time the vocabulary grows.
  const sql = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='apps'").get().sql;
  assert.ok(!/CHECK\s*\(\s*ingress_type/i.test(sql),
    'ingress_type gained a CHECK constraint — validate in tcpIngress.js instead');
});

test('the unique index on public_port is UNIQUE and PARTIAL', () => {
  const idx = db.prepare('PRAGMA index_list(apps)').all().find(i => i.name === 'idx_apps_public_port');
  assert.ok(idx, 'idx_apps_public_port is missing — nothing stops two apps sharing a host port');
  assert.equal(idx.unique, 1, 'idx_apps_public_port is not UNIQUE');
  assert.equal(idx.partial, 1,
    'the index must be partial (WHERE public_port IS NOT NULL) so unallocated apps stay out of it');
});

test('the database itself refuses to give two apps the same public port', () => {
  // Not a test of the allocator's politeness. The allocator picks the lowest
  // free port by reading and then writing; only this index makes the loser of
  // a race fail instead of double-booking a host port, which would surface as
  // one app's `docker run` dying with no visible cause.
  clearAllPorts();
  db.prepare('UPDATE apps SET public_port = ? WHERE id = ?').run(31500, APP_A);
  assert.throws(
    () => db.prepare('UPDATE apps SET public_port = ? WHERE id = ?').run(31500, APP_B),
    /UNIQUE constraint failed/i,
    'a second app was allowed to claim a host port already published by another',
  );
  assert.equal(rowOf(APP_B).public_port, null);
  clearAllPorts();
});

test('many apps hold NULL public_port at once — the partial index does not collide on them', () => {
  clearAllPorts();
  const nulls = db.prepare('SELECT COUNT(*) AS n FROM apps WHERE public_port IS NULL').get().n;
  assert.ok(nulls >= 6,
    'every http app carries a NULL public_port; a non-partial unique index would have rejected the second one');
});

test('an existing http app is completely unaffected by 072', () => {
  const row = rowOf(APP_LEGACY);
  assert.equal(row.ingress_type, 'http');
  assert.equal(row.public_port, null);
  assert.equal(isTcpApp(row), false);
  assert.equal(publicPortForApp(row), null,
    'an http app must publish nothing — this is the value docker.js binds on');
  assert.deepEqual(getIngressForApp(db, APP_LEGACY), { ingress_type: 'http', public_port: null });
});

// ---------------------------------------------------------------------------
// ingress_type vocabulary
// ---------------------------------------------------------------------------

test("ingress_type accepts only 'http' and 'tcp'", () => {
  assert.deepEqual(INGRESS_TYPES, ['http', 'tcp']);
  for (const ok of ['http', 'tcp']) {
    assert.equal(validateIngressType(ok), ok);
  }
});

test('every other ingress_type value is a validation error, not a silent fallback', () => {
  // Case matters: 'TCP' must not sneak through and then read back as http,
  // which would leave an operator convinced they had published a port.
  for (const bad of ['TCP', 'HTTP', 'udp', 'https', 'headless', 'forward_auth', '', ' tcp', 'tcp ', null, undefined, 0, 1, true, ['tcp'], { ingress_type: 'tcp' }]) {
    assert.throws(
      () => validateIngressType(bad),
      (e) => e.status === 400 && e.code === 'VALIDATION',
      `validateIngressType(${JSON.stringify(bad)}) did not reject`,
    );
  }
});

test('the effective type is reported, so a legacy or hand-edited row reads as what the runtime does', () => {
  // Only the literal 'tcp' gets a published host port, so only the literal
  // 'tcp' may be reported as tcp.
  assert.equal(effectiveIngressType('tcp'), 'tcp');
  for (const raw of ['http', null, undefined, '', 'TCP', 'layer4', 'raw']) {
    assert.equal(effectiveIngressType(raw), 'http', `effectiveIngressType(${JSON.stringify(raw)})`);
  }
});

test('a tcp app with no allocation yet publishes nothing rather than port null', () => {
  assert.equal(publicPortForApp({ ingress_type: 'tcp', public_port: null }), null);
  assert.equal(publicPortForApp({ ingress_type: 'tcp' }), null);
  assert.equal(publicPortForApp({ ingress_type: 'tcp', public_port: '31000' }), null,
    'a string is not a port — docker.js must not interpolate it into a publish binding');
  assert.equal(publicPortForApp({ ingress_type: 'tcp', public_port: 31000 }), 31000);
  assert.equal(publicPortForApp({ ingress_type: 'http', public_port: 31000 }), null,
    'a stale port on an http app must not be published');
});

// ---------------------------------------------------------------------------
// The allocator
// ---------------------------------------------------------------------------

test('allocation stays inside the dedicated 31000-31999 range', () => {
  clearAllPorts();
  assert.equal(PUBLIC_PORT_MIN, 31000);
  assert.equal(PUBLIC_PORT_MAX, 31999);
  const port = allocatePublicPort(db, APP_A);
  assert.ok(Number.isInteger(port));
  assert.ok(port >= PUBLIC_PORT_MIN && port <= PUBLIC_PORT_MAX,
    `allocated ${port}, outside the range the operator's single firewall rule covers`);
  clearAllPorts();
});

test('allocation is lowest-free-first', () => {
  clearAllPorts();
  assert.equal(allocatePublicPort(db, APP_A), PUBLIC_PORT_MIN);
  clearAllPorts();
});

test('allocation skips a port another app already holds', () => {
  clearAllPorts();
  assignPublicPort(db, APP_A, 31000);
  assert.equal(allocatePublicPort(db, APP_B), 31001, 'the allocator handed out a port already published');
  clearAllPorts();
});

test('allocation fills the lowest hole rather than appending', () => {
  // Dense, predictable allocations: an operator reading `ss -lntp` can tell at a
  // glance which ports are in play.
  clearAllPorts();
  assignPublicPort(db, APP_A, 31000);
  assignPublicPort(db, APP_B, 31002);
  assert.equal(allocatePublicPort(db, APP_C), 31001);
  clearAllPorts();
});

test('re-allocating for an app that already holds a port returns the same port', () => {
  // This is what makes a published port survive redeploys, renames and slot
  // changes: nothing in those paths recomputes it. A client pinned by MDM to
  // the port must never find it moved.
  clearAllPorts();
  const first = assignPublicPort(db, APP_A);
  assert.equal(assignPublicPort(db, APP_A), first);
  assert.equal(assignPublicPort(db, APP_A), first);
  clearAllPorts();
});

test('an allocated port is never one getPortsForSlot() could produce', () => {
  // The two schemes must not overlap: a silent collision means two containers
  // fighting for one host port, with the loser's deploy failing at `docker run`
  // for no visible reason. "Could produce" covers the slots that exist AND the
  // slots getNextSlot() can still hand out without any further app being made.
  clearAllPorts();
  const port = allocatePublicPort(db, APP_A);
  const maxSlot = db.prepare('SELECT MAX(slot) AS m FROM apps').get().m || 0;
  for (let slot = 1; slot <= maxSlot + 1000; slot++) {
    const ports = getPortsForSlot(slot);
    for (const key of ['prod_fe', 'prod_be', 'sand_fe', 'sand_be']) {
      assert.notEqual(ports[key], port,
        `public port ${port} is also slot ${slot}'s ${key} — two containers would fight for it`);
    }
  }
  clearAllPorts();
});

test('every port in the range is checked against the WHATWG blocked list, not assumed clear', () => {
  // Nothing in 31000-31999 is blocked today, but the list is external and can
  // grow; a blocked port here would mean a health probe that silently never
  // connects, which is exactly the slot-23 -> 4045 outage all over again.
  for (let p = PUBLIC_PORT_MIN; p <= PUBLIC_PORT_MAX; p++) {
    if (!isPortSafe(p)) {
      assert.throws(() => assertPublicPortAssignable(db, p, APP_A),
        `blocked port ${p} was accepted as a public port`);
    }
  }
});

test('a port outside the range is refused even when the operator names it explicitly', () => {
  clearAllPorts();
  for (const bad of [PUBLIC_PORT_MIN - 1, PUBLIC_PORT_MAX + 1, 0, 80, 443, 5001, 65536, -1]) {
    assert.throws(
      () => assertPublicPortAssignable(db, bad, APP_A),
      (e) => e.status === 400 || e.status === 409,
      `port ${bad} was accepted`,
    );
  }
  for (const bad of [31000.5, '31000', null, undefined, NaN, Infinity]) {
    assert.throws(
      () => assertPublicPortAssignable(db, bad, APP_A),
      (e) => e.code === 'VALIDATION',
      `non-integer ${JSON.stringify(bad)} was accepted`,
    );
  }
});

test('a port another app holds is refused by name, with PORT_TAKEN', () => {
  clearAllPorts();
  assignPublicPort(db, APP_A, 31007);
  assert.throws(
    () => assertPublicPortAssignable(db, 31007, APP_B),
    (e) => e.status === 409 && e.code === 'PORT_TAKEN' && /tcp-alloc-a/.test(e.message),
  );
  // ...but the app that already holds it may re-assert it.
  assert.equal(assertPublicPortAssignable(db, 31007, APP_A), 31007);
  clearAllPorts();
});

test('a public port that a real slot would claim is refused, and the range can be exhausted', () => {
  // The slot formula is unbounded — sand_fe = 3000 + 2N reaches 31000 at slot
  // 14000 — so the reserved band is not automatically clear. Verified rather
  // than assumed: with a slot-14000 app present, 31000 is a clash and the
  // allocator refuses loudly instead of double-booking a host port.
  clearAllPorts();
  const far = db.prepare('INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,?)')
    .run('far', 'tcp-far-slot', 14000, 'managed').lastInsertRowid;
  try {
    assert.equal(getPortsForSlot(14000).sand_fe, 31000, 'the premise of this test moved');
    const clash = slotPortConflict(db, 31000);
    assert.ok(clash, 'slotPortConflict missed a port a live slot already owns');
    assert.throws(
      () => assertPublicPortAssignable(db, 31000, APP_A),
      (e) => e.status === 409 && e.code === 'PORT_RESERVED',
    );
    assert.throws(
      () => allocatePublicPort(db, APP_A),
      (e) => e.status === 409 && e.code === 'NO_PUBLIC_PORT',
      'the allocator handed out a port from a band the slot scheme has reached — ' +
      'refusing is the intended trade, double-booking is not',
    );
  } finally {
    db.prepare('DELETE FROM apps WHERE id = ?').run(far);
    clearAllPorts();
  }
});

test('slotPortConflict flags a port belonging to a slot the allocator could still hand out', () => {
  clearAllPorts();
  const maxSlot = db.prepare('SELECT MAX(slot) AS m FROM apps').get().m || 0;
  const reachable = getPortsForSlot(maxSlot + 1).prod_be;
  assert.ok(slotPortConflict(db, reachable),
    `port ${reachable} belongs to the very next slot getNextSlot() will issue`);
  assert.equal(slotPortConflict(db, PUBLIC_PORT_MIN), null,
    'the public range must be clear of the slot scheme at ordinary slot counts');
});

test('releasePublicPort puts the port back in the pool', () => {
  clearAllPorts();
  assignPublicPort(db, APP_A, 31000);
  releasePublicPort(db, APP_A);
  assert.equal(rowOf(APP_A).public_port, null);
  assert.equal(allocatePublicPort(db, APP_B), 31000, 'a released port was not reusable');
  clearAllPorts();
});

// ---------------------------------------------------------------------------
// AUTHZ — the control that keeps a host port off the internet
// ---------------------------------------------------------------------------
//
// Driven through the real route on purpose. This gate is the whole reason a
// dashboard mis-click cannot publish an app; asserting it by reading the source
// would prove nothing about what an HTTP caller can actually do.

const NON_PLATFORM = [
  ['the app owner', () => owner],
  ['a plain assigned member', () => member],
  // requireAppAccess waves this tier straight through to the handler, so the
  // ingress gate is the only thing standing between them and an open port.
  ['a global admin who is not a platform admin', () => globalAdmin],
];

for (const [label, who] of NON_PLATFORM) {
  test(`${label} cannot set ingress_type='tcp'`, async () => {
    clearAllPorts();
    db.prepare("UPDATE apps SET ingress_type = 'http' WHERE id = ?").run(APP_GATE);
    const r = await req(who(), 'PUT', '/api/apps/tcp-gate', { ingress_type: 'tcp' });
    assert.equal(r.status, 403, `${label} was allowed to publish a host port: ${JSON.stringify(r.body)}`);
    const row = rowOf(APP_GATE);
    assert.equal(row.ingress_type, 'http', 'the refused request still changed ingress_type');
    assert.equal(row.public_port, null, 'the refused request still allocated a host port');
  });

  test(`${label} cannot set a public_port`, async () => {
    clearAllPorts();
    const r = await req(who(), 'PUT', '/api/apps/tcp-gate', { public_port: 31234 });
    assert.equal(r.status, 403, `${label} was allowed to choose a host port: ${JSON.stringify(r.body)}`);
    assert.equal(rowOf(APP_GATE).public_port, null);
  });
}

test('the gate covers public_port on an app that is ALREADY tcp, not just the initial flip', async () => {
  // Half a gate is no gate: if only ingress_type were checked, an owner could
  // move a published app onto any port in the band once an admin had opened it.
  const setup = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { ingress_type: 'tcp' });
  assert.equal(setup.status, 200, JSON.stringify(setup.body));
  const opened = rowOf(APP_GATE).public_port;
  assert.ok(Number.isInteger(opened));

  for (const [label, who] of NON_PLATFORM) {
    const r = await req(who(), 'PUT', '/api/apps/tcp-gate', { public_port: 31777 });
    assert.equal(r.status, 403, `${label} moved a published port: ${JSON.stringify(r.body)}`);
    assert.equal(rowOf(APP_GATE).public_port, opened, `${label} moved the published port`);
  }

  // And they cannot close it either — that is still a platform-tier change.
  for (const [label, who] of NON_PLATFORM) {
    const r = await req(who(), 'PUT', '/api/apps/tcp-gate', { ingress_type: 'http' });
    assert.equal(r.status, 403, `${label} changed ingress_type on a published app`);
    assert.equal(rowOf(APP_GATE).ingress_type, 'tcp');
  }

  await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { ingress_type: 'http' });
});

test('a mixed payload is refused whole — no partial write slips past the gate', async () => {
  // The owner may absolutely edit `description`. Smuggling ingress_type into
  // the same request must reject the entire PUT, not apply the allowed half.
  clearAllPorts();
  db.prepare("UPDATE apps SET ingress_type = 'http', description = 'before' WHERE id = ?").run(APP_GATE);
  const r = await req(owner, 'PUT', '/api/apps/tcp-gate', { description: 'after', ingress_type: 'tcp' });
  assert.equal(r.status, 403, JSON.stringify(r.body));
  const row = rowOf(APP_GATE);
  assert.equal(row.description, 'before', 'the allowed half of a refused request was written anyway');
  assert.equal(row.ingress_type, 'http');
});

test('the 403 is about ingress alone — the owner can still edit the app', async () => {
  // Guards against "fixing" the authz tests by breaking the route. If PUT were
  // simply broken for owners, every assertion above would pass for the wrong
  // reason.
  const r = await req(owner, 'PUT', '/api/apps/tcp-gate', { description: 'owner still works' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(rowOf(APP_GATE).description, 'owner still works');
});

test('an unassigned outsider is stopped before the ingress gate is even reached', async () => {
  const r = await req(outsider, 'PUT', '/api/apps/tcp-gate', { ingress_type: 'tcp' });
  assert.equal(r.status, 403);
  assert.equal(rowOf(APP_GATE).ingress_type, 'http');
});

test('a platform admin can open the port — the gate is a gate, not a lockout', async () => {
  clearAllPorts();
  db.prepare("UPDATE apps SET ingress_type = 'http' WHERE id = ?").run(APP_GATE);
  const r = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { ingress_type: 'tcp' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.app.ingress_type, 'tcp');
  assert.ok(r.body.app.public_port >= PUBLIC_PORT_MIN && r.body.app.public_port <= PUBLIC_PORT_MAX,
    'flipping to tcp must allocate a port from the dedicated range');
  assert.equal(rowOf(APP_GATE).public_port, r.body.app.public_port,
    'the response reported a port the database does not hold');
});

test('opening a port writes its own audit entry, findable by action name', async () => {
  // "A port was opened on the host" is the one change here an operator reviewing
  // the log must be able to find by name, not by reading a generic app-update
  // diff.
  const entry = db.prepare(
    "SELECT * FROM audit_log WHERE action = 'app-ingress-change' AND app_id = ? ORDER BY id DESC LIMIT 1"
  ).get(APP_GATE);
  assert.ok(entry, 'no app-ingress-change audit entry was written for a port that was opened');
  assert.equal(entry.user_id, platformAdmin.id);
  const detail = JSON.parse(entry.detail);
  assert.equal(detail.from.ingress_type, 'http');
  assert.equal(detail.to.ingress_type, 'tcp');
  assert.ok(Number.isInteger(detail.to.public_port), 'the audit entry does not record which port was opened');
});

test('a platform admin can name a specific port, and a bad one is rejected on its merits', async () => {
  const ok = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { public_port: 31900 });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.app.public_port, 31900);

  const outOfRange = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { public_port: 8080 });
  assert.equal(outOfRange.status, 400, JSON.stringify(outOfRange.body));
  assert.equal(rowOf(APP_GATE).public_port, 31900, 'a rejected port change was applied anyway');
});

test('a bad ingress_type is a 400 from the route, even for a platform admin', async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { ingress_type: 'udp' });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.equal(r.body.error?.code || r.body.code, 'VALIDATION');
  assert.equal(rowOf(APP_GATE).ingress_type, 'tcp');
});

test('public_port on an app that is not tcp is refused', async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/tcp-legacy', { public_port: 31950 });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.equal(rowOf(APP_LEGACY).public_port, null);
});

test("public_port: null is refused — releasing has exactly one path", async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { public_port: null });
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.match(JSON.stringify(r.body), /ingress_type/,
    'the error must point the caller at the one supported way to release a port');
  assert.equal(rowOf(APP_GATE).public_port, 31900, 'the port was released through an unsupported path');
});

test('two apps cannot be pointed at one port through the API either', async () => {
  const r = await req(platformAdmin, 'PUT', '/api/apps/tcp-flip', { ingress_type: 'tcp', public_port: 31900 });
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(rowOf(APP_FLIP).public_port, null);
});

// ---------------------------------------------------------------------------
// The port is PINNED to the app, not pooled
//
// An operator sets this port in the app's settings and hands it to clients by
// hand or by MDM. Returning it to a shared pool on a flip would let a later app
// be allocated the same number, and every client still configured for it would
// reach a DIFFERENT app — a silent cross-app redirection, which is worse than a
// dead port. So a flip to http stops publishing, and the reservation stays with
// the app that owns it.
// ---------------------------------------------------------------------------

test('flipping back to http keeps the port reserved to the same app', async () => {
  const before = rowOf(APP_GATE);
  assert.equal(before.ingress_type, 'tcp');
  assert.equal(before.public_port, 31900);

  const r = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { ingress_type: 'http' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.app.ingress_type, 'http');
  assert.equal(r.body.app.public_port, null,
    "an http app reports no public port — it is not published, whatever the reservation says");

  // The reservation survives on the row even though the payload reports null.
  // That is the pinning: flip back and the app gets its own number again.
  assert.equal(rowOf(APP_GATE).public_port, 31900,
    'the reservation was dropped — another app could now be allocated this port while ' +
    'clients pinned to it still point here');
  assert.equal(publicPortForApp(rowOf(APP_GATE)), null,
    'an http app must not be published, regardless of the reservation it holds');
});

test('the reserved port is NOT handed to another app', async () => {
  // APP_GATE flipped to http above but still reserves 31900. Another app asking
  // for that exact number must be refused, not double-booked.
  const taken = await req(platformAdmin, 'PUT', '/api/apps/tcp-flip', { ingress_type: 'tcp', public_port: 31900 });
  assert.equal(taken.status, 409, JSON.stringify(taken.body));
  assert.notEqual(rowOf(APP_FLIP).public_port, 31900,
    'two apps now hold one host port — the second deploy would die on "port is already allocated"');
});

test('re-pinning a live tcp app to a different port is refused', async () => {
  // The gap the flip tests missed. Overwriting public_port in place drops the
  // old number from the row, and the row is the ONLY thing reserving it — so
  // the allocator hands a still-bound port to the next app and clients pinned
  // to it reach someone else. pendingPortRelease() cannot see this path: it
  // reports only on an app already flipped to http.
  // Its own app: the shared fixtures are flipped back and forth by neighbouring
  // tests, and this one has to add a live deployment, which would leak into them.
  const APP_REPIN = mkApp('tcp-repin');
  const on = await req(platformAdmin, 'PUT', '/api/apps/tcp-repin', { ingress_type: 'tcp' });
  assert.equal(on.status, 200, JSON.stringify(on.body));
  const held = rowOf(APP_REPIN).public_port;
  assert.ok(Number.isInteger(held), 'the app did not end up pinned');

  // The guard is deliberately scoped to an app that is actually PUBLISHING:
  // a port allocated before the first deploy is bound by nothing, so re-pinning
  // it then is safe and is the common case. Establish the dangerous state.
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(APP_REPIN);

  const r = await req(platformAdmin, 'PUT', '/api/apps/tcp-repin', { ingress_type: 'tcp', public_port: held + 7 });
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(r.body.error.code, 'PORT_STILL_HELD');
  assert.equal(rowOf(APP_REPIN).public_port, held, 'the app moved off a port it still binds');

  // And the old number must not have become allocatable in the attempt.
  const other = mkApp('tcp-repin-other');
  const taken = await req(platformAdmin, 'PUT', '/api/apps/tcp-repin-other', { ingress_type: 'tcp', public_port: held });
  assert.equal(taken.status, 409, 'the still-held port was handed to another app');
  assert.notEqual(rowOf(other).public_port, held);
});

test('flipping back to tcp returns the same port, not a new one', async () => {
  const again = await req(platformAdmin, 'PUT', '/api/apps/tcp-gate', { ingress_type: 'tcp' });
  assert.equal(again.status, 200, JSON.stringify(again.body));
  assert.equal(again.body.app.public_port, 31900,
    'the app was given a different port than the one its clients are configured for');
});

test('the release also fires an audit entry', () => {
  const entries = db.prepare(
    "SELECT detail FROM audit_log WHERE action = 'app-ingress-change' AND app_id = ? ORDER BY id DESC"
  ).all(APP_GATE).map(r => JSON.parse(r.detail));
  const release = entries.find(d => d.from.ingress_type === 'tcp' && d.to.ingress_type === 'http');
  assert.ok(release, 'closing a published port was not audited under its own action');
  assert.equal(release.to.public_port, null);
});

// ---------------------------------------------------------------------------
// Both fields are REPORTED, not merely accepted
// ---------------------------------------------------------------------------
//
// auth_mode spent three versions write-only and that blind spot is what made
// "my app gets no identity headers" a recurring triage. A port published
// straight onto the host is a bigger thing for an operator to be unable to see.

function assertLegible(payload, where) {
  assert.ok(payload && typeof payload === 'object', `${where}: no app payload`);
  assert.ok('ingress_type' in payload, `${where}: ingress_type is absent from the payload`);
  assert.ok('public_port' in payload, `${where}: public_port is absent from the payload`);
  assert.ok(INGRESS_TYPES.includes(payload.ingress_type),
    `${where}: ingress_type is ${JSON.stringify(payload.ingress_type)}`);
  assert.ok(payload.public_port === null || Number.isInteger(payload.public_port),
    `${where}: public_port must be an integer or null, got ${JSON.stringify(payload.public_port)}`);
  if (payload.ingress_type !== 'tcp') {
    assert.equal(payload.public_port, null,
      `${where}: a non-tcp app reported a public port it does not publish`);
  }
}

test('every read path reports both fields, and they agree', async () => {
  await req(platformAdmin, 'PUT', '/api/apps/tcp-flip', { ingress_type: 'tcp' });

  const list = (await req(platformAdmin, 'GET', '/api/apps')).body.apps;
  for (const slug of ['tcp-gate', 'tcp-flip', 'tcp-legacy']) {
    const listed = list.find(a => a.slug === slug);
    assertLegible(listed, `GET /api/apps (${slug})`);

    const detail = (await req(platformAdmin, 'GET', `/api/apps/${slug}`)).body.app;
    assertLegible(detail, `GET /api/apps/${slug}`);
    assert.equal(detail.ingress_type, listed.ingress_type, `${slug}: list and detail disagree on ingress_type`);
    assert.equal(detail.public_port, listed.public_port, `${slug}: list and detail disagree on public_port`);

    const noop = await req(platformAdmin, 'PUT', `/api/apps/${slug}`, {});
    assert.equal(noop.body.message, 'No changes', `${slug}: expected the no-op branch`);
    assertLegible(noop.body.app, `PUT /api/apps/${slug} (no changes)`);
    assert.equal(noop.body.app.ingress_type, detail.ingress_type,
      `${slug}: the no-op PUT response disagrees with every other serializer`);
    assert.equal(noop.body.app.public_port, detail.public_port);
  }

  assert.equal(list.find(a => a.slug === 'tcp-flip').ingress_type, 'tcp',
    'a published app must be visibly published in the list an operator scans');
});

test('an ordinary member sees the ingress fields too — they just cannot change them', async () => {
  const detail = (await req(member, 'GET', '/api/apps/tcp-flip')).body.app;
  assertLegible(detail, 'GET /api/apps/tcp-flip as a member');
  assert.equal(detail.ingress_type, 'tcp');
});

test('a newly created app reports http and no port, rather than absent fields', async () => {
  const r = await req(platformAdmin, 'POST', '/api/apps', {
    name: 'TCP New', slug: 'tcp-new', source_type: 'managed',
  });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assertLegible(r.body.app, 'POST /api/apps');
  assert.equal(r.body.app.ingress_type, 'http',
    'a new app is fronted by Caddy; the create response must say so rather than leave it to be inferred');
  assert.equal(r.body.app.public_port, null);
});

test('a stale public_port on an http app reads back as null everywhere', async () => {
  // Defence in depth against the mixed state the route can leave behind if
  // allocation fails after the ingress_type write commits: the column may hold
  // a value the runtime will not publish, and no reader may claim otherwise.
  db.prepare("UPDATE apps SET ingress_type = 'http', public_port = 31990 WHERE id = ?").run(APP_LEGACY);
  try {
    const detail = (await req(platformAdmin, 'GET', '/api/apps/tcp-legacy')).body.app;
    assert.equal(detail.public_port, null);
    assert.equal(detail.ingress_type, 'http');
    const listed = (await req(platformAdmin, 'GET', '/api/apps')).body.apps.find(a => a.slug === 'tcp-legacy');
    assert.equal(listed.public_port, null);
    assert.deepEqual(getIngressForApp(db, APP_LEGACY), { ingress_type: 'http', public_port: null });
  } finally {
    db.prepare('UPDATE apps SET public_port = NULL WHERE id = ?').run(APP_LEGACY);
  }
});
