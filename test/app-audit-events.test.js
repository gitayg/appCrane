import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// App audit events (services/appAudit/*, routes/appAuditService.js,
// routes/appAudit.js, migration 205): a hosted app's server writes structured
// audit events with its own APPCRANE_SERVICE_TOKEN; they are bound to that
// app, deduped by idempotency key, bounded, sealed into the audit chain, and
// readable only by the people allowed to see that app's audit trail. Real
// requests through the real routers over a socket.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-app-audit-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { errorHandler } = await import('../server/utils/errors.js');
const { issueServiceToken } = await import('../server/services/appServiceToken.js');
const { identitySecretFor, signIdentityV2 } = await import('../server/services/identitySignature.js');
const chain = await import('../server/services/auditChain.js');
const retention = await import('../server/services/appAudit/retention.js');
const svc = await import('../server/routes/appAuditService.js');
initDb();
const db = getDb();

function mkUser(name, role = 'user') {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')")
    .run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid);
  return { id, key, name };
}
let slot = 7100;
const mkApp = (slug) => Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'managed')").run(`App ${slug}`, slug, ++slot).lastInsertRowid);
const assign = (appId, u, role) => db.prepare('INSERT OR REPLACE INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, u.id, role);

const admin = mkUser('aaadmin', 'platform_admin');
const owner = mkUser('aaowner');
const appAdmin = mkUser('aaappadmin');
const member = mkUser('aamember');
const outsider = mkUser('aaoutsider');
const ALPHA = mkApp('aa-alpha');
const BETA = mkApp('aa-beta');
assign(ALPHA, owner, 'owner');
assign(ALPHA, appAdmin, 'admin');
assign(ALPHA, member, 'user');
assign(BETA, outsider, 'owner');
const alphaToken = issueServiceToken(ALPHA);
const betaToken = issueServiceToken(BETA);
for (const [a, act] of [[ALPHA, 'invoice.paid'], [ALPHA, 'user.signed_in'], [ALPHA, 'doc.shared'], [BETA, 'report.run']]) {
  db.prepare('INSERT INTO app_audit_event_types (app_id, action) VALUES (?, ?)').run(a, act);
}

const api = express();
api.use('/api/service/audit', svc.default);
api.use(express.json());
api.use('/api', (await import('../server/routes/appAudit.js')).default);
api.use(errorHandler);
const server = await new Promise((r) => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });

async function write(body, headers = {}) {
  const r = await fetch(`${BASE}/api/service/audit/events`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}
const asApp = (token) => ({ 'x-appcrane-service-token': token });
async function get(path, user) {
  const r = await fetch(`${BASE}${path}`, { headers: { 'x-api-key': user.key } });
  const text = await r.text();
  let body = null;
  try { body = JSON.parse(text); } catch (_) {}
  return { status: r.status, body, text, headers: r.headers };
}
const count = (appId) => db.prepare('SELECT COUNT(*) AS n FROM app_audit_events WHERE app_id = ?').get(appId).n;

function signedIdentity(appId, userId, { env = 'production', ts = Math.floor(Date.now() / 1000) } = {}) {
  const h = {
    'X-AppCrane-User': 'u', 'X-AppCrane-User-Id': String(userId), 'X-AppCrane-User-Email': 'u@t.test', 'X-AppCrane-User-Name': 'U',
    'X-AppCrane-User-Role': 'user', 'X-AppCrane-App-Role': 'user', 'X-AppCrane-Is-Admin': 'false', 'X-AppCrane-Identity-Ts': String(ts),
  };
  h['X-AppCrane-Identity-Sig-V2'] = signIdentityV2(identitySecretFor(db, appId, env), ts, (k) => h[k]);
  return h;
}

test('an app writes an event with its service token; the event is bound to that app and acts as the app', async () => {
  const r = await write({
    action: 'invoice.paid', occurred_at: new Date(Date.now() - 60_000).toISOString(),
    targets: [{ type: 'invoice', id: 'inv_1', name: 'Invoice 1' }], context: { location: '203.0.113.9', user_agent: 'test-agent' },
    metadata: { amount: 120, currency: 'EUR' }, app: 'aa-beta', app_id: BETA,
  }, asApp(alphaToken));
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.event.source, 'app');
  assert.equal(r.body.event.app.slug, 'aa-alpha', 'app/app_id in the body are ignored');
  assert.deepEqual(r.body.event.actor, { type: 'app', id: 'aa-alpha', name: 'App aa-alpha', verified: true });
  assert.equal(count(BETA), 0);
  const row = db.prepare('SELECT * FROM app_audit_events WHERE id = ?').get(r.body.event.id);
  assert.equal(row.app_id, ALPHA);
});

test("another app's token cannot write to this app: its events land on itself, and this app's types do not apply to it", async () => {
  const before = count(ALPHA);
  const r = await write({ action: 'invoice.paid', app_id: ALPHA, app_slug: 'aa-alpha' }, asApp(betaToken));
  assert.equal(r.status, 422, 'invoice.paid is registered on alpha only');
  assert.equal(r.body.error.code, 'UNREGISTERED_ACTION');
  const ok = await write({ action: 'report.run', app_id: ALPHA }, asApp(betaToken));
  assert.equal(ok.status, 201);
  assert.equal(ok.body.event.app.slug, 'aa-beta');
  assert.equal(count(ALPHA), before, 'nothing reached alpha');
});

test('a user API key is refused on the write path, whichever header carries it; so is a proxied request', async () => {
  for (const headers of [{ 'x-api-key': owner.key }, { authorization: `Bearer ${owner.key}` }, asApp(owner.key), asApp(admin.key), {}]) {
    const r = await write({ action: 'invoice.paid' }, headers);
    assert.equal(r.status, 401, JSON.stringify(headers));
    assert.equal(r.body.error.code, 'BAD_SERVICE_TOKEN');
  }
  const p = await write({ action: 'invoice.paid' }, { ...asApp(alphaToken), 'x-forwarded-for': '198.51.100.1' });
  assert.equal(p.status, 403);
});

test('idempotency: the same key gives one row; reusing it for a different event is a 409', async () => {
  const before = count(ALPHA);
  const body = { action: 'doc.shared', idempotency_key: 'share-42', targets: [{ type: 'doc', id: '42' }] };
  const a = await write(body, asApp(alphaToken));
  const b = await write(body, asApp(alphaToken));
  assert.equal(a.status, 201);
  assert.equal(b.status, 200);
  assert.equal(b.body.deduped, true);
  assert.equal(b.body.event.id, a.body.event.id);
  assert.equal(count(ALPHA), before + 1);
  const c = await write({ ...body, targets: [{ type: 'doc', id: '43' }] }, asApp(alphaToken));
  assert.equal(c.status, 409);
  assert.equal(c.body.error.code, 'IDEMPOTENCY_CONFLICT');
  const h1 = await write({ action: 'doc.shared' }, { ...asApp(alphaToken), 'idempotency-key': 'hdr-1' });
  const h2 = await write({ action: 'doc.shared' }, { ...asApp(alphaToken), 'idempotency-key': 'hdr-1' });
  assert.equal(h1.status, 201);
  assert.equal(h2.status, 200);
  const other = await write({ action: 'report.run', idempotency_key: 'share-42' }, asApp(betaToken));
  assert.equal(other.status, 201, 'keys are per app');
  assert.equal(count(ALPHA), before + 2);
});

test('caps: metadata size and depth, targets, strings, body size, unregistered actions and the per-app rate', async () => {
  const cases = [
    [{ action: 'invoice.paid', metadata: { blob: 'x'.repeat(900), b: 'y'.repeat(900), c: 'z'.repeat(900), d: 'w'.repeat(900), e: 'v'.repeat(900) } }, 400],
    [{ action: 'invoice.paid', metadata: { a: { b: { c: { d: 1 } } } } }, 400],
    [{ action: 'invoice.paid', targets: Array.from({ length: 21 }, (_, i) => ({ type: 't', id: String(i) })) }, 400],
    [{ action: 'Invoice Paid' }, 400],
    [{ action: 'invoice.paid', context: { location: 'not-an-ip' } }, 400],
    [{ action: 'invoice.paid', occurred_at: new Date(Date.now() + 3_600_000).toISOString() }, 400],
    [{ action: 'invoice.paid', actor: { type: 'user', id: '1' } }, 400],
    [{ action: 'invoice.paid', actor: { type: 'app', id: 'aa-beta' } }, 400],
    [{ action: 'never.registered' }, 422],
  ];
  for (const [body, want] of cases) {
    const r = await write(body, asApp(alphaToken));
    assert.equal(r.status, want, JSON.stringify(body).slice(0, 80));
  }
  const big = await write(JSON.stringify({ action: 'invoice.paid', pad: 'x'.repeat(40_000) }), asApp(alphaToken));
  assert.equal(big.status, 413);
  const ok = await write({ action: 'invoice.paid', metadata: { a: { b: { c: 1 } } } }, asApp(alphaToken));
  assert.equal(ok.status, 201, 'three levels are allowed');

  db.prepare('INSERT INTO app_audit_settings (app_id, allow_unregistered) VALUES (?, 1)').run(ALPHA);
  const flagged = await write({ action: 'never.registered' }, asApp(alphaToken));
  assert.equal(flagged.status, 201);
  assert.equal(flagged.body.event.unregistered, true);
  db.prepare('DELETE FROM app_audit_settings WHERE app_id = ?').run(ALPHA);

  svc._resetAppAuditRateForTests();
  // The limit is a fixed per-minute window: start the burst well inside one.
  const msLeft = 60_000 - (Date.now() % 60_000);
  if (msLeft < 15_000) await new Promise((r) => setTimeout(r, msLeft + 50));
  let last;
  for (let i = 0; i <= svc.RATE_PER_MINUTE; i++) last = await write({ action: 'report.run' }, asApp(betaToken));
  assert.equal(last.status, 429);
  assert.ok(last.status === 429 && (await write({ action: 'invoice.paid' }, asApp(alphaToken))).status === 201, 'the limit is per app');
  svc._resetAppAuditRateForTests();
});

test('an event names an AppCrane user only with a valid signed identity for THIS app', async () => {
  const ok = await write({ action: 'user.signed_in', identity: signedIdentity(ALPHA, member.id) }, asApp(alphaToken));
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  assert.deepEqual(ok.body.event.actor, { type: 'user', id: String(member.id), name: member.name, verified: true, identity_env: 'production' });
  const sb = await write({ action: 'user.signed_in', identity: signedIdentity(ALPHA, member.id, { env: 'sandbox' }) }, asApp(alphaToken));
  assert.equal(sb.body.event.actor.identity_env, 'sandbox');

  const other = await write({ action: 'user.signed_in', identity: signedIdentity(BETA, member.id) }, asApp(alphaToken));
  assert.equal(other.status, 401, "beta's signature is not alpha's");
  assert.equal(other.body.error.code, 'IDENTITY_INVALID');
  const forged = signedIdentity(ALPHA, member.id);
  forged['X-AppCrane-User-Id'] = String(admin.id);
  assert.equal((await write({ action: 'user.signed_in', identity: forged }, asApp(alphaToken))).status, 401, 'an altered user id breaks the signature');
  const old = await write({ action: 'user.signed_in', identity: signedIdentity(ALPHA, member.id, { ts: Math.floor(Date.now() / 1000) - 600 }) }, asApp(alphaToken));
  assert.equal(old.status, 401, 'an expired signature is refused');

  const claimed = await write({ action: 'user.signed_in', actor: { type: 'customer', id: 'c-9', name: 'Cust' } }, asApp(alphaToken));
  assert.equal(claimed.status, 201);
  assert.equal(claimed.body.event.actor.verified, false, 'an app-reported actor is marked unverified');
});

test('the audit chain seals app events, verifies clean, and names a tampered or deleted app event', async () => {
  chain._resetAuditChainForTests();
  await chain.sealNew();
  chain.checkpointNow({ now: Date.now() });
  const clean = await chain.verifyChain();
  assert.deepEqual(clean.problems, []);
  const sealed = db.prepare("SELECT COUNT(*) AS n FROM app_audit_chain WHERE src = 'app_audit_events'").get().n;
  assert.equal(sealed, db.prepare('SELECT COUNT(*) AS n FROM app_audit_events').get().n);

  const target = db.prepare('SELECT id, metadata FROM app_audit_events WHERE app_id = ? ORDER BY id LIMIT 1 OFFSET 1').get(ALPHA);
  db.exec('DROP TRIGGER app_audit_events_append_only');
  db.prepare('UPDATE app_audit_events SET metadata = ? WHERE id = ?').run('{"amount":1}', target.id);
  const bad = await chain.verifyChain();
  assert.equal(bad.ok, false);
  assert.equal(bad.first_broken.app_audit_events, target.id);
  assert.deepEqual([...new Set(bad.problems.map(p => p.type))], ['modified']);
  db.prepare('UPDATE app_audit_events SET metadata = ? WHERE id = ?').run(target.metadata, target.id);
  db.exec("CREATE TRIGGER app_audit_events_append_only BEFORE UPDATE ON app_audit_events BEGIN SELECT RAISE(ABORT, 'app audit events are append-only'); END;");
  assert.equal((await chain.verifyChain()).ok, true, 'restoring the row restores the chain');

  const victim = db.prepare('SELECT * FROM app_audit_events WHERE app_id = ? ORDER BY id DESC LIMIT 1').get(ALPHA);
  db.prepare('DELETE FROM app_audit_events WHERE id = ?').run(victim.id);
  const del = await chain.verifyChain();
  assert.equal(del.first_broken.app_audit_events, victim.id);
  assert.ok(del.problems.some(p => p.type === 'deleted' && p.src === 'app_audit_events'));
  const cols = Object.keys(victim);
  db.prepare(`INSERT INTO app_audit_events (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(...cols.map(c => victim[c]));
  assert.equal((await chain.verifyChain()).ok, true);
});

test('retention removes old app events under a signed window; the verifier counts them as pruned, not deleted', async () => {
  const DAY = 86_400_000;
  const old = new Date(Date.now() - 400 * DAY).toISOString().replace('T', ' ').slice(0, 19);
  db.prepare(`INSERT INTO app_audit_events (app_id, app_slug, action, occurred_at, actor_type, actor_id, actor_verified, payload_hash, created_at)
              VALUES (?, 'aa-alpha', 'invoice.paid', ?, 'app', 'aa-alpha', 1, 'h', ?)`).run(ALPHA, new Date(Date.now() - 400 * DAY).toISOString(), old);
  await chain.sealNew();
  chain.checkpointNow({ now: Date.now() });
  const removed = await retention.pruneAppAuditEvents({ now: Date.now() + 1000 });
  assert.equal(removed, 1);
  const r = await chain.verifyChain();
  assert.deepEqual(r.problems, []);
  assert.equal(r.pruned, 1);
});

test('read: owner and app admins see only their app; a member and an outsider are refused; platform admins see every app', async () => {
  const o = await get('/api/apps/aa-alpha/audit-events?limit=200', owner);
  assert.equal(o.status, 200);
  assert.ok(o.body.events.length > 0);
  assert.ok(o.body.events.every(e => e.app.slug === 'aa-alpha' && e.source === 'app'));
  assert.equal((await get('/api/apps/aa-alpha/audit-events', appAdmin)).status, 200);
  assert.equal((await get('/api/apps/aa-alpha/audit-events', member)).status, 403);
  assert.equal((await get('/api/apps/aa-alpha/audit-events', outsider)).status, 403);
  assert.equal((await get('/api/apps/aa-alpha/audit-events/export?format=csv', member)).status, 403);
  assert.equal((await get('/api/app-audit-events', owner)).status, 403);
  const all = await get('/api/app-audit-events?limit=200', admin);
  assert.equal(all.status, 200);
  assert.deepEqual([...new Set(all.body.events.map(e => e.app.slug))].sort(), ['aa-alpha', 'aa-beta']);
  const onlyBeta = await get('/api/app-audit-events?app=aa-beta&limit=200', admin);
  assert.ok(onlyBeta.body.events.every(e => e.app.slug === 'aa-beta'));
});

test('filters (action, prefix, actor, target, time) and CSV/JSON export', async () => {
  const byAction = await get('/api/apps/aa-alpha/audit-events?action=doc.shared', owner);
  assert.ok(byAction.body.events.length >= 2 && byAction.body.events.every(e => e.action === 'doc.shared'));
  const byPrefix = await get('/api/apps/aa-alpha/audit-events?action=user.', owner);
  assert.ok(byPrefix.body.events.length && byPrefix.body.events.every(e => e.action.startsWith('user.')));
  const byActor = await get(`/api/apps/aa-alpha/audit-events?actor_type=user&actor_id=${member.id}`, owner);
  assert.ok(byActor.body.events.length >= 2 && byActor.body.events.every(e => e.actor.id === String(member.id)));
  assert.equal(await write({ action: 'doc.shared', targets: [{ type: 'doc', id: '43' }] }, asApp(alphaToken)).then(r => r.status), 201);
  const byTarget = await get('/api/apps/aa-alpha/audit-events?target_type=doc&target_id=42', owner);
  assert.equal(byTarget.body.events.length, 1);
  assert.deepEqual(byTarget.body.events[0].targets, [{ type: 'doc', id: '42' }]);
  const byType = await get('/api/apps/aa-alpha/audit-events?target_type=doc', owner);
  assert.equal(byType.body.events.length, 2);
  const future = await get(`/api/apps/aa-alpha/audit-events?since=${encodeURIComponent(new Date(Date.now() + 60_000).toISOString())}`, owner);
  assert.equal(future.body.events.length, 0);
  assert.equal((await get('/api/apps/aa-alpha/audit-events?since=yesterday', owner)).status, 400);
  const page = await get('/api/apps/aa-alpha/audit-events?limit=2', owner);
  const next = await get(`/api/apps/aa-alpha/audit-events?limit=2&before=${page.body.next_before}`, owner);
  assert.ok(next.body.events.every(e => e.id < page.body.next_before));

  await write({ action: 'doc.shared', actor: { type: 'customer', id: 'c-1', name: '=HYPERLINK("x")' } }, asApp(alphaToken));
  const csv = await get('/api/apps/aa-alpha/audit-events/export?format=csv&action=doc.shared', owner);
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get('content-type'), /text\/csv/);
  assert.match(csv.text.split('\r\n')[0], /^id,app_slug,occurred_at/);
  assert.ok(csv.text.includes(`,"'=HYPERLINK(""x"")",`), 'a formula-looking cell is defused');
  assert.ok(!csv.text.includes(',=HYPERLINK'));
  const json = await get('/api/apps/aa-alpha/audit-events/export?format=json', owner);
  assert.ok(json.body.events.every(e => e.app.slug === 'aa-alpha'));
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'app-audit-events-export' AND app_id = ?").get(ALPHA), 'exports are audited');
});

test('event types: owner and app admins register them, a member cannot', async () => {
  const add = (u, action) => fetch(`${BASE}/api/apps/aa-alpha/audit-events/types`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': u.key }, body: JSON.stringify({ action }),
  });
  assert.equal((await add(member, 'x.y')).status, 403);
  assert.equal((await add(outsider, 'x.y')).status, 403);
  assert.equal((await add(appAdmin, 'Bad Action')).status, 400);
  assert.equal((await add(appAdmin, 'order.created')).status, 201);
  assert.equal((await add(owner, 'order.created')).status, 409);
  assert.equal((await write({ action: 'order.created' }, asApp(alphaToken))).status, 201);
  const cfg = await get('/api/apps/aa-alpha/audit-events/config', owner);
  assert.ok(cfg.body.types.some(t => t.action === 'order.created'));
});

test('MCP appcrane_get_audit source "app" reads the app\'s own events behind app.audit.view', async () => {
  const { getAuditTool } = await import('../server/services/mcpGaps/getAuditTool.js');
  const u = (x, role = 'user') => ({ id: x.id, role, name: x.name, kind: 'human' });
  const r = await getAuditTool.handler(u(owner), { slug: 'aa-alpha', source: 'app', action: 'doc.shared', limit: 2 });
  assert.equal(r.source, 'app');
  assert.equal(r.entries.length, 2);
  assert.ok(r.entries.every(e => e.app.slug === 'aa-alpha' && e.action === 'doc.shared'));
  assert.ok(r.next_before);
  const all = await getAuditTool.handler(u(owner), { slug: 'aa-alpha', source: 'app', limit: 200 });
  assert.ok(all.entries.length > 5 && all.entries.every(e => e.app.slug === 'aa-alpha'));
  const platform = await getAuditTool.handler(u(owner), { slug: 'aa-alpha' });
  assert.ok(platform.entries.every(e => !e.source), 'the default is still the platform trail');
  await assert.rejects(getAuditTool.handler(u(member), { slug: 'aa-alpha', source: 'app' }), /app\.audit\.view/);
});

test('the node-react scaffold helper writes an event as the signed-in user', async () => {
  const { auditEvent } = await import('../templates/scaffold/node-react/server/audit.js');
  const saved = { u: process.env.CRANE_INTERNAL_URL, t: process.env.APPCRANE_SERVICE_TOKEN };
  process.env.CRANE_INTERNAL_URL = BASE;
  process.env.APPCRANE_SERVICE_TOKEN = alphaToken;
  try {
    const headers = Object.fromEntries(Object.entries(signedIdentity(ALPHA, member.id)).map(([k, v]) => [k.toLowerCase(), v]));
    const ev = await auditEvent('invoice.paid', { req: { headers: { ...headers, 'user-agent': 'scaffold-test' }, ip: '::ffff:192.0.2.7' }, targets: [{ type: 'invoice', id: 'inv-s' }] });
    assert.equal(ev.actor.type, 'user');
    assert.equal(ev.actor.id, String(member.id));
    assert.deepEqual(ev.context, { location: '192.0.2.7', user_agent: 'scaffold-test' });
    const asApp = await auditEvent('invoice.paid');
    assert.equal(asApp.actor.type, 'app');
    await assert.rejects(auditEvent('not.registered.here'), /422 UNREGISTERED_ACTION/);
  } finally {
    process.env.CRANE_INTERNAL_URL = saved.u ?? '';
    process.env.APPCRANE_SERVICE_TOKEN = saved.t ?? '';
  }
});

test('the operations guide states the write path and the limits the code enforces', async () => {
  const { readFileSync } = await import('fs');
  const { LIMITS } = await import('../server/services/appAudit/schema.js');
  const g = readFileSync(new URL('../server/services/guides/operations.md', import.meta.url), 'utf8');
  const sec = g.slice(g.indexOf('## App audit events'), g.indexOf('## Keeping ENCRYPTION_KEY'));
  assert.ok(sec.includes('POST ${CRANE_INTERNAL_URL}/api/service/audit/events'));
  assert.ok(sec.includes(`${svc.RATE_PER_MINUTE} events a`));
  assert.ok(sec.includes(`metadata ${LIMITS.metadataBytes / 1024} KB, ${LIMITS.metadataDepth} levels deep, ${LIMITS.metadataKeys} keys`));
  assert.ok(sec.includes(`${LIMITS.targetsMax}\n  targets`) || sec.includes(`${LIMITS.targetsMax} targets`));
  assert.ok(sec.includes('Body 32 KB'));
});
