import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import express from 'express';

// Protected settings (v2.147.0): the generic PUT /api/settings/:key answers
// 409 for every protection, limit or state key and names the route that owns
// it; /api/settings/protected/:key writes the ones with no route of their own
// (dashboard session only, step-up when the change weakens, audited with old
// and new value) and never writes the state AppCrane records.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-protected-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const owned = await import('../server/services/settingsOwnedKeys.js');
const { SPEC } = await import('../server/routes/protectedSettings.js');

const user = (name, role) => {
  const key = generateApiKey('dhk_t');
  const id = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,'human')").run(name, `${name}@t.test`, role, hashApiKey(key)).lastInsertRowid;
  return { id, key };
};
const session = (userId, ageMinutes) => {
  const tok = randomBytes(24).toString('base64url');
  db.prepare(`INSERT INTO identity_sessions (user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, datetime('now','+1 day'), datetime('now', ?))`).run(userId, hashApiKey(tok), `-${ageMinutes} minutes`);
  return tok;
};
const ADMIN = user('pa', 'platform_admin');
const PLAIN = user('pu', 'user');
const FRESH = session(ADMIN.id, 0);
const STALE = session(ADMIN.id, 60);
const PLAIN_FRESH = session(PLAIN.id, 0);

const api = express();
api.use(express.json());
api.use('/api/settings/protected', (await import('../server/routes/protectedSettings.js')).default);
api.use('/api/settings', (await import('../server/routes/settings.js')).default);
api.use((await import('../server/utils/errors.js')).errorHandler);
const server = await new Promise((res) => { const s = api.listen(0, '127.0.0.1', () => res(s)); });
after(() => { server.closeAllConnections?.(); server.close(); rmSync(ROOT, { recursive: true, force: true }); });
const BASE = `http://127.0.0.1:${server.address().port}`;

const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const call = async (method, path, headers, body) => {
  const r = await fetch(`${BASE}${path}`, { method, headers: { ...headers, 'Content-Type': 'application/json' }, ...(body !== undefined && { body: JSON.stringify(body) }) });
  return { status: r.status, body: await r.json() };
};
const value = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value ?? null;
const audits = () => db.prepare("SELECT user_id, detail FROM audit_log WHERE action = 'protected-setting-change' ORDER BY id").all().map((r) => ({ user_id: r.user_id, ...JSON.parse(r.detail) }));
const clear = (k) => db.prepare('DELETE FROM settings WHERE key = ?').run(k);

const ELSEWHERE = {
  managed_db_auth_alert_threshold: 'PUT /api/managed-db/settings',
  managed_db_conn_limit: 'PUT /api/managed-db/settings',
  memory_admission_mode: 'PUT /api/settings/server-capacity',
  cpu_overcommit_ratio: 'PUT /api/settings/server-capacity',
  mcp_oauth_only: 'PUT /api/api-key-policy',
  mcp_oauth_only_exempt_user_ids: 'PUT /api/api-key-policy',
  llm_gateway_retention_days: 'PUT /api/ai-act/retention',
  event_retention_critical_days: 'PUT /api/events/retention',
  edge_refuse_brotli_bodies: 'PUT /api/settings/edge/brotli',
  container_runtime_default: 'PUT /api/container-runtime/settings',
  pull_base_images_app_dockerfiles: 'PUT /api/runtime-patch/policy',
  host_hardening_auto_apply: 'PUT /api/settings/host-hardening/auto',
};

test('the protected route serves exactly the keys the generic route sends to it', () => {
  assert.deepEqual(Object.keys(SPEC).sort(), [...owned.PROTECTED_ROUTE_KEYS].sort());
});

test('generic PUT /api/settings/:key refuses every protected, owned-elsewhere and state key with 409, nothing written', async () => {
  const keys = [...owned.PROTECTED_ROUTE_KEYS, ...owned.READ_ONLY_KEYS, ...Object.keys(ELSEWHERE)];
  for (const k of keys) {
    clear(k);
    const r = await call('PUT', `/api/settings/${k}`, bearer(FRESH), { value: '0' });
    assert.equal(r.status, 409, `${k}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error.code, 'PROTECTED_SETTING', k);
    if (owned.READ_ONLY_KEYS.includes(k)) {
      assert.equal(r.body.error.route, null, k);
      assert.match(r.body.error.message, /recorded by AppCrane only/, k);
    } else {
      const want = ELSEWHERE[k] || `PUT /api/settings/protected/${k}`;
      assert.equal(r.body.error.route, want, k);
      assert.ok(r.body.error.message.includes(want), k);
    }
    assert.equal(value(k), null, `${k} was written by the generic route`);
  }
  const plainKey = await call('PUT', '/api/settings/branding', bearer(FRESH), { value: 'x' });
  assert.equal(plainKey.status, 200, 'an unprotected key is still writable');
});

test('reads: session and user API key, plain user refused, unknown key 404', async () => {
  db.prepare("INSERT INTO settings (key, value) VALUES ('host_gateway_repairs', '{\"a\":1}') ON CONFLICT(key) DO UPDATE SET value = excluded.value").run();
  const s = await call('GET', '/api/settings/protected/host_gateway_repairs', bearer(FRESH));
  assert.equal(s.status, 200);
  assert.deepEqual(s.body, { key: 'host_gateway_repairs', value: '{"a":1}', writable: false, read_only: true });
  const k = await call('GET', '/api/settings/protected/max_dev_containers', { 'X-API-Key': ADMIN.key });
  assert.equal(k.status, 200);
  assert.equal(k.body.effective, 5);
  const all = await call('GET', '/api/settings/protected', { 'X-API-Key': ADMIN.key });
  assert.equal(all.body.settings.length, owned.PROTECTED_ROUTE_KEYS.length + owned.READ_ONLY_KEYS.length);
  assert.equal((await call('GET', '/api/settings/protected/max_dev_containers', bearer(PLAIN_FRESH))).status, 403);
  assert.equal((await call('GET', '/api/settings/protected/branding', bearer(FRESH))).status, 404);
});

test('writes: API key refused, read-only keys refused, invalid values refused, nothing written or audited', async () => {
  clear('host_gateway_auto_repair');
  const k = await call('PUT', '/api/settings/protected/host_gateway_auto_repair', { 'X-API-Key': ADMIN.key }, { value: true });
  assert.equal(k.status, 403);
  assert.equal(k.body.error.code, 'SESSION_REQUIRED');
  for (const ro of owned.READ_ONLY_KEYS) {
    const r = await call('PUT', `/api/settings/protected/${ro}`, bearer(FRESH), { value: '{}' });
    assert.equal(r.status, 409, ro);
    assert.equal(r.body.error.code, 'READ_ONLY_SETTING', ro);
  }
  assert.equal(value('host_gateway_repairs'), '{"a":1}', 'a read-only key was written');
  assert.equal((await call('PUT', '/api/settings/protected/max_dev_containers', bearer(FRESH), { value: 0 })).status, 400);
  assert.equal((await call('PUT', '/api/settings/protected/host_gateway_auto_repair', bearer(FRESH), { value: 'maybe' })).status, 400);
  assert.equal((await call('PUT', '/api/settings/protected/max_dev_containers', bearer(PLAIN_FRESH), { value: 3 })).status, 403);
  assert.equal(value('host_gateway_auto_repair'), null);
  assert.equal(value('max_dev_containers'), null);
  assert.deepEqual(audits(), []);
});

test('a weakening write needs a step-up; a tightening one does not; both audited with old and new value', async () => {
  const off = await call('PUT', '/api/settings/protected/host_gateway_auto_repair', bearer(STALE), { value: false });
  assert.equal(off.status, 401);
  assert.equal(off.body.error.code, 'STEP_UP_REQUIRED');
  assert.equal(off.body.error.step_up.action, 'platform_archive');
  assert.equal(off.body.error.step_up.mode, 'reauth');
  assert.equal(value('host_gateway_auto_repair'), null, 'turned off without a step-up');

  const offFresh = await call('PUT', '/api/settings/protected/host_gateway_auto_repair', bearer(FRESH), { value: false });
  assert.equal(offFresh.status, 200, JSON.stringify(offFresh.body));
  assert.equal(offFresh.body.effective, false);
  assert.equal(value('host_gateway_auto_repair'), '0');

  const onStale = await call('PUT', '/api/settings/protected/host_gateway_auto_repair', bearer(STALE), { value: true });
  assert.equal(onStale.status, 200, 'turning a protection back on asked for a step-up');
  assert.equal(value('host_gateway_auto_repair'), '1');

  const raise = await call('PUT', '/api/settings/protected/restart_loop_short_count', bearer(STALE), { value: 50 });
  assert.equal(raise.status, 401, 'raising the loop threshold did not ask for a step-up');
  const lowerOk = await call('PUT', '/api/settings/protected/restart_loop_short_count', bearer(STALE), { value: 2 });
  assert.equal(lowerOk.status, 200);
  const shorten = await call('PUT', '/api/settings/protected/restart_incident_retention_days', bearer(STALE), { value: 7 });
  assert.equal(shorten.status, 401, 'shortening retention did not ask for a step-up');
  const vuln = await call('PUT', '/api/settings/protected/vuln_alerts_immediate', bearer(STALE), { value: false });
  assert.equal(vuln.status, 401);
  const vulnOk = await call('PUT', '/api/settings/protected/vuln_alerts_immediate', bearer(FRESH), { value: false });
  assert.equal(vulnOk.status, 200);
  assert.equal(value('vuln_alerts_immediate'), 'false');

  const rows = audits();
  assert.deepEqual(rows.map((r) => [r.key, r.from, r.to, r.weakens]), [
    ['host_gateway_auto_repair', null, '0', true],
    ['host_gateway_auto_repair', '0', '1', false],
    ['restart_loop_short_count', null, '2', false],
    ['vuln_alerts_immediate', null, 'false', true],
  ]);
  assert.ok(rows.every((r) => r.user_id === ADMIN.id && r.ip));
});

test('db_allowlist_mode: off, observe or enforce; moving towards off needs a step-up; every write audited; a write re-syncs APPCRANE-DB at once', async () => {
  const chain = await import('../server/services/hostFirewall/dbChain.js');
  const calls = [];
  chain._resetDbChainForTests();
  const run = async (cmd, args) => { calls.push(`${cmd} ${args.join(' ')}`); return { code: 0, stdout: '-N APPCRANE-DB\n', stderr: '', missing: false, error: null }; };
  chain.enableDbChain({ platform: 'linux', uid: 0, run });
  after(() => chain._resetDbChainForTests());
  const K = '/api/settings/protected/db_allowlist_mode';
  clear('db_allowlist_mode');
  const before = audits().length;
  const syncedMode = async () => {
    for (let i = 0; i < 50 && !chain.getLastDbSync(); i++) await new Promise((r) => setTimeout(r, 10));
    const m = chain.getLastDbSync()?.allowlist_mode;
    chain._resetDbChainForTests();
    chain.enableDbChain({ platform: 'linux', uid: 0, run });
    return m;
  };

  const read = await call('GET', K, bearer(FRESH));
  assert.equal(read.status, 200);
  assert.deepEqual([read.body.effective, read.body.kind, read.body.values, read.body.default], ['observe', 'enum', ['off', 'observe', 'enforce'], 'observe']);
  const generic = await call('PUT', '/api/settings/db_allowlist_mode', bearer(FRESH), { value: 'off' });
  assert.equal(generic.status, 409);
  assert.equal(generic.body.error.route, `PUT ${K}`);

  assert.equal((await call('PUT', K, { 'X-API-Key': ADMIN.key }, { value: 'enforce' })).status, 403, 'an API key changed the mode');
  assert.equal((await call('PUT', K, bearer(FRESH), { value: 'drop' })).status, 400);
  assert.equal(value('db_allowlist_mode'), null);
  assert.equal(calls.length, 0, 'a refused write re-synced the chain');

  const enforce = await call('PUT', K, bearer(STALE), { value: 'ENFORCE' });
  assert.equal(enforce.status, 200, 'tightening asked for a step-up');
  assert.equal(value('db_allowlist_mode'), 'enforce');
  assert.equal(await syncedMode(), 'enforce', 'the write did not re-sync APPCRANE-DB');
  assert.ok(calls.some(c => c.startsWith('iptables -w -S APPCRANE-DB')), calls.join('\n'));

  const observeStale = await call('PUT', K, bearer(STALE), { value: 'observe' });
  assert.equal(observeStale.status, 401, 'enforce -> observe without a step-up');
  assert.equal(observeStale.body.error.step_up.action, 'platform_archive');
  assert.equal(value('db_allowlist_mode'), 'enforce');
  assert.equal((await call('PUT', K, bearer(FRESH), { value: 'observe' })).status, 200);
  assert.equal(await syncedMode(), 'observe');
  assert.equal((await call('PUT', K, bearer(STALE), { value: 'off' })).status, 401, 'observe -> off without a step-up');
  const off = await call('PUT', K, bearer(FRESH), { value: 'off' });
  assert.equal(off.status, 200);
  assert.equal(off.body.effective, 'off');
  assert.equal(await syncedMode(), 'off');

  const rows = audits().slice(before);
  assert.deepEqual(rows.map((r) => [r.key, r.from, r.to, r.weakens]), [
    ['db_allowlist_mode', null, 'enforce', false],
    ['db_allowlist_mode', 'enforce', 'observe', true],
    ['db_allowlist_mode', 'observe', 'off', true],
  ]);
});
