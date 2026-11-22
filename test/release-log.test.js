import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Release log: status derived from the deployer's own columns (live, replaced,
// rolled back, auto-reverted, failed), promote links between environments,
// person vs agent, metrics while live on an injected clock (requests pro-rated
// per UTC day, distinct users, restarts from the audit log), release labels
// (validation at deploy time over REST and MCP, edit afterwards), CSV with a
// formula guard, and per-app authz through the real routers.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-releases-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();
const activity = await import('../server/services/envActivity.js');
const usage = await import('../server/services/usageAnalytics.js');
const { listReleases, releasesCsv } = await import('../server/services/releaseLog.js');
const { callTool } = await import('../server/services/mcpTools.js');

const NOW = Date.parse('2026-11-20T12:00:00Z');
usage._setUsageClockForTests(() => NOW);
const sql = (iso) => iso.replace('T', ' ').slice(0, 19);
const at = (day, h) => Date.parse(`${day}T${String(h).padStart(2, '0')}:00:00Z`);

function mkUser(name, role = 'user', kind = 'human') {
  const key = generateApiKey('dhk_user');
  const id = Number(db.prepare('INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES (?,?,?,?,1,?)')
    .run(name, `${name}@t.test`, role, hashApiKey(key), kind).lastInsertRowid);
  return { ...db.prepare('SELECT * FROM users WHERE id = ?').get(id), key };
}
let slot = 600;
function mkApp(slug) {
  const id = Number(db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch,repo_backend) VALUES (?,?,?,'managed','main','local')")
    .run(slug, slug, ++slot).lastInsertRowid);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
function grant(app, u, role) {
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(app.id, u.id, role);
}
function dep(app, env, status, startedIso, finishedIso, extra = {}) {
  return Number(db.prepare(`INSERT INTO deployments (app_id, env, version, status, commit_hash, commit_message, log, deployed_by,
      release_label, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(app.id, env, extra.version || null, status, extra.commit || null, extra.message || null, extra.log || null,
      extra.by ?? null, extra.label || null, sql(startedIso), finishedIso ? sql(finishedIso) : null).lastInsertRowid);
}

const admin = mkUser('rl-platadmin', 'platform_admin');
const owner = mkUser('rl-owner');
const appAdmin = mkUser('rl-appadmin');
const member = mkUser('rl-member');
const outsider = mkUser('rl-outsider');
const agent = mkUser('rl-agent', 'user', 'agent');
const app = mkApp('rl-app');
const other = mkApp('rl-other');
grant(app, owner, 'owner'); grant(app, appAdmin, 'admin'); grant(app, member, 'user'); grant(app, agent, 'user');
grant(other, owner, 'owner');

// production: d1 deploy -> d2 deploy -> d3 rollback to d1 -> d4 promote of s1 (live) -> d5 failed + reverted
const d1 = dep(app, 'production', 'rolled_back', '2026-11-01T09:55:00Z', '2026-11-01T10:00:00Z', { version: '1.0.0', commit: 'aaa1111', message: 'First, with "quotes", and commas', by: owner.id });
const d2 = dep(app, 'production', 'rolled_back', '2026-11-05T09:55:00Z', '2026-11-05T10:00:00Z', { version: '1.1.0', by: owner.id });
const d3 = dep(app, 'production', 'rolled_back', '2026-11-06T09:55:00Z', '2026-11-06T10:00:00Z', { version: '1.0.0', by: owner.id, log: `Rollback to deployment #${d1}` });
const s0 = dep(app, 'sandbox', 'failed', '2026-11-08T08:00:00Z', '2026-11-08T08:01:00Z', { version: '1.2.0', by: agent.id, log: 'Health check failed' });
const s1 = dep(app, 'sandbox', 'live', '2026-11-09T08:00:00Z', '2026-11-09T08:05:00Z', { version: '1.2.0', by: agent.id, label: 'rules=v3' });
const d4 = dep(app, 'production', 'live', '2026-11-10T09:55:00Z', '2026-11-10T10:00:00Z', { version: '1.2.0', by: owner.id, label: 'rules=v3', log: `Promote from sandbox #${s1} - fresh production build` });
const d5 = dep(app, 'production', 'failed', '2026-11-12T09:00:00Z', '2026-11-12T09:02:00Z', { version: '1.3.0', by: owner.id, log: 'Health check failed (status)\nReverting to previous image: x' });
dep(other, 'production', 'live', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z');

activity.ensureTracking(db, app.id, 'production', Date.parse('2026-10-01T00:00:00Z'));
activity.ensureTracking(db, app.id, 'sandbox', Date.parse('2026-11-09T12:00:00Z'));
for (let t = Date.parse('2026-11-01T00:00:00Z'); t <= Date.parse('2026-11-20T00:00:00Z'); t += 86_400_000) {
  const day = new Date(t).toISOString().slice(0, 10);
  for (let i = 0; i < 10; i++) activity.noteRequest(app.id, 'production', owner.id, at(day, 1));
  if (day >= '2026-11-10') activity.noteRequest(app.id, 'production', member.id, at(day, 1));
  activity.flushActivity(db, at(day, 2));
}
const audit = db.prepare("INSERT INTO audit_log (user_id, app_id, action, detail, created_at) VALUES (?, ?, 'restart', ?, ?)");
audit.run(owner.id, app.id, JSON.stringify({ method: 'POST', path: '/x', params: { slug: app.slug, env: 'production' } }), '2026-11-02 12:00:00');
audit.run(owner.id, app.id, JSON.stringify({ method: 'POST', path: '/x', params: { slug: app.slug, env: 'production' } }), '2026-11-15 12:00:00');
audit.run(owner.id, app.id, JSON.stringify({ method: 'POST', path: '/x', params: { slug: app.slug, env: 'sandbox' } }), '2026-11-15 12:00:00');

after(() => { activity._resetActivityForTests(); usage._setUsageClockForTests(null); });

const byId = (r) => Object.fromEntries(r.releases.map(x => [x.id, x]));

test('status is derived from the deployer columns: live, replaced, rolled back, auto-reverted, failed', () => {
  const r = byId(listReleases(db, app));
  assert.equal(r[d1].status, 'replaced');
  assert.equal(r[d2].status, 'rolled back', 'd2 was replaced by a rollback release');
  assert.equal(r[d3].status, 'replaced');
  assert.equal(r[d3].kind, 'rollback');
  assert.equal(r[d3].rollback_of, d1);
  assert.equal(r[d4].status, 'live');
  assert.equal(r[d5].status, 'auto-reverted');
  assert.equal(r[s0].status, 'failed');
  assert.equal(r[d4].kind, 'promote');
  assert.equal(r[d4].promoted_from, s1);
  assert.deepEqual(r[s1].promoted_to, [d4]);
  assert.equal(r[d1].whats_new, 'First, with "quotes", and commas');
  assert.equal(r[s1].deployed_by.kind, 'agent');
  assert.equal(r[d1].deployed_by.kind, 'person');
  assert.equal(r[d1].approver, null);
});

test('time live and metrics while live: requests pro-rated per day, distinct users, restarts per env', () => {
  const r = byId(listReleases(db, app));
  assert.equal(r[d1].live_from, '2026-11-01T10:00:00.000Z');
  assert.equal(r[d1].live_until, '2026-11-05T10:00:00.000Z');
  assert.equal(r[d1].live_ms, 4 * 86_400_000);
  // 11-01 14h of 10 + 3 full days of 10 + 11-05 10h of 10 = 40
  assert.equal(r[d1].metrics.requests, 40);
  assert.equal(r[d1].metrics.requests_per_day, 10);
  assert.equal(r[d1].metrics.active_users, 1);
  assert.equal(r[d1].metrics.restarts, 1);
  assert.equal(r[d1].metrics.coverage, 'full');
  // d4: 11-10 10:00 until now (11-20 12:00); today counts in full, it has only run 12h
  assert.equal(r[d4].live_until, null);
  assert.equal(r[d4].metrics.requests, Math.round(11 * 14 / 24 + 11 * 9 + 11));
  assert.equal(r[d4].metrics.active_users, 2);
  assert.equal(r[d4].metrics.restarts, 1, 'the sandbox restart is not counted against production');
  assert.equal(r[d4].metrics.error_rate, null);
  assert.equal(r[d4].metrics.p95_ms, null);
  assert.equal(r[d5].metrics, null, 'a release that never went live has no metrics');
  assert.equal(r[s1].metrics.coverage, 'partial');
});

test('filters: env and label; labels lists every label once', () => {
  const prod = listReleases(db, app, { env: 'production' });
  assert.deepEqual(prod.releases.map(x => x.id), [d5, d4, d3, d2, d1], 'newest first');
  const v3 = listReleases(db, app, { label: 'rules=v3' });
  assert.deepEqual(v3.releases.map(x => x.id).sort(), [s1, d4].sort());
  assert.deepEqual(v3.labels, ['rules=v3']);
});

test('CSV: header, quoting, and a formula-looking cell stays text', () => {
  db.prepare('UPDATE deployments SET release_label = ? WHERE id = ?').run('=cmd', d2);
  const csv = releasesCsv(listReleases(db, app, { env: 'production' }).releases);
  db.prepare('UPDATE deployments SET release_label = NULL WHERE id = ?').run(d2);
  const lines = csv.trim().split('\r\n');
  assert.equal(lines[0].split(',')[0], 'env');
  assert.ok(lines[0].endsWith(',whats_new'));
  assert.equal(lines.length, 6);
  const l2 = lines.find(l => l.startsWith(`production,${d2},`));
  assert.ok(l2.includes(",'=cmd,"), l2);
  const l1 = lines.find(l => l.startsWith(`production,${d1},`));
  assert.ok(l1.endsWith(',"First, with ""quotes"", and commas"'), l1);
});

// ── HTTP ──────────────────────────────────────────────────────────────────

const { errorHandler } = await import('../server/utils/errors.js');
const api = express();
api.use(express.json());
api.use('/api', (await import('../server/routes/releases.js')).default);
api.use('/api/apps', (await import('../server/routes/deploy.js')).default);
api.use(errorHandler);
const server = await new Promise(r => { const s = api.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  server.closeAllConnections?.(); server.close();
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

async function call(as, method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(as ? { 'X-API-Key': as.key } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, body: json, type: res.headers.get('content-type') };
}

test('GET releases: owner, app admin and platform admin read; member and outsider 403; anonymous 401; unknown app 404', async () => {
  for (const u of [owner, appAdmin, admin]) {
    const r = await call(u, 'GET', `/api/apps/${app.slug}/releases?env=production`);
    assert.equal(r.status, 200, `${u.name}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.releases.length, 5);
  }
  for (const u of [member, agent, outsider]) {
    const r = await call(u, 'GET', `/api/apps/${app.slug}/releases`);
    assert.equal(r.status, 403, u.name);
    assert.equal(r.body.releases, undefined);
  }
  assert.equal((await call(null, 'GET', `/api/apps/${app.slug}/releases`)).status, 401);
  assert.equal((await call(owner, 'GET', '/api/apps/no-such-app/releases')).status, 404);
  assert.equal((await call(owner, 'GET', `/api/apps/${app.slug}/releases?env=staging`)).status, 400);
  assert.equal((await call(owner, 'GET', `/api/apps/${app.slug}/releases?label=a%20b`)).status, 400);
  const f = await call(owner, 'GET', `/api/apps/${app.slug}/releases?label=rules%3Dv3`);
  assert.deepEqual(f.body.releases.map(x => x.id).sort(), [s1, d4].sort());
});

test('GET releases?format=csv answers text/csv behind the same gate', async () => {
  const r = await call(owner, 'GET', `/api/apps/${app.slug}/releases?format=csv&env=sandbox`);
  assert.equal(r.status, 200);
  assert.match(r.type, /^text\/csv/);
  assert.equal(r.body.trim().split('\r\n').length, 3);
  assert.equal((await call(member, 'GET', `/api/apps/${app.slug}/releases?format=csv`)).status, 403);
});

test('PUT label: validated, persisted, cleared with null; other apps\' releases and members refused', async () => {
  const p = `/api/apps/${app.slug}/releases/${d2}/label`;
  for (const bad of ['rules v3', 'x'.repeat(41), 'rüles', 42, ['a']]) {
    const r = await call(owner, 'PUT', p, { label: bad });
    assert.equal(r.status, 400, JSON.stringify(bad));
  }
  assert.equal((await call(appAdmin, 'PUT', p, { label: 'rules=v2' })).status, 200);
  assert.equal(db.prepare('SELECT release_label FROM deployments WHERE id = ?').get(d2).release_label, 'rules=v2');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'release-label-update'").get().n, 1);
  assert.equal((await call(owner, 'PUT', p, { label: null })).status, 200);
  assert.equal(db.prepare('SELECT release_label FROM deployments WHERE id = ?').get(d2).release_label, null);
  assert.equal((await call(member, 'PUT', p, { label: 'x' })).status, 403);
  const otherDep = db.prepare('SELECT id FROM deployments WHERE app_id = ?').get(other.id).id;
  assert.equal((await call(owner, 'PUT', `/api/apps/${app.slug}/releases/${otherDep}/label`, { label: 'x' })).status, 404);
  assert.equal(db.prepare('SELECT release_label FROM deployments WHERE id = ?').get(otherDep).release_label, null);
});

const count = () => db.prepare('SELECT COUNT(*) AS n FROM deployments WHERE app_id = ?').get(app.id).n;

test('deploy label over REST: an invalid label is refused before a deployment row exists; a valid one is recorded', async () => {
  const before = count();
  const bad = await call(owner, 'POST', `/api/apps/${app.slug}/deploy/sandbox`, { label: 'no spaces' });
  assert.equal(bad.status, 400);
  assert.equal(count(), before);
  const ok = await call(owner, 'POST', `/api/apps/${app.slug}/deploy/sandbox`, { label: 'rules=v4', acknowledge_data_loss: true });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  const row = db.prepare('SELECT release_label FROM deployments WHERE id = ?').get(ok.body.deployment.id);
  assert.equal(row.release_label, 'rules=v4');
  await new Promise(r => setTimeout(r, 300));
});

async function tool(user, name, args) {
  let r;
  try { r = await callTool(user, name, args); } catch (e) { return { isError: true, text: e.message, json: null }; }
  const text = r?.content?.[0]?.text ?? '';
  return { isError: !!r?.isError, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

test('MCP: appcrane_deploy refuses an invalid label before a row exists; appcrane_list_app_releases is gated to owners and admins', async () => {
  const before = count();
  const bad = await tool(owner, 'appcrane_deploy', { slug: app.slug, env: 'sandbox', label: 'a/b', acknowledge_data_loss: true });
  assert.ok(bad.isError && /label must be/.test(bad.text), bad.text);
  assert.equal(count(), before);
  await new Promise(r => setTimeout(r, 300));
  const good = await tool(owner, 'appcrane_deploy', { slug: app.slug, env: 'sandbox', label: 'rules=v5', acknowledge_data_loss: true });
  assert.ok(!good.isError, good.text);
  assert.equal(db.prepare('SELECT release_label FROM deployments WHERE id = ?').get(good.json.deployment_id).release_label, 'rules=v5');
  await new Promise(r => setTimeout(r, 300));
  const ok = await tool(owner, 'appcrane_list_app_releases', { slug: app.slug, env: 'production', limit: 2 });
  assert.ok(!ok.isError, ok.text);
  assert.deepEqual(ok.json.releases.map(x => x.id), [d5, d4]);
  assert.equal(ok.json.releases[1].metrics.error_rate, null);
  const m = await tool(member, 'appcrane_list_app_releases', { slug: app.slug });
  assert.ok(m.isError && /owner or admin/.test(m.text), m.text);
  const o = await tool(outsider, 'appcrane_list_app_releases', { slug: app.slug });
  assert.ok(o.isError, o.text);
  assert.ok(!/rules=v3/.test(o.text));
});
