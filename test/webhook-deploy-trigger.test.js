import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// The GitHub push webhook after its deploy trigger moved to
// services/deployTrigger.js (shared with local managed-repo pushes). Every row
// the webhook writes, and its response, pinned field by field.
//
// deployApp is the real one: the app's "GitHub" URL is a local bare repo so the
// clone needs no network, and docker is a shim that fails, so no container can
// start.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-whk-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { getNextSlot } = await import('../server/services/portAllocator.js');
const lg = await import('../server/services/localGit.js');
const { default: webhooksRouter } = await import('../server/routes/webhooks.js');
const { triggerAutoDeploys, pushConfigForApp } = await import('../server/services/deployTrigger.js');

const web = express();
web.use(express.json());
web.use('/api/webhooks', webhooksRouter);
const server = await new Promise((r) => { const s = web.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  server.closeAllConnections?.();
  server.close();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

await lg.createAppRepo('whk-src');
const SRC = lg.repoPath('whk-src');

let seq = 0;
function githubApp(cfg = {}) {
  const slug = `whk-${++seq}`;
  const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES (?, ?, ?, 'github', ?, 'main')")
    .run(slug, slug, getNextSlot(db), SRC).lastInsertRowid;
  const token = crypto.randomBytes(16).toString('hex');
  const secret = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO webhook_configs (app_id, token, secret) VALUES (?, ?, ?)').run(appId, token, secret);
  for (const [k, v] of Object.entries(cfg)) db.prepare(`UPDATE webhook_configs SET ${k} = ? WHERE app_id = ?`).run(v, appId);
  return { appId, slug, token, secret };
}

async function send(hook, body, { event = 'push', badSig = false } = {}) {
  const raw = JSON.stringify(body);
  const sig = 'sha256=' + crypto.createHmac('sha256', badSig ? 'wrong' : hook.secret).update(raw).digest('hex');
  const r = await fetch(`${BASE}/api/webhooks/${hook.token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-github-event': event, 'x-github-delivery': 'dlv-1', 'x-hub-signature-256': sig },
    body: raw,
  });
  return { status: r.status, body: await r.json(), payloadHash: crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16) };
}

const push = (branch, extra = {}) => ({ ref: `refs/heads/${branch}`, after: 'abcdef1234567890abcdef1234567890abcdef12', head_commit: { message: 'hello from github' }, ...extra });
const deploysOf = (appId) => db.prepare('SELECT * FROM deployments WHERE app_id = ? ORDER BY id').all(appId);
const deliveriesOf = (appId) => db.prepare('SELECT event, delivery_id, payload_hash, branch, commit_hash, sig_valid, action_taken, result, deploy_id FROM webhook_deliveries WHERE app_id = ? ORDER BY id').all(appId).map((r) => ({ ...r }));
const auditsOf = (appId) => db.prepare('SELECT user_id, action, detail, actor_kind FROM audit_log WHERE app_id = ? ORDER BY id').all(appId).map((r) => ({ ...r }));

async function settle(appId) {
  const deadline = Date.now() + 60000;
  while (db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND status IN ('pending','building','deploying')").get(appId).n) {
    if (Date.now() > deadline) throw new Error('deploys did not settle');
    await new Promise((r) => setTimeout(r, 100));
  }
}

test('default config: a push to main starts one sandbox deployment, recorded exactly as the webhook always has', async () => {
  const hook = githubApp();
  const res = await send(hook, push('main'));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { message: `Webhook processed for ${hook.slug}`, triggered: ['sandbox'] });

  const rows = deploysOf(hook.appId);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].env, 'sandbox');
  assert.equal(rows[0].commit_hash, 'abcdef12');
  assert.equal(rows[0].commit_message, 'hello from github');
  assert.equal(rows[0].deployed_by, null);
  // rows[0].log is rewritten by the real deployApp as soon as it starts; the
  // insert-time note is pinned in the injected-deps test at the end.

  assert.deepEqual(deliveriesOf(hook.appId), [{
    event: 'push', delivery_id: 'dlv-1', payload_hash: res.payloadHash, branch: 'main', commit_hash: 'abcdef12',
    sig_valid: 1, action_taken: 'deploy_triggered', result: 'deploy_triggered', deploy_id: rows[0].id,
  }]);
  assert.deepEqual(auditsOf(hook.appId), [{ user_id: null, action: 'webhook-deploy', detail: '{"env":"sandbox","commit":"abcdef12"}', actor_kind: null }]);

  await settle(hook.appId);
  assert.match(deploysOf(hook.appId)[0].log, /Cloning/, 'deployApp did not run for the webhook deployment');
});

test('auto_deploy_prod=1: sandbox then production, one delivery and one audit per environment, in that order', async () => {
  const hook = githubApp({ auto_deploy_prod: 1 });
  const res = await send(hook, push('main'));
  assert.deepEqual(res.body.triggered, ['sandbox', 'production']);
  const rows = deploysOf(hook.appId);
  assert.deepEqual(rows.map((r) => [r.env, r.commit_hash]), [['sandbox', 'abcdef12'], ['production', 'abcdef12']]);
  assert.deepEqual(deliveriesOf(hook.appId).map((d) => [d.action_taken, d.deploy_id]), [['deploy_triggered', rows[0].id], ['deploy_triggered', rows[1].id]]);
  assert.deepEqual(auditsOf(hook.appId).map((a) => a.detail), ['{"env":"sandbox","commit":"abcdef12"}', '{"env":"production","commit":"abcdef12"}']);
  await settle(hook.appId);
});

test('production only, when sandbox is off', async () => {
  const hook = githubApp({ auto_deploy_sandbox: 0, auto_deploy_prod: 1 });
  const res = await send(hook, push('main'));
  assert.deepEqual(res.body.triggered, ['production']);
  assert.deepEqual(deploysOf(hook.appId).map((r) => r.env), ['production']);
  await settle(hook.appId);
});

test('a push to another branch, or with both flags off, deploys nothing and says so', async () => {
  const off = githubApp();
  const r1 = await send(off, push('dev'));
  assert.deepEqual(r1.body, { message: 'Ignored push to branch dev (filter: main)' });
  assert.equal(deploysOf(off.appId).length, 0);
  assert.deepEqual(deliveriesOf(off.appId).map((d) => [d.action_taken, d.branch, d.deploy_id]), [['skipped_branch', 'dev', null]]);

  const none = githubApp({ auto_deploy_sandbox: 0, auto_deploy_prod: 0 });
  const r2 = await send(none, push('main'));
  assert.deepEqual(r2.body, { message: `Webhook received for ${none.slug} but no auto-deploy configured` });
  assert.equal(deploysOf(none.appId).length, 0);
  assert.deepEqual(deliveriesOf(none.appId).map((d) => d.action_taken), ['skipped_no_auto']);
  assert.equal(auditsOf(none.appId).length, 0);
});

test('a branch_filter overrides the app branch; with neither the filter is main', async () => {
  const hook = githubApp({ branch_filter: 'release' });
  assert.deepEqual((await send(hook, push('main'))).body, { message: 'Ignored push to branch main (filter: release)' });
  assert.deepEqual((await send(hook, push('release'))).body.triggered, ['sandbox']);
  await settle(hook.appId);
});

test('a push with no head_commit stores a NULL commit message', async () => {
  const hook = githubApp();
  const body = push('main');
  delete body.head_commit;
  assert.deepEqual((await send(hook, body)).body.triggered, ['sandbox']);
  assert.equal(deploysOf(hook.appId)[0].commit_message, null);
  await settle(hook.appId);
});

test('signature and event gates are unchanged', async () => {
  const hook = githubApp();
  const bad = await send(hook, push('main'), { badSig: true });
  assert.equal(bad.status, 401);
  const ping = await send(hook, { zen: 'x' }, { event: 'ping' });
  assert.deepEqual(ping.body, { message: 'Ignored event: ping' });
  assert.equal(deploysOf(hook.appId).length, 0);
  assert.deepEqual(deliveriesOf(hook.appId).map((d) => [d.action_taken, d.sig_valid]), [['sig_invalid', 0], ['skipped_event', 1]]);
});

test('the shared trigger, webhook source: insert-time row, deployApp arguments, and a rejected deploy logged not thrown', async () => {
  const hook = githubApp({ auto_deploy_prod: 1 });
  const calls = [];
  const deps = {
    deployApp: (...a) => { calls.push(a); return Promise.reject(new Error('boom')); },
    getPortsForSlot: (slot) => ({ slot }),
  };
  const deliveries = [];
  const triggered = await triggerAutoDeploys({
    config: pushConfigForApp(hook.appId), branch: 'main', commitSha: 'abcdef12', commitMessage: undefined,
    logDelivery: (d) => deliveries.push(d), deps,
  });
  const rows = deploysOf(hook.appId);
  assert.deepEqual(triggered, [{ env: 'sandbox', deployment_id: rows[0].id }, { env: 'production', deployment_id: rows[1].id }]);
  assert.deepEqual(rows.map((r) => [r.env, r.status, r.commit_hash, r.commit_message, r.log]), [
    ['sandbox', 'pending', 'abcdef12', null, 'Triggered by webhook'],
    ['production', 'pending', 'abcdef12', null, 'Triggered by webhook'],
  ]);
  assert.deepEqual(deliveries, [
    { actionTaken: 'deploy_triggered', branch: 'main', commitSha: 'abcdef12', deployId: rows[0].id },
    { actionTaken: 'deploy_triggered', branch: 'main', commitSha: 'abcdef12', deployId: rows[1].id },
  ]);
  const slot = db.prepare('SELECT slot FROM apps WHERE id = ?').get(hook.appId).slot;
  assert.deepEqual(calls.map((c) => [c[0], c[1].id, c[2], c[3]]), [[rows[0].id, hook.appId, 'sandbox', { slot }], [rows[1].id, hook.appId, 'production', { slot }]]);
  await new Promise((r) => setImmediate(r));
});
