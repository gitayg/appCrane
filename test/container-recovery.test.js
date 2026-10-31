import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-container-recovery-'));

const { initDb, getDb } = await import('../server/db.js');
initDb();
const cr = await import('../server/services/containerRecovery.js');
const { assertNoInflightDeploy } = await import('../server/services/deployer.js');
const { logAudit } = await import('../server/middleware/audit.js');

const db = getDb();
const owner = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Owner','owner@example.com','user','unused',1,'human')").run().lastInsertRowid;
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('Admin','admin@example.com','platform_admin','unused2',1,'human')").run();

let slot = 900;
function makeApp(slug, { sourceType = 'github', liveAgo = 3600, live = {} } = {}) {
  const appId = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type,github_url,branch,container_port) VALUES (?,?,?,?,'https://github.com/example-owner/example-repo','main',3000)",
  ).run(slug, slug, slot++, sourceType).lastInsertRowid;
  db.prepare('INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,?)').run(appId, owner, 'owner');
  const liveId = db.prepare(`
    INSERT INTO deployments (app_id, env, version, status, commit_hash, commit_sha, release_path, tree_sha256, image_ref, started_at, finished_at)
    VALUES (?, 'production', '1.2.3', 'live', ?, ?, ?, ?, ?, datetime('now', ?), datetime('now', ?))
  `).run(appId, live.commit_hash ?? 'abc1234', live.commit_sha ?? null, live.release_path ?? `/data/apps/${slug}/production/releases/r1`,
    live.tree_sha256 ?? 'sha256:tree', live.image_ref ?? null, `-${liveAgo + 60} seconds`, `-${liveAgo} seconds`).lastInsertRowid;
  return { appId: Number(appId), liveId: Number(liveId), name: `appcrane-${slug}-production` };
}

function makeDeps(over = {}) {
  const calls = { deployApp: [] };
  let now = 1_000_000_000_000;
  const deps = {
    db,
    listContainers: async () => new Map(),
    restoring: () => false,
    assertNoInflightDeploy,
    deployApp: async (id, app, env, ports, opts) => {
      calls.deployApp.push({ id, slug: app.slug, env, opts });
      db.prepare("UPDATE deployments SET status = 'live', finished_at = datetime('now') WHERE id = ?").run(id);
      return { success: true };
    },
    getPortsForSlot: () => ({ prod_be: 1, sand_be: 2 }),
    imageCached: async () => true,
    fileExists: () => true,
    logAudit,
    notify: cr.notifyRecovery,
    now: () => now,
    ...over,
  };
  return { deps, calls, advance: (ms) => { now += ms; } };
}

const audits = (appId) => db.prepare('SELECT action, detail FROM audit_log WHERE app_id = ? ORDER BY id').all(appId);
const mails = (appId) => db.prepare("SELECT to_email, subject FROM email_queue WHERE app_id = ? AND source = 'container-recovery' ORDER BY id").all(appId);

beforeEach(() => {
  db.prepare('DELETE FROM deployments').run();
  cr.__testables.attempts.clear();
});

test('missing container + live release: the live release is run again, live row untouched, audited, mailed', async () => {
  const a = makeApp('rec-missing');
  const { deps, calls } = makeDeps();
  const out = await cr.sweep(deps);

  assert.equal(calls.deployApp.length, 1);
  const call = calls.deployApp[0];
  assert.equal(call.slug, 'rec-missing');
  assert.deepEqual(call.opts, {
    preExtractedDir: '/data/apps/rec-missing/production/releases/r1', commitHash: 'abc1234',
    expectTreeSha: 'sha256:tree', releaseCheck: 'skip', rollback: true,
  });
  assert.equal(out.results[0].outcome, 'recovered');
  const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(call.id);
  assert.match(row.log, /^auto-heal: container absent; re-running live deployment #\d+/);
  assert.equal(row.version, '1.2.3');
  assert.equal(row.release_path, '/data/apps/rec-missing/production/releases/r1');
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(a.liveId).status, 'live', 'the old live row is not marked rolled_back');
  assert.deepEqual(audits(a.appId).map(r => r.action), ['container-recovered']);
  assert.deepEqual(mails(a.appId).map(m => m.to_email).sort(), ['admin@example.com', 'owner@example.com']);
});

test('an exited container is recovered too; running, restarting and paused are left alone', async () => {
  makeApp('rec-exited');
  makeApp('rec-running');
  makeApp('rec-paused');
  makeApp('rec-restarting');
  const { deps, calls } = makeDeps({
    listContainers: async () => new Map([
      ['appcrane-rec-exited-production', 'exited'], ['appcrane-rec-running-production', 'running'],
      ['appcrane-rec-paused-production', 'paused'], ['appcrane-rec-restarting-production', 'restarting'],
    ]),
  });
  await cr.sweep(deps);
  assert.deepEqual(calls.deployApp.map(c => c.slug), ['rec-exited']);
});

test('the newest LIVE row is the target even when a failed deploy came after it', async () => {
  const a = makeApp('rec-failed-after');
  db.prepare("INSERT INTO deployments (app_id, env, status, log) VALUES (?, 'production', 'failed', 'auto-heal: earlier attempt')").run(a.appId);
  const { deps, calls } = makeDeps();
  await cr.sweep(deps);
  assert.equal(calls.deployApp.length, 1);
  assert.match(db.prepare('SELECT log FROM deployments WHERE id = ?').get(calls.deployApp[0].id).log, new RegExp(`#${a.liveId}$`));
});

test('a live deploy inside the 300 s grace window is not touched', async () => {
  makeApp('rec-fresh', { liveAgo: 60 });
  const { deps, calls } = makeDeps();
  await cr.sweep(deps);
  assert.equal(calls.deployApp.length, 0);
});

test('an env under a restore is untouched', async () => {
  const a = makeApp('rec-restoring');
  const { deps, calls } = makeDeps({ restoring: (slug, env) => slug === 'rec-restoring' && env === 'production' });
  const out = await cr.sweep(deps);
  assert.equal(calls.deployApp.length, 0);
  assert.deepEqual(out.skipped, [{ name: a.name, why: 'restore in progress' }]);
  assert.deepEqual(audits(a.appId), []);
});

test('a deploy in flight: skipped, no new row, no backoff, no audit', async () => {
  const a = makeApp('rec-inflight');
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'building')").run(a.appId);
  const before = db.prepare('SELECT COUNT(*) AS n FROM deployments WHERE app_id = ?').get(a.appId).n;
  const { deps, calls } = makeDeps();
  const out = await cr.sweep(deps);
  assert.equal(calls.deployApp.length, 0);
  assert.equal(out.results[0].outcome, 'skipped');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM deployments WHERE app_id = ?').get(a.appId).n, before);
  assert.equal(cr.__testables.attempts.size, 0);
  assert.deepEqual(audits(a.appId), []);
});

test('failure: backs off, no retry until due, retries when due, one mail for the outage', async () => {
  const a = makeApp('rec-broken');
  const { deps, calls, advance } = makeDeps({ deployApp: async (id, app, env, ports, opts) => { calls.deployApp.push({ id, opts }); throw new Error('health check failed'); } });
  await cr.sweep(deps);
  assert.equal(calls.deployApp.length, 1);
  const st = cr.__testables.attempts.get(cr.keyOf(a.appId, 'production'));
  assert.equal(st.failures, 1);
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(calls.deployApp[0].id).status, 'failed',
    'a row deployApp left pending is closed, or it would block the env as a deploy in flight');

  advance(cr.backoffMs(1) - 1);
  const held = await cr.sweep(deps);
  assert.equal(calls.deployApp.length, 1, 'no retry before the backoff is due');
  assert.match(held.skipped[0].why, /^backing off until /);

  advance(1);
  await cr.sweep(deps);
  assert.equal(calls.deployApp.length, 2, 'retried once due');
  assert.equal(cr.__testables.attempts.get(cr.keyOf(a.appId, 'production')).failures, 2);
  assert.deepEqual(audits(a.appId).map(r => r.action), ['container-recovery-failed', 'container-recovery-failed']);
  assert.equal(mails(a.appId).length, 2, 'one mail per recipient for the whole outage (owner + admin)');
  assert.match(mails(a.appId)[0].subject, /recovery failed/);
});

test('backoff doubles and is capped at 6 hours', () => {
  assert.equal(cr.backoffMs(1), 10 * 60 * 1000);
  assert.equal(cr.backoffMs(2), 20 * 60 * 1000);
  assert.equal(cr.backoffMs(20), cr.BACKOFF_CAP_MS);
  assert.equal(cr.BACKOFF_CAP_MS, 6 * 60 * 60 * 1000);
});

test('image no longer cached: the release is still re-run, but takes the disk guard (no rollback flag)', async () => {
  makeApp('rec-nocache');
  const { deps, calls } = makeDeps({ imageCached: async () => false });
  await cr.sweep(deps);
  assert.equal(calls.deployApp[0].opts.rollback, undefined);
  assert.equal(calls.deployApp[0].opts.preExtractedDir, '/data/apps/rec-nocache/production/releases/r1');
});

test('release directory gone: rebuild pinned to the live commit; none recorded: refused and backed off', async () => {
  makeApp('rec-gone', { live: { commit_hash: 'unknown', commit_sha: 'deadbeef1234' } });
  const b = makeApp('rec-nothing', { live: { commit_hash: 'unknown' } });
  const { deps, calls } = makeDeps({ fileExists: () => false });
  const out = await cr.sweep(deps);
  assert.deepEqual(calls.deployApp.map(c => [c.slug, c.opts]), [['rec-gone', { targetCommit: 'deadbeef1234', releaseCheck: 'skip' }]]);
  const nothing = out.results.find(r => r.name === b.name);
  assert.equal(nothing.outcome, 'failed');
  assert.match(nothing.detail.error, /release directory .* is gone and no commit is recorded/);
  assert.equal(cr.__testables.attempts.get(cr.keyOf(b.appId, 'production')).failures, 1);
});

test('image app: restarts the live digest', async () => {
  makeApp('rec-image', { sourceType: 'image', live: { image_ref: 'registry.example.test/x@sha256:00ff', release_path: null } });
  const { deps, calls } = makeDeps();
  await cr.sweep(deps);
  assert.deepEqual(calls.deployApp[0].opts, { imageRef: 'registry.example.test/x@sha256:00ff', commitHash: 'abc1234', releaseCheck: 'skip', rollback: true });
});

test('Docker not answering is never read as every container gone', async () => {
  makeApp('rec-dockerdown');
  const { deps, calls } = makeDeps({ listContainers: async () => { throw new Error('Cannot connect to the Docker daemon'); } });
  const out = await cr.sweep(deps);
  assert.equal(out.dockerDown, true);
  assert.equal(calls.deployApp.length, 0);
});

test('one recovery at a time: a sweep requested during a sweep queues one more, never runs alongside', async () => {
  makeApp('rec-serial');
  let active = 0;
  let peak = 0;
  let release;
  const gate = new Promise(r => { release = r; });
  const { deps } = makeDeps({
    listContainers: async () => { active++; peak = Math.max(peak, active); await gate; active--; return new Map([['appcrane-rec-serial-production', 'running']]); },
  });
  const first = cr.runSweep(deps);
  const second = await cr.runSweep(deps);
  assert.equal(second, null, 'second call does not start a parallel sweep');
  release();
  await first;
  assert.equal(peak, 1);
});
