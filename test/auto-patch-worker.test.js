import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// The RCE auto-patch worker end to end, with the network, docker, git and the
// deployer replaced by recording stubs. Each guardrail has a test that shows
// production is not touched when it fails.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-auto-patch-worker-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.BASE_URL = 'http://crane.test';
delete process.env.CRANE_DOMAIN;

const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'auto-patch');
const read = (f) => readFileSync(join(FIX, f), 'utf8');
const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { openVulnRequests } = await import('../server/services/vulnRequests.js');
const W = await import('../server/services/autoPatch/worker.js');
const { sendAutoPatchMail } = await import('../server/services/autoPatch/mail.js');
const { setAppOptOut } = await import('../server/services/autoPatch/policy.js');

const H = 3600_000;
const TIP = 'a'.repeat(40);
const BUMP = 'b'.repeat(40);
const REVERT = 'c'.repeat(40);

const ownerId = Number(db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES ('Olga','olga@acme.test','user',1,'h1','human')").run().lastInsertRowid);
const owner = db.prepare('SELECT * FROM users WHERE id = ?').get(ownerId);
function makeApp(slug, slot, local) {
  const id = Number(db.prepare(`INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES (?,?,?,'managed',?,'main')`)
    .run(slug, slug, slot, local ? 'local' : null).lastInsertRowid);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, ownerId);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const app = makeApp('svc', 950, true);
const gh = makeApp('ghapp', 951, false);

const FINDING = { name: 'minimist', version: '1.2.5', ecosystem: 'npm', ids: ['GHSA-RCE1'], fixed: '1.2.6' };
const NOT_RCE = { name: 'lodash', version: '4.17.15', ecosystem: 'npm', ids: ['GHSA-PP01'], fixed: '4.17.19' };
for (const a of [app, gh]) {
  db.prepare(`INSERT INTO app_vuln_scans (app_id, env, source, ecosystem, status, package_count, findings_json)
    VALUES (?, 'production', 'deploy', 'npm', 'findings', 4, ?)`).run(a.id, JSON.stringify([FINDING, NOT_RCE]));
  openVulnRequests(db, a, 'production', 'deploy', [FINDING, NOT_RCE]);
}
const reqFor = (a, id) => db.prepare('SELECT id, app_slug, vuln_key FROM enhancement_requests WHERE app_slug = ? AND vuln_key LIKE ?').get(a.slug, `%"${id}"]`);

const ADVISORIES = {
  'GHSA-RCE1': { id: 'GHSA-RCE1', summary: 'Code injection in minimist', database_specific: { cwe_ids: ['CWE-94'] } },
  'GHSA-PP01': { id: 'GHSA-PP01', summary: 'Prototype Pollution in lodash', database_specific: { cwe_ids: ['CWE-1321'] } },
};
const repoFiles = { 'package.json': read('base.package.json'), 'package-lock.json': read('base.package-lock.json') };

let S;
let calls;
function reset() {
  for (const t of ['auto_patch_runs', 'enhancement_comments', 'audit_log', 'events', 'email_queue', 'deployments', 'health_state', 'app_auto_patch']) db.prepare(`DELETE FROM ${t}`).run();
  db.prepare("DELETE FROM settings WHERE key = 'auto_approve_rce_fixes'").run();
  // Production runs the branch tip: the only state auto-patch may build on.
  db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, finished_at) VALUES (?, 'production', 'live', ?, datetime('now', '-1 day'))`).run(app.id, TIP.slice(0, 8));
  S = {
    tip: TIP, onReleaseCheck: null, onPromote: null, objects: [TIP, BUMP, REVERT],
    now: Date.parse('2026-10-22T12:00:00Z'), publishedAgoH: 48, fixedHasAdvisory: false, bump: null,
    sandbox: 'live', sandboxDown: false, rcBlocked: false, prod: 'live', prodDown: false, coder: { live: false }, restore: false,
  };
  calls = { push: [], deploy: [], promote: [], rollback: [], releaseCheck: 0, bump: 0, osv: 0 };
  W._setAutoPatchDepsForTests({
    now: () => S.now, pollMs: 1, healthSettleMs: 0, deployTimeoutMs: 2000,
    fetchAdvisories: async (ids) => ({ records: new Map(ids.map((i) => [i, ADVISORIES[i]])), failures: new Map() }),
    queryOsv: async () => { calls.osv++; return { ok: true, findings: S.fixedHasAdvisory ? [{ ...FINDING, version: '1.2.6', ids: ['GHSA-NEW1'] }] : [] }; },
    versionInfo: async () => ({ published: new Date(S.now - S.publishedAgoH * H), deprecated: S.deprecated || null }),
    branchHead: async () => S.tip,
    readFile: async (_a, path) => { if (repoFiles[path]) return { content: repoFiles[path] }; const e = new Error('nope'); e.code = 'FILE_NOT_FOUND'; throw e; },
    runBump: async () => { calls.bump++; if (S.bumpError) throw S.bumpError; return S.bump || { packageJson: repoFiles['package.json'], packageLock: read('transitive.package-lock.json') }; },
    push: async (_a, files, opts) => { calls.push.push({ files: files.map((f) => f.path), opts }); return { commit: { sha: calls.push.length === 1 ? BUMP : REVERT } }; },
    deployApp: async (id, _a, env) => {
      calls.deploy.push({ id, env });
      db.prepare("UPDATE deployments SET status = ?, commit_hash = ?, commit_sha = ?, finished_at = datetime('now') WHERE id = ?").run(S.sandbox, BUMP.slice(0, 8), S.sandboxSha || null, id);
      db.prepare("INSERT OR REPLACE INTO health_state (app_id, env, is_down, last_check_at) VALUES (?, 'sandbox', ?, datetime('now'))").run(app.id, S.sandboxDown ? 1 : 0);
    },
    runReleaseCheck: async () => { calls.releaseCheck++; await S.onReleaseCheck?.(); return { id: 77, blocked: S.rcBlocked, result: S.rcBlocked ? 'fail' : 'pass', checks: S.rcBlocked ? [{ status: 'fail', label: 'Dependency scan', reasons: ['1 vulnerable package'] }] : [] }; },
    promoteApp: async (a, userId, opts) => {
      calls.promote.push({ userId, opts });
      await S.onPromote?.();
      const id = Number(db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, finished_at) VALUES (?, 'production', ?, ?, datetime('now', '-1 minute'))`).run(a.id, S.prod, BUMP.slice(0, 8)).lastInsertRowid);
      db.prepare("INSERT OR REPLACE INTO health_state (app_id, env, is_down, last_check_at) VALUES (?, 'production', ?, datetime('now', '+1 minute'))").run(a.id, S.prodDown ? 1 : 0);
      return { deployment_id: id };
    },
    rollbackApp: async (...a) => { calls.rollback.push(a); return { deployment_id: 999, rollback_to: 1 }; },
    admitHelper: async () => ({ allowed: true }),
    refuseDeployForMemory: async () => {},
    assessRisk: async () => ({ at_risk: false }),
    coderState: async () => S.coder,
    restoreInProgress: async () => S.restore,
    // The repository's objects: a hash resolves only when exactly one has that prefix.
    resolveCommit: async (_slug, h) => { const m = S.objects.filter((o) => o.startsWith(String(h))); return m.length === 1 ? m[0] : null; },
  });
}
beforeEach(reset);

const run = (a = app, id = 'GHSA-RCE1') => W.processRequest(db, reqFor(a, id));
const runRow = () => db.prepare("SELECT * FROM auto_patch_runs WHERE advisory_id = 'GHSA-RCE1' AND app_id = ?").get(app.id);
const audits = (action) => db.prepare('SELECT * FROM audit_log WHERE action = ?').all(action);

test('applied: every guardrail holds, production gets exactly the bump, one audit row, one event, one e-mail', async () => {
  const r = await run();
  assert.equal(r.action, 'applied', r.reason);
  const row = runRow();
  assert.equal(row.status, 'applied');
  assert.equal(row.from_version, '1.2.5');
  assert.equal(row.to_version, '1.2.6');
  assert.equal(row.commit_sha, BUMP);
  assert.deepEqual(calls.push.map((p) => p.files), [['package-lock.json']]);
  assert.equal(calls.push[0].opts.expectParent, TIP);
  assert.equal(calls.push[0].opts.deployOnPush, false);
  assert.equal(calls.promote.length, 1);
  assert.equal(calls.promote[0].userId, null);
  assert.equal(calls.promote[0].opts.expectSandboxDeploymentId, row.sandbox_deployment_id);
  assert.equal(calls.rollback.length, 0);

  const a = audits('change.auto_approved');
  assert.equal(a.length, 1);
  assert.equal(a[0].user_id, null);
  assert.equal(a[0].actor_kind, 'system');
  const d = JSON.parse(a[0].detail);
  assert.equal(d.actor, 'AppCrane auto-patch');
  assert.match(d.policy, /RCE auto-patch policy/);
  assert.equal(d.advisory, 'GHSA-RCE1');
  assert.equal(d.outcome, 'applied');
  assert.equal(d.sandbox_deployment_id, row.sandbox_deployment_id);
  assert.equal(d.production_deployment_id, row.production_deployment_id);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM events WHERE kind = 'change.auto_approved'").get().n, 1);

  const notes = db.prepare('SELECT * FROM enhancement_comments WHERE enhancement_id = ?').all(row.request_id);
  assert.equal(notes.length, 1);
  assert.equal(notes[0].author_name, 'AppCrane auto-patch');
  assert.equal(notes[0].status, 'resolved');

  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'auto-patch' AND to_email = 'olga@acme.test'").get().n, 1);
  assert.equal(sendAutoPatchMail(db, app, row), 0, 'a second send is deduped');
  const sweep = await W.runAutoPatchSweep(db);
  assert.ok(!sweep.results.some((x) => x.request_id === row.request_id), 'not looked at again');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'auto-patch'").get().n, 1);
  assert.equal(audits('change.auto_approved').length, 1);
});

test('fallback: the fixed version has an advisory of its own; nothing is committed', async () => {
  S.fixedHasAdvisory = true;
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /advisories of its own/);
  assert.equal(calls.push.length, 0);
  assert.equal(calls.promote.length, 0);
  const note = db.prepare('SELECT * FROM enhancement_comments').get();
  assert.equal(note.status, 'open');
  assert.match(note.body, /did not apply/);
  assert.equal(audits('change.auto_patch_fallback').length, 1);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'auto-patch'").get().n, 1);
});

test('cooldown: a fix published 2h ago is deferred, then applied once 24h have passed', async () => {
  S.publishedAgoH = 2;
  const r = await run();
  assert.equal(r.action, 'deferred');
  assert.equal(calls.push.length, 0);
  assert.equal(calls.bump, 0);
  assert.ok(runRow().retry_after, JSON.stringify(runRow()));
  assert.equal(W.candidateRequests(db, S.now).some((c) => c.app_slug === 'svc' && c.vuln_key.includes('GHSA-RCE1')), false, 'not retried before the cooldown');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'auto-patch'").get().n, 0);
  S.now += 23 * H;
  S.publishedAgoH = 25;
  assert.equal(W.candidateRequests(db, S.now).some((c) => c.app_slug === 'svc' && c.vuln_key.includes('GHSA-RCE1')), true);
  assert.equal((await run()).action, 'applied');
});

test('sandbox health fails: back to a person, the bump is reverted, production untouched', async () => {
  S.sandboxDown = true;
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /sandbox deployment #\d+ is failing its health check/);
  assert.equal(calls.promote.length, 0);
  assert.equal(calls.releaseCheck, 0);
  assert.equal(calls.push.length, 2);
  assert.equal(calls.push[1].opts.expectParent, BUMP);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE env = 'production'").get().n, 1, 'only the release that was already there');
});

test('sandbox deploy fails outright: back to a person, production untouched', async () => {
  S.sandbox = 'failed';
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.equal(calls.promote.length, 0);
});

test('release check refuses: no promote', async () => {
  S.rcBlocked = true;
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /release check #77 did not pass/);
  assert.equal(calls.promote.length, 0);
  assert.equal(runRow().release_check_id, 77);
});

test('production fails its deploy health gate: recorded as rolled back, owners told', async () => {
  S.prod = 'failed';
  const r = await run();
  assert.equal(r.action, 'rolled_back');
  const a = audits('change.auto_approved');
  assert.equal(a.length, 1);
  assert.equal(JSON.parse(a[0].detail).outcome, 'rolled_back');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'auto-patch'").get().n, 1);
});

test('production goes live then fails health: automatic rollback', async () => {
  S.prodDown = true;
  const r = await run();
  assert.equal(r.action, 'rolled_back');
  assert.equal(calls.rollback.length, 1);
  assert.equal(calls.rollback[0][1], 'production');
});

test('a bump that moves an unrelated dependency is refused before anything is committed', async () => {
  const lock = JSON.parse(read('transitive.package-lock.json'));
  lock.packages['node_modules/ms'].version = '2.1.2';
  S.bump = { packageJson: repoFiles['package.json'], packageLock: JSON.stringify(lock, null, 2) };
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /changed more than minimist/);
  assert.equal(calls.push.length, 0);
});

test('a non-RCE advisory is left to the human flow silently', async () => {
  const r = await run(app, 'GHSA-PP01');
  assert.equal(r.action, 'ineligible');
  assert.equal(calls.bump, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM enhancement_comments').get().n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM email_queue').get().n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM audit_log').get().n, 0);
});

test('a GitHub-backed app is not touched at all', async () => {
  const r = await run(gh);
  assert.equal(r.action, 'skip');
  assert.match(r.reason, /not a crane-hosted/);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM auto_patch_runs WHERE app_id = ?').get(gh.id).n, 0);
  assert.equal(calls.osv + calls.bump + calls.push.length, 0);
});

test('one auto-patch per app at a time', async () => {
  db.prepare("INSERT INTO auto_patch_runs (app_id, advisory_id, ecosystem, package, status) VALUES (?, 'GHSA-OTHER', 'npm', 'x', 'running')").run(app.id);
  const r = await run();
  assert.equal(r.action, 'skip');
  assert.match(r.reason, /another auto-patch is running/);
  assert.equal(calls.push.length + calls.bump, 0);
  assert.throws(() => db.prepare("INSERT INTO auto_patch_runs (app_id, advisory_id, ecosystem, package, status) VALUES (?, 'GHSA-THIRD', 'npm', 'y', 'running')").run(app.id), /UNIQUE/);
});

test('a coder session with uncommitted work (or mid-turn) is never overridden', async () => {
  S.coder = { live: true, dirty: true };
  let r = await run();
  assert.equal(r.action, 'skip');
  assert.match(r.reason, /uncommitted work/);
  S.coder = { live: true, busy: true };
  r = await run();
  assert.equal(r.action, 'skip');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM auto_patch_runs').get().n, 0);
  assert.equal(calls.push.length + calls.bump, 0);
});

test('skipped during a database restore, and when the app is opted out', async () => {
  S.restore = true;
  assert.match((await run()).reason, /restore/);
  S.restore = false;
  const admin = db.prepare("SELECT * FROM users WHERE id = ?").get(ownerId);
  setAppOptOut(db, app, { opted_out: true }, admin);
  assert.match((await run()).reason, /auto-patch is off/);
  assert.equal(calls.push.length + calls.bump, 0);
  void owner;
});

const { setPolicy } = await import('../server/services/autoPatch/policy.js');
const platformAdmin = () => {
  const id = db.prepare("SELECT id FROM users WHERE email = 'pa@acme.test'").get()?.id
    ?? Number(db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES ('Pat','pa@acme.test','platform_admin',1,'h2','human')").run().lastInsertRowid);
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
};
const prodRows = () => db.prepare("SELECT COUNT(*) n FROM deployments WHERE env = 'production'").get().n;

test('the branch has a commit production does not run: back to a person, nothing pushed or promoted', async () => {
  S.tip = 'd'.repeat(40);
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /changes that are not in production/);
  assert.equal(calls.bump, 0);
  assert.equal(calls.push.length, 0);
  assert.equal(calls.deploy.length, 0);
  assert.equal(calls.promote.length, 0);
  assert.equal(prodRows(), 1);
});

test('production has no live release: back to a person, nothing pushed', async () => {
  db.prepare("DELETE FROM deployments WHERE env = 'production'").run();
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /production has no live release/);
  assert.equal(calls.push.length + calls.promote.length, 0);
});

for (const [name, flip, re] of [
  ['the platform switch is turned off', () => setPolicy(db, { enabled: false }, platformAdmin()), /turned off .*platform setting is off/],
  ['the app is opted out', () => setAppOptOut(db, app, { opted_out: true }, owner), /turned off .*opted out/],
  ['a database restore starts', () => { S.restore = true; }, /database restore started/],
]) {
  test(`${name} between sandbox and promote: no promote, the bump is reverted, owners told`, async () => {
    S.onReleaseCheck = flip;
    const r = await run();
    assert.equal(r.action, 'fallback');
    assert.match(r.reason, re);
    assert.match(r.reason, /nothing was promoted/);
    assert.equal(calls.promote.length, 0);
    assert.equal(calls.push.length, 2, 'bump, then its revert');
    assert.equal(calls.push[1].opts.expectParent, BUMP);
    assert.match(calls.push[1].opts.message, /not promoted/);
    assert.equal(prodRows(), 1);
    assert.equal(runRow().status, 'fallback');
    assert.equal(audits('change.auto_patch_fallback').length, 1);
    assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'auto-patch'").get().n, 1);
  });
}

test('production changed between sandbox and promote: no promote', async () => {
  S.onReleaseCheck = () => db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash) VALUES (?, 'production', 'live', 'eeeeeeee')`).run(app.id);
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /production changed/);
  assert.equal(calls.promote.length, 0);
});

test('turned off after promote: an unhealthy production is not rolled back by the worker, and owners are told to act', async () => {
  S.prodDown = true;
  S.onPromote = () => setPolicy(db, { enabled: false }, platformAdmin());
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /automatic rollback did not run because auto-patch was turned off/);
  assert.equal(calls.rollback.length, 0);
  const mail = db.prepare("SELECT subject FROM email_queue WHERE source = 'auto-patch'").get();
  assert.match(mail.subject, /NOT rolled back/);
});

test('a restore that starts after promote stops the worker\'s rollback too', async () => {
  S.prodDown = true;
  S.onPromote = () => { S.restore = true; };
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /database restore started/);
  assert.equal(calls.rollback.length, 0);
});

test('a tip that shares production\'s short hash but is a different commit: back to a person', async () => {
  const crafted = TIP.slice(0, 8) + '9'.repeat(32);
  S.tip = crafted;
  db.prepare("UPDATE deployments SET commit_sha = ? WHERE env = 'production'").run(TIP);
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /changes that are not in production/);
  assert.equal(calls.push.length + calls.promote.length + calls.bump, 0);
});

test('an older production row whose short hash is ambiguous in the repository: back to a person', async () => {
  S.tip = TIP;
  S.objects = [TIP, TIP.slice(0, 8) + '9'.repeat(32), BUMP, REVERT];
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /does not name exactly one commit/);
  assert.equal(calls.push.length + calls.promote.length + calls.bump, 0);
});

test('a production row with the full SHA recorded is matched exactly, without resolving the short hash', async () => {
  db.prepare("UPDATE deployments SET commit_sha = ?, commit_hash = 'zzzzzzzz' WHERE env = 'production'").run(TIP);
  const r = await run();
  assert.equal(r.action, 'applied', r.reason);
});

test('sandbox reports a build sharing the bump\'s short hash but a different commit: no promote', async () => {
  S.sandboxSha = BUMP.slice(0, 8) + '7'.repeat(32);
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /not the bump commit/);
  assert.equal(calls.promote.length, 0);
});

test('a fixed version deprecated on npm ("Bad release") is not shipped: back to a person, nothing committed', async () => {
  S.deprecated = 'Bad release. Please use lodash@4.17.21 instead.';
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /is deprecated on npm \("Bad release/);
  assert.equal(calls.bump + calls.push.length + calls.promote.length, 0);
});

test('the npm helper\'s network cannot be confined: back to a person, nothing committed or deployed', async () => {
  const { EgressError } = await import('../server/services/autoPatch/egress.js');
  S.bumpError = new EgressError('docker network create --internal failed');
  const r = await run();
  assert.equal(r.action, 'fallback');
  assert.match(r.reason, /could not be confined to the npm registry .*nothing ran/);
  assert.equal(calls.push.length + calls.deploy.length + calls.promote.length, 0);
});
