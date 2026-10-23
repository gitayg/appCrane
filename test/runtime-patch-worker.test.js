import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Runtime auto-patch end to end, with docker, the registry, git and the
// deployer replaced by recording stubs. Each guardrail shows production is not
// touched when it fails.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-runtime-worker-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.BASE_URL = 'http://crane.test';
delete process.env.CRANE_DOMAIN;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const W = await import('../server/services/autoPatch/runtimeWorker.js');
const A = await import('../server/services/autoPatch/runtimeAdvisories.js');
const { UnsupportedRegistry } = await import('../server/services/autoPatch/runtimeRegistry.js');
const { setAppOptOut } = await import('../server/services/autoPatch/policy.js');

const TIP = 'a'.repeat(40);
const OTHER = 'd'.repeat(40);
const OLD_DIGEST = `sha256:${'01'.repeat(32)}`;
const NEW_DIGEST = `sha256:${'02'.repeat(32)}`;

const ownerId = Number(db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES ('Olga','olga@acme.test','user',1,'h1','human')").run().lastInsertRowid);
const owner = db.prepare('SELECT * FROM users WHERE id = ?').get(ownerId);
db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES ('Ada','ada@acme.test','platform_admin',1,'h2','human')").run();
function makeApp(slug, slot, fields) {
  const id = Number(db.prepare(`INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch,github_url,image_ref) VALUES (?,?,?,?,?,'main',?,?)`)
    .run(slug, slug, slot, fields.source_type, fields.repo_backend || null, fields.github_url || null, fields.image_ref || null).lastInsertRowid);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, ownerId);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const app = makeApp('shop', 960, { source_type: 'managed', repo_backend: 'local' });
const gh = makeApp('blog', 961, { source_type: 'github', github_url: 'https://github.com/acme/blog' });
const img = makeApp('wiki', 962, { source_type: 'image', image_ref: 'acme/wiki:1' });

let S;
let calls;
function seedLive(a, env, sha, php = '8.3') {
  db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, commit_sha, php_version, finished_at) VALUES (?, ?, 'live', ?, ?, ?, datetime('now', '-1 day'))`)
    .run(a.id, env, sha ? sha.slice(0, 8) : null, sha, php);
}
function reset() {
  for (const t of ['runtime_patch_runs', 'runtime_advisory_notices', 'enhancement_comments', 'enhancement_requests', 'audit_log', 'events', 'email_queue', 'deployments', 'health_state', 'app_auto_patch', 'auto_patch_runs']) db.prepare(`DELETE FROM ${t}`).run();
  db.prepare("DELETE FROM settings WHERE key = 'auto_approve_rce_fixes'").run();
  for (const a of [app, gh]) { seedLive(a, 'production', TIP); seedLive(a, 'sandbox', TIP); }
  seedLive(img, 'production', null, null);
  S = {
    tip: TIP, objects: [TIP, OTHER], registry: NEW_DIGEST, sandboxVersion: '8.3.36', prodVersion: '8.3.36',
    sandbox: 'live', sandboxDown: false, prod: 'live', prodDown: false, rcBlocked: false, restore: false, coder: { live: false },
    onReleaseCheck: null, onProdHealth: null,
    containers: {
      shop: { production: '8.3.35', sandbox: '8.3.35' },
      blog: { production: '8.3.35', sandbox: '8.3.35' },
      wiki: { production: '8.3.30' },
    },
    images: {},
  };
  calls = { deploy: [], promote: [], rollback: [], retag: [], releaseCheck: 0, registry: 0 };
  W._setRuntimePatchDepsForTests({
    now: () => Date.now(), pollMs: 1, healthSettleMs: 0, deployTimeoutMs: 2000,
    inspect: async (slug, env) => {
      const v = S.containers[slug]?.[env];
      if (!v) return null;
      return { image_id: `sha256:img-${slug}-${env}`, runtime: 'php', version: v, version_source: 'image', base_image: slug === 'wiki' ? null : 'php:8.3-apache', base_digest: slug === 'wiki' ? null : OLD_DIGEST };
    },
    advisories: (rt, v) => A.runtimeAdvisories(rt, v, { osvRecords: [] }),
    currentDigest: async (ref) => { calls.registry++; if (S.registryError) throw S.registryError; return S.registry; },
    containerImage: async (slug, env) => S.images[`${slug}/${env}`] || `appcrane-${slug}-${env}:aaaaaaaa`,
    imageVersion: async (ref) => (ref.includes('-sandbox:') ? S.sandboxVersion : S.prodVersion),
    imageBase: async () => ({ image: 'php:8.3-apache', digest: NEW_DIGEST }),
    retag: async (from, to) => { calls.retag.push([from, to]); },
    branchHead: async () => S.tip,
    usesLocalRepo: async (a) => a.repo_backend === 'local',
    resolveCommit: async (_slug, h) => { const m = S.objects.filter((o) => o.startsWith(String(h))); return m.length === 1 ? m[0] : null; },
    deployApp: async (id, a, env, _ports, opts) => {
      calls.deploy.push({ id, env, opts });
      db.prepare("UPDATE deployments SET status = ?, finished_at = datetime('now') WHERE id = ?").run(S.sandbox, id);
      db.prepare("INSERT OR REPLACE INTO health_state (app_id, env, is_down, last_check_at) VALUES (?, 'sandbox', ?, datetime('now'))").run(a.id, S.sandboxDown ? 1 : 0);
      S.images[`${a.slug}/sandbox`] = `appcrane-${a.slug}-sandbox:aaaaaaaa-rt1`;
    },
    runReleaseCheck: async () => { calls.releaseCheck++; await S.onReleaseCheck?.(); return { id: 88, blocked: S.rcBlocked, result: S.rcBlocked ? 'fail' : 'pass', checks: [] }; },
    promoteApp: async (a, userId, opts) => {
      calls.promote.push({ app: a.slug, userId, opts });
      const id = Number(db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, commit_sha, finished_at) VALUES (?, 'production', ?, ?, ?, datetime('now', '-1 minute'))`)
        .run(a.id, S.prod, TIP.slice(0, 8), TIP).lastInsertRowid);
      db.prepare("INSERT OR REPLACE INTO health_state (app_id, env, is_down, last_check_at) VALUES (?, 'production', ?, datetime('now', '+1 minute'))").run(a.id, S.prodDown ? 1 : 0);
      S.images[`${a.slug}/production`] = `appcrane-${a.slug}-production:aaaaaaaa-rt2`;
      await S.onProdHealth?.();
      return { deployment_id: id };
    },
    rollbackApp: async (...x) => { calls.rollback.push(x); return { deployment_id: 999, rollback_to: 1 }; },
    refuseDeployForMemory: async () => {},
    assessRisk: async () => ({ at_risk: false }),
    coderState: async () => S.coder,
    restoreInProgress: async () => S.restore,
    ports: async () => ({ be: 1 }),
  });
}
beforeEach(reset);

const sweep = () => W.runRuntimePatchSweep(db);
const runFor = (a) => db.prepare('SELECT * FROM runtime_patch_runs WHERE app_id = ? ORDER BY id DESC').get(a.id);
const resultFor = (r, a) => r.results.find((x) => x.app === a.slug);
const audits = (action) => db.prepare('SELECT * FROM audit_log WHERE action = ?').all(action);

test('happy path: same commit rebuilt on a fresh base, sandbox then production, audited, request created and closed, owners mailed', async () => {
  const r = await sweep();
  const res = resultFor(r, app);
  assert.equal(res.action, 'applied', res.reason);
  const shopDeploys = calls.deploy.filter((c) => c.id && db.prepare('SELECT app_id FROM deployments WHERE id = ?').get(c.id).app_id === app.id);
  assert.equal(shopDeploys.length, 1);
  assert.equal(shopDeploys[0].env, 'sandbox');
  assert.deepEqual(shopDeploys[0].opts, { targetCommit: TIP, freshBase: true });
  assert.equal(calls.promote[0].userId, null);
  assert.equal(calls.promote[0].opts.freshBase, true);
  assert.equal(calls.rollback.length, 0);

  const run = runFor(app);
  assert.equal(run.status, 'applied');
  assert.equal(run.commit_sha, TIP);
  assert.equal(run.from_version, '8.3.35');
  assert.equal(run.to_version, '8.3.36');
  assert.equal(run.fixed_version, '8.3.36');
  assert.equal(run.from_digest, OLD_DIGEST);
  assert.equal(run.to_digest, NEW_DIGEST);
  const sb = db.prepare('SELECT * FROM deployments WHERE id = ?').get(run.sandbox_deployment_id);
  assert.equal(sb.commit_sha, TIP, 'the same commit, no repository write');
  assert.equal(sb.base_digest, NEW_DIGEST);
  assert.equal(db.prepare('SELECT base_image FROM deployments WHERE id = ?').get(run.production_deployment_id).base_image, 'php:8.3-apache');

  const a = audits('change.auto_approved').map((x) => JSON.parse(x.detail)).filter((d) => d.run_id === run.id);
  assert.equal(a.length, 1);
  assert.equal(a[0].actor, 'AppCrane runtime patch');
  assert.equal(a[0].kind, 'runtime');
  assert.equal(a[0].advisory, 'CVE-2026-109618, CVE-2026-109619');

  const req = db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(run.request_id);
  assert.match(req.message, /^Rebuild on patched PHP 8\.3\.36 \(CVE-2026-109618, CVE-2026-109619\)/);
  assert.equal(req.status, 'done');
  assert.equal(req.vuln_key, null, 'not a scanner request: the scan must not close it, and the npm worker must not pick it up');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'runtime-patch' AND app_id = ?").get(app.id).n, 1);
  assert.deepEqual(calls.retag.filter(([f]) => f.includes('-shop-')), [
    ['appcrane-shop-sandbox:aaaaaaaa-rt1', 'appcrane-shop-sandbox:aaaaaaaa'],
    ['appcrane-shop-production:aaaaaaaa-rt2', 'appcrane-shop-production:aaaaaaaa'],
  ]);

  const again = await sweep();
  assert.match(resultFor(again, app)?.reason || 'not looked at', /already handled|not looked at/);
});

test('sandbox health fails: back to a person, production untouched', async () => {
  S.sandboxDown = true;
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'fallback');
  assert.match(resultFor(r, app).reason, /sandbox deployment #\d+ is failing its health check; production was not touched/);
  assert.equal(calls.promote.filter((p) => p.app === 'shop').length, 0);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM deployments WHERE app_id = ? AND env = 'production'").get(app.id).n, 1);
  const run = runFor(app);
  const req = db.prepare('SELECT * FROM enhancement_requests WHERE id = ?').get(run.request_id);
  assert.equal(req.status, 'new');
  assert.equal(audits('change.auto_patch_fallback').length >= 1, true);
});

test('production health fails: rolled back automatically', async () => {
  S.prodDown = true;
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'rolled_back');
  assert.ok(calls.rollback.some((x) => x[0].id === app.id && x[1] === 'production'));
  assert.equal(calls.retag.filter(([f]) => f.includes('-shop-')).length, 0, 'the old image keeps the commit tag, so rollback restores it');
});

test('branch tip is not production: back to a person, nothing built', async () => {
  S.tip = OTHER;
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'fallback');
  assert.match(resultFor(r, app).reason, /branch has changes that are not in production/);
  assert.equal(calls.deploy.filter((c) => db.prepare('SELECT app_id FROM deployments WHERE id = ?').get(c.id).app_id === app.id).length, 0);
});

for (const [name, flip, re] of [
  ['the app is opted out', () => setAppOptOut(db, app, { opted_out: true }, owner), /turned off .*opted out/],
  ['the platform switch is off', () => db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_approve_rce_fixes', 'false')").run(), /turned off .*platform setting/],
  ['a restore starts', () => { S.restore = true; }, /restore started/],
]) {
  test(`re-checked before promote: ${name} after sandbox → nothing promoted`, async () => {
    let flipped = false;
    S.onReleaseCheck = () => { if (!flipped) { flipped = true; flip(); } };
    const r = await sweep();
    const res = resultFor(r, app);
    assert.equal(res.action, 'fallback');
    assert.match(res.reason, re);
    assert.equal(calls.promote.filter((p) => p.app === 'shop').length, 0);
  });
}

test('re-checked before rollback: switch turned off while production fails → no automatic rollback, a person is told', async () => {
  S.prodDown = true;
  S.onProdHealth = () => db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_approve_rce_fixes', 'false')").run();
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'fallback');
  assert.match(resultFor(r, app).reason, /automatic rollback did not run/);
  assert.equal(calls.rollback.length, 0);
});

test('image-source app: never rebuilt, flagged for a person', async () => {
  const r = await sweep();
  const row = r.rows.find((x) => x.slug === 'wiki');
  assert.equal(row.handling, 'person');
  assert.match(row.why, /prebuilt image/);
  assert.equal(resultFor(r, img), undefined);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM runtime_patch_runs WHERE app_id = ?').get(img.id).n, 0);
});

test('Job Health list and one admin e-mail per advisory', async () => {
  S.containers.shop.production = '8.1.31';
  const r = await sweep();
  const rows = r.rows.map((x) => [x.slug, x.env, x.version, x.fixed_version, x.handling]);
  assert.deepEqual(rows, [
    ['shop', 'production', '8.1.31', null, 'person'],
    ['shop', 'sandbox', '8.3.35', '8.3.36', 'person'],
    ['blog', 'production', '8.3.35', '8.3.36', 'auto'],
    ['blog', 'sandbox', '8.3.35', '8.3.36', 'auto'],
    ['wiki', 'production', '8.3.30', '8.3.36', 'person'],
  ]);
  assert.match(r.rows[0].why, /PHP 8\.1 gets no fix for this flaw: move the app to a supported PHP branch/);
  assert.deepEqual(W.latestSurvey().rows.length, 5);
  const mails = db.prepare("SELECT * FROM email_queue WHERE source = 'runtime-advisory'").all();
  assert.equal(mails.length, 1);
  assert.equal(mails[0].to_email, 'ada@acme.test');
  assert.match(mails[0].subject, /3 apps run a runtime with a remote-code-execution flaw \(CVE-2026-109618, CVE-2026-109619\)/);
  assert.match(mails[0].body_text, /wiki \(production\): PHP 8\.3\.30, fixed in 8\.3\.36; a person must act: deployed from a prebuilt image/);
  await sweep();
  assert.equal(db.prepare("SELECT COUNT(*) n FROM email_queue WHERE source = 'runtime-advisory'").get().n, 1, 'once per advisory');
});

test('registry still serves the digest already built on: deferred, nothing built', async () => {
  S.registry = OLD_DIGEST;
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'deferred');
  assert.match(resultFor(r, app).reason, /waiting for a patched image/);
  assert.equal(calls.deploy.length, 0);
});

test('base not on Docker Hub: back to a person', async () => {
  S.registryError = new UnsupportedRegistry('ghcr.io/acme/php:8.3 is not on Docker Hub');
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'fallback');
  assert.equal(calls.deploy.length, 0);
});

test('rebuilt sandbox still runs the vulnerable PHP (the tag has no fix yet): deferred, not promoted', async () => {
  S.sandboxVersion = '8.3.35';
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'deferred');
  assert.match(resultFor(r, app).reason, /no fixed image yet/);
  assert.equal(calls.promote.length, 0);
});

test('production rebuilt but still vulnerable (no fresh base on the production build): a person is told', async () => {
  S.prodVersion = '8.3.35';
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'fallback');
  assert.match(resultFor(r, app).reason, /still runs PHP 8\.3\.35/);
});

test('GitHub app: rebuilt when sandbox runs production\'s exact commit; back to a person when it does not', async () => {
  const r = await sweep();
  assert.equal(resultFor(r, gh).action, 'applied', resultFor(r, gh).reason);
  reset();
  db.prepare("UPDATE deployments SET commit_sha = ? WHERE app_id = ? AND env = 'sandbox'").run(OTHER, gh.id);
  const r2 = await sweep();
  assert.equal(resultFor(r2, gh).action, 'fallback');
  assert.match(resultFor(r2, gh).reason, /sandbox does not run production's commit/);
});

test('skipped while a coder session has uncommitted work', async () => {
  S.coder = { live: true, dirty: true };
  const r = await sweep();
  assert.equal(resultFor(r, app).action, 'skip');
  assert.match(resultFor(r, app).reason, /uncommitted work/);
  assert.equal(calls.deploy.length, 0);
});
