import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Runtime auto-patch for Node.js apps (CVE-2026-111497, "Node2Shell"): the same
// worker path as PHP, with docker, the registry and the deployer stubbed.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-runtime-node-'));
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.BASE_URL = 'http://crane.test';
delete process.env.CRANE_DOMAIN;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const W = await import('../server/services/autoPatch/runtimeWorker.js');
const A = await import('../server/services/autoPatch/runtimeAdvisories.js');
const { inspectContainerRuntime } = await import('../server/services/autoPatch/runtimeInspect.js');

const TIP = 'a'.repeat(40);
const OLD_DIGEST = `sha256:${'01'.repeat(32)}`;
const NEW_DIGEST = `sha256:${'02'.repeat(32)}`;

const ownerId = Number(db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES ('Olga','olga@acme.test','user',1,'h1','human')").run().lastInsertRowid);
db.prepare("INSERT INTO users (name,email,role,active,api_key_hash,kind) VALUES ('Ada','ada@acme.test','platform_admin',1,'h2','human')").run();
function makeApp(slug, slot) {
  const id = Number(db.prepare(`INSERT INTO apps (name,slug,slot,source_type,repo_backend,branch) VALUES (?,?,?,'managed','local','main')`).run(slug, slug, slot).lastInsertRowid);
  db.prepare("INSERT INTO app_user_roles (app_id,user_id,app_role) VALUES (?,?,'owner')").run(id, ownerId);
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}
const api = makeApp('api', 970);
const legacy = makeApp('legacy', 971);
const BASES = { api: 'node:22-alpine', legacy: 'node:20-alpine' };

let S, calls;
function reset() {
  for (const t of ['runtime_patch_runs', 'runtime_advisory_notices', 'enhancement_comments', 'enhancement_requests', 'audit_log', 'events', 'email_queue', 'deployments', 'health_state', 'app_auto_patch', 'auto_patch_runs']) db.prepare(`DELETE FROM ${t}`).run();
  for (const a of [api, legacy]) for (const env of ['production', 'sandbox']) {
    db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, commit_sha, base_image, finished_at) VALUES (?, ?, 'live', ?, ?, ?, datetime('now', '-1 day'))`)
      .run(a.id, env, TIP.slice(0, 8), TIP, BASES[a.slug]);
  }
  S = { containers: { api: '22.22.0', legacy: '20.20.2' }, rebuilt: '22.23.4', images: {} };
  calls = { deploy: [], promote: [] };
  W._setRuntimePatchDepsForTests({
    now: () => Date.now(), pollMs: 1, healthSettleMs: 0, deployTimeoutMs: 2000,
    inspect: async (slug) => (S.containers[slug]
      ? { image_id: `sha256:img-${slug}`, runtime: 'node', version: S.containers[slug], version_source: 'image', base_image: BASES[slug], base_digest: OLD_DIGEST }
      : null),
    advisories: (rt, v) => A.runtimeAdvisories(rt, v, { osvRecords: [] }),
    currentDigest: async () => NEW_DIGEST,
    containerImage: async (slug, env) => S.images[`${slug}/${env}`] || `appcrane-${slug}-${env}:aaaaaaaa`,
    imageVersion: async (_ref, runtime) => { assert.equal(runtime, 'node'); return S.rebuilt; },
    imageBase: async () => ({ image: 'node:22-alpine', digest: NEW_DIGEST }),
    retag: async () => {},
    branchHead: async () => TIP,
    usesLocalRepo: async () => true,
    resolveCommit: async (_s, h) => (TIP.startsWith(String(h)) ? TIP : null),
    deployApp: async (id, a, env, _p, opts) => {
      calls.deploy.push({ id, env, opts });
      db.prepare("UPDATE deployments SET status = 'live', finished_at = datetime('now') WHERE id = ?").run(id);
      db.prepare("INSERT OR REPLACE INTO health_state (app_id, env, is_down, last_check_at) VALUES (?, 'sandbox', 0, datetime('now'))").run(a.id);
      S.images[`${a.slug}/sandbox`] = `appcrane-${a.slug}-sandbox:aaaaaaaa-rt1`;
    },
    productionBaseline: async () => ({ ok: true, scan_id: 1, findings: [] }),
    runReleaseCheck: async () => ({ id: 77, blocked: false, result: 'pass', checks: [] }),
    promoteApp: async (a, userId, opts) => {
      calls.promote.push({ app: a.slug, opts });
      const id = Number(db.prepare(`INSERT INTO deployments (app_id, env, status, commit_hash, commit_sha, finished_at) VALUES (?, 'production', 'live', ?, ?, datetime('now', '-1 minute'))`).run(a.id, TIP.slice(0, 8), TIP).lastInsertRowid);
      db.prepare("INSERT OR REPLACE INTO health_state (app_id, env, is_down, last_check_at) VALUES (?, 'production', 0, datetime('now', '+1 minute'))").run(a.id);
      S.images[`${a.slug}/production`] = `appcrane-${a.slug}-production:aaaaaaaa-rt2`;
      return { deployment_id: id };
    },
    rollbackApp: async () => ({ deployment_id: 999, rollback_to: 1 }),
    refuseDeployForMemory: async () => {},
    assessRisk: async () => ({ at_risk: false }),
    coderState: async () => ({ live: false }),
    restoreInProgress: async () => false,
    ports: async () => ({ be: 1 }),
  });
}
beforeEach(reset);

test('advisory matching: a Node release line is its major, and EOL lines get no fix', async () => {
  const at = async (v) => A.runtimeAdvisories('node', v, { osvRecords: [] });
  assert.deepEqual(await at('22.22.0').then((r) => [r.affected, r.fixedVersion, r.unsupportedBranch]), [true, '22.23.4', false]);
  assert.deepEqual(await at('24.22.0').then((r) => [r.affected, r.fixedVersion, r.unsupportedBranch]), [true, '24.22.1', false]);
  assert.deepEqual(await at('26.12.0').then((r) => [r.affected, r.fixedVersion, r.unsupportedBranch]), [true, '26.12.1', false]);
  for (const v of ['22.23.4', '24.22.1', '26.12.1']) assert.equal((await at(v)).affected, false, v);
  for (const v of ['20.20.2', '23.11.1', '25.3.0']) {
    const r = await at(v);
    assert.deepEqual([r.affected, r.fixedVersion, r.unsupportedBranch], [true, null, true], v);
  }
  assert.equal(A.branchOf('22.22.0', 'node'), '22.x');
  assert.equal(A.branchOf('8.3.35', 'php'), '8.3', 'PHP keeps major.minor branches');
  assert.equal(A.RUNTIMES.node.enabled, true);
});

test('a Node app on 22.22.0 is rebuilt on a fresh node:22-alpine through the same worker path; Node 20 goes to a person', async () => {
  const r = await W.runRuntimePatchSweep(db);
  const rows = r.rows.map((x) => [x.slug, x.env, x.version, x.fixed_version, x.handling]);
  assert.deepEqual(rows, [
    ['api', 'production', '22.22.0', '22.23.4', 'auto'],
    ['api', 'sandbox', '22.22.0', '22.23.4', 'auto'],
    ['legacy', 'production', '20.20.2', null, 'person'],
    ['legacy', 'sandbox', '20.20.2', null, 'person'],
  ]);
  assert.match(r.rows[2].why, /Node\.js 20\.x gets no fix for this flaw: move the app to a supported Node\.js branch/);
  const res = r.results.find((x) => x.app === 'api');
  assert.equal(res.action, 'applied', res.reason);
  const run = db.prepare('SELECT * FROM runtime_patch_runs WHERE app_id = ?').get(api.id);
  assert.deepEqual([run.runtime, run.from_version, run.to_version, run.fixed_version, run.base_image, run.to_digest],
    ['node', '22.22.0', '22.23.4', '22.23.4', 'node:22-alpine', NEW_DIGEST]);
  assert.deepEqual(calls.deploy[0].opts, { targetCommit: TIP, freshBase: true });
  assert.equal(calls.promote[0].opts.freshBase, true);
  const mails = db.prepare("SELECT * FROM email_queue WHERE source = 'runtime-advisory'").all();
  assert.equal(mails.length, 1);
  assert.match(mails[0].subject, /2 apps run a runtime with a remote-code-execution flaw \(CVE-2026-111497\)/);
  assert.match(mails[0].body_text, /legacy \(production\): Node\.js 20\.20\.2, fixed in no release on this branch; a person must act/);
});

test('a rebuild whose base still ships the vulnerable Node is deferred, production untouched', async () => {
  S.rebuilt = '22.22.0';
  const r = await W.runRuntimePatchSweep(db);
  const res = r.results.find((x) => x.app === 'api');
  assert.equal(res.action, 'deferred');
  assert.match(res.reason, /runs Node\.js 22\.22\.0, not 22\.23\.4 or later/);
  assert.equal(calls.promote.length, 0);
});

test('inspectContainerRuntime reads NODE_VERSION from the image, as the official node images set it', async () => {
  const run = async (args) => {
    if (args[0] === 'inspect') return JSON.stringify({ State: { Running: true }, Image: 'sha256:x', Config: { Image: 'appcrane-api-production:aaaa', Env: ['NODE_VERSION=99.0.0'] } });
    return JSON.stringify({ Env: ['PATH=/usr/local/bin', 'NODE_VERSION=22.22.0', 'YARN_VERSION=1.22.22'], Labels: { 'appcrane.base.image': 'node:22-alpine' } });
  };
  const info = await inspectContainerRuntime('api', 'production', { run });
  assert.deepEqual([info.runtime, info.version, info.version_source, info.base_image], ['node', '22.22.0', 'image', 'node:22-alpine']);
});

// Opt-in (RUNTIME_PATCH_LIVE=1, needs Docker and Docker Hub): a tiny Node app
// with no Dockerfile, built by the real generator and docker.js with a fresh
// pull, runs a Node with the CVE-2026-111497 fix.
const LIVE = process.env.RUNTIME_PATCH_LIVE === '1';
test('live: generated Node 22 app on a freshly pulled node:22-alpine runs a Node2Shell-fixed Node', { skip: !LIVE && 'set RUNTIME_PATCH_LIVE=1 to build for real' }, async () => {
  const { writeFileSync, readFileSync, mkdirSync } = await import('fs');
  const { execFileSync } = await import('child_process');
  const { ensureDockerfile } = await import('../server/services/dockerfileGen.js');
  const docker = await import('../server/services/docker.js');
  const { imageRuntimeVersion } = await import('../server/services/autoPatch/runtimeInspect.js');
  const rel = mkdtempSync(join(tmpdir(), 'crane-runtime-node-live-'));
  mkdirSync(rel, { recursive: true });
  writeFileSync(join(rel, 'package.json'), JSON.stringify({ name: 'hello', version: '1.0.0', scripts: { start: 'node server.js' } }));
  writeFileSync(join(rel, 'package-lock.json'), JSON.stringify({ name: 'hello', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'hello', version: '1.0.0' } } }));
  writeFileSync(join(rel, 'server.js'), "require('http').createServer((q, s) => s.end(process.version)).listen(3000);\n");
  // The generator reads the Node line from deployhub.json (node_version), not package.json.
  ensureDockerfile({ releaseDir: rel, manifest: { node_version: '22' }, appBasePath: '/hello/' });
  assert.match(readFileSync(join(rel, 'Dockerfile'), 'utf8'), /^FROM node:22-alpine/m);
  const lines = [];
  const tag = await docker.buildImageIfNeeded({ slug: 'rtnodelive', env: 'sandbox', contextDir: rel, commitHash: `t${Date.now()}`, appBasePath: '/hello/', onLog: (l) => lines.push(l) });
  try {
    console.log(lines.filter((l) => /Pulled|Could not pull/.test(l)).join('\n'));
    assert.ok(lines.includes('Pulled the latest node:22-alpine'), lines.slice(0, 5).join('\n'));
    const base = await docker.imageBaseInfo(tag);
    console.log('base', JSON.stringify(base));
    const envVersion = await imageRuntimeVersion(tag, 'node');
    const inside = execFileSync('docker', ['run', '--rm', '--pull', 'never', '--entrypoint', 'node', tag, '-v'], { encoding: 'utf8' }).trim();
    console.log('NODE_VERSION env', envVersion, 'node -v', inside);
    assert.equal(inside, `v${envVersion}`);
    const adv = await A.runtimeAdvisories('node', envVersion, { osvRecords: [] });
    assert.equal(adv.affected, false, `${envVersion} is still affected`);
  } finally {
    execFileSync('docker', ['rmi', tag]);
  }
});
