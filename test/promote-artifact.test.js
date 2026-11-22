import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, symlinkSync, lstatSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// appcrane_promote on a managed app whose live sandbox release came from
// appcrane_deploy_artifact. Its commit_hash is sha256:<bundle digest>, not a
// commit, and promote used to rebuild from it: production deployment 4919 of a
// managed app failed in a second with 'invalid commit "sha256:...": expected a
// hex SHA'. It must copy the sandbox release instead.
//
// docker is a shim that fails, so the deploy stops after the copy under test.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-promote-art-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'f'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
writeFileSync(join(SHIM, 'git'), '#!/bin/sh\necho "git must not run" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { promoteApp } = await import('../server/services/deployer.js');
const { digestTree } = await import('../server/services/artifactDigest.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const adminId = db.prepare(
  "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('padmin','p@x.test','platform_admin','h',1,'human')",
).run().lastInsertRowid;

let slot = 760;
function managedApp(slug) {
  const id = db.prepare(
    "INSERT INTO apps (name, slug, slot, source_type, github_url, branch) VALUES (?, ?, ?, 'managed', ?, 'main')",
  ).run(slug, slug, slot++, `https://github.com/svc-owner/AMC_${slug}`).lastInsertRowid;
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env) VALUES (?, ?)').run(id, env);
    db.prepare('INSERT INTO health_state (app_id, env) VALUES (?, ?)').run(id, env);
  }
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

/** A sandbox release as an artifact deploy leaves it: bundle files plus the runtime .env and data links. */
function artifactRelease(app) {
  const sandboxDir = join(ROOT, 'apps', app.slug, 'sandbox');
  const rel = join(sandboxDir, 'releases', '1000-upload');
  mkdirSync(join(rel, 'dist', 'assets'), { recursive: true });
  mkdirSync(join(rel, 'src', 'data'), { recursive: true });
  mkdirSync(join(sandboxDir, 'shared', 'data'), { recursive: true });
  writeFileSync(join(rel, 'package.json'), '{"name":"x","version":"2.6.4"}');
  writeFileSync(join(rel, 'dist', 'assets', 'index.js'), 'console.log(1)');
  writeFileSync(join(rel, 'src', 'data', 'seed.json'), '{"a":1}');
  writeFileSync(join(sandboxDir, 'shared', '.env.sandbox'), 'SECRET=sandbox\n');
  symlinkSync(join(sandboxDir, 'shared', '.env.sandbox'), join(rel, '.env'));
  symlinkSync(join(sandboxDir, 'shared', 'data'), join(rel, 'data'));
  const tree = digestTree(rel).sha256;
  const id = db.prepare(`
    INSERT INTO deployments (app_id, env, version, status, commit_hash, release_path, tree_sha256,
                             artifact_sha256, artifact_bytes, artifact_filename, deployed_by)
    VALUES (?, 'sandbox', '2.6.4', 'live', ?, ?, ?, ?, 1234, 'bundle.tgz', ?)
  `).run(app.id, `sha256:${'3424febd'.padEnd(64, '0')}`, rel, tree, '3424febd'.padEnd(64, '0'), adminId).lastInsertRowid;
  return { id, rel, tree };
}

async function settled(id) {
  let row;
  for (let i = 0; i < 100; i++) {
    row = db.prepare('SELECT * FROM deployments WHERE id = ?').get(id);
    if (row.status === 'failed' || row.status === 'live') break;
    await new Promise((r) => setTimeout(r, 50));
  }
  return row;
}

test('a managed app promotes a deploy_artifact sandbox release by copying it, never by a git checkout of its sha256 id', async () => {
  const app = managedApp('art-promote');
  const sb = artifactRelease(app);
  const r = await promoteApp(app, adminId);
  assert.equal(r.mode, 'copy');
  assert.equal(r.from_sandbox, sb.id);

  const row = await settled(r.deployment_id);
  assert.doesNotMatch(row.log || '', /expected a hex SHA|check out commit/);
  assert.equal(row.commit_hash, `sha256:${'3424febd'.padEnd(64, '0')}`);
  assert.equal(row.artifact_sha256, '3424febd'.padEnd(64, '0'), 'the artifact identity travels to production');
  assert.equal(row.artifact_filename, 'bundle.tgz');

  const prodRel = row.release_path;
  assert.ok(prodRel && prodRel.includes('/production/releases/'), prodRel);
  assert.equal(readFileSync(join(prodRel, 'dist', 'assets', 'index.js'), 'utf8'), 'console.log(1)');
  assert.equal(digestTree(prodRel).sha256, sb.tree, 'production holds the bytes sandbox ran');
  assert.match(row.log || '', new RegExp(`Release tree verified: ${sb.tree.slice(0, 12)}`));
});

test('the copy keeps a nested data/ directory and re-points only the runtime .env and data links at production', async () => {
  const app = managedApp('art-data');
  artifactRelease(app);
  const r = await promoteApp(app, adminId);
  const row = await settled(r.deployment_id);
  const prodRel = row.release_path;
  assert.equal(readFileSync(join(prodRel, 'src', 'data', 'seed.json'), 'utf8'), '{"a":1}');
  assert.ok(lstatSync(join(prodRel, '.env')).isSymbolicLink());
  assert.doesNotMatch(readFileSync(join(prodRel, '.env'), 'utf8'), /sandbox/);
  assert.ok(lstatSync(join(prodRel, 'data')).isSymbolicLink());
  assert.ok(existsSync(join(ROOT, 'apps', app.slug, 'production', 'shared', '.env.production')));
});

test('a managed app whose sandbox was built from a commit still rebuilds production from that commit', async () => {
  const app = managedApp('art-git');
  db.prepare("INSERT INTO deployments (app_id, env, version, status, commit_hash, deployed_by) VALUES (?, 'sandbox', '1.0.0', 'live', 'abc1234', ?)")
    .run(app.id, adminId);
  const r = await promoteApp(app, adminId);
  assert.equal(r.mode, 'rebuild');
  assert.equal(readdirSync(join(ROOT, 'apps')).includes('art-git') && existsSync(join(ROOT, 'apps', 'art-git', 'production', 'releases'))
    ? readdirSync(join(ROOT, 'apps', 'art-git', 'production', 'releases')).filter((d) => d.endsWith('-promote')).length : 0, 0);
});
