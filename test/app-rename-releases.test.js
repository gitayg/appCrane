import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

// A rename on a live box (2026-10-28) left the app with no way back:
//
//   - deployments.release_path is an absolute path under data/apps/<slug>, and
//     the rename moved the directory without rewriting it, so rolling back to
//     the last good release failed with "Release directory missing on disk".
//   - the redeploy query read `SELECT env ... WHERE status = 'live'`, one row
//     per past release still marked live, so the rename started about 60
//     concurrent redeploys per environment instead of one.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-rename-rel-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM = join(ROOT, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { renameApp } = await import('../server/services/appRename.js');
const { rollbackApp } = await import('../server/services/deployer.js');

after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
  try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {}
});

const adminId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('ra','ra@x.test','platform_admin','h',1,'human')")
  .run().lastInsertRowid;
const admin = db.prepare('SELECT * FROM users WHERE id = ?').get(adminId);
const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Old','old-reports',20041,'github','main')")
  .run().lastInsertRowid;

// Past releases on disk and in the table, every one still marked live, as on
// the real box. At most 5 per environment: a deploy, the failed redeploy here
// included, prunes releases down to the newest 5.
const oldBase = resolve(ROOT, 'apps', 'old-reports');
const LIVE = { production: 4, sandbox: 3 };
const ids = {};
for (const [env, n] of Object.entries(LIVE)) {
  ids[env] = [];
  for (let i = 0; i < n; i++) {
    const dir = join(oldBase, env, 'releases', `179300000000${i}-git`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'server.js'), '');
    ids[env].push(db.prepare(
      "INSERT INTO deployments (app_id, env, status, version, release_path, started_at) VALUES (?, ?, 'live', ?, ?, datetime('now', ?))",
    ).run(appId, env, `1.0.${i}`, dir, `-${n - i} hours`).lastInsertRowid);
  }
}
// Another app whose path shares the prefix must not be touched.
const otherId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('Other','old-reports-2',20042,'github','main')")
  .run().lastInsertRowid;
const otherPath = join(resolve(ROOT, 'apps', 'old-reports-2'), 'production', 'releases', 'x-git');
const otherDep = db.prepare("INSERT INTO deployments (app_id, env, status, release_path) VALUES (?, 'production', 'live', ?)")
  .run(otherId, otherPath).lastInsertRowid;

const maxBefore = db.prepare('SELECT MAX(id) AS m FROM deployments').get().m;
const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
const out = await renameApp({ app, newSlug: 'new-hub', redirect: true, user: admin });

// The queued redeploys fail on the docker shim; let them finish before reading.
for (let i = 0; i < 100; i++) {
  if (!db.prepare("SELECT 1 FROM deployments WHERE id > ? AND status IN ('pending','building','deploying')").get(maxBefore)) break;
  await new Promise((r) => setTimeout(r, 100));
}

test('one redeploy per environment, not one per past live release', () => {
  const queued = db.prepare('SELECT env, COUNT(*) AS n FROM deployments WHERE id > ? GROUP BY env ORDER BY env').all(maxBefore);
  assert.deepEqual(queued, [{ env: 'production', n: 1 }, { env: 'sandbox', n: 1 }]);
  assert.deepEqual([...out.redeploying].sort(), ['production', 'sandbox']);
});

test('every stored release path follows the app to its new directory, and exists', () => {
  const newBase = resolve(ROOT, 'apps', 'new-hub');
  for (const env of Object.keys(LIVE)) {
    for (const id of ids[env]) {
      const p = db.prepare('SELECT release_path FROM deployments WHERE id = ?').get(id).release_path;
      assert.ok(p.startsWith(newBase + '/'), p);
      assert.ok(existsSync(p), `missing on disk: ${p}`);
    }
  }
  assert.equal(existsSync(oldBase), false, 'control: the directory did not move');
});

test('another app whose slug starts with the old one keeps its paths', () => {
  assert.equal(db.prepare('SELECT release_path FROM deployments WHERE id = ?').get(otherDep).release_path, otherPath);
});

test('rolling back to a release from before the rename finds it', async () => {
  const renamed = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
  let code = null;
  try { await rollbackApp(renamed, 'production', ids.production[2], adminId); } catch (e) { code = e.code || e.message; }
  assert.notEqual(code, 'RELEASE_GONE');
  assert.equal(existsSync(join(ROOT, 'apps', 'new-hub', 'production', 'current')), true, `rollback stopped before the swap: ${code}`);
});
