import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// An upload app must be redeployable from the release it is already running
// (v2.53.2).
//
// v2.53.0 made 'upload' a real source type, but every code path that reached
// deployApp WITHOUT a bundle in hand — appcrane_deploy, a plain redeploy, and
// the rename endpoint's post-move redeploy of each live environment — fell
// through to the final else and threw:
//
//   App '<slug>' has source_type='upload' which is not deployable on this
//   AppCrane install.
//
// which is wrong: the release is on disk, and the app is serving from it. The
// rename case was the damaging one — that throw lands after the containers have
// already been stopped, so the app goes down and stays down until someone
// re-uploads a bundle by hand.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-ulredeploy-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

// Docker unreachable — the deploy is expected to fail at the build. What is
// under test is which branch it takes to get there.
const SHIM = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { deployApp } = await import('../server/services/deployer.js');
const { getPortsForSlot } = await import('../server/services/portAllocator.js');

let userId;
before(() => {
  userId = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin','h',1,'human')"
  ).run().lastInsertRowid;
});

let slot = 950;
function makeUploadApp(slug, { releases = [] } = {}) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES (?,?,?,'upload')")
    .run(slug, slug, slot++).lastInsertRowid;
  for (const r of releases) {
    const dir = join(process.env.DATA_DIR, 'apps', slug, 'production', 'releases', r);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: slug, version: '1.0.0' }));
  }
  return db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
}

/** Run a deploy with no bundle and return the log the deployer wrote. */
async function redeploy(app) {
  const deployId = db.prepare(
    "INSERT INTO deployments (app_id, env, status, deployed_by) VALUES (?, 'production', 'pending', ?)"
  ).run(app.id, userId).lastInsertRowid;
  await deployApp(deployId, app, 'production', getPortsForSlot(app.slot)).catch(() => {});
  return db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(deployId);
}

test('redeploying an upload app replays its newest release', async () => {
  const app = makeUploadApp('ul-app', { releases: ['1700000000000-upload', '1800000000000-upload'] });
  const row = await redeploy(app);

  assert.doesNotMatch(row.log || '', /not deployable on this AppCrane install/,
    'the release is on disk and the app is serving from it — refusing to redeploy it is false, ' +
    'and after a rename it leaves the app stopped with no way back but a manual upload');
  assert.match(row.log, /Redeploying the current uploaded release: 1800000000000-upload/,
    'the newest release must be chosen, not the first one readdir happens to return');
});

test('an upload app with no release on disk says so, and says what to do', async () => {
  const app = makeUploadApp('ul-empty');
  const row = await redeploy(app);
  assert.match(row.log, /no release on disk to redeploy/);
  assert.match(row.log, /deploy\/upload|deploy_artifact/,
    'the error has to name the way out, or it is just a dead end');
});

test("'managed' with no github_url still gets its own specific error", async () => {
  // The upload branch sits directly above the managed/github diagnostics; a
  // mis-placed branch would swallow them.
  const id = db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('M','m-app',?, 'managed')")
    .run(slot++).lastInsertRowid;
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(id);
  const row = await redeploy(app);
  assert.match(row.log, /no github_url set/);
});
