import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// image_retention defaults to 1 — the running image plus the one behind it.
//
// Until v2.78.0 it was 0 on every row of every install: 031 created the column
// with DEFAULT 0 and each later rebuild of apps restated it, so `?? 0` fallbacks
// never fired and deployer.js pruned with keep = 1. The previous commit's image
// was deleted at the end of the deploy that superseded it — which is exactly the
// image a rollback to that release needs, since rollbackApp re-runs deployApp
// with the target's commit_hash and buildImageIfNeeded skips the build only
// while that tag still exists on the host.
//
// Two halves have to hold, and they are covered separately because they fail
// separately: EXISTING rows are raised by migration 096, and NEW rows get the
// value because every app-creation path names the column. The column DEFAULT is
// deliberately still 0 — see the migration's header — so a creation path that
// forgets the column silently reintroduces the bug for new apps, which is what
// the static scan below exists to catch.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-imgret-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

// Nothing here deploys, but appcrane_create_app reloads Caddy and the app-dir
// setup runs; a docker that always fails keeps the tool on its no-daemon path.
const SHIM = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { callTool } = await import('../server/services/mcpTools.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const { DEFAULT_IMAGE_RETENTION, imagesToKeep } = await import('../server/services/imageRetention.js');

const MIGRATION = '096-default-image-retention.sql';
const migrationsDir = new URL('../server/migrations/', import.meta.url);

let admin;
let slot = 7700;
before(() => {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@example.com','platform_admin',?,1,'human')"
  ).run(hashApiKey(generateApiKey('dhk_admin'))).lastInsertRowid;
  admin = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
});

// appcrane_create_app calls refreshAppChecks, which arms a per-app setInterval.
// Left running, the process never drains its event loop and node:test reports
// the whole FILE as a timeout with every assertion already green.
after(async () => {
  const { stopHealthChecker } = await import('../server/services/healthChecker.js');
  stopHealthChecker();
});

const unwrap = (r) => (typeof r === 'string' ? JSON.parse(r) : (r?.content ? JSON.parse(r.content[0].text) : r));
const call = async (n, a) => unwrap(await callTool(admin, n, a));
const retentionOf = (slug) => db.prepare('SELECT image_retention FROM apps WHERE slug = ?').get(slug).image_retention;

// ===========================================================================
// The default itself
// ===========================================================================

test('the default is 1 — current image plus the previous one', () => {
  assert.equal(DEFAULT_IMAGE_RETENTION, 1);
});

test('keep = retention + 1, so the default leaves TWO images per (slug, env)', () => {
  // The off-by-one here is the whole feature: keep counts images on disk,
  // image_retention counts the ones behind the running one. keep = 1 at the
  // default would delete the previous image again and make every rollback a
  // rebuild; keep = 3 would silently double the disk cost of the change.
  assert.equal(imagesToKeep({ image_retention: 1 }), 2);
  assert.equal(imagesToKeep({ image_retention: 0 }), 1, '0 must still mean "keep only the newest"');
  assert.equal(imagesToKeep({ image_retention: 5 }), 6);
  assert.equal(imagesToKeep({}), 2, 'a partially-selected app row falls back to the default, not to 0');
});

// ===========================================================================
// Existing rows: migration 096
// ===========================================================================

test('096 raises a row left at 0 and leaves an operator-chosen 5 alone', () => {
  // The migration statement, run against rows that look like a pre-096
  // install. Re-executing the file is the honest way to test it: initDb has
  // already applied it, and on a fresh database `apps` is empty, so the
  // interesting rows have to be put there first.
  db.prepare("INSERT INTO apps (name, slug, slot, image_retention) VALUES ('Z','ret-zero',?,0)").run(slot++);
  db.prepare("INSERT INTO apps (name, slug, slot, image_retention) VALUES ('F','ret-five',?,5)").run(slot++);
  db.prepare("INSERT INTO apps (name, slug, slot, image_retention) VALUES ('O','ret-one',?,1)").run(slot++);

  db.exec(readFileSync(new URL(MIGRATION, migrationsDir), 'utf8'));

  assert.equal(retentionOf('ret-zero'), 1, 'a row still holding the old column default must be raised');
  assert.equal(retentionOf('ret-five'), 5,
    'a non-zero value is an operator decision and must survive untouched — including the 5s and 10s on busy apps');
  assert.equal(retentionOf('ret-one'), 1);
});

test('096 is recorded as applied, so a 0 set AFTER it is never re-raised', () => {
  // This is what keeps 0 meaningful. The migration is a one-shot UPDATE, and
  // the only thing stopping it from re-running over an operator's deliberate 0
  // is that the runner keys on the file name.
  const applied = db.prepare('SELECT name FROM _migrations WHERE name = ?').get(MIGRATION);
  assert.ok(applied, `${MIGRATION} must be recorded in _migrations after initDb`);
});

test('an operator can still set 0, and it stays 0', async () => {
  const slug = 'ret-operator-zero';
  await call('appcrane_create_app', { name: 'Op Zero', slug, github_url: 'https://github.com/example-owner/opzero' });
  assert.equal(retentionOf(slug), DEFAULT_IMAGE_RETENTION);

  await call('appcrane_update_app', { slug, image_retention: 0 });
  assert.equal(retentionOf(slug), 0, 'setting 0 must not be silently re-raised to the default');
  assert.equal(imagesToKeep(db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug)), 1,
    'and it must reach the prune as keep = 1 — the pre-v2.78.0 behaviour, on request');
});

// ===========================================================================
// New rows: the creation paths
// ===========================================================================

test('appcrane_create_app gives a fresh app the default', async () => {
  await call('appcrane_create_app', {
    name: 'Fresh GH', slug: 'ret-fresh-gh', github_url: 'https://github.com/example-owner/fresh',
  });
  assert.equal(retentionOf('ret-fresh-gh'), DEFAULT_IMAGE_RETENTION);
});

test('an image app gets it too — pulled images are pruned by the same number', async () => {
  // pruneOldImages runs a second, repository-scoped pass for source_type='image'
  // with the same keep, so the default has to reach these rows as well or an
  // image app still loses the digest its rollback would restart.
  await call('appcrane_create_app', {
    name: 'Fresh Img', slug: 'ret-fresh-img', image_ref: 'nginx:1.27', container_port: 80, health_path: '/',
  });
  assert.equal(retentionOf('ret-fresh-img'), DEFAULT_IMAGE_RETENTION);
});

test('EVERY INSERT INTO apps in server/ names image_retention', () => {
  // The column default is still 0 (SQLite cannot ALTER one, and a rebuild of
  // the apps table to move it is out of proportion — see 096's header), so an
  // INSERT that omits the column writes 0 and quietly restores the old
  // behaviour for every app created through it. A scan rather than four
  // hand-written cases, because the failure mode is a FIFTH creation path
  // added later by someone who never read this file.
  const root = new URL('../server/', import.meta.url);
  const files = [];
  (function walk(dir) {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules') continue;
      const next = new URL(e.name + (e.isDirectory() ? '/' : ''), dir);
      if (e.isDirectory()) walk(next);
      else if (e.name.endsWith('.js')) files.push(next);
    }
  })(root);

  const offenders = [];
  let found = 0;
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    // The column list of an `INSERT INTO apps (...)`, up to the closing paren.
    for (const m of src.matchAll(/INSERT\s+(?:OR\s+\w+\s+)?INTO\s+apps\s*\(([^)]*)\)/gis)) {
      found += 1;
      if (!/\bimage_retention\b/.test(m[1])) {
        offenders.push(`${f.pathname.split('/server/')[1]}: INSERT INTO apps (${m[1].trim().slice(0, 80)}…)`);
      }
    }
  }

  assert.ok(found >= 4,
    `only ${found} INSERT INTO apps statements matched — the regex stopped working, ` +
    'so this test is asserting nothing. Expected at least the four creation paths ' +
    '(routes/apps.js, mcpTools.js create_app, mcpTools.js create_managed_app, services/reconcile.js).');
  assert.deepEqual(offenders, [],
    'these app-creation paths omit image_retention, so the apps they create fall back to the ' +
    'column default of 0 and lose their previous image on every deploy:\n  ' + offenders.join('\n  '));
});
