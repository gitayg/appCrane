import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Migration 158 repairs the stored release paths of apps renamed before
// v2.125.6, so a box that upgrades can roll a renamed app back without anyone
// editing the database or the disk by hand. The rows are written the way the
// old rename left them, then the migration's own SQL is run against them.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-mig158-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
after(() => { try { rmSync(ROOT, { recursive: true, force: true }); } catch (_) {} });

const SQL = readFileSync(new URL('../server/migrations/158-repair-renamed-release-paths.sql', import.meta.url), 'utf8');
const A = '/home/u/appCrane/data/apps';
const mkApp = (slug, slot) => db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'github','main')").run(slug, slug, slot).lastInsertRowid;
const dep = (appId, path) => db.prepare("INSERT INTO deployments (app_id, env, status, release_path) VALUES (?, 'production', 'live', ?)").run(appId, path).lastInsertRowid;
const rename = (appId, from, to) => db.prepare('INSERT INTO app_slug_renames (app_id, old_slug, new_slug) VALUES (?, ?, ?)').run(appId, from, to);
const pathOf = (id) => db.prepare('SELECT release_path FROM deployments WHERE id = ?').get(id).release_path;

// Renamed once, as on the live box.
const hub = mkApp('supply-hub', 20051);
rename(hub, 'supply-chain-reports', 'supply-hub');
const hubOld = dep(hub, `${A}/supply-chain-reports/production/releases/1793043959881-git`);
const hubNew = dep(hub, `${A}/supply-hub/production/releases/1793100000000-git`);
// Renamed twice: c is the current slug.
const chain = mkApp('c', 20052);
rename(chain, 'a', 'b'); rename(chain, 'b', 'c');
const fromA = dep(chain, `${A}/a/sandbox/releases/1-git`);
const fromB = dep(chain, `${A}/b/sandbox/releases/2-git`);
// Never renamed, and a slug that merely starts with the renamed one.
const other = mkApp('supply-chain-reports-2', 20053);
const otherDep = dep(other, `${A}/supply-chain-reports-2/production/releases/3-git`);
// An image deploy has no release path.
const imageDep = db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(hub).lastInsertRowid;

db.exec(SQL);

test('a renamed app\'s old release paths point at its current slug', () => {
  assert.equal(pathOf(hubOld), `${A}/supply-hub/production/releases/1793043959881-git`);
  assert.equal(pathOf(hubNew), `${A}/supply-hub/production/releases/1793100000000-git`, 'already right, unchanged');
});

test('a chain of renames resolves to the current slug in one pass', () => {
  assert.equal(pathOf(fromA), `${A}/c/sandbox/releases/1-git`);
  assert.equal(pathOf(fromB), `${A}/c/sandbox/releases/2-git`);
});

test('other apps and image deploys are untouched, and a second run changes nothing', () => {
  assert.equal(pathOf(otherDep), `${A}/supply-chain-reports-2/production/releases/3-git`);
  assert.equal(pathOf(imageDep), null);
  const before = db.prepare('SELECT id, release_path FROM deployments ORDER BY id').all();
  db.exec(SQL);
  assert.deepEqual(db.prepare('SELECT id, release_path FROM deployments ORDER BY id').all(), before);
});
