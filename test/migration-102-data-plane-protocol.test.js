import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Migration 102 rebuilds `apps` (DROP + RENAME) to add data_plane_protocol.
// That only works with foreign keys OFF, and SQLite ignores
// `PRAGMA foreign_keys` inside a transaction — so the file must declare
// `-- migration:no-transaction`, like every rebuild before it. A fresh
// database has no child rows, so it applies either way; this test re-runs 102
// on a database whose apps are referenced, which is what every real install is.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-m102-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

test('102 re-applies on a database whose apps have child rows, and keeps them', () => {
  const appId = db.prepare(
    "INSERT INTO apps (name, slug, slot, ingress_type, public_port, data_plane_port, repo_backend) VALUES ('W', 'm102-wg', 8901, 'dual', 31890, 51820, 'local')"
  ).run().lastInsertRowid;
  db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')").run(appId);

  db.prepare("DELETE FROM _migrations WHERE name = '102-app-data-plane-protocol.sql'").run();
  initDb();   // applies 102 again, over referenced rows

  const live = getDb();
  const row = live.prepare("SELECT * FROM apps WHERE slug = 'm102-wg'").get();
  assert.equal(row.data_plane_port, 51820);
  assert.equal(row.repo_backend, 'local', 'columns written since 090 survive the rebuild');
  assert.equal(row.data_plane_protocol, null, 'existing rows read as tcp');
  assert.equal(live.prepare('SELECT COUNT(*) AS n FROM deployments WHERE app_id = ?').get(appId).n, 1);
  assert.equal(live.prepare('PRAGMA foreign_key_check').all().length, 0);
  assert.equal(live.pragma('foreign_keys', { simple: true }), 1, 'foreign keys are back ON afterwards');
});

test('the CHECK admits only tcp and udp', () => {
  const live = getDb();
  live.prepare("UPDATE apps SET data_plane_protocol = 'udp' WHERE slug = 'm102-wg'").run();
  assert.throws(() => live.prepare("UPDATE apps SET data_plane_protocol = 'sctp' WHERE slug = 'm102-wg'").run(), /CHECK/);
});
