import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Migration 200 grandfathers capabilities already in use. An install whose
// secret_connections, managed_databases or llm_gateway_apps hold a row for an
// app that no longer exists (written with foreign keys off, as older releases
// could) must still migrate: the orphan gets no grant, and AppCrane boots.

const dir = mkdtempSync(join(tmpdir(), 'crane-m200-'));
process.env.DATA_DIR = dir;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

test('200 re-applies over orphan rows in every grandfathered table', () => {
  const live = Number(db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('Live', 'm200-live', 8950)").run().lastInsertRowid);
  db.prepare("INSERT INTO managed_databases (app_id, engine, db_name, db_user, password_enc) VALUES (?, 'postgres', 'd_live', 'u_live', 'x')").run(live);
  const ORPHAN = 987654;
  db.pragma('foreign_keys = OFF');
  db.prepare("INSERT INTO secret_connections (name, provider, app_id) VALUES ('gone', 'vault', ?)").run(ORPHAN);
  db.prepare("INSERT INTO managed_databases (app_id, engine, db_name, db_user, password_enc) VALUES (?, 'postgres', 'd_gone', 'u_gone', 'x')").run(ORPHAN);
  db.prepare('INSERT INTO llm_gateway_apps (app_id, enabled) VALUES (?, 1)').run(ORPHAN);
  db.pragma('foreign_keys = ON');

  db.prepare('DELETE FROM capability_requests').run();
  db.prepare("DELETE FROM _migrations WHERE name = '200-capability-approvals.sql'").run();
  assert.doesNotThrow(() => initDb(), 'migration 200 failed on orphan rows');

  const rows = getDb().prepare("SELECT app_id, capability FROM capability_requests WHERE origin = 'grandfathered'").all();
  assert.ok(rows.some((r) => r.app_id === live && r.capability === 'managed_database'), 'the live app kept its grant');
  assert.ok(!rows.some((r) => r.app_id === ORPHAN), 'an orphan got a grant');
  assert.ok(getDb().prepare("SELECT 1 FROM _migrations WHERE name = '200-capability-approvals.sql'").get());
  rmSync(dir, { recursive: true, force: true });
});
