import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import Database from 'better-sqlite3';
import { REPAIR_REASON } from '../server/services/hostGateway.js';

// Migration 300 rebuilds restart_incidents so trigger may be the gateway
// repair's (REPAIR_REASON in hostGateway.js). Run on a database migrated to 291 that already holds
// incidents: every row and column survives, the indexes are back, the new
// trigger is accepted and an unknown one is still refused.

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');
const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();

test('300 keeps every incident and widens only the trigger CHECK', () => {
  const db = new Database(':memory:');
  for (const f of files.filter((f) => f < '300')) db.exec(readFileSync(join(dir, f), 'utf8'));
  const appId = db.prepare("INSERT INTO apps (name, slug, slot, source_type, branch) VALUES ('M', 'mig', 7, 'managed', 'main')").run().lastInsertRowid;
  const ins = db.prepare(`INSERT INTO restart_incidents (app_id, env, trigger, action, kind, summary, detail, memory_current, memory_max,
    memory_source, oom_kill_events, exit_state, log_tail, not_captured, container_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  ins.run(appId, 'production', 'crash', 'observed', 'exit', 'exited with code 1', '{"exit_code":1}', 10, 20, 'cgroup', 0, '{"status":"exited"}', '["x"]', '[]', 'abc', '2026-11-01 10:00:00');
  ins.run(appId, 'sandbox', 'manual', 'restarted', 'planned', 'manual restart', null, null, null, null, null, null, null, null, null, '2026-11-02 10:00:00');
  assert.throws(() => ins.run(appId, 'sandbox', REPAIR_REASON, 'restarted', 'planned', 's', null, null, null, null, null, null, null, null, null, '2026-11-03 10:00:00'), /CHECK/);
  const before = db.prepare('SELECT * FROM restart_incidents ORDER BY id').all();
  const cols = db.prepare('PRAGMA table_info(restart_incidents)').all();

  db.exec(readFileSync(join(dir, files.find((f) => f.startsWith('300-'))), 'utf8'));

  assert.deepEqual(db.prepare('SELECT * FROM restart_incidents ORDER BY id').all(), before);
  assert.deepEqual(db.prepare('PRAGMA table_info(restart_incidents)').all(), cols);
  const idx = db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'restart_incidents' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((r) => r.name);
  assert.deepEqual(idx, ['idx_restart_incidents_app_env', 'idx_restart_incidents_created']);
  ins.run(appId, 'sandbox', REPAIR_REASON, 'restarted', 'planned', 'recreated', null, null, null, null, null, null, null, null, null, '2026-11-03 10:00:00');
  assert.throws(() => ins.run(appId, 'sandbox', 'nonsense', 'restarted', 'planned', 's', null, null, null, null, null, null, null, null, null, '2026-11-03 10:00:00'), /CHECK/);
  assert.equal(db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1);
  db.prepare('DELETE FROM apps WHERE id = ?').run(appId);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM restart_incidents').get().n, 0, 'ON DELETE CASCADE lost in the rebuild');
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
});
