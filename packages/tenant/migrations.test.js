import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'os';
import { join } from 'path';
import { mkdtempSync } from 'fs';
import { Worker } from 'worker_threads';
import { createRequire } from 'module';
import { tenantDb } from './index.js';

// Lazy per-tenant schema migrations (appcrane-tenant 1.1.0).
//
// One SQLite file per user means one schema per file, and with thousands of
// files the trap is drift: some files upgraded, some not. tenantDb(req,
// { migrations }) upgrades each file the first time it is opened after a
// deploy, keyed on PRAGMA user_version, inside one IMMEDIATE transaction, so a
// file is never upgraded twice and never left half-upgraded.

const Database = createRequire(import.meta.url)('better-sqlite3');
const req = (id) => ({ get: (n) => ({ 'X-AppCrane-User-Email': 'dana@acme.test', 'X-AppCrane-User-Id': String(id) })[n] });
const root = () => mkdtempSync(join(tmpdir(), 'tenant-mig-'));

const V1 = 'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)';
const V2 = 'ALTER TABLE notes ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0';
const userVersion = (db) => db.pragma('user_version', { simple: true });

test('a new file gets every migration, and user_version records how many', () => {
  const r = root();
  const db = tenantDb(req(1), { root: r, migrations: [V1, V2] });
  assert.equal(userVersion(db), 2);
  db.prepare('INSERT INTO notes (body, pinned) VALUES (?, 1)').run('hi');
  db.close();
});

test('reopening runs only the migrations the file has not had', () => {
  const r = root();
  tenantDb(req(2), { root: r, migrations: [V1] }).close();
  // Next deploy adds a step. V1 must not run again (it would fail: table exists).
  const db = tenantDb(req(2), { root: r, migrations: [V1, V2] });
  assert.equal(userVersion(db), 2);
  assert.ok(db.prepare("SELECT 1 FROM pragma_table_info('notes') WHERE name = 'pinned'").get());
  db.close();
});

test('a migration may be a function of the open database', () => {
  const r = root();
  const db = tenantDb(req(3), { root: r, migrations: [V1, (d) => d.prepare("INSERT INTO notes (body) VALUES ('seed')").run()] });
  assert.equal(db.prepare('SELECT body FROM notes').get().body, 'seed');
  db.close();
});

test('a failing step rolls the whole upgrade back and throws', () => {
  const r = root();
  tenantDb(req(4), { root: r, migrations: [V1] }).close();
  assert.throws(() => tenantDb(req(4), { root: r, migrations: [V1, V2, 'THIS IS NOT SQL'] }));
  const db = tenantDb(req(4), { root: r });
  assert.equal(userVersion(db), 1, 'user_version moved although the upgrade failed');
  assert.equal(db.prepare("SELECT 1 FROM pragma_table_info('notes') WHERE name = 'pinned'").get(), undefined,
    'V2 stayed applied although a later step in the same upgrade failed');
  db.close();
});

test('a file newer than the code (a rolled-back deploy) is opened, not downgraded or refused', () => {
  const r = root();
  tenantDb(req(5), { root: r, migrations: [V1, V2] }).close();
  const db = tenantDb(req(5), { root: r, migrations: [V1] });
  assert.equal(userVersion(db), 2);
  db.close();
});

test('eight connections opening the same new file at once upgrade it exactly once', async () => {
  const r = root();
  const src = `
    import { workerData, parentPort } from 'worker_threads';
    import { tenantDb } from ${JSON.stringify(new URL('./index.js', import.meta.url).href)};
    const req = { get: (n) => ({ 'X-AppCrane-User-Email': 'dana@acme.test', 'X-AppCrane-User-Id': '6' })[n] };
    const db = tenantDb(req, { root: workerData.root, migrations: [
      'CREATE TABLE runs (n INTEGER)',
      // Hold the upgrade open so the other workers read user_version = 0 and
      // queue on the lock: the case the re-read under the lock exists for.
      (d) => { const t = Date.now(); while (Date.now() - t < 300) {} d.prepare('INSERT INTO runs VALUES (1)').run(); },
    ] });
    db.close();
    parentPort.postMessage('done');`;
  const workers = Array.from({ length: 8 }, () => new Promise((resolve, reject) => {
    const w = new Worker(new URL(`data:text/javascript,${encodeURIComponent(src)}`), { workerData: { root: r } });
    w.once('message', resolve);
    w.once('error', reject);
  }));
  await Promise.all(workers);
  const db = new Database(join(r, 'acme.test', 'u6', 'db.sqlite'));
  assert.equal(db.prepare('SELECT COUNT(*) n FROM runs').get().n, 1, 'a migration ran more than once');
  assert.equal(userVersion(db), 2);
  db.close();
});
