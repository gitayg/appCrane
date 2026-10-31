import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// deployments.log used to be kept for as long as the app existed. Retention
// clears the log text (never the row) of deployments that are outside the
// newest 20 of their app+env AND older than 90 days; the live row and any in
// flight keep theirs whatever their age.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-deploylog-ret-'));
process.env.ENCRYPTION_KEY = 'r'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { pruneDeployLogs, KEEP_NEWEST, MAX_AGE_DAYS } = await import('../server/services/deployLogRetention.js');

const NOW = Date.parse('2026-10-30T12:00:00Z');
const DAY = 86_400_000;
const at = (daysAgo) => new Date(NOW - daysAgo * DAY).toISOString().replace('T', ' ').slice(0, 19);

db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('A', 'reta', 45), ('B', 'retb', 46)").run();
const A = db.prepare("SELECT id FROM apps WHERE slug = 'reta'").get().id;
const B = db.prepare("SELECT id FROM apps WHERE slug = 'retb'").get().id;
const ins = db.prepare('INSERT INTO deployments (app_id, env, status, log, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?)');
const add = (app, env, status, daysAgo) => ins.run(app, env, status, `log ${status} ${daysAgo}`, at(daysAgo), status === 'pending' ? null : at(daysAgo)).lastInsertRowid;

// App A sandbox, oldest first: a live row 400 days old, an in-flight row 300
// days old (stuck), 30 failed/rolled-back rows 200..171 days old, then 20 recent.
const liveOld = add(A, 'sandbox', 'live', 400);
const stuck = add(A, 'sandbox', 'pending', 300);
const old = [];
for (let i = 0; i < 30; i++) old.push(add(A, 'sandbox', i % 2 ? 'failed' : 'rolled_back', 200 - i));
const recent = [];
for (let i = 0; i < KEEP_NEWEST; i++) recent.push(add(A, 'sandbox', 'failed', 10 - i * 0.1));
// App A production: 25 rows, all 100 days old. Only the 5 outside the newest 20 go.
const prod = [];
for (let i = 0; i < 25; i++) prod.push(add(A, 'production', 'rolled_back', 100));
// App B: 30 rows 60 days old. Outside the newest 20, but too young.
const young = [];
for (let i = 0; i < 30; i++) young.push(add(B, 'sandbox', 'failed', 60));

const logOf = (id) => db.prepare('SELECT log FROM deployments WHERE id = ?').get(id)?.log;
const exists = (id) => !!db.prepare('SELECT 1 FROM deployments WHERE id = ?').get(id);

test('retention constants', () => {
  assert.equal(KEEP_NEWEST, 20);
  assert.equal(MAX_AGE_DAYS, 90);
});

test('old logs outside the newest 20 are cleared in batches; rows stay; live, in-flight, recent and young keep theirs', async () => {
  const cleared = await pruneDeployLogs({ now: NOW, db, batch: 7 });
  assert.equal(cleared, 30 + 5);
  for (const id of old) { assert.equal(logOf(id), null, `old #${id}`); assert.ok(exists(id), 'row kept'); }
  for (const id of prod.slice(0, 5)) assert.equal(logOf(id), null, `prod old #${id}`);
  for (const id of prod.slice(5)) assert.ok(logOf(id), `prod newest-20 #${id}`);
  for (const id of recent) assert.ok(logOf(id), `recent #${id}`);
  for (const id of young) assert.ok(logOf(id), `young #${id}`);
  assert.equal(logOf(liveOld), 'log live 400');
  assert.equal(logOf(stuck), 'log pending 300');
});

test('a second run has nothing to do', async () => {
  assert.equal(await pruneDeployLogs({ now: NOW, db }), 0);
});
