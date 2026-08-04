import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// /api/dashboard/app-cpu (v2.31.0). The contract that matters: sandbox and
// production are SUMMED, not averaged — an app's cost to the box is what both
// containers burn together. Averaging would halve an app whose sandbox is
// idle, which is exactly backwards for spotting the app that starves Caddy.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-cpu-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);

const { initDb, getDb } = await import('../server/db.js');
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
initDb();
const db = getDb();

const KEY = generateApiKey('dhk_admin');
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin',?,1,'human')")
  .run(hashApiKey(KEY));

const busy = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('Busy','busy',1,'managed')").run().lastInsertRowid;
const quiet = db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('Quiet','quiet',2,'managed')").run().lastInsertRowid;
db.prepare("INSERT INTO apps (name,slug,slot,source_type) VALUES ('Silent','silent',3,'managed')").run();

const sample = db.prepare(
  "INSERT INTO metrics_history (app_id, env, cpu_percent, mem_mb, recorded_at) VALUES (?, ?, ?, 0, datetime('now'))"
);
// busy: production averages 40, sandbox averages 20 → combined 60
sample.run(busy, 'production', 30); sample.run(busy, 'production', 50);
sample.run(busy, 'sandbox', 20);
// quiet: production only, 0.4 (sub-integer — must not round away to a flat 0)
sample.run(quiet, 'sandbox', 0.4);
// 'silent' has no samples at all.

const monitoring = (await import('../server/routes/monitoring.js')).default;
const app = express();
app.use(express.json());
app.use('/api', monitoring);
const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
after(() => { server.closeAllConnections?.(); server.unref(); server.close(); });

const BASE = `http://127.0.0.1:${server.address().port}`;
const get = async (p) => {
  const res = await fetch(`${BASE}${p}`, { headers: { 'X-API-Key': KEY } });
  return { status: res.status, body: await res.json() };
};

test('sandbox and production are combined, not averaged', async () => {
  const { body } = await get('/api/dashboard/app-cpu');
  const b = body.apps.find(a => a.slug === 'busy');
  assert.ok(b, 'busy app present');
  const today = b.counts[b.counts.length - 1];
  assert.equal(today, 60, `expected 40 (prod avg) + 20 (sandbox) = 60, got ${today}`);
});

test('sub-1% apps keep a decimal instead of flattening to zero', async () => {
  const { body } = await get('/api/dashboard/app-cpu');
  const q = body.apps.find(a => a.slug === 'quiet');
  assert.equal(q.counts[q.counts.length - 1], 0.4);
});

test('returns 7 days and apps sorted busiest-first', async () => {
  const { body } = await get('/api/dashboard/app-cpu');
  assert.equal(body.days.length, 7);
  assert.equal(body.apps[0].slug, 'busy', 'busiest app leads the legend');
  body.apps.forEach(a => assert.equal(a.counts.length, 7, `${a.slug} must have a point per day`));
});

test('apps with no samples are omitted rather than drawn as flat zero lines', async () => {
  const { body } = await get('/api/dashboard/app-cpu');
  assert.ok(!body.apps.some(a => a.slug === 'silent'));
});

test('admin-gated', async () => {
  const res = await fetch(`${BASE}/api/dashboard/app-cpu`);
  assert.equal(res.status, 401);
});
