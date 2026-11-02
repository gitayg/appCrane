import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The health checker's background load: the 15-minute disk-quota sweep runs a
// few `du` walks at a time instead of one after another, and the per-app probe
// timers start at spread offsets instead of all in the same tick. `du` is a
// PATH shim that sleeps and logs when each walk starts and ends.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-perf-health-'));
process.env.ENCRYPTION_KEY = 'h'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM_DIR = join(process.env.DATA_DIR, 'bin');
const DU_LOG = join(process.env.DATA_DIR, 'du.log');
mkdirSync(SHIM_DIR, { recursive: true });
writeFileSync(join(SHIM_DIR, 'du'),
  '#!/usr/bin/env node\n' +
  'const { appendFileSync } = require("fs");\n' +
  'appendFileSync(process.env.CRANE_TEST_DU_LOG, `start ${Date.now()}\\n`);\n' +
  'setTimeout(() => { appendFileSync(process.env.CRANE_TEST_DU_LOG, `end ${Date.now()}\\n`); process.stdout.write("4\\t" + process.argv[3] + "\\n"); }, 300);\n',
  { mode: 0o755 });
process.env.CRANE_TEST_DU_LOG = DU_LOG;
process.env.PATH = `${SHIM_DIR}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const hc = await import('../server/services/healthChecker.js');
after(() => hc.stopHealthChecker());

const N = 4;
const ids = [];
for (let i = 0; i < N; i++) {
  const slug = `hp${i}`;
  const id = db.prepare('INSERT INTO apps (name, slug, slot, source_type, image_ref) VALUES (?, ?, ?, ?, ?)').run(slug, slug, 800 + i, 'image', 'nginx:1').lastInsertRowid;
  ids.push(id);
  for (const env of ['production', 'sandbox']) {
    mkdirSync(join(process.env.DATA_DIR, 'apps', slug, env, 'shared', 'data'), { recursive: true });
    db.prepare('INSERT INTO health_configs (app_id, env, interval_sec) VALUES (?, ?, 30)').run(id, env);
  }
}

test('the disk-quota sweep runs du a few at a time: 8 walks of 300 ms at most 3 at once, well under 8 x 300 ms', async () => {
  const t0 = Date.now();
  await hc.runDiskChecks();
  const wall = Date.now() - t0;
  const events = readFileSync(DU_LOG, 'utf8').split('\n').filter(Boolean).map((l) => l.split(' ')).map(([k, t]) => [Number(t), k === 'start' ? 1 : -1]);
  events.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let cur = 0;
  let max = 0;
  for (const [, d] of events) { cur += d; max = Math.max(max, cur); }
  assert.equal(events.length, 2 * N * 2, 'every app-env measured');
  assert.equal(max, 3, `max du walks at once: ${max}`);
  assert.ok(wall < N * 2 * 300, `sweep took ${wall} ms`);
});

test('probe timers start at spread offsets inside the interval, not all in one tick', () => {
  const realSetTimeout = globalThis.setTimeout;
  const delays = [];
  globalThis.setTimeout = (fn, ms, ...rest) => { delays.push(ms); return realSetTimeout(fn, ms, ...rest); };
  try {
    for (const id of ids) hc.refreshAppChecks(id);
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
  hc.stopHealthChecker();
  assert.equal(delays.length, N * 2, `one start timer per app-env, got ${delays.length}`);
  assert.ok(delays.every((d) => d >= 0 && d < 30_000), delays.join(','));
  assert.ok(new Set(delays).size >= N * 2 - 1, `offsets: ${delays.join(',')}`);
  assert.equal(hc.probeOffsetMs('7-production', 30_000), hc.probeOffsetMs('7-production', 30_000), 'stable across restarts');
});
