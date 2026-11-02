import { test, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The probe timers start at spread offsets, but the first probe still waits a
// full interval after an app is scheduled (as it did before the stagger): an
// app scheduled at creation or right after a deploy must not be probed, and
// counted toward its fail threshold, in the same instant.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-triage-health-'));
process.env.ENCRYPTION_KEY = 't'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const hc = await import('../server/services/healthChecker.js');
after(() => hc.stopHealthChecker());

const probes = [];
global.fetch = async (url) => {
  probes.push(String(url));
  return { ok: true, status: 200, headers: new Headers(), text: async () => '', json: async () => ({}) };
};

const ids = [];
for (let i = 0; i < 4; i++) {
  const slug = `fp${i}`;
  const id = db.prepare('INSERT INTO apps (name, slug, slot, source_type, image_ref) VALUES (?, ?, ?, ?, ?)').run(slug, slug, 820 + i, 'image', 'nginx:1').lastInsertRowid;
  ids.push(id);
  for (const env of ['production', 'sandbox']) {
    db.prepare('INSERT INTO health_configs (app_id, env, interval_sec) VALUES (?, ?, 30)').run(id, env);
  }
}

const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };

test('no app-env is probed before one full interval has passed; every one is by two', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    for (const id of ids) hc.refreshAppChecks(id);
    mock.timers.tick(29_999);
    await settle();
    assert.deepEqual(probes, [], 'probed before a full interval had passed');
    mock.timers.tick(30_001);
    await settle();
    assert.equal(new Set(probes).size, ids.length * 2, `probes by two intervals: ${probes.join(', ')}`);
  } finally {
    hc.stopHealthChecker();
    mock.timers.reset();
  }
});
