import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A deploy's log: the row keeps every line (bounded to ~1 MB, head + tail), the
// platform log keeps only the deploy's own steps, warnings and failure, not the
// indented build and container output that used to put hundreds of journal
// lines per deploy on the disk.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-deploylog-'));
process.env.ENCRYPTION_KEY = 'l'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { createDeployLog, capDeployLog, MAX_DEPLOY_LOG_CHARS } = await import('../server/services/deployLog.js');

db.prepare("INSERT INTO apps (name, slug, slot) VALUES ('Log App', 'logapp', 44)").run();
const appId = db.prepare("SELECT id FROM apps WHERE slug = 'logapp'").get().id;
const newDeploy = () => db.prepare("INSERT INTO deployments (app_id, env, status) VALUES (?, 'sandbox', 'pending')").run(appId).lastInsertRowid;
const row = (id) => db.prepare('SELECT status, log FROM deployments WHERE id = ?').get(id);

function recorder() {
  const out = { info: [], warn: [], error: [] };
  return { out, logger: { info: (m) => out.info.push(m), warn: (m) => out.warn.push(m), error: (m) => out.error.push(m) } };
}

test('build and container output (indented) is stored but not echoed; steps, warnings and failure are', () => {
  const id = newDeploy();
  const { out, logger } = recorder();
  const w = createDeployLog(id, db, logger);
  w.append('Building docker image...');
  for (let i = 0; i < 300; i++) w.append(`  #${i} RUN npm ci`);
  w.append('⚠ memory is tight');
  w.append('DEPLOY FAILED: health check failed');
  assert.deepEqual(out.info, [`[deploy:${id}] Building docker image...`]);
  assert.deepEqual(out.warn, [`[deploy:${id}] ⚠ memory is tight`]);
  assert.deepEqual(out.error, [`[deploy:${id}] DEPLOY FAILED: health check failed`]);
  const stored = row(id);
  assert.equal(stored.status, 'building');
  assert.equal(stored.log.split('\n').length, 303, 'every line, indented or not, is in the row');
  assert.match(stored.log, /\] {3}#299 RUN npm ci\n/);
});

test('after finish() the row is not written any more', () => {
  const id = newDeploy();
  const { logger } = recorder();
  const w = createDeployLog(id, db, logger);
  w.append('one');
  w.finish();
  w.append('two');
  assert.doesNotMatch(row(id).log, /two/);
  assert.match(w.text(), /two/);
});

test('a stored log over ~1 MB keeps its head and tail, and says how much was cut', () => {
  const id = newDeploy();
  const { logger } = recorder();
  const w = createDeployLog(id, db, logger);
  w.append('FIRST LINE');
  const big = 'x'.repeat(10_000);
  for (let i = 0; i < 300; i++) w.append(`  ${big}`);
  w.append('LAST LINE');
  const stored = row(id).log;
  assert.equal(stored.length, MAX_DEPLOY_LOG_CHARS);
  assert.match(stored, /^\[\d\d:\d\d:\d\d\] FIRST LINE\n/);
  assert.match(stored, /LAST LINE$/);
  assert.match(stored, /\n\.\.\. \[\d+ characters of deploy log omitted\] \.\.\.\n/);
});

test('a log under the cap is stored unchanged', () => {
  assert.equal(capDeployLog('a\nb'), 'a\nb');
});
