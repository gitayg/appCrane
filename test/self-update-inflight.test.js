import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Self-update/restart vs. in-flight deployments.
//
// A single row left in 'building' by a hung deploy used to block every update,
// and the dashboard showed a raw error with no way through — an operator had
// to hand-write a forced POST in the browser console. Three things fix that:
// stale rows stop blocking, the refusal says what it is waiting on, and the
// dashboard offers Wait / Force.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-inflight-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { inflightRefusal, listInflightDeploys, STALE_INFLIGHT_MINUTES } = await import('../server/services/inflightDeploys.js');

const appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')")
  .run('Billing Portal', 'billing-portal', 1).lastInsertRowid;

function deploy(status, minutesAgo, env = 'production') {
  return db.prepare(
    `INSERT INTO deployments (app_id, env, status, started_at) VALUES (?, ?, ?, datetime('now', ?))`
  ).run(appId, env, status, `-${minutesAgo} minutes`).lastInsertRowid;
}

function reset() { db.prepare('DELETE FROM deployments').run(); }

test('the default stale threshold is 60 minutes', () => {
  assert.equal(STALE_INFLIGHT_MINUTES, 60);
});

test('nothing in flight means nothing blocks', () => {
  reset();
  deploy('live', 5);
  deploy('failed', 500);
  assert.equal(inflightRefusal(db, 'self-update'), null);
});

test('a fresh build blocks, and the refusal names the app, env, status and age', () => {
  reset();
  const id = deploy('building', 5, 'sandbox');
  const r = inflightRefusal(db, 'self-update');
  assert.ok(r, 'a 5-minute-old build must block');
  assert.equal(r.error.code, 'BUILDS_IN_FLIGHT');
  assert.equal(r.error.in_flight.length, 1);
  const d = r.error.in_flight[0];
  assert.equal(d.id, Number(id));
  assert.equal(d.app_slug, 'billing-portal');
  assert.equal(d.app_name, 'Billing Portal');
  assert.equal(d.env, 'sandbox');
  assert.equal(d.status, 'building');
  assert.equal(d.stale, false);
  assert.ok(d.age_seconds >= 290 && d.age_seconds <= 330, `age ${d.age_seconds}s`);
  assert.match(d.started_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/,
    'started_at must carry a zone, or the browser reads UTC as local time');
  assert.match(r.error.message, /self-update/);
});

test('a row older than the threshold does not block and is reported stale', () => {
  reset();
  const id = deploy('building', STALE_INFLIGHT_MINUTES + 5);
  assert.equal(inflightRefusal(db, 'self-update'), null,
    'one hung build must not block every update');
  const { blocking, stale } = listInflightDeploys(db);
  assert.equal(blocking.length, 0);
  assert.equal(stale.length, 1);
  assert.equal(stale[0].id, Number(id));
  assert.equal(stale[0].stale, true);
});

test('with a fresh and a stale row, only the fresh one blocks and the stale one is listed', () => {
  reset();
  deploy('pending', 2);
  deploy('deploying', 600);
  const r = inflightRefusal(db, 'restart');
  assert.ok(r);
  assert.equal(r.error.in_flight.length, 1);
  assert.equal(r.error.in_flight[0].status, 'pending');
  assert.equal(r.error.stale.length, 1);
  assert.equal(r.error.stale[0].status, 'deploying');
  assert.equal(r.error.stale_after_minutes, 60);
  assert.match(r.error.message, /restart/);
});

test('describing rows never changes them', () => {
  reset();
  const id = deploy('building', 600);
  inflightRefusal(db, 'self-update');
  assert.equal(db.prepare('SELECT status FROM deployments WHERE id = ?').get(id).status, 'building');
});

// Handlers: asserted against the source, because invoking either one would
// git-reset the checkout or exit the test runner.
const SRC = readFileSync(new URL('../server/index.js', import.meta.url), 'utf8');
const UPDATE = SRC.slice(SRC.indexOf("app.post('/api/self-update',"), SRC.indexOf("app.post('/api/self-update/restart'"));
const RESTART = SRC.slice(SRC.indexOf("app.post('/api/self-update/restart'"), SRC.indexOf("app.get('/api/self-update/status'"));

for (const [name, H, action] of [['self-update', UPDATE, 'self-update'], ['restart', RESTART, 'restart']]) {
  test(`${name}: uses the stale-aware check, and ?force=1 still skips it`, () => {
    assert.ok(H.length > 300, `could not find the ${name} handler`);
    assert.match(H, new RegExp(`if \\(!req\\.query\\.force\\) \\{\\s*const \\{ inflightRefusal \\}[^]*?inflightRefusal\\(getDb\\(\\), '${action}'\\)[^]*?res\\.status\\(409\\)\\.json\\(refusal\\)`),
      'the in-flight check must sit behind ?force=1 and answer 409 with the refusal body');
    assert.doesNotMatch(H, /status IN \('pending','building','deploying'\)/,
      'a raw in-flight query here would bring back the stale-row block');
  });
}

test('boot still fails rows left in flight by the previous process', () => {
  // Builds are driven in-process (deployer.js awaits docker build and writes
  // the final status itself), so a row from before this boot can never finish.
  const boot = SRC.slice(SRC.indexOf('app.listen(PORT, HOST'));
  assert.match(boot, /SET status = 'failed'[^]*?interrupted by service restart[^]*?WHERE status IN \('deploying', 'building', 'pending'\)/);
});

// Dashboard
const LAYOUT = readFileSync(new URL('../studio-web/src/components/Layout.tsx', import.meta.url), 'utf8');
const FLOW = readFileSync(new URL('../studio-web/src/components/selfUpdateFlow.ts', import.meta.url), 'utf8');
const DIALOG = readFileSync(new URL('../studio-web/src/components/UpdateBlockedDialog.tsx', import.meta.url), 'utf8');

test('the dashboard recognises BUILDS_IN_FLIGHT and shows the dialog', () => {
  assert.match(FLOW, /err\.code !== 'BUILDS_IN_FLIGHT'/);
  assert.match(LAYOUT, /const blocked = buildsInFlightOf\(err\)/);
  assert.match(LAYOUT, /<UpdateBlockedDialog[^]*?onForce=\{forceSelfUpdate\}/);
  assert.match(DIALOG, /Update waiting on \{n\} deployment/);
  assert.match(DIALOG, /Interrupts these builds|interrupts these builds; those apps will need redeploying/);
});

test('Force update posts with ?force=1', () => {
  assert.match(LAYOUT, /function forceSelfUpdate\(\)[^]*?attemptSelfUpdate\(true\)/);
  assert.match(LAYOUT, /adminApi\.post\(`\/api\/self-update\$\{force \? '\?force=1' : ''\}`/);
});

test('a dropped connection after the update starts means reconnecting, not failure', () => {
  assert.match(LAYOUT, /if \(!isConnectionDrop\(err\)\)/);
  assert.match(LAYOUT, /waitForNewVersion\(from\)/);
  assert.match(FLOW, /fetch\('\/api\/info'/);
});
