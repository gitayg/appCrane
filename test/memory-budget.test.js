import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import os from 'os';
import { tmpdir } from 'os';
import { join } from 'path';

// Does the sum of the per-container limits fit in the host? (v2.48.0)
//
// The August 2026 incident review: a container OOM-killed on a host with zero
// swap, running --memory=512m --memory-swap=1g — a 512 MB swap budget that the
// host could not deliver. The same shape one level up is the fleet total: ~25
// GB of per-container ceilings committed against 7.6 GB of RAM. Neither number
// is enforced as written, and nothing in AppCrane said so.
//
// This module REPORTS and does not BLOCK, and that decision is asserted here
// (see "an over-committed fleet never throws"), because the tempting change is
// to turn it into a gate — which would reject every ordinary edit from the
// moment it shipped, including the edits that reduce the total.
//
// Host RAM is mocked at the incident host's 7680 MB throughout, so the
// boundary cases are exact instead of depending on the machine running the
// suite. The one test of hostMemoryMb() itself runs unmocked.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-membudget-'));
process.env.ENCRYPTION_KEY = 'm'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();

const { hostMemoryMb, memoryBudget, assessMemoryChange } =
  await import('../server/services/memoryBudget.js');

const HOST_MB = 7680;
const MB = 1024 * 1024;

function mockHost(mb = HOST_MB) {
  mock.method(os, 'totalmem', () => mb * MB);
}

let slot = 1;
/** @param {number|null|'absent'|'garbage'} ram */
function makeApp(slug, ram = 512, { deployed = true } = {}) {
  const limits =
    ram === 'absent' ? '{"max_cpu_percent":50}'
      : ram === 'garbage' ? 'not json at all'
        : ram === null ? null
          : JSON.stringify({ max_ram_mb: ram, max_cpu_percent: 50 });

  const id = db.prepare(
    `INSERT INTO apps (name, slug, slot, source_type, resource_limits)
     VALUES (?, ?, ?, 'managed', ?)`
  ).run(slug, slug, slot++, limits).lastInsertRowid;

  if (deployed) {
    db.prepare(
      `INSERT INTO deployments (app_id, env, status) VALUES (?, 'production', 'live')`
    ).run(id);
  }
  return id;
}

function reset() {
  db.prepare('DELETE FROM deployments').run();
  db.prepare('DELETE FROM apps').run();
  mock.restoreAll();
}

test('hostMemoryMb is os.totalmem in MB', () => {
  reset();
  assert.equal(hostMemoryMb(), Math.round(os.totalmem() / MB));
  // And it moves when the host does, so it is a reading and not a constant.
  mockHost(4096);
  assert.equal(hostMemoryMb(), 4096);
  mock.restoreAll();
});

test('an empty platform commits nothing and is not over-committed', () => {
  reset();
  mockHost();
  const b = memoryBudget(db);
  assert.deepEqual(b, {
    host_mb: HOST_MB,
    committed_mb: 0,
    headroom_mb: HOST_MB,
    over_committed: false,
    ratio: 0,
    app_count: 0,
    top: [],
  });
});

test('a deployed app commits BOTH environments, not one', () => {
  reset();
  mockHost();
  makeApp('alpha', 512);
  const b = memoryBudget(db);
  // 512 in the row, 1024 committed: production and sandbox are two containers
  // created from the same limit, and a cold start brings both up.
  assert.equal(b.committed_mb, 1024);
  assert.equal(b.app_count, 1);
  assert.deepEqual(b.top, [{ slug: 'alpha', max_ram_mb: 512 }]);
  assert.equal(b.headroom_mb, HOST_MB - 1024);
  assert.equal(b.over_committed, false);
});

test('an app with no explicit limit falls back to 512', () => {
  reset();
  mockHost();
  makeApp('null-limits', null);
  makeApp('no-ram-key', 'absent');
  makeApp('unparseable', 'garbage');
  makeApp('zero', 0);
  const b = memoryBudget(db);
  assert.equal(b.app_count, 4);
  // Every one of these is 512 to `docker run`, so every one is 512 here.
  assert.equal(b.committed_mb, 4 * 512 * 2);
  assert.deepEqual(b.top.map(a => a.max_ram_mb), [512, 512, 512, 512]);
});

test('an app that was never deployed commits nothing', () => {
  reset();
  mockHost();
  makeApp('live-one', 512);
  makeApp('never-deployed', 8192, { deployed: false });
  const b = memoryBudget(db);
  assert.equal(b.app_count, 1);
  assert.equal(b.committed_mb, 1024);
  assert.deepEqual(b.top, [{ slug: 'live-one', max_ram_mb: 512 }]);
});

test('top is the biggest limits first, capped, tie-broken by slug', () => {
  reset();
  mockHost();
  makeApp('zeta', 512);
  makeApp('alpha', 512);
  makeApp('huge', 4096);
  makeApp('mid-b', 1024);
  makeApp('mid-a', 1024);
  makeApp('small', 128);
  const b = memoryBudget(db);
  assert.equal(b.top.length, 5, 'top is capped');
  assert.deepEqual(b.top, [
    { slug: 'huge', max_ram_mb: 4096 },
    { slug: 'mid-a', max_ram_mb: 1024 },
    { slug: 'mid-b', max_ram_mb: 1024 },
    { slug: 'alpha', max_ram_mb: 512 },
    { slug: 'zeta', max_ram_mb: 512 },
  ]);
  assert.equal(b.committed_mb, (512 + 512 + 4096 + 1024 + 1024 + 128) * 2);
});

test('THE BOUNDARY: committed exactly equal to host RAM still fits', () => {
  reset();
  mockHost();
  makeApp('exactly-half', HOST_MB / 2);   // x2 environments == the whole host
  const b = memoryBudget(db);
  assert.equal(b.committed_mb, HOST_MB);
  assert.equal(b.headroom_mb, 0);
  assert.equal(b.ratio, 1);
  assert.equal(b.over_committed, false, 'filling the host is not exceeding it');

  // One MB more per container is two MB more committed, and that is over.
  db.prepare(`UPDATE apps SET resource_limits = ? WHERE slug = 'exactly-half'`)
    .run(JSON.stringify({ max_ram_mb: HOST_MB / 2 + 1 }));
  const over = memoryBudget(db);
  assert.equal(over.committed_mb, HOST_MB + 2);
  assert.equal(over.headroom_mb, -2);
  assert.equal(over.over_committed, true);
});

test('ratio names the over-commitment factor, rounded to two places', () => {
  reset();
  mockHost();
  makeApp('a', 3840);   // 7680 committed == 1.00x
  makeApp('b', 3840);   // 15360 committed == 2.00x
  assert.equal(memoryBudget(db).ratio, 2);
  makeApp('c', 960);    // 17280 / 7680 == 2.25x
  assert.equal(memoryBudget(db).ratio, 2.25);
});

test('a change the host can still hold is ok, and says so with numbers', () => {
  reset();
  mockHost();
  const id = makeApp('roomy', 512);
  const r = assessMemoryChange(db, id, 1024);
  assert.equal(r.level, 'ok');
  assert.equal(r.budget.committed_mb, 2048);
  assert.equal(r.budget.over_committed, false);
  assert.match(r.message, /2048 MB/);
  assert.match(r.message, /7680 MB/);
  assert.match(r.message, /5632 MB headroom/);
});

test('THE CASE: a change that pushes the total past the host warns, and names the kill', () => {
  reset();
  mockHost();
  const id = makeApp('grower', 512);
  makeApp('filler', 3328);   // committed 1024 + 6656 == 7680, exactly full

  const r = assessMemoryChange(db, id, 2048);
  assert.equal(r.level, 'warn');
  assert.equal(r.budget.committed_mb, 4096 + 6656);
  assert.equal(r.budget.over_committed, true);
  assert.match(r.message, /grower/, 'the operator has to know which app');
  assert.match(r.message, /2048 MB/, 'the proposed number');
  assert.match(r.message, /7680 MB/, 'the before total, and the host');
  assert.match(r.message, /10752 MB/, 'the after total');
  assert.match(r.message, /3072 MB more than the host has/, 'the deficit, spelled out');
  assert.match(r.message, /1\.4x/, 'the factor');
  assert.match(r.message, /OOM/i);
  assert.match(r.message, /largest process/,
    'the consequence is a GLOBAL kill of something else, not of the app that grew');
  assert.match(r.message, /cold start/i);
});

test('an already-over fleet warns again on any further increase', () => {
  reset();
  mockHost();
  const id = makeApp('grower', 512);
  makeApp('hog', 8192);   // fleet already 17408 MB against 7680

  const r = assessMemoryChange(db, id, 640);
  assert.equal(r.level, 'warn', 'over is over — there is no size of increase the kernel forgives');
  assert.match(r.message, /17408 MB to 17664 MB/);
});

test('an already-over fleet is a notice, not a warn, when the change does not worsen it', () => {
  reset();
  mockHost();
  const id = makeApp('steady', 512);
  makeApp('hog', 8192);

  const same = assessMemoryChange(db, id, 512);
  assert.equal(same.level, 'notice');
  assert.match(same.message, /does not move that total/);
  assert.match(same.message, /17408 MB/);
  assert.match(same.message, /9728 MB more than the host has/);
  assert.match(same.message, /OOM/i);
});

test('a change that REDUCES the total is never a warn, even while still over', () => {
  reset();
  mockHost();
  const id = makeApp('shrinker', 4096);
  makeApp('hog', 8192);   // 24576 MB committed

  const r = assessMemoryChange(db, id, 1024);
  assert.equal(r.level, 'notice', 'punishing the fix is how a control gets disabled');
  assert.notEqual(r.level, 'warn');
  assert.equal(r.budget.committed_mb, 2048 + 16384);
  assert.match(r.message, /gives back 6144 MB/);
  assert.match(r.message, /improvement/);
});

test('a change that brings the fleet back under the host reads ok', () => {
  reset();
  mockHost();
  const id = makeApp('hog', 8192);
  const r = assessMemoryChange(db, id, 1024);
  assert.equal(r.level, 'ok');
  assert.match(r.message, /back inside the host/);
  assert.match(r.message, /16384 MB/, 'what it was before the change');
});

test('nextMb null is a read, not a change: the current picture, unmoved', () => {
  reset();
  mockHost();
  const id = makeApp('steady', 8192);
  const r = assessMemoryChange(db, id, null);
  assert.equal(r.level, 'notice');
  assert.equal(r.budget.committed_mb, 16384);
  assert.match(r.message, /does not move that total/);
});

test('changing an UNDEPLOYED app moves no total', () => {
  reset();
  mockHost();
  const id = makeApp('not-yet', 512, { deployed: false });
  makeApp('live', 512);
  const r = assessMemoryChange(db, id, 16384);
  assert.equal(r.level, 'ok');
  assert.equal(r.budget.committed_mb, 1024, 'an app with no container commits nothing');
  assert.equal(r.budget.app_count, 1);
});

test('an over-committed fleet never throws — REPORT, DO NOT BLOCK', () => {
  reset();
  mockHost();
  const id = makeApp('grower', 8192);
  for (let i = 0; i < 20; i++) makeApp(`filler-${i}`, 512);

  // Every one of these is an ordinary edit on a fleet that is already ~3x over.
  // None may throw, or the module becomes a gate that has to be disabled.
  for (const next of [64, 512, 1024, 16384, null]) {
    const r = assessMemoryChange(db, id, next);
    assert.ok(['ok', 'notice', 'warn'].includes(r.level));
    assert.equal(r.budget.over_committed, true);
  }
  assert.equal(memoryBudget(db).over_committed, true);
});

test('the budget carried by an assessment is the PROJECTED one, re-ranked', () => {
  reset();
  mockHost();
  const id = makeApp('small-today', 128);
  makeApp('biggest', 2048);

  const r = assessMemoryChange(db, id, 4096);
  assert.deepEqual(r.budget.top, [
    { slug: 'small-today', max_ram_mb: 4096 },
    { slug: 'biggest', max_ram_mb: 2048 },
  ], 'the proposal has to be ranked as if it were already applied');
  assert.equal(r.budget.committed_mb, (4096 + 2048) * 2);
});
