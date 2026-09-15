import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { snapshotDatabasePaced } from '../server/services/dbSnapshot.js';

const ROOT = mkdtempSync(join(tmpdir(), 'crane-snap-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));

function fixture(name, fillerMb) {
  const src = join(ROOT, `${name}.db`);
  const db = new Database(src);
  db.pragma('journal_mode = WAL');
  db.exec('CREATE TABLE filler (b BLOB); CREATE TABLE a (id INTEGER PRIMARY KEY, v INT); CREATE TABLE b (id INTEGER PRIMARY KEY, v INT);');
  const ins = db.prepare('INSERT INTO filler VALUES (?)');
  db.transaction(() => { for (let i = 0; i < fillerMb; i++) ins.run(Buffer.alloc(1 << 20, i & 255)); })();
  let next = 1;
  const ia = db.prepare('INSERT INTO a VALUES (?, ?)');
  const ib = db.prepare('INSERT INTO b VALUES (?, ?)');
  const write = db.transaction(() => { ia.run(next, next * 7); ib.run(next, next * 7); next++; });
  for (let i = 0; i < 20; i++) write();
  return { src, db, write, rows: () => next - 1 };
}

test('a stepped snapshot under continuous writes is one point in time, fsynced step by step, in rollback-journal format', async () => {
  const f = fixture('live', 48);
  const dest = join(ROOT, 'live-copy.db');
  const writer = setInterval(f.write, 1);
  const startRows = f.rows();
  let s;
  try {
    s = await snapshotDatabasePaced(f.src, dest, { pages: 128 });
  } finally {
    clearInterval(writer);
  }
  const endRows = f.rows();
  f.db.close();
  assert.ok(endRows > startRows + 10, 'fixture: writes must continue during the snapshot');
  assert.ok(s.steps >= 50, `only ${s.steps} steps for a ${48} MB copy at 128 pages a step`);
  assert.equal(s.syncs, s.steps, 'the destination must be fdatasynced after every step');
  assert.ok(s.t1 > s.t0);

  const hdr = readFileSync(dest).subarray(0, 20);
  assert.deepEqual([hdr[18], hdr[19]], [1, 1], 'copy must be a rollback-journal file like VACUUM INTO wrote');
  assert.ok(!existsSync(`${dest}-wal`) && !existsSync(`${dest}-shm`));

  const snap = new Database(dest, { readonly: true });
  try {
    assert.equal(snap.pragma('integrity_check', { simple: true }), 'ok');
    const a = snap.prepare('SELECT COUNT(*) c, MAX(id) m, SUM(v) s FROM a').get();
    const b = snap.prepare('SELECT COUNT(*) c, MAX(id) m, SUM(v) s FROM b').get();
    assert.deepEqual(a, b, 'two tables written in one transaction disagree');
    assert.equal(a.c, a.m, 'ids are not gapless');
    assert.ok(a.c >= startRows && a.c < endRows, `snapshot holds ${a.c} rows, outside [${startRows}, ${endRows})`);
    assert.equal(snap.prepare('SELECT COUNT(*) c FROM filler').get().c, 48);
  } finally {
    snap.close();
  }
});

test('sync: false skips the per-step fdatasync', async () => {
  const f = fixture('nosync', 4);
  f.db.close();
  const s = await snapshotDatabasePaced(f.src, join(ROOT, 'nosync-copy.db'), { pages: 64, sync: false });
  assert.equal(s.syncs, 0);
  assert.ok(s.steps > 0);
});

test('a missing source or destination directory rejects with a database snapshot error', async () => {
  await assert.rejects(snapshotDatabasePaced(join(ROOT, 'absent.db'), join(ROOT, 'x.db')), /database snapshot failed/);
  const f = fixture('nodir', 1);
  f.db.close();
  await assert.rejects(snapshotDatabasePaced(f.src, join(ROOT, 'no', 'such', 'dir', 'x.db')), /database snapshot failed/);
});
