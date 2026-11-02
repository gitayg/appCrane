import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// db.prepare(sql) hands back one cached Statement per SQL text. These pin the
// two things that makes worth having and the ways a shared Statement could
// carry one caller's state into the next.

process.env.LOG_LEVEL = 'error';
const { openDb, STATEMENT_CACHE_MAX } = await import('../server/db.js');
const db = openDb(mkdtempSync(join(tmpdir(), 'crane-stmt-cache-')));
db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
const ins = db.prepare('INSERT INTO t (v) VALUES (?)');
for (const v of ['a', 'b', 'c']) ins.run(v);

test('the same SQL text is compiled once', () => {
  assert.equal(db.prepare('SELECT v FROM t WHERE id = ?'), db.prepare('SELECT v FROM t WHERE id = ?'));
  assert.notEqual(db.prepare('SELECT v FROM t WHERE id = ?'), db.prepare('SELECT v FROM t WHERE id = ? '));
});

test('pluck/raw/expand on a cached statement do not leak to the next caller', () => {
  const sql = 'SELECT v FROM t ORDER BY id';
  assert.deepEqual(db.prepare(sql).pluck().all(), ['a', 'b', 'c']);
  assert.deepEqual(db.prepare(sql).all(), [{ v: 'a' }, { v: 'b' }, { v: 'c' }]);
  assert.deepEqual(db.prepare(sql).raw().get(), ['a']);
  assert.deepEqual(db.prepare(sql).get(), { v: 'a' });
  assert.deepEqual(db.prepare(sql).expand().get(), { t: { v: 'a' } });
  assert.deepEqual(db.prepare(sql).get(), { v: 'a' });
});

test('bind on a cached statement does not leave it bound', () => {
  const sql = 'SELECT v FROM t WHERE id = ?';
  assert.equal(db.prepare(sql).bind(2).get().v, 'b');
  assert.equal(db.prepare(sql).get(3).v, 'c');
});

test('the same SQL can be run while an iterate() over it is still open', () => {
  const sql = 'SELECT id, v FROM t ORDER BY id';
  const seen = [];
  for (const row of db.prepare(sql).iterate()) {
    seen.push(`${row.v}:${db.prepare(sql).all().length}`);
    for (const inner of db.prepare(sql).iterate()) if (inner.id === row.id) seen.push(inner.v);
  }
  assert.deepEqual(seen, ['a:3', 'a', 'b:3', 'b', 'c:3', 'c']);
});

test('a schema change is seen by an already cached SELECT *', () => {
  const sql = 'SELECT * FROM t WHERE id = 1';
  assert.deepEqual(db.prepare(sql).get(), { id: 1, v: 'a' });
  db.exec("ALTER TABLE t ADD COLUMN w TEXT DEFAULT 'x'");
  assert.deepEqual(db.prepare(sql).get(), { id: 1, v: 'a', w: 'x' });
});

test('the cache is bounded and keeps the most recently used', () => {
  const hot = db.prepare('SELECT 1 AS hot');
  const cold = db.prepare('SELECT -1 AS n');
  for (let i = 0; i < STATEMENT_CACHE_MAX + 50; i++) {
    db.prepare(`SELECT ${i} AS n`);
    if (i % 100 === 0) db.prepare('SELECT 1 AS hot');
  }
  assert.equal(db.prepare('SELECT 1 AS hot'), hot);
  assert.notEqual(db.prepare('SELECT -1 AS n'), cold);
  assert.equal(db.prepare('SELECT -1 AS n').get().n, -1);
});
