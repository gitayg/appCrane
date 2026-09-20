import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';

// initDb() was the only way to get a database handle, and it migrates. So
// `crane regenerate-key` and `crane reconcile` — neither of which has any
// business touching the schema — applied every pending migration as a side
// effect of reading one row. Harmless against a booted server (nothing is
// pending), but not when the code on disk is newer than the running process:
// the CLI would move the schema under a server still serving the old one.
//
// openDb() opens and publishes the handle, full stop. pendingMigrationNames()
// answers the schema question without writing, so a caller can refuse.
process.env.LOG_LEVEL = 'error';
const { openDb, initDb, pendingMigrationNames, getDb } = await import('../server/db.js');

const fresh = () => mkdtempSync(join(tmpdir(), 'crane-opendb-'));
const tables = () =>
  getDb().prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);

test('openDb applies no migration and creates no _migrations table', () => {
  openDb(fresh());
  const names = tables();
  assert.deepEqual(names, [], `openDb created tables: ${names.join(', ')}`);
  assert.ok(pendingMigrationNames().length > 0, 'a fresh database should report every migration pending');
});

test('pendingMigrationNames does not write to the database it inspects', () => {
  openDb(fresh());
  pendingMigrationNames();
  assert.ok(!tables().includes('_migrations'), 'asking what is pending created the bookkeeping table');
});

test('initDb still migrates, and then nothing is pending', () => {
  initDb(fresh());
  assert.ok(tables().includes('_migrations'), 'initDb did not create the migrations table');
  assert.ok(tables().includes('apps'), 'initDb did not apply the schema');
  assert.deepEqual(pendingMigrationNames(), [], 'initDb left migrations pending');
});

// The split only helps if the two commands actually use it. Source guard: the
// blocks are reached by a real database and a real server, so this is the
// cheap check that survives a refactor moving the import around.
test('regenerate-key and reconcile open without migrating', () => {
  const src = readFileSync(new URL('../cli/index.js', import.meta.url), 'utf8');
  const block = (name) => {
    const at = src.indexOf(`.command('${name}')`);
    assert.ok(at > -1, `${name} is not a registered command any more`);
    const next = src.indexOf(".command('", at + 10);
    return src.slice(at, next === -1 ? src.length : next);
  };
  for (const name of ['regenerate-key', 'reconcile']) {
    const b = block(name);
    assert.ok(!/\binitDb\(/.test(b), `crane ${name} calls initDb() — it would migrate the schema`);
    assert.ok(/\bopenDb\(/.test(b), `crane ${name} does not call openDb()`);
    assert.ok(/refuseIfBehind\(/.test(b), `crane ${name} does not check for a schema behind its code`);
  }
  assert.ok(/\binitDb\(/.test(block('init')), 'crane init must still migrate — it is the bootstrap');
});
