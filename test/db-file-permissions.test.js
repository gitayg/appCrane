import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, chmodSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

process.env.ENCRYPTION_KEY = 'e'.repeat(64);
const { openDb } = await import('../server/db.js');

const mode = (p) => statSync(p).mode & 0o777;

test('opening the database leaves the data directory 700 and the database files 600', () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'crane-dbperm-')), 'data');
  mkdirSync(dir);
  chmodSync(dir, 0o755);
  writeFileSync(join(dir, 'deployhub.db'), '');
  chmodSync(join(dir, 'deployhub.db'), 0o644);
  const db = openDb(dir);
  db.prepare('CREATE TABLE t (x)').run();
  assert.equal(mode(dir), 0o700);
  for (const f of ['deployhub.db', 'deployhub.db-wal', 'deployhub.db-shm']) {
    assert.equal(mode(join(dir, f)), 0o600, f);
  }
  db.close();
});

test('a shared sticky directory such as /tmp is not narrowed', async () => {
  const { restrictDataFiles } = await import('../server/db.js');
  const dir = mkdtempSync(join(tmpdir(), 'crane-dbperm-sticky-'));
  chmodSync(dir, 0o1777);
  restrictDataFiles(dir, join(dir, 'deployhub.db'));
  assert.equal(statSync(dir).mode & 0o7777, 0o1777);
});
