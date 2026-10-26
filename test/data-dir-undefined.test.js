import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import { existsSync, mkdtempSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

test('an unset value assigned to DATA_DIR is refused instead of creating an "undefined" directory', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'datadir-undef-'));
  const r = spawnSync(process.execPath, ['-e', `process.env.DATA_DIR = undefined; const { openDb } = await import(${JSON.stringify(join(ROOT, 'server/db.js'))}); openDb();`, '--input-type=module'], { cwd, encoding: 'utf8' });
  assert.notEqual(r.status, 0, 'openDb must refuse DATA_DIR="undefined"');
  assert.match(r.stderr, /DATA_DIR is the string "undefined"/);
  assert.equal(existsSync(join(cwd, 'undefined')), false);
});

test('the backup memory child refuses to run without a data directory', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'datadir-child-'));
  const r = spawnSync(process.execPath, [join(ROOT, 'test/backup-memory.child.mjs')], { cwd, encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.equal(existsSync(join(cwd, 'undefined')), false);
});
