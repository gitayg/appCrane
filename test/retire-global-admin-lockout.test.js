import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

// Migration 105 retires the global admin role. On a box whose only privileged
// accounts are global admins it must not leave nobody able to manage it: the
// oldest admin becomes platform admin (066's rule), the rest become 'user'.

const SQL = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server/migrations/105-retire-global-admin.sql'), 'utf8');
const run = (rows) => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL)');
  for (const [id, role] of rows) db.prepare('INSERT INTO users (id, role) VALUES (?, ?)').run(id, role);
  db.exec(SQL);
  return Object.fromEntries(db.prepare('SELECT id, role FROM users').all().map(r => [r.id, r.role]));
};

test('admins only: the oldest becomes platform admin, nobody is locked out', () => {
  assert.deepEqual(run([[5, 'admin'], [6, 'admin'], [7, 'user']]), { 5: 'platform_admin', 6: 'user', 7: 'user' });
});

test('with a platform admin present, every admin becomes user and nobody is promoted', () => {
  assert.deepEqual(run([[1, 'platform_admin'], [5, 'admin'], [6, 'admin']]), { 1: 'platform_admin', 5: 'user', 6: 'user' });
});
