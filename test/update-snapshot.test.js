import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';

// Pre-update data snapshots (v2.27.0). The contract these tests pin down:
// a self-update must leave behind a consistent, point-in-time copy of the
// database and .env BEFORE it touches the working tree — because code
// rollback cannot undo a damaged DB or a lost ENCRYPTION_KEY.

const DATA = mkdtempSync(join(tmpdir(), 'crane-snap-'));
process.env.DATA_DIR = DATA;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('U','u@x.io','platform_admin','h',1)").run();

// Stand-in repo root holding the crown-jewel key.
const cwd = mkdtempSync(join(tmpdir(), 'crane-repo-'));
writeFileSync(join(cwd, '.env'), 'ENCRYPTION_KEY=deadbeef\nPORT=5001\n');

const { createPreUpdateSnapshot, listSnapshots } = await import('../server/services/updateSnapshot.js');

test('snapshot captures the database and .env', () => {
  const s = createPreUpdateSnapshot(cwd, { from: '2.26.0', sha: 'abc1234' });
  assert.equal(s.ok, true, s.error);
  assert.ok(existsSync(join(s.dir, 'deployhub.db')), 'database copied');
  assert.ok(existsSync(join(s.dir, 'env.backup')), '.env copied');
  assert.match(readFileSync(join(s.dir, 'env.backup'), 'utf8'), /ENCRYPTION_KEY/);

  const man = JSON.parse(readFileSync(join(s.dir, 'manifest.json'), 'utf8'));
  assert.equal(man.from_version, '2.26.0');
  assert.equal(man.previous_sha, 'abc1234');
});

test('snapshot DB is valid, readable, and a point-in-time copy', () => {
  const s = createPreUpdateSnapshot(cwd, { from: 'pit' });
  assert.equal(s.ok, true, s.error);

  // Must be a real SQLite file containing the live row — this is what proves
  // `VACUUM INTO` produced a usable copy rather than an empty/torn file.
  const copy = new Database(join(s.dir, 'deployhub.db'), { readonly: true });
  assert.equal(copy.prepare("SELECT email FROM users WHERE email='u@x.io'").get()?.email, 'u@x.io');

  // A write after the snapshot must NOT appear in it.
  db.prepare("INSERT INTO users (name,email,role,api_key_hash,active) VALUES ('L',?,'user','h2',1)")
    .run(`later-${Date.now()}@x.io`);
  const after = copy.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  const live = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  assert.ok(after < live, 'snapshot is frozen at creation time');
  copy.close();
});

test('a snapshot failure never throws (upgrades must not be blocked)', () => {
  // An unwritable target is the realistic failure (disk full, permissions).
  const prev = process.env.DATA_DIR;
  process.env.DATA_DIR = '/proc/nonexistent-cannot-create';
  const s = createPreUpdateSnapshot(cwd, { from: 'x' });
  assert.equal(s.ok, false);
  assert.ok(s.error, 'reports why, so the caller can warn "no restore point"');
  process.env.DATA_DIR = prev;
});

test('retention keeps only the most recent snapshots', { timeout: 30000 }, async () => {
  for (let i = 0; i < 6; i++) {
    await new Promise(r => setTimeout(r, 1100)); // ids are second-resolution
    createPreUpdateSnapshot(cwd, { from: `x${i}` });
  }
  const kept = listSnapshots();
  assert.equal(kept.length, 5, `expected 5 retained, got ${kept.length}`);
  assert.equal(kept[0].from_version, 'x5', 'newest retained');
});
