import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Rename must work when DATA_DIR is RELATIVE (v2.54.1).
//
// v2.54.0 extracted the rename into a service and, in the move, replaced
// utils/paths.js resolveSafe() with a hand-rolled containment check:
//
//   const dir = resolve(join(appsBase, slug));
//   if (dir !== join(appsBase, slug)) throw new AppError('Invalid slug path')
//
// resolve() returns an absolute path; join() does not. The two are equal only
// when appsBase is ALREADY absolute. DATA_DIR defaults to './data', so on a
// normal install the check was true for every slug and every rename failed with
// "Invalid slug path" — a message pointing at the slug, for a bug that had
// nothing to do with it.
//
// Every other test in this repo sets DATA_DIR to an absolute mkdtemp path, so
// the entire suite was blind to it. This one runs the other case, which is the
// one production actually uses.

const CWD = mkdtempSync(join(tmpdir(), 'crane-relcwd-'));
process.chdir(CWD);
process.env.DATA_DIR = './data';          // the default shape, not an absolute path
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

const SHIM = join(CWD, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { renameApp } = await import('../server/services/appRename.js');

let user;
before(() => {
  const id = db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin','h',1,'human')"
  ).run().lastInsertRowid;
  user = id;
});

test('DATA_DIR is relative — the case production runs and the suite never tried', () => {
  assert.ok(!process.env.DATA_DIR.startsWith('/'),
    'this test is only meaningful with a relative DATA_DIR');
});

test('a rename succeeds with a relative DATA_DIR', async () => {
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('S','squatter',970,'upload')").run();
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'squatter'").get();
  mkdirSync(join('./data', 'apps', 'squatter'), { recursive: true });
  writeFileSync(join('./data', 'apps', 'squatter', 'marker'), 'x');

  const out = await renameApp({ app, newSlug: 'squatter-retired', redirect: false, userId: user });

  assert.equal(out.new_slug, 'squatter-retired');
  assert.equal(db.prepare('SELECT slug FROM apps WHERE id = ?').get(app.id).slug, 'squatter-retired');
  assert.ok(existsSync(join('./data', 'apps', 'squatter-retired', 'marker')),
    'the data directory moved with the app');
  assert.ok(!existsSync(join('./data', 'apps', 'squatter')), 'and nothing was left at the old path');
});

test('a dashed slug is accepted — the shape blamed for the failure was never the cause', async () => {
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('D','plain',971,'upload')").run();
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'plain'").get();
  mkdirSync(join('./data', 'apps', 'plain'), { recursive: true });

  const out = await renameApp({ app, newSlug: 'a-b-c-dashed', redirect: false, userId: user });
  assert.equal(out.new_slug, 'a-b-c-dashed');
});

test('traversal is still refused, relative DATA_DIR or not', async () => {
  db.prepare("INSERT INTO apps (name, slug, slot, source_type) VALUES ('T','trav',972,'upload')").run();
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'trav'").get();
  // The slug regex rejects this first; the assertion is that fixing the path
  // comparison did not open a hole behind it.
  await assert.rejects(() => renameApp({ app, newSlug: '../escape', redirect: false, userId: user }),
    /lowercase alphanumeric|Path traversal/);
});
