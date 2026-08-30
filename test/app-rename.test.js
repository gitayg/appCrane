import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';

// Renaming an app must not half-finish (v2.53.2).
//
// POST /api/apps/:slug/rename stops both containers and renames
// data/apps/<slug> on disk BEFORE it writes the new slug to the database. That
// ordering was fine while the write could not fail. It can:
//
//   app_skills.app_slug -> apps.slug, ON UPDATE NO ACTION, foreign_keys = ON
//
// so for any app with a skill attached, `UPDATE apps SET slug = ?` raises
// SQLITE_CONSTRAINT_FOREIGNKEY. Measured before the fix: rename succeeds with no
// skills, and is blocked with one. The block lands after the containers are down
// and the directory has already moved — leaving the app stopped, the data at the
// new path, and the database still naming the old one. Not renamed, and no
// longer running.
//
// The fix is both halves: carry app_skills across in the same transaction so the
// write can succeed, and do that write FIRST so anything that still fails does
// so before external state is touched.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-rename-'));
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';

// Docker unreachable: the route stops containers and queues redeploys, neither
// of which is what these assertions are about.
const SHIM = join(process.env.DATA_DIR, 'bin');
mkdirSync(SHIM, { recursive: true });
writeFileSync(join(SHIM, 'docker'), '#!/bin/sh\necho "no docker" >&2\nexit 1\n', { mode: 0o755 });
process.env.PATH = `${SHIM}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { generateApiKey, hashApiKey } = await import('../server/services/encryption.js');
const appsRouter = (await import('../server/routes/apps.js')).default;

const KEY = generateApiKey('dhk_admin');
let server; let BASE;

before(async () => {
  db.prepare(
    "INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('A','a@x.io','platform_admin',?,1,'human')"
  ).run(hashApiKey(KEY));
  const api = express();
  api.use(express.json());
  api.use('/api/apps', appsRouter);
  // Surface the real error instead of Express's opaque 500 HTML page.
  api.use((err, _req, res, _next) => {
    if (!err.status || err.status >= 500) console.error('ROUTE ERROR:', err.message);
    res.status(err.status || 500).json({ error: { code: err.code, message: err.message } });
  });
  server = await new Promise((r) => { const s = api.listen(0, () => r(s)); });
  BASE = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server?.closeAllConnections?.(); server?.unref(); server?.close(); });

let slot = 900;
/** An app with its data directory on disk, optionally carrying a skill. */
function makeApp(slug, { withSkill = false } = {}) {
  const id = db.prepare("INSERT INTO apps (name, slug, slot) VALUES (?, ?, ?)")
    .run(slug.toUpperCase(), slug, slot++).lastInsertRowid;
  const dir = join(process.env.DATA_DIR, 'apps', slug);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'marker.txt'), slug);
  if (withSkill) {
    db.prepare("INSERT OR IGNORE INTO skills (slug,name) VALUES ('a-skill','A Skill')").run();
    db.prepare('INSERT INTO app_skills (app_slug, skill_slug) VALUES (?, ?)').run(slug, 'a-skill');
  }
  return id;
}

const rename = (slug, new_slug) => fetch(`${BASE}/api/apps/${slug}/rename`, {
  method: 'POST',
  headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({ new_slug }),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));

const appBySlug = (s) => db.prepare('SELECT * FROM apps WHERE slug = ?').get(s);
const dataDir = (s) => join(process.env.DATA_DIR, 'apps', s);

test('an app with NO skills renames (the case that already worked)', async () => {
  const id = makeApp('plain-one');
  const { status } = await rename('plain-one', 'plain-two');
  assert.equal(status, 200);
  assert.equal(db.prepare('SELECT slug FROM apps WHERE id = ?').get(id).slug, 'plain-two');
  assert.ok(existsSync(dataDir('plain-two')), 'the data directory follows the slug');
});

test('an app WITH a skill attached renames, and the skill follows it', async () => {
  const id = makeApp('skilled-one', { withSkill: true });
  const { status, body } = await rename('skilled-one', 'skilled-two');

  assert.equal(status, 200, `rename failed: ${JSON.stringify(body)}`);
  assert.equal(db.prepare('SELECT slug FROM apps WHERE id = ?').get(id).slug, 'skilled-two');

  const skills = db.prepare('SELECT app_slug FROM app_skills WHERE skill_slug = ?').all('a-skill');
  assert.deepEqual(skills.map((s) => s.app_slug), ['skilled-two'],
    'the skill still points at the old slug — it must travel with the app, not be orphaned or dropped');
  assert.equal(db.prepare('PRAGMA foreign_key_check').all().length, 0);
});

test('a rejected rename leaves the app exactly as it was', async () => {
  makeApp('keeper');
  const taken = makeApp('taken-slug');
  const { status } = await rename('keeper', 'taken-slug');

  assert.equal(status, 409, 'renaming onto an existing slug must be refused');
  assert.ok(appBySlug('keeper'), 'the app kept its slug');
  assert.ok(existsSync(dataDir('keeper')), 'and its data directory was not moved');
  assert.ok(appBySlug('taken-slug').id === taken, 'the other app is untouched');
});

test('the database write happens before containers and disk are touched', () => {
  // Ordering, asserted against the source. The failure this prevents is not
  // reachable in-process any more — the FK that used to cause it is carried
  // correctly now — but the ordering is the reason a FUTURE constraint cannot
  // strand an app the same way, and nothing else records that.
  // v2.54.0: the logic moved to services/appRename.js so the MCP tool and the
  // REST route share one implementation. Same property, new home.
  const body = readFileSync(new URL('../server/services/appRename.js', import.meta.url), 'utf8');

  const dbWrite = body.indexOf('UPDATE apps SET slug');
  const stop = body.indexOf('stopApp(');
  const disk = body.indexOf('renameSync(');

  assert.ok(dbWrite > -1 && stop > -1 && disk > -1, 'rename handler shape changed — re-read this test');
  assert.ok(dbWrite < stop, 'containers are stopped before the DB write can fail');
  assert.ok(dbWrite < disk, 'the data directory is moved before the DB write can fail');
});
