import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';

// apps.secrets_namespace against what keeps an app's identity or fails to: the
// real data archive export and import, and migration 167 over rows that exist.
// Its own file because an import swaps the database file under the process.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-secret-namespace-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const { exportDataArchive, importDataArchive } = await import('../server/services/configBackup.js');
const { resolveEnvValues } = await import('../server/services/secretRefs.js');

const MIGRATIONS = new URL('../server/migrations/', import.meta.url);
const THIS_ONE = '167-app-secrets-namespace.sql';
const readMigration = (f) => readFileSync(new URL(f, MIGRATIONS), 'utf8');
const NAMESPACE = /^[a-f0-9]{32}$/;
const mk = (db, slug, slot) => db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES (?,?,?,'managed','main')").run(slug, slug, slot).lastInsertRowid;

const namespaceAsked = async (app) => {
  let asked = null;
  await resolveEnvValues(app, 'sandbox', [{ key: 'K', plain: 'secretsmanager:TOKEN' }], { getSecret: async (ns) => { asked = ns; return 'v'; } });
  return asked;
};

test('a restore keeps each app\'s namespace; the app id it hands out again reaches nothing of the old holder', async () => {
  initDb();
  const db = getDb();
  const one = mk(db, 'one', 16001);
  const two = mk(db, 'two', 16002);
  const before = db.prepare('SELECT id, slug, secrets_namespace FROM apps ORDER BY id').all();
  const { path } = await exportDataArchive({ contents: 'config' });

  // Created after the backup, so the restore forgets it and not its AWS secrets.
  const lost = db.prepare('SELECT * FROM apps WHERE id = ?').get(mk(db, 'after-backup', 16003));
  assert.equal(lost.id, two + 1);
  const lostNamespace = await namespaceAsked(lost);

  await importDataArchive(path, { restoreEnv: false });
  const restored = new Database(join(ROOT, 'deployhub.db'));
  assert.deepEqual(restored.prepare('SELECT id, slug, secrets_namespace FROM apps ORDER BY id').all(), before);
  assert.deepEqual(before.map((a) => a.id), [one, two]);

  // Why the path cannot be keyed on apps.id: the counter restored with the file.
  const next = restored.prepare('SELECT * FROM apps WHERE id = ?').get(mk(restored, 'unrelated', 16004));
  assert.equal(next.id, lost.id, 'the restored counter no longer hands the id out again: the comment in migration 167 is out of date');
  const nextNamespace = await namespaceAsked(next);
  assert.match(nextNamespace, NAMESPACE);
  assert.notEqual(nextNamespace, lostNamespace, 'an app reusing an id read the secrets of the app that held it');

  assert.equal(await namespaceAsked(restored.prepare('SELECT * FROM apps WHERE id = ?').get(one)), before[0].secrets_namespace);
  restored.close();
});

function migratedUpTo(stop) {
  const db = new Database(':memory:');
  for (const f of readdirSync(MIGRATIONS).filter((n) => n.endsWith('.sql')).sort()) {
    if (f >= stop) break;
    db.exec(readMigration(f));
  }
  return db;
}

test('migration 167 gives every existing app its own namespace and loses nothing', () => {
  const db = migratedUpTo(THIS_ONE);
  const a = mk(db, 'a', 16101);
  const b = mk(db, 'b', 16102);
  const c = mk(db, 'c', 16103);
  db.prepare('DELETE FROM apps WHERE id = ?').run(c);
  db.prepare('UPDATE apps SET custom_domain_auth = 1, data_plane_protocol = ? WHERE id = ?').run('udp', a);
  db.prepare("INSERT INTO env_vars (app_id, env, key, value_encrypted) VALUES (?, 'sandbox', 'K', 'x')").run(a);
  const before = db.prepare('SELECT * FROM apps ORDER BY id').all();

  db.exec(readMigration(THIS_ONE));

  const after = db.prepare('SELECT * FROM apps ORDER BY id').all();
  assert.deepEqual(after.map(({ secrets_namespace: _n, ...rest }) => rest), before);
  for (const row of after) assert.match(row.secrets_namespace, NAMESPACE);
  assert.notEqual(after[0].secrets_namespace, after[1].secrets_namespace);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM env_vars WHERE app_id = ?').get(a).n, 1, 'the rebuild cascaded into a child table');
  assert.equal(after[0].custom_domain_auth, 1);
  assert.equal(mk(db, 'd', 16104), c + 1, 'the rebuild reset the id counter');
  const triggers = db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'apps'").all().map((t) => t.name).sort();
  assert.deepEqual(triggers, ['apps_secrets_namespace_immutable', 'apps_slug_not_alias_insert', 'apps_slug_not_alias_update']);
  const indexes = db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'apps' AND sql IS NOT NULL").all().map((i) => i.name).sort();
  assert.deepEqual(indexes, ['idx_apps_public_port', 'idx_apps_sandbox_public_port', 'idx_apps_service_token']);
  db.close();
});

test('a namespace cannot be changed, cleared or shared, and every writer gets a fresh one', () => {
  const live = migratedUpTo('999');
  const a = mk(live, 'a', 16201);
  const b = mk(live, 'b', 16202);
  const row = (id) => live.prepare('SELECT secrets_namespace FROM apps WHERE id = ?').get(id).secrets_namespace;
  const nsA = row(a);
  assert.match(nsA, NAMESPACE);
  assert.notEqual(nsA, row(b));
  assert.throws(() => live.prepare('UPDATE apps SET secrets_namespace = ? WHERE id = ?').run('f'.repeat(32), a), /SECRETS_NAMESPACE_IMMUTABLE/);
  assert.throws(() => live.prepare('UPDATE apps SET secrets_namespace = ? WHERE id = ?').run(nsA, b), /SECRETS_NAMESPACE_IMMUTABLE/);
  assert.throws(() => live.prepare('UPDATE apps SET secrets_namespace = NULL WHERE id = ?').run(a), /SECRETS_NAMESPACE_IMMUTABLE/);
  assert.equal(row(a), nsA);
  assert.throws(() => live.prepare("INSERT INTO apps (name,slug,slot,source_type,branch,secrets_namespace) VALUES ('x','x',16203,'managed','main',?)").run(nsA), /UNIQUE/);
  live.prepare('UPDATE apps SET slug = ? WHERE id = ?').run('a-renamed', a);
  assert.equal(row(a), nsA, 'a rename changed the namespace');
  live.close();
});

test('a later rebuild of apps carries the namespace across instead of giving every app a new one', () => {
  const rebuilds = readdirSync(MIGRATIONS)
    .filter((f) => f.endsWith('.sql') && readMigration(f).includes('CREATE TABLE apps_new'))
    .sort();
  const newest = rebuilds[rebuilds.length - 1];
  assert.ok(newest >= THIS_ONE, `${newest} rebuilt apps before ${THIS_ONE}`);
  const insert = /INSERT INTO apps_new \(([\s\S]*?)\)\s*SELECT([\s\S]*?)FROM apps;/.exec(readMigration(newest));
  assert.ok(insert, `could not read the INSERT in ${newest}`);
  if (newest !== THIS_ONE) {
    assert.match(insert[1], /\bsecrets_namespace\b/, `${newest} rebuilds apps without keeping secrets_namespace: every app would lose its AWS secrets`);
    assert.match(insert[2], /\bsecrets_namespace\b/);
  } else {
    assert.doesNotMatch(insert[1], /\bsecrets_namespace\b/);
  }
});
