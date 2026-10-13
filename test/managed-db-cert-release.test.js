import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readdirSync, writeFileSync, symlinkSync, mkdirSync, lstatSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Deprovisioning ONE engine's database removes only that engine's client
// certificate files (services/dbCerts.js releaseClientCerts, called by
// managedDb.deprovision and deprovisionApp right after the row is deleted).
//
// The bug this pins: the login name is the same for every engine of an app,
// so its _tls/client/<login> directory holds client.* (Postgres/MariaDB/Mongo,
// one certificate per login) AND redis-client.* (its Redis). Dropping either
// used to `rm -rf` the whole directory, and the database that was left
// refused the app until its next deploy re-issued the files.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-certrel-'));
process.env.ENCRYPTION_KEY = 'c'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
const certs = await import('../server/services/dbCerts.js');

const LOGIN = 'crane_a1_u';
const DIR = join(process.env.DATA_DIR, 'managed-db', '_tls', 'client', LOGIN);
let db;
let appId;

before(() => {
  initDb(process.env.DATA_DIR);
  db = getDb();
  appId = db.prepare("INSERT INTO apps (name,slug,slot,source_type,branch) VALUES ('a','a',1,'managed','main')").run().lastInsertRowid;
});
after(() => { try { rmSync(process.env.DATA_DIR, { recursive: true, force: true }); } catch (_) {} });

beforeEach(() => {
  db.prepare('DELETE FROM managed_databases').run();
  db.prepare('DELETE FROM managed_db_certs').run();
  rmSync(join(process.env.DATA_DIR, 'managed-db'), { recursive: true, force: true });
});

function addRow(engine) {
  const r = { app_id: appId, tenant: '', engine, db_name: 'crane_a1', db_user: LOGIN, password_enc: 'x' };
  r.id = db.prepare('INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc) VALUES (?,?,?,?,?,?)')
    .run(r.app_id, r.tenant, r.engine, r.db_name, r.db_user, r.password_enc).lastInsertRowid;
  return r;
}

/** What secureLogin() writes for each engine, through the real functions. */
function issue(engine) {
  if (engine === 'redis') {
    certs.writeClientFiles(LOGIN, certs.ensureRedisClientCert('crane_a1', LOGIN), null, { prefix: certs.REDIS_CLIENT_PREFIX });
  } else {
    certs.writeClientFiles(LOGIN, certs.ensureClientCert(LOGIN), null);
  }
}

/** Deprovision as managedDb does: delete the row, then release its files. */
function drop(row) {
  db.prepare('DELETE FROM managed_databases WHERE id = ?').run(row.id);
  certs.releaseClientCerts(row);
}

const files = () => (existsSync(DIR) ? readdirSync(DIR).sort() : null);
const SQL = ['client.crt', 'client.key', 'client.pem'];
const REDIS = ['redis-client.crt', 'redis-client.key', 'redis-client.pem'];

test('dropping Redis keeps the Postgres client files (and the shared ca.crt)', () => {
  const pg = addRow('postgres'); const rd = addRow('redis');
  issue('postgres'); issue('redis');
  drop(rd);
  assert.deepEqual(files(), ['ca.crt', ...SQL].sort());
  assert.ok(certs.clientFilesCurrent(LOGIN), 'Postgres certificate still matches its stored row');
  void pg;
});

test('dropping Postgres keeps the Redis client files', () => {
  const pg = addRow('postgres'); addRow('redis');
  issue('postgres'); issue('redis');
  drop(pg);
  assert.deepEqual(files(), ['ca.crt', ...REDIS].sort());
  assert.equal(certs.clientCertInfo(LOGIN), null, 'no non-Redis database left: the login certificate row is gone');
});

test('the login certificate is shared by Postgres/MariaDB/Mongo: dropping one keeps it while another remains', () => {
  const pg = addRow('postgres'); const my = addRow('mariadb');
  issue('postgres');
  drop(pg);
  assert.deepEqual(files(), ['ca.crt', ...SQL].sort(), 'MariaDB still uses client.*');
  assert.ok(certs.clientCertInfo(LOGIN), 'certificate row kept for MariaDB');
  drop(my);
  assert.equal(files(), null, 'last engine gone: directory removed');
});

test('the directory is removed when the last engine goes, in either order', () => {
  const pg = addRow('postgres'); const rd = addRow('redis');
  issue('postgres'); issue('redis');
  drop(pg);
  drop(rd);
  assert.equal(files(), null);
  assert.ok(existsSync(join(DIR, '..')), 'only the login directory, never the parent');
});

test('a file this code did not write keeps the directory; a symlinked directory is never followed', () => {
  const rd = addRow('redis');
  issue('redis');
  writeFileSync(join(DIR, 'operator-note.txt'), 'keep');
  drop(rd);
  assert.deepEqual(files(), ['operator-note.txt']);

  // A symlink planted at the login's path: nothing behind it is touched.
  rmSync(DIR, { recursive: true, force: true });
  const elsewhere = join(process.env.DATA_DIR, 'elsewhere');
  mkdirSync(elsewhere, { recursive: true });
  for (const f of ['ca.crt', ...SQL]) writeFileSync(join(elsewhere, f), 'victim');
  symlinkSync(elsewhere, DIR);
  const pg = addRow('postgres');
  drop(pg);
  assert.deepEqual(readdirSync(elsewhere).sort(), ['ca.crt', ...SQL].sort(), 'files behind the symlink survive');
  assert.ok(lstatSync(DIR).isSymbolicLink());
});
