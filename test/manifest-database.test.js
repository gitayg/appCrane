import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// A custom (non-catalogue) app declaring its managed database in deployhub.json.
//
// Before this, only catalogue apps had credentials injected, and the password is
// never returned by any API — so a custom app could own a database it had no way
// to connect to. These tests pin the manifest -> needs path, its strict
// validation, the precedence rules, auto-provisioning, and that no password
// reaches a log line. No Docker: databases are seeded as rows, and provision()
// is injected.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-mfdb-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { initDb, getDb } = await import('../server/db.js');
initDb(process.env.DATA_DIR);

const { encrypt } = await import('../server/services/encryption.js');
const { applyManagedDbEnv, managedDbUrl } = await import('../server/services/deployer.js');
const { credentialsFor } = await import('../server/services/managedDb.js');
const {
  parseManifestDatabase, ensureManifestDatabase, readReleaseManifestDatabase,
} = await import('../server/services/manifestDatabase.js');

const db = getDb();

function seedApp({ slug, catalogSlug = null, engine = null, password, dbName, dbUser }) {
  const appId = db.prepare(
    "INSERT INTO apps (name,slug,slot,source_type) VALUES (?,?,?,'image')"
  ).run(slug, slug, db.prepare('SELECT COUNT(*)+10 c FROM apps').get().c).lastInsertRowid;
  if (engine) {
    db.prepare(`
      INSERT INTO managed_databases (app_id, tenant, engine, db_name, db_user, password_enc)
      VALUES (?, '', ?, ?, ?, ?)
    `).run(appId, engine, dbName, dbUser, encrypt(password));
  }
  return { id: Number(appId), slug, catalog_slug: catalogSlug };
}

// ---------------------------------------------------------------------------
// (a) minimal block -> DATABASE_URL with the provisioned credentials
// ---------------------------------------------------------------------------

test('(a) a custom app declaring { engine: postgres } gets DATABASE_URL', () => {
  const pw = 'PgCustomPw-aaaaaaaaaaaaaa';
  const app = seedApp({ slug: 'custom-pg', engine: 'postgres', password: pw, dbName: 'crane_a1', dbUser: 'crane_a1_u' });
  const needs = parseManifestDatabase({ engine: 'postgres' });
  assert.deepEqual(needs, { engine: 'postgres', env: {}, url_env: 'DATABASE_URL' });

  const envMap = {};
  const r = applyManagedDbEnv(app, envMap, [], needs);
  assert.deepEqual(r.injected, ['DATABASE_URL']);
  assert.equal(r.source, 'manifest');
  assert.equal(envMap.DATABASE_URL, managedDbUrl(credentialsFor({ appId: app.id }, 'postgres')));
  assert.match(envMap.DATABASE_URL, /^postgresql:\/\/crane_a1_u:PgCustomPw-a+@host\.docker\.internal:\d+\/crane_a1$/);
});

test('(a) defaults per engine when only engine is given', () => {
  assert.equal(parseManifestDatabase({ engine: 'mariadb' }).url_env, 'DATABASE_URL');
  assert.equal(parseManifestDatabase({ engine: 'mongo' }).url_env, 'MONGODB_URI');
  assert.equal(parseManifestDatabase({ engine: 'redis' }).url_env, 'REDIS_URL');
  assert.equal(parseManifestDatabase(undefined), null);
});

// ---------------------------------------------------------------------------
// (b) explicit env mapping
// ---------------------------------------------------------------------------

test('(b) an explicit env mapping injects the discrete vars too', () => {
  const pw = 'PgDiscretePw-bbbbbbbbbbbb';
  const app = seedApp({ slug: 'custom-pg-env', engine: 'postgres', password: pw, dbName: 'crane_a2', dbUser: 'crane_a2_u' });
  const needs = parseManifestDatabase({
    engine: 'postgres', url_env: 'PG_URL',
    env: { host: 'DB_HOST', port: 'DB_PORT', name: 'DB_NAME', user: 'DB_USER', password: 'DB_PASSWORD' },
  });
  const envMap = {};
  const r = applyManagedDbEnv(app, envMap, [], needs);
  assert.deepEqual(r.injected.sort(), ['DB_HOST', 'DB_NAME', 'DB_PASSWORD', 'DB_PORT', 'DB_USER', 'PG_URL']);
  assert.equal(envMap.DB_NAME, 'crane_a2');
  assert.equal(envMap.DB_USER, 'crane_a2_u');
  assert.equal(envMap.DB_PASSWORD, pw);
  assert.equal(envMap.DB_HOST, 'host.docker.internal');
  assert.equal(typeof envMap.DB_PORT, 'string');
  assert.equal(envMap.DATABASE_URL, undefined, 'an explicit url_env replaces the default name');
});

test('(b) url_env: null with an env mapping injects only the discrete vars', () => {
  const needs = parseManifestDatabase({ engine: 'mariadb', url_env: null, env: { host: 'MYSQL_HOST' } });
  assert.deepEqual(needs, { engine: 'mariadb', env: { host: 'MYSQL_HOST' } });
});

// ---------------------------------------------------------------------------
// (c) the app's own env var wins
// ---------------------------------------------------------------------------

test('(c) an env var the app set itself wins over the injected credential', () => {
  const app = seedApp({ slug: 'custom-own', engine: 'postgres', password: 'OwnPw-ccccccccccccccccc', dbName: 'crane_a3', dbUser: 'crane_a3_u' });
  const needs = parseManifestDatabase({ engine: 'postgres', env: { host: 'DB_HOST' } });
  const envMap = { DATABASE_URL: 'postgresql://mine@elsewhere/real' };
  const r = applyManagedDbEnv(app, envMap, ['DB_HOST'], needs);
  assert.equal(envMap.DATABASE_URL, 'postgresql://mine@elsewhere/real');
  assert.equal(envMap.DB_HOST, undefined, 'a claimed (undecryptable) key is not filled in');
  assert.deepEqual(r.deferred.sort(), ['DATABASE_URL', 'DB_HOST']);
  assert.deepEqual(r.injected, []);
});

// ---------------------------------------------------------------------------
// (d) catalogue needs win over the manifest
// ---------------------------------------------------------------------------

test('(d) a catalogue entry\'s needs win over a manifest database block', () => {
  const app = seedApp({ slug: 'cat-bs', catalogSlug: 'bookstack', engine: 'mariadb', password: 'CatPw-dddddddddddddddd', dbName: 'crane_a4', dbUser: 'crane_a4_u' });
  const needs = parseManifestDatabase({ engine: 'postgres', url_env: 'MY_URL' });
  const envMap = {};
  const r = applyManagedDbEnv(app, envMap, [], needs);
  assert.equal(r.source, 'catalogue');
  assert.equal(r.manifestIgnored, true);
  assert.equal(r.engine, 'mariadb');
  assert.equal(envMap.MY_URL, undefined);
  assert.equal(envMap.DB_DATABASE, 'crane_a4', 'BookStack\'s own variable names were used');
});

test('(d) the deployer logs that the manifest block was ignored and only provisions for the manifest source', () => {
  const src = readFileSync('server/services/deployer.js', 'utf8');
  assert.match(src, /if \(mdbEnv\.manifestIgnored\) \{\s*appendLog\(/);
  // Shared-scope provisioning is for the manifest source only, and never on a
  // restart; the separate sandbox database is the other trigger (its own test).
  assert.match(src, /if \(resolved\.needs && \(separateSandbox \|\| \(resolved\.source === 'manifest' && !isRestart\)\)\) \{\s*await ensureManifestDatabase\(/);
});

// ---------------------------------------------------------------------------
// (e) strict validation, naming the field
// ---------------------------------------------------------------------------

test('(e) invalid blocks throw an error naming the field', () => {
  const cases = [
    [{ engine: 'oracle' }, /deployhub\.json database\.engine: must be one of: postgres, mariadb, mongo, redis/],
    [{}, /database\.engine/],
    [{ engine: 'postgres', url_env: 'database-url' }, /database\.url_env: must be an env var name/],
    [{ engine: 'postgres', url_env: 'lowercase' }, /database\.url_env/],
    [{ engine: 'postgres', url_env: 'PORT' }, /database\.url_env: "PORT" is reserved/],
    [{ engine: 'postgres', url_env: 'APPCRANE_DB' }, /database\.url_env: "APPCRANE_DB" is reserved/],
    [{ engine: 'postgres', env: { password: 'CRANE_URL' } }, /database\.env\.password: "CRANE_URL" is reserved/],
    [{ engine: 'postgres', env: { pass: 'DB_PASS' } }, /database\.env\.pass: unknown field/],
    [{ engine: 'postgres', env: { host: 'DB HOST' } }, /database\.env\.host: must be an env var name/],
    [{ engine: 'postgres', env: { host: 'X', port: 'X' } }, /"X" is mapped more than once/],
    [{ engine: 'postgres', extra: 1 }, /database\.extra: unknown key/],
    [{ engine: 'postgres', url_env: null }, /declares no variable/],
    ['postgres', /deployhub\.json database: must be an object/],
  ];
  for (const [block, re] of cases) {
    assert.throws(() => parseManifestDatabase(block), re, JSON.stringify(block));
  }
});

test('(e) the deployer validates the block right after reading the manifest, before the build', () => {
  const src = readFileSync('server/services/deployer.js', 'utf8');
  const parseAt = src.indexOf('const manifestDbNeeds = parseManifestDatabase(manifest.database);');
  assert.ok(parseAt > 0, 'deployApp validates manifest.database');
  assert.ok(parseAt < src.indexOf('ensureDockerfile({ releaseDir'), 'validation runs before the image build');
  // Not wrapped in a swallowing try: it sits at the deploy body's own indentation.
  assert.match(src, /\n {4}const manifestDbNeeds = parseManifestDatabase\(manifest\.database\);/);
});

// ---------------------------------------------------------------------------
// (f) auto-provision only when missing
// ---------------------------------------------------------------------------

test('(f) auto-provision runs when the app has no database for the engine', async () => {
  const app = seedApp({ slug: 'custom-new' });
  const calls = [];
  const logs = [];
  const r = await ensureManifestDatabase(app, { engine: 'postgres' }, {
    appendLog: (l) => logs.push(l),
    provision: async (scope, engine) => { calls.push([scope, engine]); return { password: 'ReturnedPw-ffffffffff' }; },
  });
  assert.equal(r.provisioned, true);
  assert.deepEqual(calls, [[{ appId: app.id }, 'postgres']]);
  assert.deepEqual(logs, ['Provisioned a managed postgres database for this app (declared in deployhub.json)']);
});

test('(f) auto-provision is skipped when a database already exists', async () => {
  const app = seedApp({ slug: 'custom-has', engine: 'postgres', password: 'HasPw-ffffffffffffffff', dbName: 'crane_a6', dbUser: 'crane_a6_u' });
  let called = 0;
  const r = await ensureManifestDatabase(app, { engine: 'postgres' }, { provision: async () => { called++; } });
  assert.equal(r.provisioned, false);
  assert.equal(called, 0);
});

test('(f) a provision failure fails with the reason', async () => {
  const app = seedApp({ slug: 'custom-fail' });
  await assert.rejects(
    ensureManifestDatabase(app, { engine: 'mariadb' }, { provision: async () => { throw new Error('server did not start'); } }),
    /Provisioning the managed mariadb database declared in deployhub\.json failed: server did not start/
  );
});

// ---------------------------------------------------------------------------
// (g) no password in any log line
// ---------------------------------------------------------------------------

test('(g) nothing the deploy logs carries the password', async () => {
  const pw = 'NeverLogThisPw-gggggggggg';
  const app = seedApp({ slug: 'custom-secret', engine: 'postgres', password: pw, dbName: 'crane_a7', dbUser: 'crane_a7_u' });
  const needs = parseManifestDatabase({ engine: 'postgres', env: { password: 'DB_PASSWORD' } });
  const logs = [];
  await ensureManifestDatabase(app, needs, { appendLog: (l) => logs.push(l) });
  const fresh = seedApp({ slug: 'custom-secret-new' });
  await ensureManifestDatabase(fresh, needs, { appendLog: (l) => logs.push(l), provision: async () => ({ password: pw, url: `postgresql://u:${pw}@h/d` }) });
  const envMap = {};
  const r = applyManagedDbEnv(app, envMap, [], needs);
  assert.equal(envMap.DB_PASSWORD, pw, 'precondition: the password really was injected');
  assert.ok(envMap.DATABASE_URL.includes(pw), 'precondition: the URL carries it');
  // Every deploy-log line about the database is built from these.
  assert.equal(JSON.stringify(r).includes(pw), false);
  assert.equal(logs.join('\n').includes(pw), false);
});

// ---------------------------------------------------------------------------
// Restart path: the live release's manifest supplies the needs
// ---------------------------------------------------------------------------

test('restart reads the live release\'s database block, and never throws', () => {
  const appEnvDir = mkdtempSync(join(tmpdir(), 'crane-mfdb-rel-'));
  assert.deepEqual(readReleaseManifestDatabase(appEnvDir), { needs: null, error: null });

  const rel = join(appEnvDir, 'releases', 'r1');
  mkdirSync(rel, { recursive: true });
  symlinkSync(rel, join(appEnvDir, 'current'));
  writeFileSync(join(rel, 'deployhub.json'), JSON.stringify({ database: { engine: 'redis' } }));
  assert.deepEqual(readReleaseManifestDatabase(appEnvDir).needs, { engine: 'redis', env: {}, url_env: 'REDIS_URL' });

  writeFileSync(join(rel, 'deployhub.json'), JSON.stringify({ database: { engine: 'nope' } }));
  const bad = readReleaseManifestDatabase(appEnvDir);
  assert.equal(bad.needs, null);
  assert.match(bad.error, /database\.engine/);
});
