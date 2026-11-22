import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { signedHeaders } from './helpers.js';
import { migrate, migrationFiles } from '../server/migrate.js';

const MIGRATIONS = join(dirname(fileURLToPath(import.meta.url)), '..', 'server', 'migrations');

// The migration runner's bookkeeping, against a recording client: no database
// needed, so it always runs.
function recordingPool(alreadyApplied = []) {
  const log = [];
  const client = {
    async query(sql) {
      log.push(sql);
      if (sql === 'SELECT name FROM schema_migrations') return { rows: alreadyApplied.map((name) => ({ name })) };
      if (sql.includes('FAIL_ME')) throw new Error('boom');
      return { rows: [] };
    },
    release() { log.push('RELEASE'); },
  };
  return { log, pool: { connect: async () => client } };
}

test('migrations apply in order, each in a transaction, under the advisory lock', async () => {
  const { log, pool } = recordingPool();
  const applied = await migrate(pool, MIGRATIONS);
  assert.deepEqual(applied, migrationFiles(MIGRATIONS));
  assert.ok(applied.length >= 1);
  assert.match(log[0], /pg_advisory_lock/);
  const begin = log.indexOf('BEGIN');
  assert.ok(begin > 0 && log[begin + 1].includes('CREATE TABLE notes') && log[begin + 3] === 'COMMIT');
  assert.match(log.at(-2), /pg_advisory_unlock/);
  assert.equal(log.at(-1), 'RELEASE');
});

test('a migration already recorded is not applied again', async () => {
  const { log, pool } = recordingPool(migrationFiles(MIGRATIONS));
  assert.deepEqual(await migrate(pool, MIGRATIONS), []);
  assert.equal(log.includes('BEGIN'), false);
});

// Against a real Postgres. Point TEST_DATABASE_URL at a throwaway database,
// for example: docker run --rm -e POSTGRES_PASSWORD=pw -p 5433:5432 postgres:16-alpine
// and TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:5433/postgres
const url = process.env.TEST_DATABASE_URL;

test('real Postgres: migrate twice, then write and read a note through the API', { skip: url ? false : 'TEST_DATABASE_URL is not set' }, async () => {
  const { createPool } = await import('../server/db.js');
  const { createApp } = await import('../server/app.js');
  const pool = createPool(url);
  after(() => pool.end());
  await pool.query('DROP TABLE IF EXISTS notes, schema_migrations');
  assert.deepEqual(await migrate(pool, MIGRATIONS), migrationFiles(MIGRATIONS));
  assert.deepEqual(await migrate(pool, MIGRATIONS), []);

  const server = createApp({ version: '0.1.0', db: pool }).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  after(() => { server.closeAllConnections?.(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;

  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.database, 'ok');
  const post = await fetch(`${base}/api/notes`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...signedHeaders({ appRole: 'user' }) },
    body: JSON.stringify({ body: 'stored in postgres' }),
  });
  assert.equal(post.status, 201);
  const list = await (await fetch(`${base}/api/notes`, { headers: signedHeaders({ appRole: 'viewer' }) })).json();
  assert.equal(list.notes[0].body, 'stored in postgres');
  assert.equal(list.notes[0].author_id, '42');
});
