import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// Forward-only SQL migrations: server/migrations/NNN_name.sql, applied in name
// order, each in its own transaction, recorded in schema_migrations. Add a new
// file for every change; never edit or delete one that has been deployed.
//
// A session advisory lock makes two containers starting at once (a deploy
// overlapping the old release) apply each file exactly once.
const LOCK_KEY = 7240311;

export function migrationFiles(dir) {
  return readdirSync(dir).filter((f) => /^\d+_[a-z0-9_]+\.sql$/.test(f)).sort();
}

export async function migrate(pool, dir) {
  const client = await pool.connect();
  const applied = [];
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_KEY]);
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    const done = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map((r) => r.name));
    for (const file of migrationFiles(dir)) {
      if (done.has(file)) continue;
      await client.query('BEGIN');
      try {
        await client.query(readFileSync(join(dir, file), 'utf8'));
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw new Error(`migration ${file} failed: ${e.message}`);
      }
      applied.push(file);
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    client.release();
  }
  return applied;
}
