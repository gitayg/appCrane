import Database from 'better-sqlite3';
import { readFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import log from './utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

let db;

export function getDb() {
  if (!db) throw new Error('Database not initialized. Call initDb() first.');
  return db;
}

export function initDb(dataDir) {
  const dbDir = dataDir || process.env.DATA_DIR || join(__dirname, '..', 'data');
  if (!existsSync(dbDir)) mkdirSync(dbDir, { recursive: true });

  const dbPath = join(dbDir, 'deployhub.db');
  log.info(`Opening database at ${dbPath}`);

  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  runMigrations();
  return db;
}

function runMigrations() {
  db.exec(`CREATE TABLE IF NOT EXISTS _migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);

  const migrationsDir = join(__dirname, 'migrations');
  if (!existsSync(migrationsDir)) return;

  const files = readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  const applied = new Set(
    db.prepare('SELECT name FROM _migrations').all().map(r => r.name)
  );

  // Migrations whose first non-blank line is `-- migration:no-transaction`
  // are run outside the implicit db.transaction wrapper. Required for any
  // SQL that touches connection-level state SQLite refuses to mutate inside
  // a transaction (PRAGMA writable_schema, PRAGMA foreign_keys, ...). The
  // tradeoff is a partial failure mid-file leaves the DB in an inconsistent
  // state, so keep these short and safely re-runnable.
  const NO_TX_RE = /^\s*--\s*migration:\s*no-transaction\b/im;

  for (const file of files) {
    if (applied.has(file)) continue;

    log.info(`Applying migration: ${file}`);
    const sql = readFileSync(join(migrationsDir, file), 'utf8');
    const noTransaction = NO_TX_RE.test(sql);

    if (noTransaction) {
      log.info(`  (running outside transaction; file declares migration:no-transaction)`);
      db.exec(sql);
      db.prepare('INSERT INTO _migrations (name) VALUES (?)').run(file);
    } else {
      db.transaction(() => {
        db.exec(sql);
        db.prepare('INSERT INTO _migrations (name) VALUES (?)').run(file);
      })();
    }

    log.info(`Migration ${file} applied`);
  }
}

export default { initDb, getDb };
