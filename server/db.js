import Database from 'better-sqlite3';
import { readFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import log from './utils/logger.js';
// Cyclic by construction: updateSnapshot.js imports getDb from here. Safe
// because `getDb` is a hoisted function declaration and is only ever called at
// runtime — and the pre-migration path passes its live handle in explicitly,
// so it never reaches the not-yet-published singleton at all.
import { createPreUpdateSnapshot } from './services/updateSnapshot.js';

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

  snapshotBeforeMigrations();
  runMigrations();
  return db;
}

/**
 * Snapshot the database + .env when migrations are about to run (v2.30.0).
 *
 * This is the point where an upgrade can actually damage data. `git reset
 * --hard` doesn't: `data/` and `.env` are gitignored, so the pull leaves them
 * untouched. What mutates the database is the migrations applied on first boot
 * of the new code — ALTER TABLE, UPDATE, occasionally a table rebuild.
 *
 * Snapshotting here rather than only in /api/self-update matters for a reason
 * that isn't obvious: the self-update handler runs the code that is ALREADY
 * running, so a box on an older build pulls the new one without ever executing
 * the new snapshot logic — the first upgrade after shipping that feature is
 * exactly the one it can't protect. Migrations run in the NEW code, so a
 * snapshot taken here covers the upgrade that delivered it, and also covers
 * paths that skip /api/self-update entirely: a manual `git pull`, a container
 * rebuild, a restore onto a newer build.
 *
 * Gated on there being pending migrations, so ordinary restarts don't
 * accumulate snapshots. Best-effort: a failure is logged, never fatal — a
 * missing restore point must not stop the server from booting.
 */
function snapshotBeforeMigrations() {
  try {
    ensureMigrationsTable();
    const pending = pendingMigrations();
    if (pending.length === 0) return;

    log.info(`[snapshot] ${pending.length} migration(s) pending — snapshotting before applying: ${pending.join(', ')}`);
    // `db` (the live handle) is passed explicitly: the module singleton isn't
    // published until initDb returns, so getDb() would throw here.
    createPreUpdateSnapshot(join(__dirname, '..'), { reason: 'pre-migration', pending }, db);
  } catch (e) {
    log.warn(`[snapshot] pre-migration snapshot skipped: ${e.message}`);
  }
}

function ensureMigrationsTable() {
  db.exec(`CREATE TABLE IF NOT EXISTS _migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
}

function migrationFiles() {
  const migrationsDir = join(__dirname, 'migrations');
  if (!existsSync(migrationsDir)) return [];
  return readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();
}

function pendingMigrations() {
  const applied = new Set(db.prepare('SELECT name FROM _migrations').all().map(r => r.name));
  return migrationFiles().filter(f => !applied.has(f));
}

function runMigrations() {
  ensureMigrationsTable();

  const migrationsDir = join(__dirname, 'migrations');
  if (!existsSync(migrationsDir)) return;

  const files = migrationFiles();

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
