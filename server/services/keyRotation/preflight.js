import Database from 'better-sqlite3';
import { readdirSync, statSync, statfsSync, existsSync, mkdirSync, copyFileSync, chmodSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations');

/**
 * Open deployhub.db and take SQLite's exclusive lock for the life of the
 * handle. A running AppCrane keeps the database open in WAL mode, and an idle
 * WAL connection in another process makes this fail with SQLITE_BUSY
 * (measured with better-sqlite3), so success means nothing else has it open —
 * and nothing can open it until this handle closes.
 */
export function openExclusive(dbPath) {
  const db = new Database(dbPath, { fileMustExist: true, timeout: 0 });
  try {
    db.pragma('locking_mode = EXCLUSIVE');
    db.exec('BEGIN EXCLUSIVE');
    db.prepare('SELECT COUNT(*) FROM sqlite_master').get();
    db.exec('COMMIT');
  } catch (e) {
    db.close();
    if (e.code === 'SQLITE_BUSY' || e.code === 'SQLITE_LOCKED') {
      throw Object.assign(new Error('the database is open in another process: AppCrane appears to be running. Stop it first'), { code: 'IN_USE' });
    }
    throw e;
  }
  return db;
}

/** True when something answers HTTP on the AppCrane port. */
export async function serverAnswers(port, host = '127.0.0.1') {
  try {
    await fetch(`http://${host}:${port}/api/health`, { signal: AbortSignal.timeout(1500) });
    return true;
  } catch {
    return false;
  }
}

export function pendingMigrations(db) {
  const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql')).sort();
  const hasTable = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_migrations'").get();
  const applied = new Set(hasTable ? db.prepare('SELECT name FROM _migrations').all().map((r) => r.name) : []);
  return files.filter((f) => !applied.has(f));
}

/** null when the data directory has room for the backup, else why not. */
export function diskRefusal(dataDir, dbPath) {
  const need = statSync(dbPath).size * 2 + 16 * 1024 * 1024;
  const fs = statfsSync(dataDir);
  const free = fs.bavail * fs.bsize;
  return free >= need ? null : `not enough free disk under ${dataDir}: ${free} bytes free, ${need} needed for the backup`;
}

/** VACUUM INTO + a 0600 copy of .env, in DATA_DIR/backups/key-rotation-<ts>/ (0700). Returns the directory. */
export function backupBeforeRotation(db, { dataDir, envPath, now = new Date() }) {
  const ts = now.toISOString().replace(/[:.]/g, '-');
  const dir = join(dataDir, 'backups', `key-rotation-${ts}`);
  if (existsSync(dir)) throw new Error(`backup directory ${dir} already exists`);
  mkdirSync(join(dataDir, 'backups'), { recursive: true });
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  const dbCopy = join(dir, 'deployhub.db');
  db.prepare('VACUUM INTO ?').run(dbCopy);
  chmodSync(dbCopy, 0o600);
  const envCopy = join(dir, 'env.backup');
  copyFileSync(envPath, envCopy);
  chmodSync(envCopy, 0o600);
  return dir;
}
