import { Router } from 'express';
import { isAppOwnerOrPlatformAdmin } from '../services/permissions.js';
import { getDb } from '../db.js';
import { requireAuth, requireAppUser, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, statSync, mkdtempSync, rmSync } from 'fs';
import { join, resolve, sep } from 'path';
import { managedDbScopeFor, SANDBOX_TENANT, envForTenant } from '../services/sandboxDb.js';
import { dumpScope, restoreDatabase, rowsForScope } from '../services/managedDbBackup.js';

const router = Router();

// Engine handles for the managed-database dump/restore. null = the real ones
// (managedDb.backupAccess). Tests replace them so the gate and the cross-app
// checks can be exercised without database servers; the streamed dump and
// restore commands still go through `docker`, which tests shim on PATH.
let dbOps = null;
export function __setBackupDbOpsForTests(ops) { dbOps = ops; }

const DB_ENGINES = new Set(['postgres', 'mariadb', 'mongo', 'redis']);

/** The `databases` column, parsed. Server-written; malformed reads as none. */
function parseDatabases(raw) {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((d) => d && DB_ENGINES.has(d.engine) && typeof d.db_name === 'string') : [];
  } catch (_) {
    return [];
  }
}

/** What the API says about a backup's databases: no host paths. */
function databasesView(raw) {
  return parseDatabases(raw).map((d) => ({
    engine: d.engine,
    env: envForTenant(d.tenant || null),
    db_name: d.db_name,
    size_bytes: Number(d.size_bytes) || 0,
  }));
}

router.use(requireAuth);

/**
 * POST /api/apps/:slug/backup/:env - Create backup
 */
router.post('/:slug/backup/:env', requireAppUser, auditMiddleware('backup-create'), async (req, res) => {
  const { env } = req.params;
  if (!['production', 'sandbox'].includes(env)) {
    throw new AppError('env must be production or sandbox', 400, 'INVALID_ENV');
  }
  const db = getDb();
  const app = req.app;
  const dataDir = process.env.DATA_DIR || './data';

  const sourceDir = join(dataDir, 'apps', app.slug, env, 'shared', 'data');
  const backupDir = join(dataDir, 'backups', app.slug);
  mkdirSync(backupDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = `${env}-${timestamp}`;
  const backupFile = join(backupDir, `${base}.tar.gz`);

  // The databases of the scope THIS environment connects to — the same
  // function the deployer uses to inject DB_* — so a sandbox backup of an app
  // without a separate sandbox database dumps the shared (production)
  // database, which is what that sandbox actually reads and writes. Only this
  // app's rows: rowsForScope selects on app_id, and nothing else decides
  // which databases a per-app backup contains.
  const scope = managedDbScopeFor(db, app, env);
  const hasDb = rowsForScope(scope.appId, scope.tenant).length > 0;

  if (!existsSync(sourceDir) && !hasDb) {
    throw new AppError(`No data directory found for ${app.slug} ${env}`, 404, 'NO_DATA');
  }

  try {
    if (existsSync(sourceDir)) {
      execFileSync('tar', ['-czf', backupFile, '-C', sourceDir, '.'], { timeout: 120000, stdio: 'pipe' });
    } else {
      // A database-only app (no /data yet): an empty archive keeps every
      // backup record the same shape, and restoring it extracts nothing.
      const empty = mkdtempSync(join(backupDir, '.empty-'));
      try { execFileSync('tar', ['-czf', backupFile, '-C', empty, '.'], { timeout: 120000, stdio: 'pipe' }); }
      finally { rmSync(empty, { recursive: true, force: true }); }
    }
  } catch (e) {
    throw new AppError(`Backup failed: ${e.message}`, 500, 'BACKUP_FAILED');
  }

  let databases = [];
  if (hasDb) {
    try {
      databases = await dumpScope(scope, backupDir, base, { ops: dbOps });
    } catch (e) {
      // All or nothing: a record that claimed a backup while its database was
      // missing would be restored later as if it were complete.
      rmSync(backupFile, { force: true });
      for (const eng of DB_ENGINES) rmSync(join(backupDir, `${base}.${eng}.dump`), { force: true });
      throw new AppError(`Database backup failed: ${e.message}`, 500, 'BACKUP_FAILED');
    }
  }

  const stats = statSync(backupFile);

  const result = db.prepare(`
    INSERT INTO backups (app_id, env, size_bytes, file_path, created_by, databases)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(app.id, env, stats.size, backupFile, req.user.id, databases.length ? JSON.stringify(databases) : null);

  res.json({
    backup: {
      id: result.lastInsertRowid,
      app: app.slug,
      env,
      size_bytes: stats.size,
      databases: databasesView(databases.length ? JSON.stringify(databases) : null),
      created_at: new Date().toISOString(),
    },
    message: databases.length
      ? `Backup created successfully, including ${databases.map((d) => d.engine).join(', ')} database${databases.length > 1 ? 's' : ''}`
      : 'Backup created successfully',
  });
});

/**
 * GET /api/apps/:slug/backups - List backups
 */
router.get('/:slug/backups', requireAppAccess, (req, res) => {
  const db = getDb();
  const backups = db.prepare(`
    SELECT b.*, u.name as created_by_name FROM backups b
    LEFT JOIN users u ON b.created_by = u.id
    WHERE b.app_id = ?
    ORDER BY b.created_at DESC
    LIMIT 50
  `).all(req.app.id);

  res.json({
    backups: backups.map((b) => {
      const databases = databasesView(b.databases);
      return { ...b, databases, includes_database: databases.length > 0 };
    }),
  });
});

/**
 * POST /api/apps/:slug/restore/:id - Restore from backup
 */
router.post('/:slug/restore/:id', requireAppUser, auditMiddleware('backup-restore'), async (req, res) => {
  const db = getDb();
  const backup = db.prepare('SELECT * FROM backups WHERE id = ? AND app_id = ?')
    .get(parseInt(req.params.id), req.app.id);

  if (!backup) throw new AppError('Backup not found', 404, 'NOT_FOUND');

  // include_database: opt-out, default on when the backup has a database.
  const databases = parseDatabases(backup.databases);
  // Body only: requireAppUser replaces req.app with the app ROW, and Express 5's
  // req.query getter reads its parser from req.app.get() — so req.query throws
  // on every route behind that middleware.
  const includeDb = databases.length > 0 && (req.body || {}).include_database !== false;

  // Security audit 2026-10-06, M2: restoring overwrites that environment's data.
  if (backup.env === 'production' && !isAppOwnerOrPlatformAdmin(req.user, req.app)) {
    throw new AppError('Only the app owner or a platform admin can restore production data', 403, 'FORBIDDEN');
  }
  // The same rule, applied to the DATABASE rather than the env label. A
  // sandbox backup of an app whose sandbox shares production's database holds
  // a dump of that shared database, and restoring it overwrites production's
  // data — so it is gated as production, whoever may restore sandbox /data.
  if (includeDb && databases.some((d) => (d.tenant || '') !== SANDBOX_TENANT)
      && !isAppOwnerOrPlatformAdmin(req.user, req.app)) {
    throw new AppError(
      'This backup\'s database is the one production uses (sandbox shares it), so only the app owner or a platform admin can restore it. Retry with include_database=false to restore only the sandbox files.',
      403, 'FORBIDDEN',
    );
  }
  if (!existsSync(backup.file_path)) throw new AppError('Backup file missing from disk', 404, 'FILE_MISSING');

  const dataDir = process.env.DATA_DIR || './data';
  const backupRoot = resolve(join(dataDir, 'backups', req.app.slug));
  if (includeDb) {
    for (const d of databases) {
      // Server-written paths, still confined: a dump is only ever read from
      // this app's own backups directory.
      const abs = resolve(String(d.file || ''));
      if (!abs.startsWith(backupRoot + sep) || !existsSync(abs)) {
        throw new AppError(`Database dump for ${d.engine} missing from disk`, 404, 'FILE_MISSING');
      }
      // Checked BEFORE anything is overwritten (restoreDatabase checks again
      // at the point of use): the dump must be of a database THIS app owns.
      const own = rowsForScope(req.app.id, d.tenant || '').find((r) => r.engine === d.engine);
      if (!own || own.db_name !== d.db_name) {
        throw new AppError(`This backup's ${d.engine} dump is not of this app's database; refusing to restore across apps`, 403, 'CROSS_APP_RESTORE');
      }
    }
  }

  const targetDir = join(dataDir, 'apps', req.app.slug, backup.env, 'shared', 'data');
  mkdirSync(targetDir, { recursive: true });

  try {
    // TODO: Stop app before restore
    execFileSync('tar', ['-xzf', backup.file_path, '-C', targetDir], { timeout: 120000, stdio: 'pipe' });
    // TODO: Restart app after restore
  } catch (e) {
    throw new AppError(`Restore failed: ${e.message}`, 500, 'RESTORE_FAILED');
  }

  const restored = [];
  if (includeDb) {
    for (const d of databases) {
      try {
        // appId is THIS app, always; restoreDatabase refuses a dump whose
        // database is not this app's (cross-app), on the server.
        restored.push(await restoreDatabase(
          { appId: req.app.id, tenant: d.tenant || '', engine: d.engine, expectDbName: d.db_name },
          resolve(d.file), { ops: dbOps },
        ));
      } catch (e) {
        if (e.code === 'CROSS_APP_RESTORE') throw new AppError(e.message, 403, 'CROSS_APP_RESTORE');
        throw new AppError(`Database restore failed (${d.engine}): ${e.message}`, e.status || 500, 'RESTORE_FAILED');
      }
    }
  }

  res.json({
    message: `Restored backup #${backup.id} to ${req.app.slug} ${backup.env}`
      + (restored.length ? `, including the ${restored.map((r) => r.engine).join(', ')} database` : ''),
    databases_restored: restored,
  });
});

/**
 * POST /api/apps/:slug/copy-data - Copy prod data to sandbox
 */
router.post('/:slug/copy-data', requireAppUser, auditMiddleware('copy-data'), (req, res) => {
  // Security audit 2026-10-06, M2: this copies production data into sandbox,
  // which members can deploy code to and so read.
  if (!isAppOwnerOrPlatformAdmin(req.user, req.app)) {
    throw new AppError('Only the app owner or a platform admin can copy production data to sandbox', 403, 'FORBIDDEN');
  }
  const dataDir = process.env.DATA_DIR || './data';
  const prodData = join(dataDir, 'apps', req.app.slug, 'production', 'shared', 'data');
  const sandData = join(dataDir, 'apps', req.app.slug, 'sandbox', 'shared', 'data');

  if (!existsSync(prodData)) {
    throw new AppError('No production data to copy', 404, 'NO_DATA');
  }

  mkdirSync(sandData, { recursive: true });

  try {
    execFileSync('rsync', ['-a', '--delete', prodData + '/', sandData + '/'], { timeout: 120000, stdio: 'pipe' });
  } catch (e) {
    // Fallback to cp if rsync not available
    try {
      execFileSync('cp', ['-r', prodData + '/.', sandData + '/'], { timeout: 120000, stdio: 'pipe' });
    } catch (e2) {
      throw new AppError(`Copy failed: ${e2.message}`, 500, 'COPY_FAILED');
    }
  }

  res.json({ message: `Copied production data to sandbox for ${req.app.slug}` });
});

export default router;
