import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAppUser, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, statSync } from 'fs';
import { join } from 'path';

const router = Router();

router.use(requireAuth);

/**
 * POST /api/apps/:slug/backup/:env - Create backup
 */
router.post('/:slug/backup/:env', requireAppUser, auditMiddleware('backup-create'), (req, res) => {
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
  const backupFile = join(backupDir, `${env}-${timestamp}.tar.gz`);

  if (!existsSync(sourceDir)) {
    throw new AppError(`No data directory found for ${app.slug} ${env}`, 404, 'NO_DATA');
  }

  try {
    execFileSync('tar', ['-czf', backupFile, '-C', sourceDir, '.'], { timeout: 120000, stdio: 'pipe' });
  } catch (e) {
    throw new AppError(`Backup failed: ${e.message}`, 500, 'BACKUP_FAILED');
  }

  const stats = statSync(backupFile);

  const result = db.prepare(`
    INSERT INTO backups (app_id, env, size_bytes, file_path, created_by)
    VALUES (?, ?, ?, ?, ?)
  `).run(app.id, env, stats.size, backupFile, req.user.id);

  res.json({
    backup: {
      id: result.lastInsertRowid,
      app: app.slug,
      env,
      size_bytes: stats.size,
      created_at: new Date().toISOString(),
    },
    message: 'Backup created successfully',
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

  res.json({ backups });
});

/**
 * POST /api/apps/:slug/restore/:id - Restore from backup
 */
router.post('/:slug/restore/:id', requireAppUser, auditMiddleware('backup-restore'), (req, res) => {
  const db = getDb();
  const backup = db.prepare('SELECT * FROM backups WHERE id = ? AND app_id = ?')
    .get(parseInt(req.params.id), req.app.id);

  if (!backup) throw new AppError('Backup not found', 404, 'NOT_FOUND');
  if (!existsSync(backup.file_path)) throw new AppError('Backup file missing from disk', 404, 'FILE_MISSING');

  const dataDir = process.env.DATA_DIR || './data';
  const targetDir = join(dataDir, 'apps', req.app.slug, backup.env, 'shared', 'data');
  mkdirSync(targetDir, { recursive: true });

  try {
    // TODO: Stop app before restore
    execFileSync('tar', ['-xzf', backup.file_path, '-C', targetDir], { timeout: 120000, stdio: 'pipe' });
    // TODO: Restart app after restore
  } catch (e) {
    throw new AppError(`Restore failed: ${e.message}`, 500, 'RESTORE_FAILED');
  }

  res.json({ message: `Restored backup #${backup.id} to ${req.app.slug} ${backup.env}` });
});

/**
 * POST /api/apps/:slug/copy-data - Copy prod data to sandbox
 */
router.post('/:slug/copy-data', requireAppUser, auditMiddleware('copy-data'), (req, res) => {
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
