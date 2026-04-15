import { Router } from 'express';
import { requireAuth, requireAppUser } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { existsSync, mkdirSync, readFileSync, unlinkSync } from 'fs';
import { execFileSync } from 'child_process';
import { join } from 'path';

const router = Router();

router.use(requireAuth);

/**
 * POST /api/apps/:slug/upload/:env - Upload app bundle (.tar.gz or .zip)
 * Expects multipart form with a 'bundle' field
 */
router.post('/:slug/upload/:env', requireAppUser, auditMiddleware('upload'), async (req, res) => {
  const { env } = req.params;
  if (!['production', 'sandbox'].includes(env)) {
    return res.status(400).json({ error: { code: 'INVALID_ENV', message: 'env must be production or sandbox' } });
  }
  const app = req.app;
  const dataDir = process.env.DATA_DIR || './data';

  // Use multer for multipart
  try {
    const multer = (await import('multer')).default;
    const tmpDir = join(dataDir, 'tmp');
    mkdirSync(tmpDir, { recursive: true });

    const upload = multer({
      dest: tmpDir,
      limits: { fileSize: 200 * 1024 * 1024 }, // 200MB max
      fileFilter: (req, file, cb) => {
        const allowed = ['.tar.gz', '.tgz', '.zip'];
        const ext = file.originalname.toLowerCase();
        if (allowed.some(a => ext.endsWith(a))) {
          cb(null, true);
        } else {
          cb(new AppError('Only .tar.gz, .tgz, and .zip files allowed', 400, 'INVALID_FILE'));
        }
      },
    }).single('bundle');

    upload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({ error: { code: 'UPLOAD_ERROR', message: err.message } });
      }
      if (!req.file) {
        return res.status(400).json({ error: { code: 'NO_FILE', message: 'No bundle file uploaded' } });
      }

      const timestamp = Date.now();
      const releaseDir = join(dataDir, 'apps', app.slug, env, 'releases', `${timestamp}-upload`);
      mkdirSync(releaseDir, { recursive: true });

      try {
        const filePath = req.file.path;
        const origName = req.file.originalname.toLowerCase();

        if (origName.endsWith('.zip')) {
          execFileSync('unzip', ['-o', filePath, '-d', releaseDir], { timeout: 60000, stdio: 'pipe' });
        } else {
          execFileSync('tar', ['-xzf', filePath, '-C', releaseDir], { timeout: 60000, stdio: 'pipe' });
        }

        // Clean up temp file
        try { unlinkSync(filePath); } catch (_) {}

        // Check for deployhub.json manifest
        const manifestPath = join(releaseDir, 'deployhub.json');
        let manifest = null;
        if (existsSync(manifestPath)) {
          manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
        }

        res.json({
          message: `Uploaded and extracted to ${env}`,
          manifest,
          next_step: `POST /api/apps/${app.slug}/deploy/${env} to deploy this release`,
        });
      } catch (e) {
        return res.status(500).json({ error: { code: 'EXTRACT_FAILED', message: e.message } });
      }
    });
  } catch (e) {
    throw new AppError(`Upload handler error: ${e.message}`, 500, 'INTERNAL');
  }
});

export default router;
