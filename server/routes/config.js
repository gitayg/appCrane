import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { exportConfig, importConfig } from '../services/configMigration.js';

const router = Router();

// GET /api/config/export — snapshot this instance's settings for migration.
// Encrypted secrets stay ciphertext (never decrypted to plaintext here).
router.get('/export', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(exportConfig());
});

// POST /api/config/import — apply an export onto THIS instance, re-encrypting
// any secret with this instance's ENCRYPTION_KEY. Body: { config, old_key }.
// old_key is the SOURCE instance's ENCRYPTION_KEY — needed only to decrypt the
// ciphertext before re-encrypting. It is used transiently and never stored.
router.post('/import', requireAuth, requirePlatformAdmin, (req, res) => {
  const { config, old_key } = req.body || {};
  if (!config) throw new AppError('config (an exported object) is required', 400, 'VALIDATION');
  const result = importConfig(config, typeof old_key === 'string' && old_key.trim() ? old_key.trim() : undefined);
  res.json(result);
});

export default router;
