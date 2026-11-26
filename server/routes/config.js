import { Router } from 'express';
import crypto from 'crypto';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { logAudit } from '../middleware/audit.js';
import { exportConfig, importConfig } from '../services/configMigration.js';
import { requireArchiveSession, requireArchiveStepUp } from '../services/configArchiveGuard.js';

const router = Router();

// v2.147.0: the snapshot carries every setting (secrets as ciphertext) and an
// import rewrites them, so both take a signed-in dashboard session with a fresh
// step-up, the same gate as the platform backup routes, and both are audited.
const gate = [requireAuth, requirePlatformAdmin, requireArchiveSession, requireArchiveStepUp];
const sha256 = (v) => crypto.createHash('sha256').update(JSON.stringify(v ?? null)).digest('hex');
const actorOf = (req) => (req.real_user || req.user).id;
const ipOf = (req) => req.ip || req.socket?.remoteAddress || 'unknown';

// GET /api/config/export — snapshot this instance's settings for migration.
// Encrypted secrets stay ciphertext (never decrypted to plaintext here).
router.get('/export', ...gate, (req, res) => {
  const out = exportConfig();
  logAudit(actorOf(req), null, 'config-settings-export', { ip: ipOf(req), keys: out.settings.length, regenerate: out.regenerate.length, sha256: sha256(out) });
  res.json(out);
});

// POST /api/config/import — apply an export onto THIS instance, re-encrypting
// any secret with this instance's ENCRYPTION_KEY. Body: { config, old_key, include_protected }.
// old_key is the SOURCE instance's ENCRYPTION_KEY — needed only to decrypt the
// ciphertext before re-encrypting. It is used transiently and never stored.
// A snapshot that names a protected or route-owned setting is refused whole
// unless include_protected is true; each such key written is audited.
router.post('/import', ...gate, (req, res) => {
  const { config, old_key, include_protected } = req.body || {};
  if (!config) throw new AppError('config (an exported object) is required', 400, 'VALIDATION');
  const who = actorOf(req);
  const base = { ip: ipOf(req), body_sha256: sha256(config), include_protected: include_protected === true };
  let result;
  try {
    result = importConfig(config, typeof old_key === 'string' && old_key.trim() ? old_key.trim() : undefined, undefined, { includeProtected: include_protected === true });
  } catch (e) {
    logAudit(who, null, 'config-settings-import-refused', { ...base, code: e.code || null, keys: e.publicDetails?.keys || null, error: e.message });
    throw e;
  }
  for (const p of result.protected) logAudit(who, null, 'config-settings-import-protected', { ...base, ...p });
  logAudit(who, null, 'config-settings-import', { ...base, keys_written: result.keys, errors: result.errors.length });
  res.json(result);
});

export default router;
