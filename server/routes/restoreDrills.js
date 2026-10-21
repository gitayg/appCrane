import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { trackJob } from '../services/jobHealth.js';
import {
  getDrillConfig, setDrillConfig, listDrills, runRestoreDrill, isDrillRunning,
} from '../services/restoreDrills.js';
import log from '../utils/logger.js';

const router = Router();

// GET /api/settings/* is public at the global gate (settings reads classify
// themselves), so every route here carries its own auth.
router.get('/restore-drills', requireAuth, requirePlatformAdmin, (req, res) => {
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 30));
  res.json({ config: getDrillConfig(), running: isDrillRunning(), drills: listDrills({ limit }) });
});

router.put('/restore-drills/config', requireAuth, requirePlatformAdmin, (req, res, next) => {
  const b = req.body || {};
  const patch = {};
  if (b.enabled !== undefined) {
    if (typeof b.enabled !== 'boolean') return next(new AppError('enabled must be true or false', 400, 'VALIDATION'));
    patch.enabled = b.enabled;
  }
  for (const [k, lo, hi] of [['interval_days', 1, 90], ['hour', 0, 23], ['tolerance_pct', 0, 100]]) {
    if (b[k] === undefined) continue;
    if (!Number.isInteger(b[k]) || b[k] < lo || b[k] > hi) return next(new AppError(`${k} must be a whole number from ${lo} to ${hi}`, 400, 'VALIDATION'));
    patch[k] = b[k];
  }
  const cfg = setDrillConfig(patch, req.user.id);
  try { logAudit(req.user.id, null, 'settings.restore-drills', patch); } catch (_) {}
  res.json({ config: cfg });
});

router.post('/restore-drills/run', requireAuth, requirePlatformAdmin, (req, res, next) => {
  if (isDrillRunning()) return next(new AppError('A restore drill is already running', 409, 'ALREADY_RUNNING'));
  trackJob('restore-drill', () => runRestoreDrill({ trigger: 'manual', userId: req.user.id }))
    .catch((e) => log.warn(`[restore-drill] manual run failed: ${e.message}`));
  try { logAudit(req.user.id, null, 'restore-drill.run', {}); } catch (_) {}
  res.status(202).json({ started: true });
});

export default router;
