import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import {
  chainStatus, verificationHistory, sealNew, verifyAndRecord, exportCheckpoints, checkExternalCheckpoints,
} from '../services/auditChain.js';

// Tamper-evident audit (services/auditChain.js). Platform admins only.
// Mounted at '/api'; every route carries its own guards.

const router = Router();

router.get('/audit-chain/status', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ ...chainStatus(), history: verificationHistory() });
});

router.post('/audit-chain/verify', requireAuth, requirePlatformAdmin, async (req, res) => {
  await sealNew();
  const report = await verifyAndRecord({ trigger: 'manual' });
  logAudit(req.user.id, null, 'audit-chain-verify', { ok: report.ok, problems: report.problems.length });
  res.json({ ...report, problems: report.problems.slice(0, 200), total_problems: report.problems.length });
});

router.get('/audit-chain/checkpoints', requireAuth, requirePlatformAdmin, (req, res) => {
  logAudit(req.user.id, null, 'audit-chain-checkpoints-export', {});
  res.setHeader('Content-Disposition', 'attachment; filename="audit-chain-checkpoints.json"');
  res.json({ exported_at: new Date().toISOString(), checkpoints: exportCheckpoints() });
});

router.post('/audit-chain/checkpoints/check', requireAuth, requirePlatformAdmin, (req, res) => {
  const list = req.body?.checkpoints;
  if (!Array.isArray(list) || !list.length) throw new AppError('checkpoints must be a non-empty array', 400, 'VALIDATION');
  const results = checkExternalCheckpoints(list);
  res.json({ ok: results.every(r => r.result === 'match'), results });
});

export default router;
