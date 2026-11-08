import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';
import { listMcpKeys, adminRevokeMcpKey, revokeUnusedMcpKeys } from '../services/adminMcpKeys.js';

// /api/admin/mcp-keys: every user's personal MCP keys, for a platform admin.
// Session or user API key only; requireAuth already keeps dhk_mcp_* keys off
// non-MCP paths, and the check below says so outright.
const router = Router();
router.use(requireAuth, requirePlatformAdmin, (req, _res, next) => {
  if (req.user_mcp_key) return next(new AppError('Manage MCP keys from the dashboard, not via an MCP key', 403, 'KEY_FORBIDDEN'));
  next();
});

/** GET /api/admin/mcp-keys?status=live|all (default live: not revoked, not expired). */
router.get('/', (req, res) => {
  const status = req.query.status ?? 'live';
  if (status !== 'live' && status !== 'all') throw new AppError("status must be 'live' or 'all'", 400, 'VALIDATION');
  res.json({ status, keys: listMcpKeys(getDb(), { status }) });
});

/** POST /api/admin/mcp-keys/revoke-unused { days = 30, dry_run } */
router.post('/revoke-unused', (req, res) => {
  const { days = 30, dry_run = false } = req.body || {};
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new AppError('days must be an integer from 1 to 3650', 400, 'VALIDATION');
  if (typeof dry_run !== 'boolean') throw new AppError('dry_run must be a boolean', 400, 'VALIDATION');
  const out = revokeUnusedMcpKeys(getDb(), { days, dryRun: dry_run, adminId: req.user.id });
  if (!dry_run) log.info(`AdminMcpKeys: admin id=${req.user.id} revoked ${out.count} key(s) unused for ${days}+ days`);
  res.json(out);
});

/** DELETE /api/admin/mcp-keys/:id: revoke any user's key (soft, idempotent). */
router.delete('/:id', (req, res) => {
  const keyId = Number(req.params.id);
  if (!Number.isInteger(keyId) || keyId <= 0) throw new AppError('Invalid key id', 400, 'VALIDATION');
  const out = adminRevokeMcpKey(getDb(), keyId, req.user.id);
  if (!out) throw new AppError('Key not found', 404, 'NOT_FOUND');
  if (out.already) return res.json({ message: 'Already revoked', id: keyId });
  log.info(`AdminMcpKeys: admin id=${req.user.id} revoked key id=${keyId}`);
  res.json({ message: 'Key revoked', id: keyId });
});

export default router;
