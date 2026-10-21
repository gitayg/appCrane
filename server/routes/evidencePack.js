import { Router, raw } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import {
  listPacks, getPack, packFilePath, startEvidencePack, verifyPackFile, verifyUploadedPack,
} from '../services/evidencePack/index.js';

// Compliance evidence packs (platform admin only). Mounted at /api/evidence-packs.
const router = Router();
router.use(requireAuth, requirePlatformAdmin);

const audit = (req, action, detail) => { try { logAudit(req.user.id, null, action, detail); } catch (_) {} };

router.get('/', (req, res) => {
  res.json({ packs: listPacks(parseInt(req.query.limit, 10) || 30) });
});

router.post('/', (req, res, next) => {
  try {
    const { pack } = startEvidencePack({ from: req.body?.from, to: req.body?.to, user: req.user });
    audit(req, 'evidence-pack.create', { pack: pack.id, period: pack.period });
    res.status(202).json({ pack });
  } catch (e) {
    next(new AppError(e.message, e.status || 500, e.code || 'EVIDENCE_PACK'));
  }
});

// An uploaded pack (the raw .tar.gz body) checked against this instance's key.
router.post('/verify', raw({ type: () => true, limit: '100mb' }), async (req, res, next) => {
  if (!Buffer.isBuffer(req.body) || !req.body.length) return next(new AppError('Send the pack as the request body (application/gzip)', 400, 'VALIDATION'));
  const result = await verifyUploadedPack(req.body);
  audit(req, 'evidence-pack.verify', { uploaded: true, ok: result.ok, pack: result.pack_id || null });
  res.json(result);
});

router.get('/:id', (req, res, next) => {
  const pack = getPack(req.params.id);
  if (!pack) return next(new AppError('No such evidence pack', 404, 'NOT_FOUND'));
  res.json({ pack });
});

router.get('/:id/download', (req, res, next) => {
  const path = packFilePath(req.params.id);
  if (!path) return next(new AppError('This evidence pack is not ready or no longer on disk', 404, 'NOT_FOUND'));
  const pack = getPack(req.params.id);
  audit(req, 'evidence-pack.download', { pack: pack.id, period: pack.period, sha256: pack.sha256 });
  res.download(path, pack.file_name);
});

router.post('/:id/verify', async (req, res, next) => {
  const path = packFilePath(req.params.id);
  if (!path) return next(new AppError('This evidence pack is not ready or no longer on disk', 404, 'NOT_FOUND'));
  const result = await verifyPackFile(path);
  audit(req, 'evidence-pack.verify', { pack: req.params.id, ok: result.ok });
  res.json(result);
});

export default router;
