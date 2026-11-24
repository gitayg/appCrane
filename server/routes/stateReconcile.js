import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { listTrash, purgeTrash } from '../services/appTrash.js';
import { dismissFinding, fixFinding, lastRun, listFindings, runReconcile } from '../services/reconcileState.js';

// Deployment records against what is running (services/reconcileState.js).
// Platform admins only: findings name every app on the host. Mounted at
// /api/state-reconcile.

const router = Router();
router.use(requireAuth, requirePlatformAdmin);

const STATUSES = new Set(['active', 'all', 'open', 'auto_fixed', 'fixed', 'resolved', 'dismissed']);
const idOf = (raw) => {
  const id = Number(raw);
  if (!Number.isInteger(id) || id <= 0) throw new AppError('Invalid id', 400, 'VALIDATION');
  return id;
};

router.get('/', (req, res) => {
  const status = new URL(req.originalUrl, 'http://x').searchParams.get('status') || 'active';
  if (!STATUSES.has(status)) throw new AppError('Unknown status filter', 400, 'VALIDATION');
  const db = getDb();
  const paused = db.prepare(`SELECT p.app_id, a.slug, p.env, p.reason, p.paused_at FROM health_probe_pauses p
    JOIN apps a ON a.id = p.app_id ORDER BY a.slug, p.env`).all();
  res.json({ last_run: lastRun(db), findings: listFindings(db, { status }), paused_probes: paused, trash: listTrash(db) });
});

router.post('/run', async (req, res) => {
  const out = await runReconcile({ trigger: 'manual' });
  logAudit(req.user.id, null, 'reconcile-run', out);
  res.json(out);
});

router.post('/findings/:id/fix', async (req, res) => {
  res.json(await fixFinding(getDb(), idOf(req.params.id), req.user));
});

router.post('/findings/:id/dismiss', (req, res) => {
  res.json(dismissFinding(getDb(), idOf(req.params.id), req.user));
});

router.post('/trash/:id/purge', (req, res) => {
  const id = idOf(req.params.id);
  const out = purgeTrash(getDb(), id);
  logAudit(req.user.id, null, 'trash-purge', { trash_id: id });
  res.json(out);
});

export default router;
