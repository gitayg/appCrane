import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { roleForUserOnApp, userHasAppPermission } from '../services/permissions.js';
import { getClassification, getClassificationPolicy } from '../services/dataClassification.js';
import {
  runReleaseCheck, latestReleaseCheck, listReleaseChecks, activeExceptions,
  addException, revokeException, resolveMode, EXCEPTABLE,
} from '../services/releaseCheck.js';

const router = Router();

// The release check before production. Mounted at /api; auth is per route.

function requireProductionDeployer(req, _res, next) {
  if (isPlatformAdmin(req.user) || roleForUserOnApp(req.user, req.app) === 'owner'
    || userHasAppPermission(req.user, req.app, 'deploy.production')) return next();
  next(new AppError('Running the release check needs the right to deploy this app to production', 403, 'FORBIDDEN'));
}

/** GET /api/apps/:slug/release-check — the latest result, history, active exceptions and the mode. */
router.get('/apps/:slug/release-check', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  const { level } = getClassification(db, req.app.id);
  const policy = getClassificationPolicy(db).levels[level];
  res.json({
    data_classification: level,
    mode: resolveMode(db, level),
    exceptions_by: policy.exceptions_by,
    exceptable: EXCEPTABLE,
    latest: latestReleaseCheck(db, req.app.id),
    history: listReleaseChecks(db, req.app.id, 20),
    exceptions: activeExceptions(db, req.app.id),
  });
});

/** POST /api/apps/:slug/release-check/run — a preview against the current candidate. Deploys nothing. */
router.post('/apps/:slug/release-check/run', requireAuth, requireAppAccess, requireProductionDeployer, async (req, res) => {
  const record = await runReleaseCheck({ db: getDb(), app: req.app, userId: req.user.id, trigger: req.body?.trigger === 'promote' ? 'promote' : 'preview' });
  res.json({ release_check: record });
});

/** POST /api/apps/:slug/release-check/exceptions — { check_id, reason, days | expires_at }. */
router.post('/apps/:slug/release-check/exceptions', requireAuth, requireAppAccess, (req, res) => {
  const exception = addException(getDb(), req.app, req.body || {}, req.user);
  res.status(201).json({ exception });
});

/** DELETE /api/apps/:slug/release-check/exceptions/:id */
router.delete('/apps/:slug/release-check/exceptions/:id', requireAuth, requireAppAccess, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) throw new AppError('id must be a positive integer', 400, 'VALIDATION');
  res.json(revokeException(getDb(), req.app, id, req.user));
});

export default router;
