import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { isAppOwnerAdminOrPlatformAdmin } from '../services/permissions.js';
import { listReleases, parseReleaseQuery, releasesCsv, setReleaseLabel } from '../services/releaseLog.js';

// Release log (services/releaseLog.js). Mounted at /api.
//
//   GET /api/apps/:slug/releases?env=&label=&format=csv   owner, app admin or platform admin
//   PUT /api/apps/:slug/releases/:id/label {label|null}   same; audited
//
// Members get 403 like usage analytics: the per-release request and user
// counts say who used a small app and when.

const router = Router();

function requireReleaseReader(req, _res, next) {
  if (isAppOwnerAdminOrPlatformAdmin(req.user, req.app)) return next();
  next(new AppError('Only an owner or admin of this app can see its release log.', 403, 'FORBIDDEN'));
}

router.get('/apps/:slug/releases', requireAuth, requireAppAccess, requireReleaseReader, (req, res) => {
  // Not req.query: requireAppAccess replaces req.app with the app row.
  const params = Object.fromEntries(new URL(req.originalUrl, 'http://x').searchParams);
  const q = parseReleaseQuery(params);
  const out = listReleases(getDb(), req.app, q);
  if (params.format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${req.app.slug}-releases.csv"`);
    return res.send(releasesCsv(out.releases));
  }
  res.json(out);
});

router.put('/apps/:slug/releases/:id/label', requireAuth, requireAppAccess, requireReleaseReader, auditMiddleware('release-label-update'), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) throw new AppError('Release not found', 404, 'NOT_FOUND');
  res.json(setReleaseLabel(getDb(), req.app, id, req.body?.label));
});

export default router;
