import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { isAppOwnerAdminOrPlatformAdmin } from '../services/permissions.js';
import { appUsage, leastUsedApps, parseUsageQuery, aggregatesOnly, setAggregatesOnly, usageNow } from '../services/usageAnalytics.js';

// Usage analytics (services/usageAnalytics.js). Mounted at /api.
//
//   GET /api/apps/:slug/usage?env=&from=&to=   owner, app admin or platform admin
//   PUT /api/apps/:slug/usage/settings         same; {aggregates_only}; audited
//   GET /api/usage/apps                        platform admin: least-used apps
//                                              and the inactivity-sleep forecast
//
// Members (user, viewer) get 403: on a small app even the counts say who used
// it. aggregates_only hides the per-user table from every reader.

const router = Router();

function requireUsageReader(req, _res, next) {
  if (isAppOwnerAdminOrPlatformAdmin(req.user, req.app)) return next();
  next(new AppError('Only an owner or admin of this app can see its usage.', 403, 'FORBIDDEN'));
}

router.get('/apps/:slug/usage', requireAuth, requireAppAccess, requireUsageReader, (req, res) => {
  const db = getDb();
  const now = usageNow();
  // Not req.query: the app-access guard replaces req.app with the app row, and
  // Express 5's req.query getter reads its parser from req.app.
  const q = parseUsageQuery(Object.fromEntries(new URL(req.originalUrl, 'http://x').searchParams), now);
  const hidden = aggregatesOnly(db, req.app.id);
  const out = appUsage(db, req.app, { ...q, perUser: !hidden, now });
  res.json({ ...out, aggregates_only: hidden });
});

router.put('/apps/:slug/usage/settings', requireAuth, requireAppAccess, requireUsageReader, auditMiddleware('usage-settings-update'), (req, res) => {
  const v = req.body?.aggregates_only;
  if (typeof v !== 'boolean') throw new AppError('aggregates_only must be true or false', 400, 'VALIDATION');
  setAggregatesOnly(getDb(), req.app.id, v, req.user.id);
  res.json({ aggregates_only: v });
});

router.get('/usage/apps', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(leastUsedApps(getDb(), usageNow()));
});

export default router;
