import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { requireStepUp } from '../services/stepUp.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { egressMode, setEgressMode, setAppEnforced, appEgressView } from '../services/egress/policy.js';

// Egress allow-list (services/egress/*).
// adminRouter  /api/egress/settings          platform mode (platform admin)
// appRouter    /api/apps/:slug/egress         this app's state, allow-list and
//                                             recent egress events (owner, app
//                                             admin, platform admin); PUT turns
//                                             enforcement on for one app
//                                             (platform admin)

export const adminRouter = Router();

adminRouter.get('/settings', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ mode: egressMode(), takes_effect: 'at the next deploy or restart of each app environment' });
});

adminRouter.put('/settings', requireAuth, requirePlatformAdmin, requireStepUp('security_settings'), (req, res) => {
  res.json({ mode: setEgressMode(req.body?.mode, req.user), takes_effect: 'at the next deploy or restart of each app environment' });
});

export const appRouter = Router();

function requireEgressViewer(req, _res, next) {
  if (req.user.role === 'platform_admin') return next();
  const tier = roleForUserOnApp(req.user, req.app);
  if (tier !== 'owner' && tier !== 'admin') return next(new AppError('Only an owner or admin of this app can see its egress settings.', 403, 'FORBIDDEN'));
  next();
}

function view(app) {
  const events = getDb().prepare(`SELECT ts, kind, summary, data FROM events WHERE app_id = ? AND kind IN ('egress.allowed', 'egress.refused')
    ORDER BY id DESC LIMIT 50`).all(app.id).map((e) => { let d = {}; try { d = JSON.parse(e.data || '{}'); } catch (_) {} return { ts: e.ts, kind: e.kind, ...d }; });
  return { ...appEgressView(app), recent: events };
}

appRouter.get('/:slug/egress', requireAuth, requireAppAccess, requireEgressViewer, (req, res) => {
  res.json(view(req.app));
});

appRouter.put('/:slug/egress', requireAuth, requirePlatformAdmin, requireAppAccess, requireStepUp('security_settings'), (req, res) => {
  setAppEnforced(req.app, req.body?.enforced, req.user);
  res.json({ ...view(req.app), redeploy_needed: true });
});
