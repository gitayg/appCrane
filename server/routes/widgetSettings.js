import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { canManageAppRoles } from '../services/appRoleChange.js';
import { widgetOptIns, setWidgetOptIns } from '../services/widgetScopeOptIn.js';

// Mounted at /api/apps:
//   GET /api/apps/:slug/widget-scopes   { members, app_keys, can_change }
//   PUT /api/apps/:slug/widget-scopes   { members?: bool, app_keys?: bool }  owner or platform admin, audited
// Turns on the widget scopes that act with an owner's power (migration 216).
const router = Router();

const view = (o) => ({ members: o.members, app_keys: o['app-keys'] });

router.get('/:slug/widget-scopes', requireAuth, requireAppAccess, (req, res) => {
  const app = req.app;
  res.json({ ...view(widgetOptIns(getDb(), app.id)), can_change: canManageAppRoles(req.user, app) });
});

router.put('/:slug/widget-scopes', requireAuth, requireAppAccess, auditMiddleware('app-widget-scopes-set'), (req, res) => {
  const app = req.app;
  if (!canManageAppRoles(req.user, app)) {
    throw new AppError('Only an owner of the app or a platform admin can turn widgets on or off.', 403, 'FORBIDDEN');
  }
  const changes = {};
  for (const [field, scope] of [['members', 'members'], ['app_keys', 'app-keys']]) {
    const v = req.body?.[field];
    if (v === undefined) continue;
    if (typeof v !== 'boolean') throw new AppError(`${field} must be true or false`, 400, 'VALIDATION');
    changes[scope] = v;
  }
  if (!Object.keys(changes).length) throw new AppError('Send members and/or app_keys', 400, 'VALIDATION');
  res.json(view(setWidgetOptIns(getDb(), app.id, changes)));
});

export default router;
