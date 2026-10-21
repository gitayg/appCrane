import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { parseAccessRules, getRules, setRules, AccessRulesError } from '../services/accessRules.js';

const router = Router();

// Path role rules edited from the dashboard (services/accessRules.js).
// Mounted at /api/apps: /api/apps/:slug/access-rules[/:env]. Auth is per route,
// because a pathless guard on the shared /api/apps mount would 401 traffic
// passing through to the other routers there.
//
// Who may read and change them: the app's owners and admins, and platform
// admins. They decide who reaches which of the app's pages, which is the same
// power as changing a member's role, so a plain member gets neither.

const ENVS = ['production', 'sandbox'];

function requireRulesEditor(req, _res, next) {
  if (req.user.role === 'platform_admin') return next();
  const tier = roleForUserOnApp(req.user, req.app);
  if (tier !== 'owner' && tier !== 'admin') {
    return next(new AppError('Only an owner or admin of this app can see or change its access rules.', 403, 'FORBIDDEN'));
  }
  next();
}

function envParam(req) {
  const env = req.params.env;
  if (!ENVS.includes(env)) throw new AppError(`env must be one of: ${ENVS.join(', ')}`, 400, 'VALIDATION');
  return env;
}

/** GET /api/apps/:slug/access-rules — both environments, both sources. */
router.get('/:slug/access-rules', requireAuth, requireAppAccess, requireRulesEditor, (req, res) => {
  const db = getDb();
  const out = {};
  for (const env of ENVS) {
    out[env] = {
      manifest: getRules(db, req.app.id, env, 'manifest')?.rules || [],
      dashboard: getRules(db, req.app.id, env, 'dashboard')?.rules || [],
    };
  }
  res.json({ app: req.app.slug, rules: out });
});

/** PUT /api/apps/:slug/access-rules/:env — replace the dashboard rules. Body: { rules: [...] } */
router.put('/:slug/access-rules/:env', requireAuth, requireAppAccess, requireRulesEditor, auditMiddleware('access-rules-update'), (req, res) => {
  const env = envParam(req);
  let rules;
  try {
    rules = parseAccessRules({ rules: req.body?.rules ?? [] }, '');
  } catch (e) {
    if (e instanceof AccessRulesError) throw new AppError(e.message, 400, 'VALIDATION');
    throw e;
  }
  setRules(getDb(), req.app.id, env, 'dashboard', rules, req.user.id);
  res.json({ app: req.app.slug, env, dashboard: rules });
});

export default router;
