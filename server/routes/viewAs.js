import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { viewAsOptions, startViewAs, stopViewAs, activeViewAs } from '../services/viewAs.js';

// View as role: GET /api/auth/view-as-options, GET /api/auth/view-as,
// POST /api/auth/view-as {role, app_slug?}, POST /api/auth/stop-viewing-as.
// Every decision is made against the REAL user (req.real_user while a preview
// is active), never the previewed one.
const router = Router();

function realUserOf(req) {
  if (req.user_mcp_key) throw new AppError('View as is a dashboard feature; MCP credentials cannot use it', 403, 'KEY_FORBIDDEN');
  return req.real_user || req.user;
}

function status(req, real) {
  const va = activeViewAs(req.auth_credential_hash, real);
  return va
    ? { active: true, role: va.role, app_slug: va.app_slug, app_name: va.app_name, expires_at: va.expires_at, real_role: real.role }
    : { active: false, real_role: real.role };
}

router.get('/view-as-options', requireAuth, (req, res) => {
  const real = realUserOf(req);
  res.json({ ...viewAsOptions(real), current: status(req, real) });
});

router.get('/view-as', requireAuth, (req, res) => {
  res.json(status(req, realUserOf(req)));
});

router.post('/view-as', requireAuth, (req, res) => {
  const real = realUserOf(req);
  const { role, app_slug } = req.body || {};
  const va = startViewAs({ credentialHash: req.auth_credential_hash, realUser: real, role, appSlug: app_slug });
  try {
    logAudit(real.id, va.app_id, 'view-as-start', {
      target_role: va.role, app_slug: va.app_slug, real_role: real.role, expires_at: va.expires_at,
    });
  } catch (_) { /* a failed audit write never blocks a read-only preview */ }
  res.json(status(req, real));
});

router.post('/stop-viewing-as', requireAuth, (req, res) => {
  const real = realUserOf(req);
  const before = activeViewAs(req.auth_credential_hash, real);
  const stopped = stopViewAs(req.auth_credential_hash);
  if (stopped) {
    try {
      logAudit(real.id, before?.app_id ?? null, 'view-as-stop', {
        target_role: before?.role ?? null, app_slug: before?.app_slug ?? null, real_role: real.role,
      });
    } catch (_) { /* see above */ }
  }
  res.json({ ...status(req, real), stopped });
});

export default router;
