import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { getDb } from '../db.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { getPolicy, setPolicy, effectiveForApp, setAppOptOut } from '../services/autoPatch/policy.js';
import { usesLocalRepo } from '../services/managedRepo.js';

const router = Router();

// RCE auto-patch. Mounted at /api; auth is per route.

/** GET /api/auto-patch/policy — the platform setting (platform admin). */
router.get('/auto-patch/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const runs = db.prepare(`SELECT p.*, a.slug AS app_slug FROM auto_patch_runs p JOIN apps a ON a.id = p.app_id
    WHERE p.status != 'ineligible' ORDER BY p.id DESC LIMIT 20`).all();
  res.json({ policy: getPolicy(db), recent: runs });
});

/** PUT /api/auto-patch/policy — { enabled?, cooldown_hours? } (platform admin). */
router.put('/auto-patch/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ policy: setPolicy(getDb(), req.body || {}, req.user) });
});

function appView(db, app, user) {
  let inScope = false;
  try { inScope = usesLocalRepo(app); } catch (_) { inScope = false; }
  const eff = effectiveForApp(db, app);
  const role = isPlatformAdmin(user) ? 'platform_admin' : roleForUserOnApp(user, app);
  const lockedByAdmin = !!eff.override?.opted_out && eff.override.set_by_role === 'platform_admin';
  return {
    in_scope: inScope,
    enabled: inScope && eff.enabled,
    reason: inScope ? eff.reason : 'only apps whose repository is hosted by AppCrane are auto-patched',
    platform_enabled: eff.policy.enabled,
    cooldown_hours: eff.policy.cooldown_hours,
    opted_out: !!eff.override?.opted_out,
    opted_out_by_role: eff.override?.opted_out ? eff.override.set_by_role : null,
    can_change: role === 'platform_admin' || (role === 'owner' && !lockedByAdmin),
    runs: db.prepare(`SELECT id, request_id, advisory_id, package, from_version, to_version, status, reason,
      sandbox_deployment_id, production_deployment_id, started_at, finished_at FROM auto_patch_runs
      WHERE app_id = ? AND status != 'ineligible' ORDER BY id DESC LIMIT 10`).all(app.id),
  };
}

/** GET /api/apps/:slug/auto-patch — the app's effective setting and recent runs. */
router.get('/apps/:slug/auto-patch', requireAuth, requireAppAccess, (req, res) => {
  res.json(appView(getDb(), req.app, req.user));
});

/** PUT /api/apps/:slug/auto-patch — { opted_out: boolean, reason? } (owner or platform admin). */
router.put('/apps/:slug/auto-patch', requireAuth, requireAppAccess, (req, res) => {
  const db = getDb();
  setAppOptOut(db, req.app, req.body || {}, req.user);
  res.json(appView(db, req.app, req.user));
});

export default router;
