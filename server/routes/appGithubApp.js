/**
 * Per-app GitHub App installation (v2.75.0).
 *
 *   GET    /api/apps/:slug/github-app — installation state for this app
 *   PUT    /api/apps/:slug/github-app — attach: resolve the installation that
 *                                       covers this app's repository and store it
 *   DELETE /api/apps/:slug/github-app — detach (back to the app's own PAT)
 *
 * Every route is gated on access to THIS app (requireAppAccess), and detaching
 * additionally needs the same role permission that changing the repo URL or
 * rotating the PAT needs. Attaching is platform admin only: it issues an
 * installation token for whatever repo the app names, and an owner can name any
 * repo under any installation of this instance's App. AppCrane holds no GitHub
 * identity for a user, so there is nothing to check their access to that repo
 * against.
 */

import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { userHasAppPermission } from '../services/permissions.js';
import { isAdmin } from '../utils/roles.js';
import { getAppConfig } from '../services/githubApp.js';
import {
  attachInstallation, detachInstallation, getInstallation, parseGithubRepo, githubAppEligible,
} from '../services/githubCredential.js';

const router = Router();

function requireRepoSettings(req, _res, next) {
  if (!userHasAppPermission(req.user, req.app, 'code.modify_repo_settings')) {
    return next(new AppError('Modifying repo settings is not permitted by your role on this app', 403, 'FORBIDDEN'));
  }
  next();
}

function requirePlatformAdmin(req, _res, next) {
  if (!isAdmin(req.user)) {
    return next(new AppError('Attaching the GitHub App is limited to platform admins: it gives this app a credential for the repository it names. Ask a platform admin to attach it.', 403, 'FORBIDDEN'));
  }
  next();
}

router.get('/:slug/github-app', requireAuth, requireAppAccess, (req, res) => {
  const app = req.app;
  const cfg = getAppConfig();
  const inst = getInstallation(app.id);
  const parsed = parseGithubRepo(app.github_url);
  res.json({
    app_configured: !!cfg,
    app_slug: cfg?.slug || null,
    install_url: cfg?.install_url || null,
    eligible: githubAppEligible(app) && !!parsed,
    repo_full_name: parsed?.fullName || null,
    attached: !!inst,
    installation_id: inst?.installation_id || null,
    attached_repo: inst?.repo_full_name || null,
    attached_at: inst?.attached_at || null,
    has_github_token: !!app.github_token_encrypted,
  });
});

router.put('/:slug/github-app', requireAuth, requireAppAccess, requirePlatformAdmin,
  auditMiddleware('app-github-app-attach'), async (req, res) => {
    try {
      const result = await attachInstallation(req.app, req.user.id);
      res.json({ attached: true, ...result });
    } catch (e) {
      const notInstalled = e.status === 404 || /returned 404/.test(e.message);
      res.status(notInstalled ? 409 : 400).json({
        error: {
          code: notInstalled ? 'NOT_INSTALLED' : 'ATTACH_FAILED',
          message: notInstalled
            ? `This instance's GitHub App is not installed on ${parseGithubRepo(req.app.github_url)?.fullName || 'that repository'} yet. Install it there first, then attach.`
            : e.message,
        },
      });
    }
  });

router.delete('/:slug/github-app', requireAuth, requireAppAccess, requireRepoSettings,
  auditMiddleware('app-github-app-detach'), (req, res) => {
    detachInstallation(req.app.id);
    res.json({ attached: false });
  });

export default router;
