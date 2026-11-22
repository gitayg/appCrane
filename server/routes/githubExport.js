import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { userHasAppPermission } from '../services/permissions.js';
import { exportToGithub, exportIneligibleReason } from '../services/githubExport.js';

const router = Router();

// Mounted at /api; auth is per route.

function requireRepoSettings(req, _res, next) {
  if (!userHasAppPermission(req.user, req.app, 'code.modify_repo_settings')) {
    return next(new AppError('Exporting to GitHub is not permitted by your role on this app', 403, 'FORBIDDEN'));
  }
  next();
}

const STATUS = { pushed: 200, up_to_date: 200, refused: 409, failed: 502 };

/**
 * POST /api/apps/:slug/github-export { tags?: boolean } — push a Crane-hosted
 * app's deploy branch (and its tags unless tags=false) to its github_url,
 * fast-forward only, then verify GitHub's tips equal AppCrane's. Owners and
 * platform admins (code.modify_repo_settings). 200 pushed / up_to_date,
 * 409 refused (GitHub ahead, tag conflict, no credential), 502 failed
 * (network, or GitHub's tip did not match after the push).
 */
router.post('/apps/:slug/github-export', requireAuth, requireAppAccess, requireRepoSettings, async (req, res) => {
  const why = exportIneligibleReason(req.app);
  if (why) throw new AppError(why, 404, 'NOT_EXPORTABLE');
  const result = await exportToGithub(req.app, { userId: req.user.id, tags: req.body?.tags !== false });
  if (result.ok) return res.json(result);
  res.status(STATUS[result.state] || 502).json({
    error: { code: String(result.reason_code || 'EXPORT_FAILED').toUpperCase(), message: result.reason, ...result },
  });
});

export default router;
