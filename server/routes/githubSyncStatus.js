import { Router } from 'express';
import { requireAuth, requireAppAccess } from '../middleware/auth.js';
import { getGithubSyncStatus } from '../services/githubSyncStatus.js';

const router = Router();

// Mounted at /api; auth is per route.

/**
 * GET /api/apps/:slug/github-sync[?refresh=1] — is GitHub's copy of the app's
 * deploy branch the same as AppCrane's? `ahead` / `behind` count commits from
 * AppCrane's point of view: ahead = AppCrane has commits GitHub doesn't,
 * behind = GitHub has commits AppCrane doesn't. state 'unknown' means not
 * measured; reason_code / reason say why.
 */
router.get('/apps/:slug/github-sync', requireAuth, requireAppAccess, async (req, res) => {
  const flag = new URL(req.originalUrl, 'http://local').searchParams.get('refresh');
  const refresh = flag === '1' || flag === 'true';
  res.json(await getGithubSyncStatus(req.app, { refresh }));
});

export default router;
