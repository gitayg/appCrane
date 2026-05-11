/**
 * Admin routes for the GitHub service-account integration (v2.3.0+).
 *
 * Backed by server/services/githubService.js. Exposes:
 *   GET  /api/github-service/config — sanitized config (never returns the token)
 *   PUT  /api/github-service/config — owner/visibility/enabled + optional token rotation
 *   POST /api/github-service/verify — calls /user against GitHub with the stored token
 *                                     and returns { ok, login, scopes } or { ok: false, error }
 */

import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import {
  getServiceConfig,
  setServiceConfig,
  getServiceTokenInternal,
} from '../services/githubService.js';

const router = Router();

router.use(requireAuth);

router.get('/config', (_req, res) => {
  res.json(getServiceConfig());
});

router.put('/config', requirePlatformAdmin, (req, res) => {
  const { owner, token, visibility, enabled } = req.body || {};
  try {
    const next = setServiceConfig({ owner, token, visibility, enabled }, req.user.id);
    res.json(next);
  } catch (e) {
    res.status(400).json({ error: { code: 'VALIDATION', message: e.message } });
  }
});

/**
 * Verify the stored token actually works against GitHub. Doesn't return the
 * token — just enough to convince the operator the integration is wired up.
 */
router.post('/verify', requirePlatformAdmin, async (_req, res) => {
  const token = getServiceTokenInternal();
  if (!token) return res.status(400).json({ ok: false, error: 'no token configured' });

  try {
    const r = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept:        'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent':  'appcrane-service-verify',
      },
      signal: AbortSignal.timeout(8000),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      return res.status(200).json({ ok: false, error: body.message || `HTTP ${r.status}` });
    }
    res.json({
      ok:     true,
      login:  body.login,
      type:   body.type,
      scopes: r.headers.get('x-oauth-scopes') || null,
    });
  } catch (e) {
    res.status(200).json({ ok: false, error: e.message || String(e) });
  }
});

export default router;
