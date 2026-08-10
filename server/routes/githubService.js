/**
 * Admin routes for the GitHub service-account integration (v2.3.0+).
 *
 * Backed by server/services/githubService.js. Exposes:
 *   GET  /api/github-service/config — sanitized config, platform-admin only
 *                                     (never returns the token)
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

// v2.38.0: was requireAuth-only, so any authenticated user could learn the
// service account's GitHub org, default repo visibility, and whether a token is
// installed. That's targeting information for the account that can create repos
// on the org, and its only caller is the platform-admin-gated Settings page.
// Now matches its sibling PUT/POST.
router.get('/config', requirePlatformAdmin, (_req, res) => {
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
    // v2.10.5: authentication alone isn't enough — managed-app creation needs
    // REPO-CREATION permission, and a token can authenticate without it (the
    // 422-on-create trap). Assess capability so the operator learns here, not
    // on the first create_managed_app.
    //   - classic PAT → x-oauth-scopes header lists scopes; need 'repo'.
    //   - fine-grained PAT → no scope header; capability (Administration:write)
    //     can't be read non-destructively, so we warn rather than assert.
    const scopes = r.headers.get('x-oauth-scopes');
    const scopeList = scopes ? scopes.split(',').map(s => s.trim()).filter(Boolean) : [];
    const classicCanCreate = scopeList.includes('repo');
    let can_create_repos = null;   // null = unknown (fine-grained)
    let note = null;
    if (scopes !== null) {
      can_create_repos = classicCanCreate;
      if (!classicCanCreate) {
        note = "This classic token lacks the 'repo' scope — it can authenticate but NOT create repositories, so managed-app creation will fail with 422. Re-issue it with the 'repo' scope.";
      }
    } else {
      note = "Fine-grained token (no scope header) — Verify can't confirm repo-creation without attempting it. Ensure it has Administration: Read and write with the owner as resource owner, or managed-app creation will 422.";
    }
    res.json({
      ok:     true,
      login:  body.login,
      type:   body.type,
      scopes: scopes || null,
      can_create_repos,
      note,
    });
  } catch (e) {
    res.status(200).json({ ok: false, error: e.message || String(e) });
  }
});

export default router;
