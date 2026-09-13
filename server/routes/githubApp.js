/**
 * Platform-admin routes for THIS instance's GitHub App (v2.75.0).
 *
 *   GET    /api/github-app            — is an App registered, and what is it
 *   POST   /api/github-app/manifest   — start the manifest flow (returns the
 *                                       GitHub form action, a one-time state,
 *                                       and the manifest to POST)
 *   POST   /api/github-app/exchange   — finish it: code + state -> stored App
 *   DELETE /api/github-app            — forget the App locally
 *
 * The callback is a browser redirect from GitHub and therefore carries no API
 * credential, so it lands on the SPA, which posts `code` and `state` back here
 * WITH the admin's credential. That is what makes the state check meaningful:
 * it is bound to the admin user AND to the credential that started the flow.
 */

import { Router } from 'express';
import { createHash } from 'crypto';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { auditMiddleware, logAudit } from '../middleware/audit.js';
import {
  getAppConfig, saveAppConfig, deleteAppConfig, exchangeManifestCode,
  buildManifest, manifestFormUrl, createManifestState, consumeManifestState,
} from '../services/githubApp.js';
import { listAttachedApps, detachInstallation } from '../services/githubCredential.js';
import log from '../utils/logger.js';

const router = Router();
router.use(requireAuth, requirePlatformAdmin);

function baseUrl() {
  const craneDomain = process.env.CRANE_DOMAIN;
  return craneDomain
    ? `https://${craneDomain}`
    : (process.env.BASE_URL || `http://localhost:${process.env.PORT || 5001}`);
}

/**
 * Which credential is driving this request. The state issued by /manifest is
 * only accepted back from the same one, so a state value that leaks (browser
 * history, a shared screen) is not usable by another session.
 */
function sessionFingerprint(req) {
  const raw = req.headers['x-api-key']
    || (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  return raw ? createHash('sha256').update(String(raw)).digest('hex') : 'none';
}

router.get('/', (_req, res) => {
  const cfg = getAppConfig();
  res.json({
    ...(cfg || { configured: false }),
    attached_apps: listAttachedApps(),
    base_url: baseUrl(),
  });
});

/**
 * Step 1 of GitHub's manifest flow. The SPA renders these as a form and POSTs
 * it to `action` — GitHub requires a form POST, which a fetch() cannot do.
 */
router.post('/manifest', (req, res) => {
  const org = typeof req.body?.org === 'string' ? req.body.org.trim() : '';
  if (org && !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(org)) {
    return res.status(400).json({ error: { code: 'VALIDATION', message: 'Not a GitHub organization name.' } });
  }
  const base = baseUrl();
  let host;
  try { host = new URL(base).host; } catch (_) { host = 'local'; }
  const manifest = buildManifest({ baseUrl: base, name: `AppCrane (${host})` });
  const state = createManifestState(req.user.id, sessionFingerprint(req));
  res.json({ action: manifestFormUrl(org || null), state, manifest });
});

/**
 * Step 3 (step 2 happens on github.com). The temporary code is good for one
 * hour and is exchanged exactly once; nothing about it is logged.
 */
router.post('/exchange', auditMiddleware('github-app-create'), async (req, res) => {
  const { code, state } = req.body || {};
  if (!consumeManifestState(state, req.user.id, sessionFingerprint(req))) {
    return res.status(400).json({
      error: { code: 'BAD_STATE', message: 'This GitHub App registration did not start in this session, or it has already been completed. Start again from Settings → GitHub.' },
    });
  }
  try {
    const conversion = await exchangeManifestCode(code);
    const cfg = saveAppConfig(conversion, req.user.id);
    log.info(`[github-app] registered app ${cfg.slug} (id ${cfg.github_app_id})`);
    res.json(cfg);
  } catch (e) {
    res.status(400).json({ error: { code: 'EXCHANGE_FAILED', message: e.message } });
  }
});

/**
 * Forget the App. Refused while apps still authenticate with it, unless the
 * caller says force=1 — those apps would otherwise start failing every deploy
 * with no visible cause. force detaches them, which returns each to whatever
 * PAT it still has; that is a deliberate, audited act, not a silent fallback.
 */
router.delete('/', auditMiddleware('github-app-delete'), (req, res) => {
  const cfg = getAppConfig();
  if (!cfg) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No GitHub App is configured.' } });
  const attached = listAttachedApps();
  const force = req.query.force === '1' || req.body?.force === true;
  if (attached.length && !force) {
    return res.status(409).json({
      error: {
        code: 'APPS_ATTACHED',
        message: `${attached.length} app(s) still authenticate with this GitHub App: ${attached.map(a => a.slug).join(', ')}. `
          + 'Detach them first, or repeat with force=1 to detach them here (each then falls back to its own stored token, if it has one).',
      },
      attached_apps: attached,
    });
  }
  for (const row of attached) detachInstallation(row.app_id);
  deleteAppConfig();
  logAudit(req.user.id, null, 'github-app-delete', { detached: attached.map(a => a.slug), html_url: cfg.html_url });
  res.json({
    deleted: true,
    detached_apps: attached.map(a => a.slug),
    note: 'GitHub has no API to delete an App. Delete it on GitHub too, at the App\'s Advanced settings page, or it stays installed on those repositories.',
    github_url: cfg.html_url,
  });
});

export default router;
