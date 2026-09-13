/**
 * Platform-admin routes for THIS instance's GitHub App (v2.75.0).
 *
 *   GET    /api/github-app            — is an App registered, and what is it
 *   POST   /api/github-app/manifest   — start the manifest flow (returns the
 *                                       GitHub form action, a one-time state,
 *                                       and the manifest to POST)
 *   POST   /api/github-app/exchange   — finish it: code + state -> stored App
 *   DELETE /api/github-app            — forget the App locally
 *   POST   /api/github-app/webhook-config — PATCH /app/hook/config on GitHub
 *
 * The webhook RECEIVER (POST /api/github-app/webhook) is NOT in this router:
 * everything here requires a platform admin, and GitHub sends no credential.
 * It lives in routes/githubAppWebhook.js and is mounted ahead of this router.
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
  webhookReceiverUrl, syncWebhookConfig,
} from '../services/githubApp.js';
import { listAttachedApps, detachInstallation } from '../services/githubCredential.js';
import { lastDeliveryAt } from '../services/githubAppWebhookState.js';
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

// GitHub's REST API cannot change these (PATCH /app/hook/config takes url,
// content_type, secret and insecure_ssl only), so the admin clicks them.
const MANUAL_WEBHOOK_STEPS = (slug) => [
  `On GitHub open the App's settings: your account (or organization) Settings → Developer settings → GitHub Apps → ${slug} → Edit.`,
  'Under "Webhook", tick "Active".',
  'Under "Subscribe to events", tick "Push".',
  'Click "Save changes".',
];

function webhookStatus(cfg) {
  if (!cfg) return null;
  const receiverUrl = webhookReceiverUrl();
  const lastDelivery = lastDeliveryAt();
  let state;
  let reason = null;
  if (!receiverUrl) {
    state = 'unavailable';
    reason = 'CRANE_DOMAIN is not set, so this instance has no public URL for GitHub to deliver to. '
      + 'Webhooks stay off; deploys from App-backed repositories need a manual deploy or the per-app webhook.';
  } else if (lastDelivery) {
    state = 'receiving';
  } else if (cfg.webhook_active_at_creation || cfg.webhook_config_synced_at) {
    state = 'configured';
  } else {
    state = 'not_configured';
  }
  const needsClicks = !!receiverUrl && !lastDelivery && !cfg.webhook_active_at_creation;
  return {
    state,
    reason,
    receiver_url: receiverUrl,
    secret_stored: cfg.webhook_secret_stored,
    active_at_creation: cfg.webhook_active_at_creation,
    config_synced_at: cfg.webhook_config_synced_at,
    last_delivery_at: lastDelivery,
    can_sync: !!receiverUrl,
    manual_steps: needsClicks ? MANUAL_WEBHOOK_STEPS(cfg.slug) : [],
    polling_note: 'The PR poller keeps running every 5 minutes whether or not webhooks arrive.',
  };
}

router.get('/', (_req, res) => {
  const cfg = getAppConfig();
  res.json({
    ...(cfg || { configured: false }),
    attached_apps: listAttachedApps(),
    base_url: baseUrl(),
    webhook: webhookStatus(cfg),
  });
});

/**
 * Point an existing App's webhook at this instance (url, content_type json,
 * secret) with PATCH /app/hook/config. Activation and the Push subscription are
 * not settable by API; the response repeats the clicks still needed.
 */
router.post('/webhook-config', auditMiddleware('github-app-webhook-config'), async (_req, res) => {
  const cfg = getAppConfig();
  if (!cfg) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No GitHub App is configured.' } });
  if (!webhookReceiverUrl()) {
    return res.status(409).json({ error: { code: 'NO_CRANE_DOMAIN', message: webhookStatus(cfg).reason } });
  }
  try {
    const synced = await syncWebhookConfig();
    log.info(`[github-app] webhook config sent to GitHub for ${cfg.slug}`);
    const fresh = getAppConfig();
    res.json({ synced: true, url: synced.url, content_type: synced.content_type, secret_generated: synced.secret_generated,
      manual_steps: MANUAL_WEBHOOK_STEPS(cfg.slug), webhook: webhookStatus(fresh) });
  } catch (e) {
    res.status(502).json({ error: { code: 'GITHUB_HOOK_CONFIG_FAILED', message: e.message } });
  }
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
  const manifest = buildManifest({ baseUrl: base, name: `AppCrane (${host})`, webhooksActive: !!webhookReceiverUrl() });
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
    const cfg = saveAppConfig(conversion, req.user.id, { webhookActive: !!webhookReceiverUrl() });
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
