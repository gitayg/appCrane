/**
 * Internal service API for hosted apps (v2.8.0).
 *
 * Reachable ONLY from an app's own server process:
 *   - the app authenticates with APPCRANE_SERVICE_TOKEN (a container env var),
 *   - it reaches AppCrane at CRANE_INTERNAL_URL (http://host.docker.internal:5001),
 *     i.e. straight off the docker bridge, NOT through Caddy.
 *
 * Two guards keep it server-side-only:
 *   1. Caddy 404s /api/service/* on the public domain (see caddy.js).
 *   2. This handler rejects any request that arrived via Caddy (a proxied
 *      request carries Via / X-Forwarded-* that a direct bridge call does not).
 * Plus the token itself, which a browser can never obtain.
 */

import { Router } from 'express';
import { AppError } from '../utils/errors.js';
import { appForServiceToken } from '../services/appServiceToken.js';
import { enqueueEmail } from '../services/emailQueue.js';
import log from '../utils/logger.js';

const router = Router();

// Reject anything that came through the public reverse proxy. Legit internal
// callers hit host.docker.internal:5001 directly and carry none of these.
function assertInternal(req) {
  if (req.headers['via'] || req.headers['x-forwarded-host'] || req.headers['x-forwarded-for']) {
    throw new AppError('This endpoint is reachable only from an app container, not the public domain.', 403, 'NOT_INTERNAL');
  }
}

function authApp(req) {
  const token = (req.headers['x-appcrane-service-token'] || '').toString().trim();
  const app = appForServiceToken(token);
  if (!app) throw new AppError('Invalid or missing X-AppCrane-Service-Token', 401, 'BAD_SERVICE_TOKEN');
  if (!app.email_enabled) throw new AppError(`Email is not enabled for app '${app.slug}'`, 403, 'EMAIL_DISABLED');
  return app;
}

/**
 * POST /api/service/email
 * Body: { to, subject, text?, html?, replyTo?, env?, idempotencyKey? }
 * The recipient must be a registered platform user. Returns 202 + queue id.
 */
router.post('/email', (req, res) => {
  assertInternal(req);
  const app = authApp(req);
  const { to, subject, text, html, replyTo, env, idempotencyKey } = req.body || {};

  try {
    const { id, deduped } = enqueueEmail({
      appId: app.id,
      env: env === 'production' ? 'production' : 'sandbox',
      to, subject, text, html, replyTo,
      idempotencyKey,
      source: 'app',
    });
    log.info(`[service] email queued #${id} for app ${app.slug} → ${to}${deduped ? ' (deduped)' : ''}`);
    res.status(202).json({ queued: true, queue_id: id, deduped: !!deduped });
  } catch (e) {
    // Validation failures (bad/disallowed recipient, missing fields) → 400.
    throw new AppError(e.message, 400, 'EMAIL_REJECTED');
  }
});

export default router;
