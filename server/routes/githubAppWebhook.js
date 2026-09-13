/**
 * POST /api/github-app/webhook -- deliveries for THIS instance's GitHub App.
 *
 * Unauthenticated by design: GitHub sends no AppCrane credential. The ONLY gate
 * is the X-Hub-Signature-256 HMAC, which GitHub computes over the request body
 * with the App's webhook secret. So the handler needs the body byte-for-byte as
 * GitHub sent it: `rawWebhookBody` is mounted in server/index.js BEFORE the
 * global express.json(), which then sees an already-read stream and skips it.
 * Re-serialising parsed JSON would change whitespace and key order and no
 * genuine signature would ever match.
 *
 * Body limit: GitHub caps payloads at 25 MB and a push payload lists at most
 * 2048 commits. 10 MB is several times a 2048-commit push with typical file
 * lists; anything larger is answered 413, which GitHub shows under the App's
 * Recent Deliveries, rather than buffering 25 MB per anonymous request.
 *
 * Nothing here logs the secret or the body.
 */

import express, { Router } from 'express';
import crypto from 'crypto';
import { getAppConfig, getWebhookSecret } from '../services/githubApp.js';
import { handleGithubAppEvent } from '../services/githubAppWebhook.js';
import { claimDelivery, recordDeliveryResult } from '../services/githubAppWebhookState.js';
import log from '../utils/logger.js';

export const WEBHOOK_BODY_LIMIT = '10mb';

export const rawWebhookBody = express.raw({ type: () => true, limit: WEBHOOK_BODY_LIMIT });

/** Constant-time check of an X-Hub-Signature-256 value against the raw body. */
export function signatureMatches(raw, header, secret) {
  if (typeof header !== 'string' || !header.startsWith('sha256=')) return false;
  const expected = Buffer.from(`sha256=${crypto.createHmac('sha256', secret).update(raw).digest('hex')}`);
  const given = Buffer.from(header);
  if (given.length !== expected.length) return false;
  return crypto.timingSafeEqual(given, expected);
}

function parsePayload(raw, contentType) {
  const text = raw.toString('utf8');
  if (/application\/x-www-form-urlencoded/i.test(contentType || '')) {
    return JSON.parse(new URLSearchParams(text).get('payload') || '');
  }
  return JSON.parse(text);
}

const router = Router();

router.post('/', async (req, res) => {
  const cfg = getAppConfig();
  // 404, not 401: there is no App, so there is nothing a correct signature could
  // ever authenticate against -- the endpoint does not exist on this instance.
  if (!cfg) return res.status(404).json({ error: 'No GitHub App is configured on this AppCrane instance.' });

  let secret = null;
  try { secret = getWebhookSecret(); } catch (_) { secret = null; }
  if (!secret) {
    return res.status(401).json({ error: 'No webhook secret is stored for this GitHub App, so no delivery can be verified.' });
  }

  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (!signatureMatches(raw, req.headers['x-hub-signature-256'], secret)) {
    return res.status(401).json({ error: 'Missing or invalid X-Hub-Signature-256.' });
  }

  const event = String(req.headers['x-github-event'] || '');
  const deliveryId = String(req.headers['x-github-delivery'] || '');
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(event) || !/^[A-Za-z0-9-]{1,100}$/.test(deliveryId)) {
    return res.status(400).json({ error: 'Missing or malformed X-GitHub-Event / X-GitHub-Delivery.' });
  }

  // For an App's own webhook the target is the App. A signature made with this
  // App's secret already implies it; this only catches a secret reused elsewhere.
  const targetType = req.headers['x-github-hook-installation-target-type'];
  const targetId = req.headers['x-github-hook-installation-target-id'];
  if (targetType === 'integration' && targetId && String(targetId) !== String(cfg.github_app_id)) {
    return res.status(400).json({ error: 'Delivery is for a different GitHub App.' });
  }

  let payload;
  try { payload = parsePayload(raw, req.headers['content-type']); } catch (_) {
    return res.status(400).json({ error: 'Body is not a JSON webhook payload.' });
  }

  if (!claimDelivery(deliveryId, event, typeof payload?.action === 'string' ? payload.action : null)) {
    log.debug(`[github-app-webhook] duplicate delivery ${deliveryId} (${event}) ignored`);
    return res.status(200).json({ delivery: deliveryId, event, duplicate: true });
  }

  const payloadHash = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
  try {
    const out = await handleGithubAppEvent({ event, deliveryId, payload, payloadHash });
    recordDeliveryResult(deliveryId, out.result);
    const { status = 200, ...body } = out;
    res.status(status).json({ delivery: deliveryId, event, ...body });
  } catch (e) {
    log.warn(`[github-app-webhook] ${event} delivery ${deliveryId} failed: ${e.message}`);
    recordDeliveryResult(deliveryId, 'error');
    res.status(500).json({ delivery: deliveryId, event, error: 'Webhook processing failed.' });
  }
});

export default router;
