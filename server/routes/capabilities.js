import { Router } from 'express';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { getDb } from '../db.js';
import { requireStepUp } from '../services/stepUp.js';
import log from '../utils/logger.js';
import {
  appCapabilities, createRequest, cancelRequest, listRequests, decideRequest, confirmGrant, revokeGrant, getPolicy, setPolicy,
} from '../services/capabilities/store.js';

// Capability approvals (migration 200). Mounted at /api; auth is per route and
// who may do what is decided in services/capabilities/store.js.
const router = Router();

// An identity session is the dashboard; an X-API-Key is a script or an agent
// acting as the person. Decisions require the former.
const channelOf = (req) => (req.headers['x-api-key'] ? 'api-key' : 'session');
const decisionCtx = (req) => ({ user: req.user, channel: channelOf(req), viewAs: !!req.view_as });
// Every decision also needs a recent sign-in or step-up (services/stepUp.js).
const decisionStepUp = requireStepUp('approve_capability_request');

async function reloadIfNeeded(reload) {
  if (!reload) return;
  try { await (await import('../services/caddy.js')).reloadCaddy(); }
  catch (e) { log.warn(`[capabilities] Caddy reload after revoke failed: ${e.message}`); }
}

/** GET /api/apps/:slug/capabilities — policy, grants and open requests for this app. Any member. */
router.get('/apps/:slug/capabilities', requireAuth, requireAppAccess, (req, res) => {
  res.json(appCapabilities(getDb(), req.app, req.user));
});

/** POST /api/apps/:slug/capability-requests — { capability, scope, reason }. Owner or app admin. */
router.post('/apps/:slug/capability-requests', requireAuth, requireAppAccess, (req, res) => {
  const { capability, scope, reason } = req.body || {};
  const out = createRequest(getDb(), {
    app: req.app, user: req.user, capability, scope, reason,
    via: channelOf(req) === 'session' ? 'dashboard' : 'api',
  });
  res.status(out.created ? 201 : 200).json(out);
});

/** POST /api/apps/:slug/capability-requests/:id/cancel — the requester or the owner. */
router.post('/apps/:slug/capability-requests/:id/cancel', requireAuth, requireAppAccess, (req, res) => {
  res.json({ request: cancelRequest(getDb(), { app: req.app, user: req.user, id: req.params.id }) });
});

/** GET /api/capability-requests?status=pending|unreviewed|active|flagged|denied|all&capability= — platform admins. */
router.get('/capability-requests', requireAuth, requirePlatformAdmin, (req, res) => {
  const q = req.query || {};
  res.json({ requests: listRequests(getDb(), { status: q.status || 'pending', capability: q.capability || null }) });
});

/** POST /api/capability-requests/:id/approve — { scope?, expires_in_days?, note? }. */
router.post('/capability-requests/:id/approve', requireAuth, requirePlatformAdmin, decisionStepUp, (req, res) => {
  const b = req.body || {};
  res.json({ request: decideRequest(getDb(), { ...decisionCtx(req), id: req.params.id, approve: true, scope: b.scope, expiresInDays: b.expires_in_days, note: b.note }) });
});

/** POST /api/capability-requests/:id/deny — { note? }. */
router.post('/capability-requests/:id/deny', requireAuth, requirePlatformAdmin, decisionStepUp, (req, res) => {
  res.json({ request: decideRequest(getDb(), { ...decisionCtx(req), id: req.params.id, approve: false, note: req.body?.note }) });
});

/** POST /api/capability-requests/:id/confirm — keep a grandfathered grant. { expires_in_days?, note? } */
router.post('/capability-requests/:id/confirm', requireAuth, requirePlatformAdmin, decisionStepUp, (req, res) => {
  const b = req.body || {};
  res.json({ request: confirmGrant(getDb(), { ...decisionCtx(req), id: req.params.id, expiresInDays: b.expires_in_days, note: b.note }) });
});

/** POST /api/capability-requests/:id/revoke — end any active grant. { note? } */
router.post('/capability-requests/:id/revoke', requireAuth, requirePlatformAdmin, decisionStepUp, async (req, res) => {
  const out = revokeGrant(getDb(), { ...decisionCtx(req), id: req.params.id, note: req.body?.note });
  await reloadIfNeeded(out.reload);
  res.json({ request: out.grant, effect: out.effect });
});

/** GET /api/capability-approvals/policy — which capabilities require approval. */
router.get('/capability-approvals/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ policy: getPolicy(getDb()) });
});

/** PUT /api/capability-approvals/policy — { <capability>: { approval_required } }. */
router.put('/capability-approvals/policy', requireAuth, requirePlatformAdmin, requireStepUp('security_settings'), (req, res) => {
  res.json({ policy: setPolicy(getDb(), req.body, req.user) });
});

export default router;
