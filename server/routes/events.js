import { Router } from 'express';
import { requireAuth, requirePlatformAdmin, requireAppAccess } from '../middleware/auth.js';
import { userHasAppPermission } from '../services/permissions.js';
import { listEvents, getEvent, canSeeEvent, relatedEvents, distinctKinds } from '../services/eventQuery.js';
import { getRetention, setRetention, validRetentionDays, RETENTION_DEFAULTS, RETENTION_MIN_DAYS, RETENTION_MAX_DAYS } from '../services/eventRetention.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';

// The shared event store (services/eventStore.js). Mounted once at '/api', so
// every route carries its own requireAuth: a router.use() here would gate
// every /api request that passes through it.

const router = Router();

// requireAppAccess replaces req.app with the app row, which breaks Express's
// req.query getter, so the query string is parsed here.
const queryOf = (req) => Object.fromEntries(new URL(req.originalUrl || req.url, 'http://local').searchParams);

/** GET /api/events - every event (platform admin). */
router.get('/events', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(listEvents(queryOf(req)));
});

router.get('/events/kinds', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ kinds: distinctKinds() });
});

router.get('/events/retention', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ retention: getRetention(), defaults: RETENTION_DEFAULTS, min_days: RETENTION_MIN_DAYS, max_days: RETENTION_MAX_DAYS });
});

router.put('/events/retention', requireAuth, requirePlatformAdmin, (req, res) => {
  const body = req.body || {};
  const values = {};
  for (const sev of Object.keys(RETENTION_DEFAULTS)) {
    if (body[sev] === undefined) continue;
    const days = validRetentionDays(body[sev]);
    if (days == null) throw new AppError(`${sev} retention must be a whole number of days from ${RETENTION_MIN_DAYS} to ${RETENTION_MAX_DAYS}`, 400, 'VALIDATION');
    values[sev] = days;
  }
  const retention = setRetention(values, req.user.id);
  logAudit(req.user.id, null, 'event-retention-change', { retention });
  res.json({ retention });
});

function visibleEvent(req) {
  const id = Number(req.params.id);
  const ev = Number.isInteger(id) && id > 0 ? getEvent(id) : null;
  if (!ev || !canSeeEvent(req.user, ev)) throw new AppError('Event not found', 404, 'NOT_FOUND');
  return ev;
}

/** GET /api/events/:id - one event the caller may see. */
router.get('/events/:id', requireAuth, (req, res) => {
  res.json({ event: visibleEvent(req) });
});

/** GET /api/events/:id/related - same app or person within ±2h, filtered to what the caller may see. */
router.get('/events/:id/related', requireAuth, (req, res) => {
  const ev = visibleEvent(req);
  res.json({ event: ev, related: relatedEvents(ev, req.user) });
});

/** GET /api/apps/:slug/events - the app's timeline (owner, admin of the app, platform admin). */
router.get('/apps/:slug/events', requireAuth, requireAppAccess, (req, res) => {
  if (!userHasAppPermission(req.user, req.app, 'app.audit.view')) {
    throw new AppError("Viewing this app's events is not permitted by your role", 403, 'FORBIDDEN');
  }
  res.json(listEvents(queryOf(req), { appId: req.app.id }));
});

/** GET /api/me/events - what I did, and what was done to my account. */
router.get('/me/events', requireAuth, (req, res) => {
  res.json(listEvents(queryOf(req), { userId: req.user.id }));
});

export default router;
