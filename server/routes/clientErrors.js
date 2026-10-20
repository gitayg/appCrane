import express, { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { clientIp } from '../utils/clientIp.js';
import {
  normalizeReport, recordClientError, listClientErrors, resolveClientError, clearClientErrors,
} from '../services/clientErrors.js';

// Two routers, mounted in two places in index.js:
//
// default (reports): at '/api' BEFORE the global 50 MB express.json(), like
//   /a2a, so the report body is parsed here with its own small cap. It installs
//   no pathless middleware, so anything it does not match falls through.
//   POST /api/client-errors — anyone (the sign-in page has no session), rate-limited.
//
// adminRouter: at '/api/settings/client-errors' in the ordinary route stack
//   (after the API rate limit and the view-as write guard), ahead of the
//   settings router whose GET /:key would otherwise answer for it.
//   GET / — list; DELETE /:id — resolve one; DELETE / — clear. Platform admin.

export const BODY_LIMIT = '8kb';
export const RATE = Object.freeze({ anonPerIp: 20, userPerMin: 30, authedPerIp: 120, windowMs: 60_000 });

const router = Router();
export const adminRouter = Router();
const buckets = new Map();

export function resetClientErrorRateLimit() { buckets.clear(); }

function hit(key, limit, now) {
  const rec = buckets.get(key);
  if (!rec || now > rec.resetAt) { buckets.set(key, { count: 1, resetAt: now + RATE.windowMs }); return true; }
  if (rec.count >= limit) return false;
  rec.count++;
  return true;
}

const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [k, rec] of buckets) if (now > rec.resetAt) buckets.delete(k);
}, 5 * 60_000);
sweeper.unref?.();

function optionalAuth(req, res, next) {
  if (!req.headers['x-api-key'] && !req.headers.authorization) return next();
  requireAuth(req, res, (err) => {
    if (err) req.user = undefined;
    next();
  });
}

const reportBody = express.json({ limit: BODY_LIMIT, type: 'application/json' });

router.post('/client-errors', reportBody, optionalAuth, (req, res) => {
  const now = Date.now();
  const ip = clientIp(req);
  const userId = req.user?.id ?? null;
  const allowed = userId
    ? hit(`u:${userId}`, RATE.userPerMin, now) && hit(`aip:${ip}`, RATE.authedPerIp, now)
    : hit(`ip:${ip}`, RATE.anonPerIp, now);
  if (!allowed) return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many error reports' } });
  const report = normalizeReport(req.body);
  if (!report) return res.status(400).json({ error: { code: 'INVALID_REPORT', message: 'A report needs a message' } });
  recordClientError(report, userId);
  res.status(204).end();
});

adminRouter.get('/', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ errors: listClientErrors() });
});

adminRouter.delete('/:id', requireAuth, requirePlatformAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: { code: 'INVALID_ID', message: 'Invalid id' } });
  const removed = resolveClientError(id);
  if (!removed) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No such error' } });
  res.json({ removed });
});

adminRouter.delete('/', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ removed: clearClientErrors() });
});

router.use((err, req, res, next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: { code: 'TOO_LARGE', message: 'Report too large' } });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'Malformed report' } });
  next(err);
});

export default router;
