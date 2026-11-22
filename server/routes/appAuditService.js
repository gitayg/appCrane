import express, { Router } from 'express';
import { AppError } from '../utils/errors.js';
import { requireTasksApp } from '../services/tasksAppAuth.js';
import { recordAppEvent } from '../services/appAudit/store.js';

// POST /api/service/audit/events: a hosted app's server writes one audit event.
// Authenticated by the app's APPCRANE_SERVICE_TOKEN only (requireTasksApp: the
// token resolves the app, nothing in the request can name another one, a user
// API key is not a service token, and a request that came through the public
// proxy is refused). Mounted before the 50 MB JSON parser with its own 32 KB
// limit.

export const RATE_PER_MINUTE = 600;
const windows = new Map();

function rateLimited(appId, now = Date.now()) {
  const minute = Math.floor(now / 60_000);
  const w = windows.get(appId);
  if (!w || w.minute !== minute) { windows.set(appId, { minute, n: 1 }); return false; }
  w.n += 1;
  return w.n > RATE_PER_MINUTE;
}

export function _resetAppAuditRateForTests() { windows.clear(); }

const router = Router();

router.post('/events', requireTasksApp, express.json({ limit: '32kb' }), (req, res) => {
  const app = req.tasksApp;
  if (rateLimited(app.id)) {
    res.setHeader('Retry-After', String(60 - Math.floor((Date.now() % 60_000) / 1000)));
    throw new AppError(`More than ${RATE_PER_MINUTE} audit events a minute from this app`, 429, 'RATE_LIMITED');
  }
  const header = req.headers['idempotency-key'];
  let out;
  try {
    out = recordAppEvent(app, req.body, { idempotencyHeader: typeof header === 'string' ? header : null });
  } catch (e) {
    if (e.status) throw new AppError(e.message, e.status, e.code);
    throw e;
  }
  res.status(out.status).json({ event: out.event, deduped: out.deduped });
});

export default router;
