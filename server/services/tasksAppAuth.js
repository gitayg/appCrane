// Authenticates a hosted app on the Tasks API (/api/service/tasks/*).
//
// The app is identified by its APPCRANE_SERVICE_TOKEN (X-AppCrane-Service-Token)
// and by nothing else: no slug, app id or identity header it sends is read.
// The token is the per-app service credential the deployer already injects
// (appServiceToken.js: SHA-256 for lookup, AES-GCM for re-injection). It dies
// with the app row, and issueServiceToken() replaces it. requireAuth does not
// know it, so it opens no other /api route; Caddy 404s /api/service* on the
// public domain, and this refuses a request that came through a proxy anyway.

import { AppError } from '../utils/errors.js';
import { appForServiceToken } from './appServiceToken.js';

export function requireTasksApp(req, res, next) {
  if (req.headers['via'] || req.headers['x-forwarded-host'] || req.headers['x-forwarded-for']) {
    return next(new AppError('This endpoint is reachable only from an app container, not the public domain.', 403, 'NOT_INTERNAL'));
  }
  const token = (req.headers['x-appcrane-service-token'] || '').toString().trim();
  const app = appForServiceToken(token);
  if (!app) return next(new AppError('Invalid or missing X-AppCrane-Service-Token', 401, 'BAD_SERVICE_TOKEN'));
  req.tasksApp = app;
  next();
}
