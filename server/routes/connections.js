import { Router } from 'express';
import { requireStepUp } from '../services/stepUp.js';
import { requireAuth, requireAppAccess, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { getDb } from '../db.js';
import { roleForUserOnApp } from '../services/permissions.js';
import { connectionHandler } from '../services/connections/gateway.js';
import {
  listConnections, getConnectionRow, publicConnection, createConnection, updateConnection, deleteConnection,
} from '../services/connections/store.js';
import { usageSummary } from '../services/connections/usage.js';
import { activeGrantRows, publicRow } from '../services/capabilities/store.js';
import { CONNECTION_PREFIX } from '../services/capabilities/registry.js';

// Connections gateway (services/connections/*).
//
// default export  /api/service/connections/:name/*   the gateway: service-token
//                                                    auth, internal-only, raw
//                                                    body. Mounted before the
//                                                    global JSON parser.
// adminRouter     /api/connections[...]              register, rotate, delete,
//                                                    usage (platform admin)
// appRouter       /api/apps/:slug/connections        this app's connections,
//                                                    grants and usage (owner,
//                                                    app admin, platform admin)

const service = Router();
service.use('/:name', (req, res, next) => connectionHandler(req, res).catch(next));
export default service;

const queryParam = (req, key) => new URL(req.originalUrl, 'http://local').searchParams.get(key);

export const adminRouter = Router();

adminRouter.get('/', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ connections: listConnections() });
});

adminRouter.post('/', requireAuth, requirePlatformAdmin, requireStepUp('security_settings'), (req, res) => {
  res.status(201).json(createConnection(req.body, req.user));
});

adminRouter.get('/usage', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(usageSummary({ days: queryParam(req, 'days') }));
});

function connectionOr404(name) {
  const r = getConnectionRow(name);
  if (!r) throw new AppError('Connection not found', 404, 'NOT_FOUND');
  return r;
}

adminRouter.get('/:name', requireAuth, requirePlatformAdmin, (req, res) => {
  const r = connectionOr404(req.params.name);
  const grants = getDb().prepare(`SELECT * FROM capability_requests WHERE capability = ? AND status IN ('pending', 'approved') ORDER BY id DESC`)
    .all(CONNECTION_PREFIX + r.name).map((g) => publicRow(getDb(), g));
  res.json({ connection: publicConnection(r), grants });
});

adminRouter.put('/:name', requireAuth, requirePlatformAdmin, requireStepUp('security_settings'), (req, res) => {
  res.json(updateConnection(req.params.name, req.body, req.user));
});

adminRouter.delete('/:name', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json(deleteConnection(req.params.name, req.user));
});

adminRouter.get('/:name/usage', requireAuth, requirePlatformAdmin, (req, res) => {
  const r = connectionOr404(req.params.name);
  res.json(usageSummary({ connection: r.name, days: queryParam(req, 'days') }));
});

export const appRouter = Router();

function requireConnectionViewer(req, _res, next) {
  if (req.user.role === 'platform_admin') return next();
  const tier = roleForUserOnApp(req.user, req.app);
  if (tier !== 'owner' && tier !== 'admin') return next(new AppError('Only an owner or admin of this app can see its connections.', 403, 'FORBIDDEN'));
  next();
}

appRouter.get('/:slug/connections', requireAuth, requireAppAccess, requireConnectionViewer, (req, res) => {
  const db = getDb();
  const connections = listConnections(db).filter((c) => c.enabled).map((c) => ({
    name: c.name, provider: c.provider, description: c.description, capability: c.capability, gateway_path: c.gateway_path,
    forward_identity: c.forward_identity, rate_per_minute: c.rate_per_minute,
    grants: activeGrantRows(db, req.app.id, c.capability).map((g) => publicRow(db, g)),
  }));
  res.json({ app: req.app.slug, connections, usage: usageSummary({ appId: req.app.id, days: queryParam(req, 'days') }, db) });
});
