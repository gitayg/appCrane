import { Router } from 'express';
import { requireAuth, requireAppUser } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { isAppOwnerOrPlatformAdmin } from '../services/permissions.js';
import {
  ConnectionError, createConnection, deleteConnection, listConnections, publicView, updateConnection,
} from '../services/externalSecrets/connections.js';

// One app's own connections to outside secret stores. Assigned app users see
// which connections the app can reference (its own and the platform's, names
// only for the latter); only the owner (or an assigned platform admin) changes
// them. The rows are keyed on req.app.id, so an id from another app is a 404.
const router = Router();

const ownerOnly = (req) => {
  if (!isAppOwnerOrPlatformAdmin(req.user, req.app)) throw new AppError('Only the app owner can change its secret store connections', 403, 'FORBIDDEN');
};
const wrap = (fn) => (req, res) => {
  try { return fn(req, res); } catch (e) {
    if (e instanceof ConnectionError) throw new AppError(e.message, e.status, e.code);
    throw e;
  }
};
const idOf = (req) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) throw new AppError('invalid connection id', 400, 'VALIDATION');
  return id;
};

router.get('/:slug/secret-connections', requireAuth, requireAppUser, (req, res) => {
  const owner = isAppOwnerOrPlatformAdmin(req.user, req.app);
  res.json({
    connections: listConnections(req.app.id).map((r) => publicView(r, { detail: owner })),
    platform: listConnections(null).map((r) => publicView(r, { detail: false })),
  });
});

router.post('/:slug/secret-connections', requireAuth, requireAppUser, wrap((req, res) => {
  ownerOnly(req);
  const { name, provider, settings, credentials } = req.body || {};
  const row = createConnection({ appId: req.app.id, name, provider, settings, credentials, userId: req.user.id });
  logAudit(req.user.id, req.app.id, 'secret-connection-create', { id: row.id, name: row.name, provider: row.provider, scope: 'app' });
  res.status(201).json({ connection: publicView(row) });
}));

router.patch('/:slug/secret-connections/:id', requireAuth, requireAppUser, wrap((req, res) => {
  ownerOnly(req);
  const { settings, credentials } = req.body || {};
  const row = updateConnection(req.app.id, idOf(req), { settings, credentials });
  logAudit(req.user.id, req.app.id, 'secret-connection-update', { id: row.id, name: row.name, provider: row.provider, scope: 'app', credentials_changed: credentials !== undefined });
  res.json({ connection: publicView(row) });
}));

router.delete('/:slug/secret-connections/:id', requireAuth, requireAppUser, wrap((req, res) => {
  ownerOnly(req);
  const row = deleteConnection(req.app.id, idOf(req));
  logAudit(req.user.id, req.app.id, 'secret-connection-delete', { id: row.id, name: row.name, provider: row.provider, scope: 'app' });
  res.json({ deleted: row.id });
}));

export default router;
