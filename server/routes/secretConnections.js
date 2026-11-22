import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import {
  ConnectionError, createConnection, deleteConnection, listConnections, publicView, updateConnection,
} from '../services/externalSecrets/connections.js';

// Platform connections to outside secret stores (Vault, Infisical, 1Password,
// AWS SSM): usable by every app's references. Credentials go in and never come
// back out; the audit row holds the name and provider only.
const router = Router();

router.use(requireAuth, requirePlatformAdmin);

const wrap = (fn) => (req, res) => {
  try { return fn(req, res); } catch (e) {
    if (e instanceof ConnectionError) throw new AppError(e.message, e.status, e.code);
    throw e;
  }
};
// Which apps the connection is open to: the part of a platform connection worth an audit trail.
const scopeOf = (row) => {
  const { path_prefix: pathPrefix = null, allowed_apps: allowedApps = null } = publicView(row).settings;
  return { path_prefix: pathPrefix, allowed_apps: allowedApps };
};
const idOf = (req) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) throw new AppError('invalid connection id', 400, 'VALIDATION');
  return id;
};

router.get('/', (req, res) => {
  res.json({ connections: listConnections(null).map((r) => publicView(r)) });
});

router.post('/', wrap((req, res) => {
  const { name, provider, settings, credentials } = req.body || {};
  const row = createConnection({ appId: null, name, provider, settings, credentials, userId: req.user.id });
  logAudit(req.user.id, null, 'secret-connection-create', { id: row.id, name: row.name, provider: row.provider, scope: 'platform', ...scopeOf(row) });
  res.status(201).json({ connection: publicView(row) });
}));

router.patch('/:id', wrap((req, res) => {
  const { settings, credentials } = req.body || {};
  const row = updateConnection(null, idOf(req), { settings, credentials });
  logAudit(req.user.id, null, 'secret-connection-update', { id: row.id, name: row.name, provider: row.provider, scope: 'platform', ...scopeOf(row), credentials_changed: credentials !== undefined });
  res.json({ connection: publicView(row) });
}));

router.delete('/:id', wrap((req, res) => {
  const row = deleteConnection(null, idOf(req));
  logAudit(req.user.id, null, 'secret-connection-delete', { id: row.id, name: row.name, provider: row.provider, scope: 'platform' });
  res.json({ deleted: row.id });
}));

export default router;
