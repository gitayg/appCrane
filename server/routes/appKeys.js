import { Router } from 'express';
import { getDb } from '../db.js';
import { generateApiKey, hashApiKey } from '../services/encryption.js';
import { requireAuth } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { isAdmin } from '../utils/roles.js';
import log from '../utils/logger.js';

const router = Router();
router.use(requireAuth);

const VALID_SCOPES = ['read', 'deploy', 'full'];

/**
 * Resolve the app from :slug and verify the caller is an Owner of it
 * (or AppCrane global admin). Used by every key-management endpoint —
 * issuing or rotating an app-scoped key is reserved to Owners.
 */
function requireAppOwner(req, res, next) {
  const db = getDb();
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(req.params.slug);
  if (!app) return next(new AppError(`App '${req.params.slug}' not found`, 404, 'NOT_FOUND'));
  req.app = app;

  // App-scoped keys cannot manage other app-scoped keys (avoid loops where
  // a CI key issues a new CI key). Routes are operator-only.
  if (req.app_key) {
    return next(new AppError('App-scoped keys cannot manage keys. Sign in as a user.', 403, 'KEY_FORBIDDEN'));
  }

  if (isAdmin(req.user)) return next();

  const role = db.prepare(
    "SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?"
  ).get(app.id, req.user.id);
  if (role?.app_role === 'owner') return next();
  return next(new AppError('Only the app Owner can manage app keys', 403, 'FORBIDDEN'));
}

/**
 * GET /api/apps/:slug/keys — list keys (no plaintext, never)
 */
router.get('/:slug/keys', requireAppOwner, (req, res) => {
  const db = getDb();
  const keys = db.prepare(`
    SELECT k.id, k.label, k.scope, k.created_at, k.last_used_at, k.expires_at, k.revoked_at,
           u.name AS created_by_name, u.email AS created_by_email
    FROM app_keys k
    LEFT JOIN users u ON u.id = k.created_by
    WHERE k.app_id = ?
    ORDER BY k.id DESC
  `).all(req.app.id);
  res.json({ keys });
});

/**
 * POST /api/apps/:slug/keys — create a new key. Returns plaintext ONCE.
 * Body: { label?: string, scope?: 'read' | 'deploy' | 'full', expires_at?: ISO string }
 */
router.post('/:slug/keys', requireAppOwner, auditMiddleware('app-key-create'), (req, res) => {
  const { label, scope = 'full', expires_at } = req.body || {};
  if (!VALID_SCOPES.includes(scope)) {
    throw new AppError(`scope must be one of: ${VALID_SCOPES.join(', ')}`, 400, 'VALIDATION');
  }
  if (label && typeof label !== 'string') throw new AppError('label must be a string', 400, 'VALIDATION');
  if (label && label.length > 80) throw new AppError('label must be ≤ 80 chars', 400, 'VALIDATION');
  if (expires_at && Number.isNaN(Date.parse(expires_at))) {
    throw new AppError('expires_at must be a valid ISO datetime', 400, 'VALIDATION');
  }

  const apiKey = generateApiKey(`dhk_app_${req.app.slug}`);
  const keyHash = hashApiKey(apiKey);

  const db = getDb();
  const result = db.prepare(`
    INSERT INTO app_keys (app_id, key_hash, label, scope, created_by, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(req.app.id, keyHash, label || null, scope, req.user.id, expires_at || null);

  log.info(`AppKey: created id=${result.lastInsertRowid} app=${req.app.slug} scope=${scope} by user=${req.user.id}`);
  res.json({
    key: {
      id: result.lastInsertRowid,
      label: label || null,
      scope,
      app_slug: req.app.slug,
      expires_at: expires_at || null,
    },
    api_key: apiKey,
    warning: 'Save this API key — it will not be shown again.',
  });
});

/**
 * POST /api/apps/:slug/keys/:id/rotate — issue a new plaintext, invalidate old hash.
 * Returns plaintext ONCE.
 */
router.post('/:slug/keys/:id/rotate', requireAppOwner, auditMiddleware('app-key-rotate'), (req, res) => {
  const keyId = parseInt(req.params.id, 10);
  const db = getDb();
  const existing = db.prepare('SELECT * FROM app_keys WHERE id = ? AND app_id = ?').get(keyId, req.app.id);
  if (!existing) throw new AppError('Key not found', 404, 'NOT_FOUND');
  if (existing.revoked_at) throw new AppError('Cannot rotate a revoked key — create a new one instead', 400, 'KEY_REVOKED');

  const apiKey = generateApiKey(`dhk_app_${req.app.slug}`);
  const keyHash = hashApiKey(apiKey);
  db.prepare('UPDATE app_keys SET key_hash = ?, last_used_at = NULL WHERE id = ?').run(keyHash, keyId);

  log.info(`AppKey: rotated id=${keyId} app=${req.app.slug} by user=${req.user.id}`);
  res.json({
    key: {
      id: keyId,
      label: existing.label,
      scope: existing.scope,
      app_slug: req.app.slug,
    },
    api_key: apiKey,
    warning: 'Save this API key — it will not be shown again. The previous key is now invalid.',
  });
});

/**
 * DELETE /api/apps/:slug/keys/:id — revoke. Sets revoked_at; the row is kept
 * for audit trail. Revoked keys never authenticate.
 */
router.delete('/:slug/keys/:id', requireAppOwner, auditMiddleware('app-key-revoke'), (req, res) => {
  const keyId = parseInt(req.params.id, 10);
  const db = getDb();
  const existing = db.prepare('SELECT * FROM app_keys WHERE id = ? AND app_id = ?').get(keyId, req.app.id);
  if (!existing) throw new AppError('Key not found', 404, 'NOT_FOUND');
  if (existing.revoked_at) return res.json({ message: 'Already revoked', id: keyId });

  db.prepare("UPDATE app_keys SET revoked_at = datetime('now') WHERE id = ?").run(keyId);
  log.info(`AppKey: revoked id=${keyId} app=${req.app.slug} by user=${req.user.id}`);
  res.json({ message: 'Key revoked', id: keyId });
});

export default router;
