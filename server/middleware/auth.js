import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';

/**
 * Authentication middleware. Accepts either:
 *   - `X-API-Key:` header (admin-key flow used by the SPA + CLI)
 *   - `Authorization: Bearer <identity_token>` (portal password / OIDC /
 *     SAML sessions persisted in the identity_sessions table)
 *
 * The Bearer fallback was added so the React panels — which now run
 * embedded in /portal via the IIFE bundle — can call admin-style
 * endpoints (/api/auth/me, etc.) using the portal user's session
 * instead of erroring with "Missing X-API-Key header" → 401.
 */
export function requireAuth(req, res, next) {
  const db = getDb();

  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const user = db.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(hashApiKey(apiKey));
    if (!user) return next(new AppError('Invalid API key', 401, 'UNAUTHORIZED'));
    if (!user.active) return next(new AppError('Account is deactivated', 403, 'DEACTIVATED'));
    req.user = user;
    return next();
  }

  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (bearer) {
    const session = db.prepare(`
      SELECT u.*
      FROM identity_sessions s JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
    `).get(hashApiKey(bearer));
    if (!session) return next(new AppError('Invalid or expired session', 401, 'UNAUTHORIZED'));
    req.user = session;
    return next();
  }

  return next(new AppError('Missing X-API-Key header or Bearer token', 401, 'UNAUTHORIZED'));
}

/**
 * Require admin role.
 */
export function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return next(new AppError('Admin access required', 403, 'FORBIDDEN'));
  }
  next();
}

/**
 * Require user to be assigned to the app (from :slug param).
 * Admin can see app info but NOT env/data routes (enforced separately).
 */
export function requireAppAccess(req, res, next) {
  const { slug } = req.params;
  const db = getDb();

  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) {
    return next(new AppError(`App '${slug}' not found`, 404, 'NOT_FOUND'));
  }

  req.app = app;

  // Admin can access app info (but not env/data - enforced in those routes)
  if (req.user.role === 'admin') {
    return next();
  }

  // Check if user is assigned to this app
  const assignment = db.prepare(
    'SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?'
  ).get(app.id, req.user.id);

  if (!assignment) {
    return next(new AppError('You are not assigned to this app', 403, 'FORBIDDEN'));
  }

  next();
}

/**
 * Require app user (NOT admin) - for env vars, data, deploy operations.
 * This enforces the "admin cannot access data/env" rule.
 */
export function requireAppUser(req, res, next) {
  const { slug } = req.params;
  const db = getDb();

  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) {
    return next(new AppError(`App '${slug}' not found`, 404, 'NOT_FOUND'));
  }

  req.app = app;

  // Admin explicitly blocked from env/data/deploy operations
  if (req.user.role === 'admin') {
    return next(new AppError('Admin cannot access app data/env. Assign yourself as an app user first.', 403, 'ADMIN_BLOCKED'));
  }

  const assignment = db.prepare(
    'SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?'
  ).get(app.id, req.user.id);

  if (!assignment) {
    return next(new AppError('You are not assigned to this app', 403, 'FORBIDDEN'));
  }

  next();
}
