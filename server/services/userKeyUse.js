import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { auditExpiredUse, expiredMessage, expireUserKey, isPast } from './apiKeyExpiry.js';

// users.api_key_last_used_at is what tells a used personal key from a never-used
// one, so every route that accepts a personal key records it here: requireAuth
// and each route with its own key fallback (Ask, Plan, coder, enhancements,
// /api/me, set-password, the forward_auth verify). Stamped at most once an hour
// per user to keep it off the hot path.
export function recordUserKeyUse(userId, db = getDb()) {
  try {
    db.prepare("UPDATE users SET api_key_last_used_at = datetime('now') WHERE id = ? AND (api_key_last_used_at IS NULL OR api_key_last_used_at < datetime('now', '-1 hour'))").run(userId);
  } catch (_) {}
}

/**
 * The checks requireAuth makes on a matched personal key, for the routes that
 * match one with their own lookup: a deactivated account is refused, and an
 * expired key is refused and moved aside then, not at the next expiry sweep.
 */
export function assertUserKeyUsable(req, userId, db = getDb()) {
  const u = db.prepare('SELECT active, api_key_expires_at FROM users WHERE id = ?').get(userId);
  if (!u) throw new AppError('Invalid API key', 401, 'UNAUTHORIZED');
  if (!u.active) throw new AppError('Account is deactivated', 403, 'DEACTIVATED');
  if (u.api_key_expires_at && isPast(u.api_key_expires_at)) {
    try { expireUserKey(db, userId); } catch (_) {}
    auditExpiredUse(userId, 'user', userId, u.api_key_expires_at, req.ip);
    throw new AppError(expiredMessage(u.api_key_expires_at), 401, 'API_KEY_EXPIRED');
  }
}
