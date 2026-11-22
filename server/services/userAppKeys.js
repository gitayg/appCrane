// Personal app sign-in keys (dhk_uak_*, migration 153): the store behind
// /api/me/app-keys (routes/userAppKeys.js) and the app-keys widget
// (routes/widgets.js). Every read and write is the caller's own user id.

import { generateApiKey, hashApiKey } from './encryption.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';

export const MAX_ACTIVE_KEYS = 20;
export const DEFAULT_DAYS = 180;
export const MAX_DAYS = 365;

/**
 * Apps this user can enter right now, with the same precedence /verify uses:
 * an explicit per-app role, else platform_admin, else a public app as viewer.
 * A key for an app the user cannot enter would only ever be refused.
 */
export function enterableApps(db, user) {
  if (user.role === 'platform_admin') {
    return db.prepare('SELECT id, slug, name FROM apps ORDER BY name').all();
  }
  return db.prepare(`
    SELECT a.id, a.slug, a.name FROM apps a
    LEFT JOIN app_user_roles r ON r.app_id = a.id AND r.user_id = ?
    WHERE (r.app_role IS NOT NULL AND r.app_role != 'none')
       OR (r.app_role IS NULL AND a.visibility = 'public')
    ORDER BY a.name
  `).all(user.id);
}

export function listKeys(db, userId, appId = null) {
  return db.prepare(`
    SELECT k.id, k.label, a.slug AS app_slug, a.name AS app_name,
           k.created_at, k.last_used_at, k.expires_at, k.revoked_at
    FROM user_app_keys k JOIN apps a ON a.id = k.app_id
    WHERE k.user_id = ? AND (? IS NULL OR k.app_id = ?)
    ORDER BY k.id DESC
  `).all(userId, appId, appId);
}

/** Issue a key for one app. Returns { key, api_key }; the plaintext exists only here. */
export function issueKey(db, user, { app, label, expiresInDays, maxDays = MAX_DAYS }) {
  if (typeof app !== 'string' || !app) throw new AppError('app (the app slug) is required', 400, 'VALIDATION');
  if (label != null && typeof label !== 'string') throw new AppError('label must be a string', 400, 'VALIDATION');
  if (label && label.length > 80) throw new AppError('label must be ≤ 80 chars', 400, 'VALIDATION');
  const days = expiresInDays == null ? Math.min(DEFAULT_DAYS, maxDays) : expiresInDays;
  if (!Number.isInteger(days) || days < 1 || days > maxDays) {
    throw new AppError(`expires_in_days must be a whole number from 1 to ${maxDays}`, 400, 'VALIDATION');
  }

  const target = enterableApps(db, user).find(a => a.slug === app);
  if (!target) throw new AppError('You can only issue a key for an app you can sign in to', 403, 'FORBIDDEN');

  const active = db.prepare(`
    SELECT COUNT(*) AS n FROM user_app_keys
    WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(user.id).n;
  if (active >= MAX_ACTIVE_KEYS) {
    throw new AppError(`You already have ${MAX_ACTIVE_KEYS} active app keys; revoke one first`, 409, 'LIMIT');
  }

  const apiKey = generateApiKey('dhk_uak');
  const result = db.prepare(`
    INSERT INTO user_app_keys (user_id, app_id, key_hash, label, expires_at)
    VALUES (?, ?, ?, ?, datetime('now', ?))
  `).run(user.id, target.id, hashApiKey(apiKey), label || null, `+${days} days`);
  const row = db.prepare('SELECT expires_at FROM user_app_keys WHERE id = ?').get(result.lastInsertRowid);

  log.info(`UserAppKey: created id=${result.lastInsertRowid} user=${user.id} app=${target.slug} days=${days}`);
  return {
    key: { id: result.lastInsertRowid, label: label || null, app_slug: target.slug, app_name: target.name, expires_at: row.expires_at },
    api_key: apiKey,
  };
}

/** Revoke one of the user's own active keys (optionally only one for appId). */
export function revokeKey(db, userId, rawId, appId = null) {
  const id = parseInt(rawId, 10);
  if (!Number.isFinite(id) || id <= 0) throw new AppError('Invalid key id', 400, 'VALIDATION');
  const r = db.prepare(`
    UPDATE user_app_keys SET revoked_at = datetime('now')
    WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND (? IS NULL OR app_id = ?)
  `).run(id, userId, appId, appId);
  if (!r.changes) throw new AppError('No such active key', 404, 'NOT_FOUND');
  log.info(`UserAppKey: revoked id=${id} user=${userId}`);
}
