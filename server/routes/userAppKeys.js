import { Router } from 'express';
import { getDb } from '../db.js';
import { generateApiKey, hashApiKey } from '../services/encryption.js';
import { requireAuth } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import log from '../utils/logger.js';

// Mounted at /api/me/app-keys (not bare /api), so this requireAuth only ever
// sees its own paths.
const router = Router();
router.use(requireAuth);

/**
 * Personal app sign-in keys (dhk_uak_*, migration 153), v2.124.0.
 *
 * A user issues one for an app they can already enter. It signs them in to that
 * app's forward_auth gate and is refused everywhere else (middleware/auth.js),
 * so a script on a laptop holds one app's front door instead of the account.
 * The key carries no grant of its own: /api/identity/verify resolves the user's
 * current role on the app at every request.
 *
 * Managed from a session only, like personal MCP keys: a key that could mint
 * keys would let a leaked one reissue itself. (requireAuth already refuses
 * dhk_uak_* callers; this also refuses dhk_mcp_* callers.)
 */
function requireSession(req, res, next) {
  if (req.user_mcp_key) {
    return next(new AppError('Manage app keys from the dashboard, not via an MCP key', 403, 'KEY_FORBIDDEN'));
  }
  next();
}

const MAX_ACTIVE_KEYS = 20;
const DEFAULT_DAYS = 180;
const MAX_DAYS = 365;

/**
 * Apps this user can enter right now, with the same precedence /verify uses:
 * an explicit per-app role, else platform_admin, else a public app as viewer.
 * A key for an app the user cannot enter would only ever be refused.
 */
function enterableApps(user) {
  const db = getDb();
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

/** GET /api/me/app-keys — the caller's app keys, plus the apps a new one could be for. */
router.get('/', requireSession, (req, res) => {
  const keys = getDb().prepare(`
    SELECT k.id, k.label, a.slug AS app_slug, a.name AS app_name,
           k.created_at, k.last_used_at, k.expires_at, k.revoked_at
    FROM user_app_keys k JOIN apps a ON a.id = k.app_id
    WHERE k.user_id = ?
    ORDER BY k.id DESC
  `).all(req.user.id);
  res.json({ keys, apps: enterableApps(req.user).map(({ slug, name }) => ({ slug, name })) });
});

/**
 * POST /api/me/app-keys — issue a key for one app. Plaintext returned ONCE.
 * Body: { app: <slug>, label?, expires_in_days? (1–365, default 180) }
 */
router.post('/', requireSession, auditMiddleware('user-app-key-create'), (req, res) => {
  const { app, label } = req.body || {};
  if (typeof app !== 'string' || !app) throw new AppError('app (the app slug) is required', 400, 'VALIDATION');
  if (label != null && typeof label !== 'string') throw new AppError('label must be a string', 400, 'VALIDATION');
  if (label && label.length > 80) throw new AppError('label must be ≤ 80 chars', 400, 'VALIDATION');
  const days = req.body?.expires_in_days == null ? DEFAULT_DAYS : req.body.expires_in_days;
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) {
    throw new AppError(`expires_in_days must be a whole number from 1 to ${MAX_DAYS}`, 400, 'VALIDATION');
  }

  const target = enterableApps(req.user).find(a => a.slug === app);
  if (!target) throw new AppError('You can only issue a key for an app you can sign in to', 403, 'FORBIDDEN');

  const db = getDb();
  const active = db.prepare(`
    SELECT COUNT(*) AS n FROM user_app_keys
    WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(req.user.id).n;
  if (active >= MAX_ACTIVE_KEYS) {
    throw new AppError(`You already have ${MAX_ACTIVE_KEYS} active app keys; revoke one first`, 409, 'LIMIT');
  }

  const apiKey = generateApiKey('dhk_uak');
  const result = db.prepare(`
    INSERT INTO user_app_keys (user_id, app_id, key_hash, label, expires_at)
    VALUES (?, ?, ?, ?, datetime('now', ?))
  `).run(req.user.id, target.id, hashApiKey(apiKey), label || null, `+${days} days`);
  const row = db.prepare('SELECT expires_at FROM user_app_keys WHERE id = ?').get(result.lastInsertRowid);

  log.info(`UserAppKey: created id=${result.lastInsertRowid} user=${req.user.id} app=${target.slug} days=${days}`);
  res.json({
    key: { id: result.lastInsertRowid, label: label || null, app_slug: target.slug, app_name: target.name, expires_at: row.expires_at },
    api_key: apiKey,
    warning: 'Save this key — it will not be shown again. It signs in to this one app only.',
  });
});

/** DELETE /api/me/app-keys/:id — revoke one of the caller's own keys. */
router.delete('/:id', requireSession, auditMiddleware('user-app-key-revoke'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id) || id <= 0) throw new AppError('Invalid key id', 400, 'VALIDATION');
  const r = getDb().prepare(`
    UPDATE user_app_keys SET revoked_at = datetime('now')
    WHERE id = ? AND user_id = ? AND revoked_at IS NULL
  `).run(id, req.user.id);
  if (!r.changes) throw new AppError('No such active key', 404, 'NOT_FOUND');
  log.info(`UserAppKey: revoked id=${id} user=${req.user.id}`);
  res.json({ revoked: true });
});

export default router;
