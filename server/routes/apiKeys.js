import { Router } from 'express';
import { getDb } from '../db.js';
import { generateApiKey, hashApiKey } from '../services/encryption.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { getPolicy, maxAgeDays, sqliteToIso, updatePolicy, isPast, isExpiredHash } from '../services/apiKeyExpiry.js';
import log from '../utils/logger.js';
import { revokeAllGrantsForUser } from '../services/oauthStore.js';
import { privateApiStatus } from '../utils/ingress.js';

const router = Router();

// The caller's own user API key (dhk_user_* / dhk_admin_*): when it expires,
// and rotation. MCP keys and OAuth tokens cannot manage it, the same rule as
// personal MCP keys (userMcpKeys.js), so a leaked MCP credential cannot turn
// itself into a REST key.
function refuseMcpCredential(req, res, next) {
  if (req.user_mcp_key) return next(new AppError('Manage your API key from the dashboard, not via an MCP key or OAuth token', 403, 'KEY_FORBIDDEN'));
  next();
}

function keyState(db, userId) {
  const u = db.prepare(`SELECT api_key_hash, api_key_expired_hash, api_key_issued_at, api_key_expires_at, api_key_last_used_at
                          FROM users WHERE id = ?`).get(userId);
  if (!u) return null;
  if (!u.api_key_hash) {
    return { has_key: false, expired: false, issued_at: null, expires_at: null, last_used_at: null, max_age_days: maxAgeDays(db) };
  }
  return {
    has_key: true,
    expired: isExpiredHash(u.api_key_hash) || (!!u.api_key_expires_at && isPast(u.api_key_expires_at)),
    issued_at: sqliteToIso(u.api_key_issued_at),
    expires_at: sqliteToIso(u.api_key_expires_at),
    last_used_at: sqliteToIso(u.api_key_last_used_at),
    max_age_days: maxAgeDays(db),
  };
}

/** GET /api/me/api-key: expiry of the caller's own API key. Never the key. */
router.get('/me/api-key', requireAuth, refuseMcpCredential, (req, res) => {
  const state = keyState(getDb(), (req.real_user || req.user).id);
  if (!state) throw new AppError('User not found', 404, 'NOT_FOUND');
  res.json(state);
});

/**
 * POST /api/me/api-key/rotate: issue a new API key for the caller, shown once;
 * the old one stops working immediately (no grace period: a rotation is often
 * a response to a leak, and a grace period is a window for whoever has it).
 *
 * Accounts are created without a key (SSO, SCIM and admin-created people), so
 * for a caller who has none this is how they create their first one: same
 * response, audited as user-api-key-create instead of user-api-key-rotate, and
 * nothing else is revoked because there was no old key to leak. The expiry is
 * stamped by trg_users_api_key_rotate, which fires on NULL -> key too.
 *
 * Accepted from a dashboard session or the caller's own (unexpired) API key. A
 * key-only account (the CLI, the admin SPA signed in by key) has no other
 * credential to rotate with, so refusing the key itself would strand it at
 * expiry. Once expired, the owner signs in by password or SSO to rotate, or
 * an admin regenerates it.
 */
function auditCreateOrRotate(req, res, next) {
  const row = getDb().prepare('SELECT api_key_hash FROM users WHERE id = ?').get((req.real_user || req.user).id);
  req.api_key_first = !row?.api_key_hash;
  return auditMiddleware(req.api_key_first ? 'user-api-key-create' : 'user-api-key-rotate')(req, res, next);
}

router.post('/me/api-key/rotate', requireAuth, refuseMcpCredential, auditCreateOrRotate, (req, res) => {
  const db = getDb();
  const user = db.prepare('SELECT id, role, active, api_key_hash FROM users WHERE id = ?').get((req.real_user || req.user).id);
  if (!user || !user.active) throw new AppError('Account is deactivated', 403, 'DEACTIVATED');
  const first = !user.api_key_hash;
  const apiKey = generateApiKey(user.role === 'platform_admin' ? 'dhk_admin' : 'dhk_user');
  db.prepare('UPDATE users SET api_key_hash = ? WHERE id = ?').run(hashApiKey(apiKey), user.id);
  if (!first) revokeAllGrantsForUser(user.id);
  log.info(`UserApiKey: ${first ? 'created' : 'rotated'} user=${user.id}`);
  res.json({
    api_key: apiKey,
    created: first,
    ...keyState(db, user.id),
    warning: first
      ? 'Save this API key. It will not be shown again.'
      : 'Save this API key. It will not be shown again. The previous key no longer works.',
  });
});

/** GET /api/api-key-policy: the expiry window, the MCP OAuth-only toggle and the private API port. */
router.get('/api-key-policy', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const policy = getPolicy(db);
  const ids = policy.mcp_oauth_only_exempt_user_ids;
  const exempt = ids.length
    ? db.prepare(`SELECT id, name, email FROM users WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids)
    : [];
  // private_api: APPCRANE_PRIVATE_API_PORT (.env), read-only here.
  res.json({ ...policy, exempt_users: exempt, private_api: privateApiStatus() });
});

/** PUT /api/api-key-policy: { max_age_days?, mcp_oauth_only?, mcp_oauth_only_exempt_user_ids? } */
router.put('/api-key-policy', requireAuth, requirePlatformAdmin, auditMiddleware('api-key-policy-update'), (req, res) => {
  if (req.user_mcp_key) throw new AppError('Change the API key policy from the dashboard', 403, 'KEY_FORBIDDEN');
  try {
    res.json(updatePolicy(getDb(), req.body || {}, req.user.id));
  } catch (e) {
    if (e.status === 400) throw new AppError(e.message, 400, 'VALIDATION');
    throw e;
  }
});

export default router;
