import { Router } from 'express';
import { requireStepUp } from '../services/stepUp.js';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { enterableApps, listKeys, issueKey, revokeKey } from '../services/userAppKeys.js';

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

/** GET /api/me/app-keys — the caller's app keys, plus the apps a new one could be for. */
router.get('/', requireSession, (req, res) => {
  const db = getDb();
  res.json({ keys: listKeys(db, req.user.id), apps: enterableApps(db, req.user).map(({ slug, name }) => ({ slug, name })) });
});

/**
 * POST /api/me/app-keys — issue a key for one app. Plaintext returned ONCE.
 * Body: { app: <slug>, label?, expires_in_days? (1–365, default 180) }
 */
router.post('/', requireSession, requireStepUp('manage_api_keys'), auditMiddleware('user-app-key-create'), (req, res) => {
  const { app, label } = req.body || {};
  const { key, api_key } = issueKey(getDb(), req.user, { app, label, expiresInDays: req.body?.expires_in_days });
  res.json({ key, api_key, warning: 'Save this key — it will not be shown again. It signs in to this one app only.' });
});

/** DELETE /api/me/app-keys/:id — revoke one of the caller's own keys. */
router.delete('/:id', requireSession, auditMiddleware('user-app-key-revoke'), (req, res) => {
  revokeKey(getDb(), req.user.id, req.params.id);
  res.json({ revoked: true });
});

export default router;
