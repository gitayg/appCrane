import { Router } from 'express';
import { getDb } from '../db.js';
import { generateApiKey, hashApiKey } from '../services/encryption.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { isAdmin } from '../utils/roles.js';
import log from '../utils/logger.js';

const router = Router();
router.use(requireAuth);

/**
 * Personal MCP keys are self-issued by any logged-in user. They grant
 * MCP-only access; at call time the key's accessibility resolves to
 * "every app where the issuing user is currently Owner."
 *
 * Personal MCP keys cannot manage other personal MCP keys (avoids loops
 * where a leaked key reissues itself). Routes refuse req.user_mcp_key
 * callers — the operator must use a session login or an admin API key.
 */
function requireSession(req, res, next) {
  if (req.user_mcp_key) {
    return next(new AppError('Manage personal keys from the dashboard, not via an MCP key', 403, 'KEY_FORBIDDEN'));
  }
  next();
}

/**
 * Parse the optional `read_only` flag off a key-issuing body.
 *
 * A read-only key still authenticates as its issuer and reaches the same apps —
 * it just cannot call any MCP tool that changes state (deploy, set secret,
 * grant roles, push files). That gate lives in the MCP dispatcher; this is only
 * the switch. Omitted/false keeps the historical all-or-nothing behaviour, so
 * nothing changes for callers that never send the field.
 */
function parseReadOnly(body) {
  const v = (body || {}).read_only;
  if (v == null) return 0;
  if (typeof v !== 'boolean') throw new AppError('read_only must be a boolean', 400, 'VALIDATION');
  return v ? 1 : 0;
}

/**
 * Count of apps this user can reach via a personal MCP key. AppCrane global
 * admins see every app; everyone else only sees apps where they're Owner.
 * Mirrors the resolution in mcpTools.js → accessibleSlugsForUser.
 */
function accessibleAppCount(user) {
  const db = getDb();
  if (isAdmin(user)) {
    return db.prepare('SELECT COUNT(*) AS n FROM apps').get().n;
  }
  return db.prepare(`
    SELECT COUNT(*) AS n FROM app_user_roles
    WHERE user_id = ? AND app_role = 'owner'
  `).get(user.id).n;
}

/**
 * GET /api/me/mcp-keys — list current user's personal MCP keys
 */
router.get('/me/mcp-keys', requireSession, (req, res) => {
  const db = getDb();
  const keys = db.prepare(`
    SELECT id, label, created_at, last_used_at, expires_at, revoked_at, read_only
    FROM user_mcp_keys
    WHERE user_id = ?
    ORDER BY id DESC
  `).all(req.user.id);
  res.json({
    keys,
    accessible_app_count: accessibleAppCount(req.user),
    is_admin: isAdmin(req.user),
  });
});

/**
 * POST /api/me/mcp-keys — issue a new key. Plaintext returned ONCE.
 */
router.post('/me/mcp-keys', requireSession, auditMiddleware('user-mcp-key-create'), (req, res) => {
  const { label, expires_at } = req.body || {};
  if (label && typeof label !== 'string') throw new AppError('label must be a string', 400, 'VALIDATION');
  if (label && label.length > 80) throw new AppError('label must be ≤ 80 chars', 400, 'VALIDATION');
  if (expires_at && Number.isNaN(Date.parse(expires_at))) {
    throw new AppError('expires_at must be a valid ISO datetime', 400, 'VALIDATION');
  }
  const readOnly = parseReadOnly(req.body);

  const apiKey = generateApiKey('dhk_mcp');
  const keyHash = hashApiKey(apiKey);
  const db = getDb();
  const result = db.prepare(`
    INSERT INTO user_mcp_keys (user_id, key_hash, label, expires_at, read_only)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.user.id, keyHash, label || null, expires_at || null, readOnly);

  log.info(`UserMcpKey: created id=${result.lastInsertRowid} user=${req.user.id} read_only=${readOnly}`);
  res.json({
    key: {
      id: result.lastInsertRowid, label: label || null, expires_at: expires_at || null,
      read_only: readOnly,
    },
    api_key: apiKey,
    warning: 'Save this API key — it will not be shown again.',
    accessible_app_count: accessibleAppCount(req.user),
    is_admin: isAdmin(req.user),
  });
});

/**
 * POST /api/users/:id/mcp-keys — admin-side: issue an MCP key on behalf of
 * another user. Lets an operator hand out an MCP key without that user
 * needing to log into the dashboard first.
 *
 * The key is bound to the target user's identity — when called, the MCP
 * server resolves it to that user's apps + role, exactly the same as if
 * the user had created it themselves via /api/me/mcp-keys.
 *
 * Auth: requireAuth + requireAdmin (enforced via the middleware imports).
 * Body: { label?, expires_at? } — same shape as the self-issue endpoint.
 */
router.post('/users/:id/mcp-keys', requireAdmin, auditMiddleware('user-mcp-key-create-admin'), (req, res) => {
  if (req.user_mcp_key) {
    throw new AppError('Issuing keys for other users requires a session, not an MCP key', 403, 'KEY_FORBIDDEN');
  }
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isFinite(targetId) || targetId <= 0) {
    throw new AppError('Invalid user id', 400, 'VALIDATION');
  }
  const { label, expires_at } = req.body || {};
  if (label && typeof label !== 'string') throw new AppError('label must be a string', 400, 'VALIDATION');
  if (label && label.length > 80) throw new AppError('label must be ≤ 80 chars', 400, 'VALIDATION');
  if (expires_at && Number.isNaN(Date.parse(expires_at))) {
    throw new AppError('expires_at must be a valid ISO datetime', 400, 'VALIDATION');
  }

  const readOnly = parseReadOnly(req.body);

  const db = getDb();
  const target = db.prepare('SELECT id, name, email, active FROM users WHERE id = ?').get(targetId);
  if (!target) throw new AppError('User not found', 404, 'NOT_FOUND');
  if (!target.active) throw new AppError('Cannot issue keys for a deactivated user', 400, 'USER_INACTIVE');

  const apiKey = generateApiKey('dhk_mcp');
  const keyHash = hashApiKey(apiKey);
  const result = db.prepare(`
    INSERT INTO user_mcp_keys (user_id, key_hash, label, expires_at, read_only)
    VALUES (?, ?, ?, ?, ?)
  `).run(targetId, keyHash, label || `issued-by-admin-${req.user.id}`, expires_at || null, readOnly);

  log.info(`UserMcpKey: admin id=${req.user.id} issued key id=${result.lastInsertRowid} for user id=${targetId} read_only=${readOnly}`);
  res.json({
    key: {
      id: result.lastInsertRowid, label: label || null, expires_at: expires_at || null,
      read_only: readOnly,
    },
    api_key: apiKey,
    target: { id: target.id, name: target.name, email: target.email },
    warning: 'Save this API key — it will not be shown again. Send it to the user via a secure channel.',
  });
});

/**
 * POST /api/me/mcp-keys/:id/rotate — issue a new plaintext for an existing key,
 * invalidating the old hash. Useful when a key may have leaked.
 *
 * Deliberately does not accept `read_only`: rotation replaces the secret, not
 * the capability. Widening a read-only key to full access has to be a new key,
 * so "rotate the key I pasted into that agent" can never quietly hand that
 * agent deploy and secret-write rights.
 */
router.post('/me/mcp-keys/:id/rotate', requireSession, auditMiddleware('user-mcp-key-rotate'), (req, res) => {
  const keyId = parseInt(req.params.id, 10);
  const db = getDb();
  const existing = db.prepare('SELECT * FROM user_mcp_keys WHERE id = ? AND user_id = ?').get(keyId, req.user.id);
  if (!existing) throw new AppError('Key not found', 404, 'NOT_FOUND');
  if (existing.revoked_at) throw new AppError('Cannot rotate a revoked key — create a new one instead', 400, 'KEY_REVOKED');

  const apiKey = generateApiKey('dhk_mcp');
  const keyHash = hashApiKey(apiKey);
  db.prepare('UPDATE user_mcp_keys SET key_hash = ?, last_used_at = NULL WHERE id = ?').run(keyHash, keyId);

  log.info(`UserMcpKey: rotated id=${keyId} user=${req.user.id}`);
  res.json({
    key: { id: keyId, label: existing.label, read_only: existing.read_only },
    api_key: apiKey,
    warning: 'Save this API key — it will not be shown again. The previous value is now invalid.',
  });
});

/**
 * DELETE /api/me/mcp-keys/:id — revoke. Soft-delete (keeps row for audit).
 */
router.delete('/me/mcp-keys/:id', requireSession, auditMiddleware('user-mcp-key-revoke'), (req, res) => {
  const keyId = parseInt(req.params.id, 10);
  const db = getDb();
  const existing = db.prepare('SELECT * FROM user_mcp_keys WHERE id = ? AND user_id = ?').get(keyId, req.user.id);
  if (!existing) throw new AppError('Key not found', 404, 'NOT_FOUND');
  if (existing.revoked_at) return res.json({ message: 'Already revoked', id: keyId });
  db.prepare("UPDATE user_mcp_keys SET revoked_at = datetime('now') WHERE id = ?").run(keyId);
  log.info(`UserMcpKey: revoked id=${keyId} user=${req.user.id}`);
  res.json({ message: 'Key revoked', id: keyId });
});

export default router;
