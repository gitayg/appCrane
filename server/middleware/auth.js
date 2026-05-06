import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import { isAdmin } from '../utils/roles.js';

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

  // Optional GitHub PAT passed via header — used by the MCP route to forward
  // github_* tool calls to the user's per-user GitHub MCP container. We just
  // attach it to req here; mcp.js handles it. Not stored, not logged.
  const ghToken = req.headers['x-github-token'];
  if (ghToken && typeof ghToken === 'string') req.github_token = ghToken;

  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    // SECURITY (v1.30.2): app-scoped and personal MCP keys are MCP-only.
    // Without this guard a leaked dhk_app_<slug> "read" key would
    // authenticate as its issuer on /api/apps/<slug>/env/production etc.
    // and bypass the scope. Reject non-MCP paths up-front.
    const path = req.baseUrl + (req.path || '') || req.originalUrl || '';
    const isMcpPath = path.startsWith('/api/mcp');

    // Personal MCP key (user-issued; format: dhk_mcp_<random>). Authenticates
    // AS the user but is MCP-only — accessibility resolves dynamically to
    // "apps where this user is currently Owner" (see mcpTools.js).
    if (apiKey.startsWith('dhk_mcp_')) {
      const keyHash = hashApiKey(apiKey);
      const row = db.prepare(`
        SELECT umk.id AS umk_id, umk.label, umk.expires_at, umk.revoked_at,
               u.id AS uid, u.name, u.email, u.role, u.active, u.kind, u.username
        FROM user_mcp_keys umk
        JOIN users u ON u.id = umk.user_id
        WHERE umk.key_hash = ?
          AND umk.revoked_at IS NULL
          AND (umk.expires_at IS NULL OR umk.expires_at > datetime('now'))
      `).get(keyHash);
      if (row) {
        if (!row.active) return next(new AppError('Account is deactivated', 403, 'DEACTIVATED'));
        if (!isMcpPath) {
          return next(new AppError('Personal MCP keys (dhk_mcp_*) are restricted to /api/mcp endpoints', 403, 'KEY_SCOPE_RESTRICTED'));
        }
        try { db.prepare("UPDATE user_mcp_keys SET last_used_at = datetime('now') WHERE id = ?").run(row.umk_id); } catch (_) {}
        req.user = {
          id: row.uid, name: row.name, email: row.email,
          role: row.role, active: row.active, kind: row.kind, username: row.username,
        };
        req.user_mcp_key = { id: row.umk_id, label: row.label };
        return next();
      }
    }

    // App-scoped key (issued by an Owner; format: dhk_app_<slug>_<random>)
    if (apiKey.startsWith('dhk_app_')) {
      const keyHash = hashApiKey(apiKey);
      const row = db.prepare(`
        SELECT
          ak.id AS ak_id, ak.app_id, ak.scope, ak.label, ak.expires_at, ak.revoked_at,
          a.slug AS app_slug,
          u.id AS uid, u.name, u.email, u.role, u.active, u.kind, u.username
        FROM app_keys ak
        JOIN apps  a ON a.id = ak.app_id
        JOIN users u ON u.id = ak.created_by
        WHERE ak.key_hash = ?
          AND ak.revoked_at IS NULL
          AND (ak.expires_at IS NULL OR ak.expires_at > datetime('now'))
      `).get(keyHash);
      if (row) {
        if (!row.active) return next(new AppError('Issuer account is deactivated', 403, 'DEACTIVATED'));
        if (!isMcpPath) {
          return next(new AppError('App-scoped keys (dhk_app_*) are restricted to /api/mcp endpoints', 403, 'KEY_SCOPE_RESTRICTED'));
        }
        try { db.prepare("UPDATE app_keys SET last_used_at = datetime('now') WHERE id = ?").run(row.ak_id); } catch (_) {}
        req.user = {
          id: row.uid, name: row.name, email: row.email,
          role: row.role, active: row.active, kind: row.kind, username: row.username,
        };
        req.app_key = {
          id: row.ak_id, app_id: row.app_id, app_slug: row.app_slug,
          scope: row.scope, label: row.label,
        };
        return next();
      }
      // dhk_app_ key with no match → fall through to user-key path so the
      // error surfaces as "Invalid API key" rather than leaking that the
      // prefix is a known format.
    }

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
 * Require admin or platform_admin role. Both tiers can hit any endpoint
 * gated by this middleware — the role-permissions matrix governs the
 * fine-grained per-app capabilities, and a separate requirePlatformAdmin
 * exists for the small set of operations that must stay platform-only
 * (e.g. assigning the platform_admin role itself).
 */
export function requireAdmin(req, res, next) {
  const role = req.user?.role;
  if (!req.user || (role !== 'admin' && role !== 'platform_admin')) {
    return next(new AppError('Admin access required', 403, 'FORBIDDEN'));
  }
  next();
}

/**
 * Require platform_admin role specifically. Used only by endpoints that
 * mutate the role-tier system itself (assign/revoke platform_admin, etc.).
 */
export function requirePlatformAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'platform_admin') {
    return next(new AppError('Platform admin access required', 403, 'FORBIDDEN_PLATFORM_ADMIN'));
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

  // Admin / platform_admin can access app info (env/data still gated below)
  if (isAdmin(req.user)) {
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

  // Admin / platform_admin explicitly blocked from env/data/deploy operations
  if (isAdmin(req.user)) {
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
