import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import { isAdmin } from '../utils/roles.js';
import { activeViewAs, effectiveUser } from '../services/viewAs.js';
import { lookupAccessToken } from '../services/oauthStore.js';
import { ACCESS_PREFIX, canonicalResource, mcpResourceOf } from '../services/oauthPolicy.js';
import { auditExpiredUse, expiredMessage, expireUserKey, isPast } from '../services/apiKeyExpiry.js';
import { touchSession } from '../services/sessionPolicy.js';

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
    // SECURITY: personal MCP keys (dhk_mcp_*) are restricted to /api/mcp
    // paths. Without this guard a leaked key would authenticate as its
    // issuer on every REST endpoint. (App-scoped keys dhk_app_* were
    // removed entirely in v2.2.12; see auth.js below.)
    //
    // v2.10.6: also allow the staged-upload endpoints (/api/files/staged*).
    // That flow is the designed channel for large binaries an agent can't
    // inline through the JSON-RPC tool args (appcrane_set_data_blob), but it
    // was unreachable for MCP agents because of this restriction. It's
    // low-blast-radius: staged files are owner-scoped, expire, and do nothing
    // until appcrane_push_staged_file (itself MCP-only + per-app authz) lands
    // them — which a leaked MCP key could already invoke.
    const path = req.baseUrl + (req.path || '') || req.originalUrl || '';
    const isMcpPath = path.startsWith('/api/mcp') || path.startsWith('/api/files/staged');

    // Personal MCP key (user-issued; format: dhk_mcp_<random>). Authenticates
    // AS the user but is MCP-only — accessibility resolves dynamically to
    // "apps where this user is currently Owner" (see mcpTools.js).
    if (apiKey.startsWith('dhk_mcp_')) {
      const keyHash = hashApiKey(apiKey);
      const row = db.prepare(`
        SELECT umk.id AS umk_id, umk.label, umk.expires_at, umk.revoked_at,
               umk.read_only, umk.coder_session_id, umk.app_id,
               u.id AS uid, u.name, u.email, u.role, u.active, u.kind, u.username,
               u.mcp_app_scope
        FROM user_mcp_keys umk
        JOIN users u ON u.id = umk.user_id
        WHERE umk.key_hash = ?
          AND umk.revoked_at IS NULL
      `).get(keyHash);
      if (row && row.coder_session_id == null && row.expires_at && isPast(row.expires_at)) {
        auditExpiredUse(row.uid, 'mcp', row.umk_id, row.expires_at, req.ip);
        return next(new AppError(expiredMessage(row.expires_at, 'the MCP page (rotate it there)'), 401, 'API_KEY_EXPIRED'));
      }
      if (row && (row.expires_at == null || !isPast(row.expires_at))) {
        if (!row.active) return next(new AppError('Account is deactivated', 403, 'DEACTIVATED'));
        if (!isMcpPath) {
          return next(new AppError('Personal MCP keys (dhk_mcp_*) are restricted to /api/mcp and /api/files/staged endpoints', 403, 'KEY_SCOPE_RESTRICTED'));
        }
        let coder = null;
        if (row.coder_session_id != null) {
          // A coder session key: POST /api/mcp only (not staged files, not the
          // admin catalogue or GitHub-container routes beside it), one app.
          if (req.method !== 'POST' || !/^\/api\/mcp\/?$/.test(path)) {
            return next(new AppError('Coder session keys are restricted to POST /api/mcp', 403, 'KEY_SCOPE_RESTRICTED'));
          }
          const app = db.prepare('SELECT slug FROM apps WHERE id = ?').get(row.app_id);
          if (!app) return next(new AppError('Invalid API key', 401, 'UNAUTHORIZED'));
          coder = { sessionId: row.coder_session_id, appId: row.app_id, slug: app.slug };
        }
        try { db.prepare("UPDATE user_mcp_keys SET last_used_at = datetime('now') WHERE id = ?").run(row.umk_id); } catch (_) {}
        // SECURITY: mcp_app_scope must be carried onto req.user. This is a
        // hand-picked column list rather than `u.*`, and the column was
        // missing from it — so mcpTools.js read `user.mcp_app_scope` as
        // undefined and every scope an operator set on a dhk_mcp_* key was
        // silently ignored, including '[]' (lock out of MCP entirely). The
        // other two auth paths below select the whole users row and were
        // never affected, which is why the restriction appeared to work when
        // tested with an X-API-Key or a portal session.
        //
        // v2.44.0: user_mcp_keys.read_only travels the same path and would hit
        // the same wall, so it is stamped on BOTH views. It is a property of
        // the key, but callTool()'s userMcpKey argument is optional — a call
        // site that forgets to pass it would silently lose the restriction.
        // Either half alone is enough for the dispatcher to refuse a write.
        req.user = {
          id: row.uid, name: row.name, email: row.email,
          role: row.role, active: row.active, kind: row.kind, username: row.username,
          mcp_app_scope: coder ? coderScope(row.mcp_app_scope, coder.slug) : row.mcp_app_scope,
          mcp_read_only: !!row.read_only || !!coder,
          ...(coder ? { coder_key: coder } : {}),
        };
        req.user_mcp_key = {
          id: row.umk_id, label: row.label, read_only: !!row.read_only || !!coder,
          ...(coder ? { coder } : {}),
        };
        return next();
      }
    }

    // App-scoped MCP keys (dhk_app_*) were removed in v2.2.12. The model
    // duplicated what user keys (dhk_mcp_*) plus per-app role assignments
    // already provided. Anyone holding a `dhk_app_*` from before now gets
    // a clear migration message instead of silent rejection.
    if (apiKey.startsWith('dhk_app_')) {
      return next(new AppError(
        'App-scoped keys (dhk_app_*) were removed in v2.2.12. Issue a personal MCP key (dhk_mcp_*) for the user instead, and assign them the appropriate per-app role at /users.',
        410,
        'KEY_TYPE_REMOVED',
      ));
    }

    // v2.124.0: personal app sign-in keys (dhk_uak_*) open one app's
    // forward_auth gate and nothing on this API. Their hashes live in
    // user_app_keys, so the lookup below could never match one anyway; the
    // explicit refusal is for the person holding it, who would otherwise read
    // "Invalid API key" and assume the key is broken.
    if (apiKey.startsWith('dhk_uak_')) {
      return next(new AppError('App sign-in keys (dhk_uak_*) only sign in to the app they were issued for; they cannot call the AppCrane API', 403, 'KEY_SCOPE_RESTRICTED'));
    }

    const userKeyHash = hashApiKey(apiKey);
    const user = db.prepare('SELECT * FROM users WHERE api_key_hash = ?').get(userKeyHash);
    if (!user) {
      const gone = db.prepare('SELECT id, api_key_expires_at FROM users WHERE api_key_expired_hash = ?').get(userKeyHash);
      if (gone) {
        auditExpiredUse(gone.id, 'user', gone.id, gone.api_key_expires_at, req.ip);
        return next(new AppError(expiredMessage(gone.api_key_expires_at), 401, 'API_KEY_EXPIRED'));
      }
      return next(new AppError('Invalid API key', 401, 'UNAUTHORIZED'));
    }
    if (!user.active) return next(new AppError('Account is deactivated', 403, 'DEACTIVATED'));
    if (user.api_key_expires_at && isPast(user.api_key_expires_at)) {
      try { expireUserKey(db, user.id); } catch (_) {}
      auditExpiredUse(user.id, 'user', user.id, user.api_key_expires_at, req.ip);
      return next(new AppError(expiredMessage(user.api_key_expires_at), 401, 'API_KEY_EXPIRED'));
    }
    try {
      db.prepare("UPDATE users SET api_key_last_used_at = datetime('now') WHERE id = ? AND (api_key_last_used_at IS NULL OR api_key_last_used_at < datetime('now', '-1 hour'))").run(user.id);
    } catch (_) {}
    req.user = user;
    applyViewAs(req, apiKey);
    return next();
  }

  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (bearer && bearer.startsWith(ACCESS_PREFIX)) return oauthAccessToken(req, bearer, next);
  if (bearer) {
    const session = db.prepare(`
      SELECT u.*, s.id AS _session_id, s.last_seen_at AS _session_last_seen_at, s.absolute_expires_at AS _session_absolute_expires_at
      FROM identity_sessions s JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND datetime(s.expires_at) > datetime('now') AND u.active = 1
    `).get(hashApiKey(bearer));
    if (!session) return next(new AppError('Invalid or expired session', 401, 'UNAUTHORIZED'));
    const { _session_id, _session_last_seen_at, _session_absolute_expires_at, ...sessionUser } = session;
    try {
      touchSession(db, { id: _session_id, last_seen_at: _session_last_seen_at, absolute_expires_at: _session_absolute_expires_at }, sessionUser);
    } catch (_) {}
    req.user = sessionUser;
    applyViewAs(req, bearer);
    return next();
  }

  return next(new AppError('Missing X-API-Key header or Bearer token', 401, 'UNAUTHORIZED'));
}

// View as role (services/viewAs.js). Only the two credentials a person signs
// the dashboard in with can carry one: an identity session and a user API key.
// The record is looked up by the hash of the credential actually presented and
// re-checked against the real user, so it can only ever lower what they see.
function applyViewAs(req, credential) {
  req.auth_credential_hash = hashApiKey(credential);
  const va = activeViewAs(req.auth_credential_hash, req.user);
  if (!va) return;
  req.real_user = req.user;
  req.view_as = va;
  req.user = effectiveUser(req.user, va);
}

// MCP OAuth access token (routes/oauth.js issues them). Usable on POST /api/mcp
// only, for the resource it was issued for, with the approving user's MCP app
// scope and the grant's read-only flag, the same carriage as a dhk_mcp_* key.
function oauthAccessToken(req, token, next) {
  const row = lookupAccessToken(token);
  if (!row) return next(new AppError('Invalid or expired access token', 401, 'UNAUTHORIZED'));
  if (!row.active) return next(new AppError('Account is deactivated', 403, 'DEACTIVATED'));
  const path = req.baseUrl + (req.path || '') || req.originalUrl || '';
  if (req.method !== 'POST' || !/^\/api\/mcp\/?$/.test(path)) {
    return next(new AppError('OAuth access tokens are restricted to POST /api/mcp', 403, 'KEY_SCOPE_RESTRICTED'));
  }
  if (canonicalResource(row.resource) !== canonicalResource(mcpResourceOf(req))) {
    return next(new AppError('This access token was issued for a different resource', 401, 'UNAUTHORIZED'));
  }
  req.user = {
    id: row.uid, name: row.name, email: row.email,
    role: row.role, active: row.active, kind: row.kind, username: row.username,
    mcp_app_scope: row.mcp_app_scope,
    mcp_read_only: !!row.read_only,
  };
  req.user_mcp_key = {
    id: `oauth-${row.grant_id}`, label: row.client_name, read_only: !!row.read_only,
    oauth: { grant_id: row.grant_id, client_id: row.client_id },
  };
  return next();
}

// A coder key's scope is its one app, inside whatever scope its owner's keys
// already have: an owner scope that leaves the app out locks the key out.
function coderScope(ownerScope, slug) {
  if (ownerScope != null && ownerScope !== '') {
    let list = null;
    try { list = JSON.parse(ownerScope); } catch (_) { list = null; }
    if (Array.isArray(list) && !list.map(String).includes(slug)) return '[]';
  }
  return JSON.stringify([slug]);
}

/**
 * Require platform_admin. The global 'admin' tier was retired (migration 105):
 * it granted admin on every app without assignment. A leftover role = 'admin'
 * user object is refused here rather than trusted, so nothing depends on the
 * migration having caught every row.
 */
export function requireAdmin(req, res, next) {
  const role = req.user?.role;
  if (!req.user || role !== 'platform_admin') {
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

  const va = req.user.view_as;
  if (va && va.app_id === app.id) {
    if (va.role === 'none') return next(new AppError('You are not assigned to this app', 403, 'FORBIDDEN'));
    if (isAdmin(req.real_user)) return next();
  }

  // Platform admins can access app info (env/data still gated below)
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
 * Require app user (or platform_admin) — for env vars, data, deploy
 * operations.
 *
 * The "admin cannot access app data/env" guardrail applies to platform
 * admins: they're responsible for hub-level config and shouldn't
 * accidentally tamper with a specific app's prod env vars. To do that they
 * must "step down" by assigning themselves to the app as a regular user.
 *
 * Platform admins have been held to this rule since v2.39.0: they must be
 * assigned too (see the comment in the body). Assignment means a role row
 * in app_user_roles; app_users is a read-only view of it since v2.94.0.
 */
export function requireAppUser(req, res, next) {
  const { slug } = req.params;
  const db = getDb();

  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) {
    return next(new AppError(`App '${slug}' not found`, 404, 'NOT_FOUND'));
  }

  req.app = app;

  if (req.user.view_as?.app_id === app.id && req.user.view_as.role === 'none') {
    return next(new AppError('You are not assigned to this app', 403, 'FORBIDDEN'));
  }

  // Assignment is authoritative for EVERY role, including platform_admin.
  //
  // v2.39.0. This gate covers env vars (including ?reveal=true plaintext),
  // backup/restore/copy-data, health config, notifications and webhooks — the
  // app's own data and secrets, as distinct from platform administration.
  // platform_admin used to return early here with no assignment at all, which
  // is what let a single lifted admin session read the DECRYPTED env vars of
  // every app on the box. The role check was doing the opposite of the rule
  // envVars.js states at the top of the file: "assigned app users only —
  // admins are explicitly NOT granted access to env-var values".
  //
  // A platform admin who genuinely needs access assigns themselves through the
  // normal member-management route, which is itself admin-gated and audited.
  // That turns a silent, invisible capability into a deliberate, attributable
  // act — the same guardrail `admin` already had.
  const assignment = db.prepare(
    'SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?'
  ).get(app.id, req.user.id);

  if (assignment) return next();

  // Not assigned. Platform admins get the actionable message.
  //
  // The admin branch used to sit BEFORE this lookup, so an admin who did
  // exactly what the error told them — assign themselves — stayed blocked. The
  // advice was unreachable. Checking assignment first makes it true.
  if (req.user.role === 'platform_admin') {
    return next(new AppError(
      `Admin access does not include app data/env. Assign yourself to '${slug}' as an app user first.`,
      403, 'ADMIN_BLOCKED'));
  }

  return next(new AppError('You are not assigned to this app', 403, 'FORBIDDEN'));
}
