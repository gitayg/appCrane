import { getDb } from '../db.js';
import { hashApiKey } from './encryption.js';
import { AppError } from '../utils/errors.js';
import { readCookie } from '../utils/sessionCookie.js';
import { PLATFORM_SESSION_COOKIE_LEGACY, PLATFORM_SESSION_COOKIE_ISOLATED } from './appOrigin.js';

// View as role: a read-only preview of AppCrane as a lower role.
//
// The record lives server-side, keyed to the hash of the credential that
// started it, so it travels with that one sign-in. Nothing the browser sends
// can name a role: the only input is POST /api/auth/view-as, which checks the
// target against the caller's REAL standing, and requireAuth checks it again on
// every request. A target that is no longer below the real user is dropped.

export const VIEW_AS_TTL_MINUTES = 60;
export const APP_TARGET_ROLES = ['owner', 'admin', 'user', 'none'];

export function viewAsRefusalMessage(va) {
  const where = va?.app_slug ? ` on ${va.app_slug}` : '';
  return `You are viewing as ${va?.role || 'another role'}${where}. Stop viewing as to make changes.`;
}

function realAppRole(db, userId, appId) {
  const row = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, userId);
  return row?.app_role || null;
}

/**
 * The roles `realUser` may preview: platform-wide (app null) or on `app`.
 * A platform admin may preview the platform as a plain user and any app as any
 * per-app role. An app owner may preview THEIR app as a lower per-app role.
 * Nobody else may preview anything, and nobody may preview upwards.
 */
export function allowedTargets(db, realUser, app) {
  if (!realUser) return [];
  const isPlatformAdmin = realUser.role === 'platform_admin';
  if (!app) return isPlatformAdmin ? ['user'] : [];
  if (isPlatformAdmin) return [...APP_TARGET_ROLES];
  return realAppRole(db, realUser.id, app.id) === 'owner' ? ['admin', 'user', 'none'] : [];
}

export function viewAsOptions(realUser) {
  const db = getDb();
  const apps = realUser.role === 'platform_admin'
    ? db.prepare('SELECT id, slug, name FROM apps ORDER BY name COLLATE NOCASE').all()
    : db.prepare(`
        SELECT a.id, a.slug, a.name FROM apps a
        JOIN app_user_roles aur ON aur.app_id = a.id
        WHERE aur.user_id = ? AND aur.app_role = 'owner'
        ORDER BY a.name COLLATE NOCASE
      `).all(realUser.id);
  return {
    platform_roles: allowedTargets(db, realUser, null),
    apps: apps.map(a => ({ slug: a.slug, name: a.name, roles: allowedTargets(db, realUser, a) })),
  };
}

/**
 * The active view-as for the credential requireAuth authenticated, re-checked
 * against the real user. Expired or no-longer-lower rows are deleted here.
 */
export function activeViewAs(credentialHash, realUser) {
  if (!credentialHash || !realUser) return null;
  const db = getDb();
  const row = db.prepare('SELECT * FROM view_as_sessions WHERE credential_hash = ?').get(credentialHash);
  if (!row) return null;
  const drop = () => { db.prepare('DELETE FROM view_as_sessions WHERE credential_hash = ?').run(credentialHash); return null; };
  if (row.user_id !== realUser.id) return drop();
  if (Date.parse(row.expires_at.replace(' ', 'T') + 'Z') <= Date.now()) return drop();
  const app = row.app_id != null ? db.prepare('SELECT id, slug, name FROM apps WHERE id = ?').get(row.app_id) : null;
  if (row.app_id != null && !app) return drop();
  if (!allowedTargets(db, realUser, app).includes(row.target_role)) return drop();
  return {
    role: row.target_role,
    app_id: app ? app.id : null,
    app_slug: app ? app.slug : null,
    app_name: app ? app.name : null,
    started_at: row.started_at,
    expires_at: row.expires_at,
  };
}

/**
 * The caller as the target role sees them. The id stays the real one, so audit
 * rows keep naming the real person; the global role drops to 'user' (the only
 * role below platform_admin) and the per-app override rides on `view_as`,
 * which services/permissions.js roleForUserOnApp and the app gates in
 * middleware/auth.js read. mcp_read_only makes the MCP dispatcher refuse every
 * write tool on top of the REST write guard.
 */
export function effectiveUser(realUser, va) {
  return {
    ...realUser,
    role: 'user',
    view_as: { role: va.role, app_id: va.app_id, app_slug: va.app_slug },
    mcp_read_only: true,
  };
}

export function startViewAs({ credentialHash, realUser, role, appSlug }) {
  if (!credentialHash) {
    throw new AppError('View as needs a dashboard sign-in or a user API key', 403, 'VIEW_AS_CREDENTIAL');
  }
  const db = getDb();
  let app = null;
  if (appSlug != null && appSlug !== '') {
    if (typeof appSlug !== 'string') throw new AppError('app_slug must be a string', 400, 'VALIDATION');
    app = db.prepare('SELECT id, slug, name FROM apps WHERE slug = ?').get(appSlug);
    if (!app) throw new AppError(`App '${appSlug}' not found`, 404, 'NOT_FOUND');
  }
  if (typeof role !== 'string' || !role) throw new AppError('role is required', 400, 'VALIDATION');
  const allowed = allowedTargets(db, realUser, app);
  if (!allowed.includes(role)) {
    throw new AppError(
      app
        ? `You cannot view ${app.slug} as '${role}'. Allowed: ${allowed.length ? allowed.join(', ') : 'none (only the app owner or a platform admin can view as a lower role)'}.`
        : `You cannot view the platform as '${role}'. Allowed: ${allowed.length ? allowed.join(', ') : 'none (platform admins only)'}.`,
      403, 'VIEW_AS_FORBIDDEN');
  }
  db.prepare(`
    INSERT INTO view_as_sessions (credential_hash, user_id, target_role, app_id, expires_at)
    VALUES (?, ?, ?, ?, datetime('now', '+' || ? || ' minutes'))
    ON CONFLICT(credential_hash) DO UPDATE SET
      user_id = excluded.user_id, target_role = excluded.target_role, app_id = excluded.app_id,
      started_at = datetime('now'), expires_at = excluded.expires_at
  `).run(credentialHash, realUser.id, role, app ? app.id : null, VIEW_AS_TTL_MINUTES);
  return activeViewAs(credentialHash, realUser);
}

export function stopViewAs(credentialHash) {
  if (!credentialHash) return false;
  return getDb().prepare('DELETE FROM view_as_sessions WHERE credential_hash = ?').run(credentialHash).changes > 0;
}

// Both platform cookie names: over-matching is safe here (writes are refused).
function cookieTokens(req) {
  return [readCookie(req, PLATFORM_SESSION_COOKIE_LEGACY), readCookie(req, PLATFORM_SESSION_COOKIE_ISOLATED)].filter(Boolean);
}

/**
 * The active view-as carried by ANY credential on this request, unvalidated
 * beyond expiry. Used only to REFUSE writes, where over-matching is safe: it
 * covers routers that authenticate on their own (coder, presence, ask, plan,
 * identity) and never pass through requireAuth.
 */
export function viewAsOnAnyCredential(req) {
  const creds = [];
  const apiKey = req.headers['x-api-key'];
  if (typeof apiKey === 'string' && apiKey) creds.push(apiKey);
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (bearer) creds.push(bearer);
  creds.push(...cookieTokens(req));
  if (!creds.length) return null;
  const db = getDb();
  for (const c of creds) {
    const row = db.prepare(`
      SELECT v.target_role, a.slug AS app_slug FROM view_as_sessions v
      LEFT JOIN apps a ON a.id = v.app_id
      WHERE v.credential_hash = ? AND v.expires_at > datetime('now')
    `).get(hashApiKey(c));
    if (row) return { role: row.target_role, app_slug: row.app_slug };
  }
  return null;
}
