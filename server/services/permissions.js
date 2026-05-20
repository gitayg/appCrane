/**
 * Configurable RBAC for the per-app role tiers (user / admin / owner).
 *
 * AppCrane admin (users.role = 'admin') always has every permission — that's
 * a hardcoded escape hatch so an admin can never lock themselves out by
 * tweaking the matrix.
 *
 * The matrix in role_permissions only governs a handful of "high-stakes"
 * operations (production deploys, marking requests shipped, etc.) where
 * orgs differ on who should be allowed. Most authz in AppCrane stays
 * hardcoded via requireAdmin / requireAppAccess / requireAppUser.
 *
 * Permission names are atomic strings — code refers to them as constants.
 * Adding a new configurable permission requires (a) adding the string here
 * via PERMISSIONS, (b) seeding defaults in a migration, (c) calling
 * userHasAppPermission() at the authz site.
 */

import { getDb } from '../db.js';

/** Currently-configurable permissions. Used by the Settings UI to render
 *  the matrix and by routes to check authz. Add new entries here when
 *  introducing new configurable gates. */
export const PERMISSIONS = [
  {
    key: 'platform.create_app',
    label: 'Create apps',
    description: 'Onboard a brand-new app (dashboard "+ Add Application" button and the appcrane_create_app / appcrane_create_managed_app MCP tools).',
    // Platform-scoped: there is no app yet, so the per-app owner/admin tiers
    // don't apply. Only the global `user` tier is meaningful — global admins
    // always have it. The Settings matrix greys the per-app columns.
    scope: 'platform',
  },
  {
    key: 'deploy.production',
    label: 'Deploy to production',
    description: 'Trigger a production deploy or promote sandbox → prod for this app.',
  },
  {
    key: 'request.ship',
    label: 'Mark request shipped',
    description: 'Move a request from in_progress to shipped — the "I wrote this code, it\'s done" gate.',
  },
  {
    key: 'env.write.production',
    label: 'Write production env vars',
    description: 'Set or delete environment variables on the production environment of this app.',
  },
  {
    key: 'code.modify_repo_settings',
    label: 'Modify repo settings',
    description: 'Change the app\'s GitHub URL, branch, or repo-related fields.',
  },
  {
    key: 'app.delete',
    label: 'Delete the app',
    description: 'Permanently delete this app from AppCrane. Irreversible.',
  },
];

const PERMISSION_KEYS = new Set(PERMISSIONS.map(p => p.key));
// Platform-scoped permissions are checked against the caller's GLOBAL role
// (users.role) rather than a per-app role, because the action isn't tied to
// an existing app. Checked via userHasPlatformPermission(), not
// userHasAppPermission().
const PLATFORM_PERMISSION_KEYS = new Set(
  PERMISSIONS.filter(p => p.scope === 'platform').map(p => p.key)
);
// Per-app role tiers shown in the matrix. 'platform_admin' is technically a
// global role on users.role, but it's surfaced here so the operator can
// configure what platform admins are allowed to do per-permission, same
// UI/storage as the per-app tiers.
const VALID_ROLES = ['user', 'admin', 'owner', 'platform_admin'];

/**
 * Resolve the caller's role on a specific app:
 *   'owner' | 'admin' | 'user' | null  (null = no per-app assignment)
 *
 * AppCrane global admins are NOT mapped to a per-app role — callers handle
 * that case separately (they bypass the matrix entirely).
 */
export function roleForUserOnApp(user, app) {
  if (!user || !app) return null;
  const db = getDb();
  const row = db.prepare(
    'SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?'
  ).get(app.id, user.id);
  if (row?.app_role === 'owner' || row?.app_role === 'admin') return row.app_role;
  // Plain assignment (no role) → 'user'
  const assigned = db.prepare(
    'SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?'
  ).get(app.id, user.id);
  return assigned ? 'user' : null;
}

/**
 * Check whether `user` has `permission` on `app`. AppCrane global admin
 * always returns true. Otherwise looks up the user's per-app role and
 * checks the matrix. Returns false if no per-app role.
 *
 * Throws if `permission` isn't a known key — better to fail loudly than
 * to silently allow because of a typo.
 */
export function userHasAppPermission(user, app, permission) {
  if (!PERMISSION_KEYS.has(permission)) {
    throw new Error(`Unknown permission: ${permission}`);
  }
  if (!user) return false;
  if (user.role === 'admin' || user.role === 'platform_admin') return true;

  const role = roleForUserOnApp(user, app);
  if (!role) return false;

  const db = getDb();
  const row = db.prepare(
    'SELECT granted FROM role_permissions WHERE permission = ? AND role = ?'
  ).get(permission, role);
  return row?.granted === 1;
}

/**
 * Check whether `user` holds a platform-scoped permission (e.g. creating an
 * app, where no app exists yet to carry a per-app role). AppCrane global
 * admins always return true. Otherwise the caller's GLOBAL role
 * (users.role — 'user' for plain users) is looked up against the matrix.
 *
 * Throws if `permission` isn't a known platform permission key.
 */
export function userHasPlatformPermission(user, permission) {
  if (!PLATFORM_PERMISSION_KEYS.has(permission)) {
    throw new Error(`Unknown platform permission: ${permission}`);
  }
  if (!user) return false;
  if (user.role === 'admin' || user.role === 'platform_admin') return true;

  const db = getDb();
  const row = db.prepare(
    'SELECT granted FROM role_permissions WHERE permission = ? AND role = ?'
  ).get(permission, user.role);
  return row?.granted === 1;
}

/**
 * Return the entire matrix as { permission: { user, admin, owner, platform_admin } }
 * for the Settings UI to render. All cells default to 0 if the row is
 * missing in role_permissions.
 */
export function getMatrix() {
  const db = getDb();
  const rows = db.prepare('SELECT permission, role, granted FROM role_permissions').all();
  const matrix = {};
  for (const p of PERMISSIONS) {
    matrix[p.key] = Object.fromEntries(VALID_ROLES.map(r => [r, 0]));
  }
  for (const r of rows) {
    if (matrix[r.permission] && VALID_ROLES.includes(r.role)) {
      matrix[r.permission][r.role] = r.granted ? 1 : 0;
    }
  }
  return matrix;
}

/**
 * Bulk-set grants. Body shape: { permission: { user, admin, owner } }.
 * Skips unknown permissions. Used by the Settings UI on save.
 */
export function setMatrix(matrix) {
  const db = getDb();
  const upsert = db.prepare(`
    INSERT INTO role_permissions (permission, role, granted) VALUES (?, ?, ?)
    ON CONFLICT(permission, role) DO UPDATE SET granted = excluded.granted
  `);
  db.transaction(() => {
    for (const [permission, byRole] of Object.entries(matrix)) {
      if (!PERMISSION_KEYS.has(permission)) continue;
      for (const role of VALID_ROLES) {
        const v = byRole[role] ? 1 : 0;
        upsert.run(permission, role, v);
      }
    }
  })();
}

/** Restore the seeded defaults for one or more permissions. */
export function resetToDefaults(permissionKeys = null) {
  const DEFAULTS = {
    'platform.create_app':       { user: 0, admin: 1, owner: 1, platform_admin: 1 },
    'deploy.production':         { user: 0, admin: 1, owner: 1, platform_admin: 1 },
    'request.ship':              { user: 0, admin: 0, owner: 1, platform_admin: 1 },
    'env.write.production':      { user: 0, admin: 1, owner: 1, platform_admin: 1 },
    'code.modify_repo_settings': { user: 0, admin: 0, owner: 1, platform_admin: 1 },
    'app.delete':                { user: 0, admin: 0, owner: 1, platform_admin: 1 },
  };
  const subset = {};
  const keys = permissionKeys || Object.keys(DEFAULTS);
  for (const k of keys) {
    if (DEFAULTS[k]) subset[k] = DEFAULTS[k];
  }
  setMatrix(subset);
}
