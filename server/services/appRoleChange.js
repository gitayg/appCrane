// The one way a person's AppCrane tier on an app is set by hand.
//
// applyAppRole() is the write: the last-active-owner guard, 'none' as removal
// (role row, app-defined role grants, tenant data), the ownership sweep. Every
// path that changes a tier for one person goes through it: PUT
// /api/apps/:slug/roles and the members widget (via setAppRole, owner or
// platform admin only), the MCP grant / revoke / approve-access tools (their
// own rule: an app admin may, but only an owner touches the owner tier) and
// access-review decisions. So the guard cannot drift between them.

import { AppError } from '../utils/errors.js';
import { isAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from './permissions.js';
import { clearUserRoleGrants } from './appDefinedRoles.js';
import { purgeRevokedTenants } from './tenants.js';
import { assertNotLastActiveOwner, afterOwnershipWrite } from './appOwnership.js';

export const SETTABLE_APP_ROLES = ['owner', 'admin', 'user', 'none'];

export function canManageAppRoles(actor, app) {
  return isAdmin(actor) || roleForUserOnApp(actor, app) === 'owner';
}

export async function setAppRole(db, actor, app, userId, appRole) {
  if (!canManageAppRoles(actor, app)) {
    throw new AppError('Only the app owner can manage users on this app.', 403, 'FORBIDDEN');
  }
  if (!userId || !appRole) throw new AppError('user_id and app_role required', 400, 'VALIDATION');
  return applyAppRole(db, actor.id, app, userId, appRole);
}

/**
 * Write one person's tier after the caller has decided they may. Returns
 * { removed, appRolesRemoved } (both 0 unless appRole is 'none').
 */
export async function applyAppRole(db, actorId, app, userId, appRole, { cause = 'role-change' } = {}) {
  if (!SETTABLE_APP_ROLES.includes(appRole)) throw new AppError('app_role must be owner, admin, user, or none', 400, 'VALIDATION');

  // Last-owner guard: don't let the final active owner be demoted/removed.
  if (appRole !== 'owner') assertNotLastActiveOwner(db, app.id, userId);

  // v2.42.1: 'none' means REMOVED, so it deletes rather than writes a row.
  //
  // This route used to write app_role='none' AND insert an app_users row, which
  // granted the very access it reads as taking away: requireAppUser checks
  // app_users, so someone the dashboard showed as 'none' could read DECRYPTED
  // production env vars via GET /:slug/env/:env?reveal=true, and run
  // backup/restore/copy-data. Every human-visible signal said no — /api/me
  // reported 'none' and forward_auth denied them at /<slug> — while the one path
  // that returns plaintext said yes. That disagreement between the checks WAS
  // the bug, and it was invisible from the UI.
  //
  // Absence is now the only representation of "no role": six different checks
  // cannot disagree about a row that does not exist. Migration 073 clears the
  // rows this already created.
  //
  // The app-defined roles go too (v2.41.0) — left behind, those grants come back
  // the moment the person is re-added at any tier, in-app powers restored
  // silently along with access.
  let removed = 0;
  let appRolesRemoved = 0;
  if (appRole === 'none') {
    db.transaction(() => {
      removed = db.prepare('DELETE FROM app_user_roles WHERE app_id = ? AND user_id = ?').run(app.id, userId).changes;
      appRolesRemoved = clearUserRoleGrants(app.id, userId);
    })();
    const target = db.prepare('SELECT email FROM users WHERE id = ?').get(userId);
    await purgeRevokedTenants(db, userId, target?.email, [app.id]);
  } else {
    db.transaction(() => {
      db.prepare(`
        INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
        ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role
      `).run(app.id, userId, appRole);
    })();
  }
  afterOwnershipWrite(db, cause, actorId);
  return { removed, appRolesRemoved };
}
