import { AppError } from './errors.js';

/**
 * Role-check helpers for AppCrane's global role (users.role).
 *
 * v2.1.3 introduced 'platform_admin' as a tier above a global 'admin'. The
 * global 'admin' tier has since been retired (migration 105): it made a person
 * admin on EVERY app without anyone assigning them, which is the opposite of
 * the rule that app access is granted per app. Former holders became 'user'
 * and kept only the apps they were explicitly assigned to. The database now
 * refuses role = 'admin' outright.
 *
 * Per-app roles (owner / admin / user / viewer in app_user_roles) are a
 * different thing and are unaffected — "app admin" still exists.
 */

/**
 * True only for 'platform_admin'. Kept under this name so its many callers
 * keep compiling; a leftover 'admin' value (which the DB no longer admits)
 * deliberately grants nothing here.
 */
export function isAdmin(user) {
  if (!user) return false;
  return user.role === 'platform_admin';
}

/**
 * True only for 'platform_admin'. Use sparingly — only for operations that
 * mutate the role-tier system itself (assigning platform_admin, etc.).
 */
export function isPlatformAdmin(user) {
  return !!user && user.role === 'platform_admin';
}

// One message for every write path that refuses the retired tier (users API,
// and the DB trigger in migration 105 says the same), so an operator sees the
// same instruction wherever they hit it.
export const RETIRED_ADMIN_ROLE_MESSAGE =
  "The global 'admin' role was retired. Set the user to 'user' and give them admin on specific apps, or make them 'platform_admin'.";

/** Throws a 400 when `role` is the retired global 'admin' tier. */
export function refuseRetiredAdminRole(role) {
  if (role === 'admin') throw new AppError(RETIRED_ADMIN_ROLE_MESSAGE, 400, 'ROLE_RETIRED');
}
