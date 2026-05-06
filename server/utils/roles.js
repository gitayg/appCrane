/**
 * Role-check helpers for AppCrane's two global admin tiers.
 *
 * v2.1.3 introduced 'platform_admin' as a tier above 'admin'. Most of the
 * codebase historically wrote `user.role === 'admin'` to mean "global
 * privileged user," which now silently locks platform_admin out of those
 * paths. Use these helpers everywhere instead — they accept both tiers as
 * "admin-equivalent" while leaving `requirePlatformAdmin` for the small
 * set of operations that must stay platform-only.
 */

/**
 * True if `user` has either 'admin' or 'platform_admin' role.
 * Returns false for null/undefined users and for any per-app or non-admin
 * role.
 */
export function isAdmin(user) {
  if (!user) return false;
  return user.role === 'admin' || user.role === 'platform_admin';
}

/**
 * True only for 'platform_admin'. Use sparingly — only for operations that
 * mutate the role-tier system itself (assigning platform_admin, etc.).
 */
export function isPlatformAdmin(user) {
  return !!user && user.role === 'platform_admin';
}
