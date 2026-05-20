/**
 * Login-policy helpers.
 *
 * `auth_sso_only` (settings table) lets a platform admin force single
 * sign-on as the only browser login path. When on:
 *   - POST /api/identity/login is rejected server-side (password sign-in off)
 *   - the Login UI hides the password form AND the API-key break-glass paste
 *     (full lockdown — CLI/API keys remain the only recovery)
 *   - OIDC / SAML callbacks are unaffected, so the IdP round-trip still works
 *
 * Enabling is guarded: PUT refuses to turn it on unless an SSO provider is
 * already enabled, so an operator can't lock the org out with one click.
 */

/** True if password sign-in is disabled in favor of SSO-only. */
export function isSsoOnly(db) {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'auth_sso_only'").get();
  return row?.value === 'true';
}

/** True if at least one SSO provider (OIDC or SAML) is enabled. */
export function ssoProviderConfigured(db) {
  const rows = db
    .prepare("SELECT value FROM settings WHERE key IN ('oidc_enabled', 'saml_enabled')")
    .all();
  return rows.some(r => r.value === '1');
}
