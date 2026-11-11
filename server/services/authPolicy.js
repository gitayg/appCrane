import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';

/**
 * Login-policy helpers.
 *
 * `auth_sso_only` (settings table) is "Require SSO sign-in". It is ON unless a
 * platform admin stored 'false': a missing row counts as on. It only bites
 * while an SSO provider (OIDC or SAML) is enabled, so an install with no
 * provider keeps password sign-in and cannot be locked out by the default.
 *
 * While it is in force (ssoRequired), every way to get a dashboard session or
 * a password other than the IdP is refused server-side with 403 SSO_REQUIRED
 * and audited as `sso-required-refused`:
 *   - POST /api/identity/login (password sign-in)
 *   - POST /api/identity/mfa/verify, /enroll/start, /enroll/confirm (the
 *     second step of a password sign-in started before it was turned on)
 *   - POST /api/identity/set-password (Bearer or API key -> password + session)
 *   - PUT /api/users/:id/password (an admin setting someone's password)
 * OIDC / SAML callbacks are unaffected. API keys, MCP keys, OAuth tokens and
 * app sign-in keys keep working as API credentials; none of them yields a
 * session.
 *
 * Break-glass is host-only: `crane sso enforce off` on the server writes the
 * setting directly (no network request can do it without a platform-admin
 * credential, which PUT /api/settings/auth_sso_only already requires).
 */

export const SSO_SETTING_KEY = 'auth_sso_only';

/** The stored switch: true unless a platform admin turned it off. */
export function isSsoOnly(db) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(SSO_SETTING_KEY);
  return row?.value !== 'false';
}

/** True if at least one SSO provider (OIDC or SAML) is enabled. */
export function ssoProviderConfigured(db) {
  const rows = db
    .prepare("SELECT value FROM settings WHERE key IN ('oidc_enabled', 'saml_enabled')")
    .all();
  return rows.some(r => r.value === '1');
}

/** The effective policy: the switch is on AND a provider is enabled. */
export function ssoRequired(db) {
  return isSsoOnly(db) && ssoProviderConfigured(db);
}

/**
 * Throw 403 SSO_REQUIRED (and audit it) when SSO sign-in is required.
 * `method` names the path refused; `userId` is the account it was for, when
 * known.
 */
export function refuseUnlessSsoOptional(db, req, { method, userId = null, message } = {}) {
  if (!ssoRequired(db)) return;
  const ip = req?.ip || req?.socket?.remoteAddress || 'unknown';
  try { logAudit(userId, null, 'sso-required-refused', { method, ip }); } catch (_) {}
  throw new AppError(message || 'Single sign-on is required on this instance. Sign in with your SSO provider.', 403, 'SSO_REQUIRED');
}
