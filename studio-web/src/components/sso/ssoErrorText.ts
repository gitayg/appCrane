/**
 * The text /login shows for ?sso_error= / ?saml_error=. The server sends only a
 * code (server/utils/ssoPopup.js, POPUP_FAILURE_REASONS, which this table
 * matches); an unknown value gets the generic line, so nothing a crafted link
 * puts in the URL is ever shown.
 *
 * Kept free of imports and non-erasable TypeScript so node:test can load it
 * directly.
 */

export const SSO_ERROR_TEXT: Readonly<Record<string, string>> = Object.freeze({
  denied: 'The identity provider did not approve the sign-in.',
  no_account: 'There is no AppCrane account for this user. Ask an administrator for access.',
  domain_not_allowed: 'This email domain cannot sign up here. Ask an administrator for access.',
  email_unverified: 'The identity provider has not verified this email address.',
  link_refused: 'This Google account cannot sign in to the existing account with this email. Ask an administrator.',
  pending_approval: 'Your request to join was sent. An administrator has to approve it before you can sign in.',
  signup_denied: 'An administrator declined your request to join.',
  signup_rate_limited: 'Too many sign-up requests came from your network. Try again later.',
  browser_mismatch: 'Sign-in must finish in the browser that started it, with cookies allowed. Start again from the sign-in page.',
  expired: 'The sign-in took too long.',
  unavailable: 'The identity provider could not be reached.',
  failed: 'Sign-in could not be completed.',
})

export function ssoErrorText(code: string): string {
  return Object.hasOwn(SSO_ERROR_TEXT, code) ? SSO_ERROR_TEXT[code] : SSO_ERROR_TEXT.failed
}
