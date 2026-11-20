// AppCrane's own MFA after an SSO sign-in. A user who enrolled a second factor
// here completes it after OIDC or SAML too, through the same challenge password
// sign-in uses (services/mfa.js, POST /api/identity/mfa/verify). The challenge
// records the SSO method, so verify neither refuses it under "Require SSO
// sign-in" nor audits it as a password sign-in.
//
// Remembered devices do not apply: their cookie is SameSite=Strict, so the
// browser does not send it on the IdP's redirect back here.

import { createChallenge, isEnrolled } from './mfa.js';

// RFC 8176 values that mean the IdP itself checked a second factor.
export const IDP_MFA_AMR = Object.freeze(['mfa', 'otp', 'hwk', 'swk', 'sc', 'fpt']);

/** True when a verified id_token's amr claim (an array) says the IdP did MFA. */
export function idpDidMfa(amr) {
  return Array.isArray(amr) && amr.some((v) => IDP_MFA_AMR.includes(v));
}

/** null (issue the session) or the second step to hand the browser instead. */
export function ssoLoginMfaStep(db, user, { method }) {
  if (!isEnrolled(db, user.id)) return null;
  return {
    mfa_required: true,
    mfa_token: createChallenge(db, user, 'verify', null, Date.now(), { method }),
    remember_device_days: 0,
    error: { code: 'MFA_REQUIRED', message: 'Enter the code from your authenticator app to finish signing in.' },
  };
}
