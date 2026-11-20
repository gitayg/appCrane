-- Which sign-in a second-step challenge belongs to: NULL for password sign-in,
-- 'oidc' or 'saml' when an SSO callback asked for AppCrane's own MFA code
-- (server/services/ssoMfa.js). POST /api/identity/mfa/verify refuses a password
-- challenge while "Require SSO sign-in" is in force, but not an SSO one, and
-- audits the method it names.
ALTER TABLE mfa_challenges ADD COLUMN method TEXT;
