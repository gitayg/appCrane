// Who an SSO provider may create an account for. Sign-in by an existing user
// is not gated here; only auto-provisioning a new one is.
//
// With a public provider such as Google, any person with an account there can
// reach the callback, so auto-provisioning with no domain list would open
// sign-up to everyone. '*' says that on purpose.

export const GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration';

export function isPublicProvider(discoveryUrl) {
  try { return new URL(discoveryUrl).hostname === 'accounts.google.com'; } catch { return false; }
}

export function parseAllowedDomains(text) {
  return [...new Set(String(text || '')
    .split(/[\s,]+/)
    .map((d) => d.trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean))];
}

// null when allowed, otherwise the reason code. An entry is a domain
// (example.com) or one address (someone@example.com).
export function signupRefusal({ email, emailVerified, allowed }) {
  if (!allowed.length) return null;
  if (allowed.includes('*')) return null;
  if (!email || !emailVerified) return 'email_unverified';
  const at = email.lastIndexOf('@');
  const domain = at > 0 ? email.slice(at + 1).toLowerCase() : '';
  return allowed.includes(domain) || allowed.includes(email.toLowerCase()) ? null : 'domain_not_allowed';
}
