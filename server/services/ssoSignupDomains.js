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
//
// With a public provider, a verified email on a domain does not show the
// person belongs to it: anyone can make a Google account on an address they
// can receive mail at, and keeps it after they leave. So a domain entry
// matches there only when the token's hosted-domain claim (hd) names that
// domain, which Google sets only for accounts the domain's Workspace manages.
// A single-address entry names one mailbox, so the verified email is enough.
export function signupRefusal({ email, emailVerified, allowed, hostedDomain, requireHostedDomain = false }) {
  if (!allowed.length) return null;
  if (allowed.includes('*')) return null;
  if (!email || !emailVerified) return 'email_unverified';
  const address = email.toLowerCase();
  if (allowed.includes(address)) return null;
  const at = address.lastIndexOf('@');
  const domain = at > 0 ? address.slice(at + 1) : '';
  if (!allowed.includes(domain)) return 'domain_not_allowed';
  if (requireHostedDomain && String(hostedDomain || '').toLowerCase() !== domain) return 'domain_not_allowed';
  return null;
}
