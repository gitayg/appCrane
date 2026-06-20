/**
 * Validation for an app's custom domain (v2.10.0).
 *
 * Setting `apps.domain` makes AppCrane serve the app at the root of that domain
 * with no SSO and no topbar (the app does its own auth). Shared by the API
 * write path and the Caddy generator (which re-checks the format before
 * emitting a site block, so a bad value can never produce a broken Caddyfile).
 */

// A conservative public-hostname check: dot-separated labels, each 1-63 chars,
// a-z 0-9 and hyphens (not leading/trailing), at least two labels, TLD letters.
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function isValidDomainFormat(domain) {
  return typeof domain === 'string' && HOSTNAME_RE.test(domain);
}

/**
 * Normalize + validate a custom domain for write. Returns the normalized domain
 * (lowercase, trimmed) or null to clear. Throws Error on invalid input.
 *
 * @param {string|null} domain
 * @param {string|null} craneDomain  the platform's own domain (can't be reused)
 */
export function validateCustomDomain(domain, craneDomain) {
  if (domain == null || domain === '') return null;
  const d = String(domain).trim().toLowerCase();
  if (d === '') return null;
  if (!isValidDomainFormat(d)) {
    throw new Error(`Invalid custom domain "${domain}" — must be a hostname like app.example.com`);
  }
  const crane = (craneDomain || '').trim().toLowerCase();
  if (crane && d === crane) {
    throw new Error(`Custom domain cannot be the AppCrane platform domain (${crane})`);
  }
  return d;
}
