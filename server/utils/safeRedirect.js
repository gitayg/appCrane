/**
 * Same-origin redirect validation, server side.
 *
 * This is the exact rule implemented by the SPA in
 * `studio-web/src/utils/safeRedirect.ts` (v2.35.0). It is duplicated here
 * rather than shared because the two halves ship as separate bundles — but the
 * SEMANTICS must not drift. A credentialed WAS scan found the original open
 * redirect precisely because three copies of a "looks correct" check disagreed
 * about the edges; if you change one of these files, change the other.
 *
 * Why `startsWith('/')` is not a same-origin test:
 *
 *   "//attacker.example".startsWith("/")   === true
 *
 * `//host` is a protocol-relative URL — an absolute, cross-origin address that
 * merely begins with a slash. `/\host` is treated the same way by browsers and
 * survives normalizers that only strip a second slash. And because Express
 * percent-decodes `req.query`, `?redirect=/%09/attacker.example` arrives as a
 * literal TAB: browsers strip TAB/CR/LF before parsing a URL, so that value
 * also resolves cross-origin.
 *
 * An open redirect is a phishing amplifier — the link the attacker sends is
 * genuinely on our domain, the victim inspects the host, sees it is real, and
 * is then bounced elsewhere. CWE-601.
 *
 * Rule: accept only a single leading slash, followed by a character that cannot
 * begin an authority, and no control characters anywhere. Everything else —
 * absolute URLs, protocol-relative, backslash variants, `javascript:` — is
 * refused and the caller falls back.
 */

export function isSafeRedirect(value) {
  // Unlike the TypeScript original, the input here is untyped request data:
  // `?redirect=a&redirect=b` gives Express an array, and a bracket-notation
  // query gives it an object. Neither is a redirect target.
  if (typeof value !== 'string' || value === '') return false;
  // Must start with exactly one '/'. Reject '//host', '/\host', and any scheme.
  if (!value.startsWith('/')) return false;
  if (value.length > 1 && (value[1] === '/' || value[1] === '\\')) return false;
  // Control characters (including encoded newlines and tabs that survive
  // decoding) can split a Location header or confuse a URL parser — refuse
  // outright. \x7f (DEL) is excluded alongside \x00-\x1f to match the client
  // guard exactly.
  if (/[\x00-\x1f\x7f]/.test(value)) return false;
  return true;
}

/**
 * The redirect target if it is safe, otherwise `fallback`. Use this rather than
 * hand-rolling the check — the whole finding was copies of a check that looked
 * correct in isolation.
 */
export function safeRedirectTarget(value, fallback = '/launch') {
  return isSafeRedirect(value) ? value : fallback;
}
