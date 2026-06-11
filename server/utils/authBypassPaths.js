/**
 * Validation + normalization for app.auth_bypass_paths.
 *
 * Shared between server/routes/apps.js (write side), the MCP set_app_meta tool,
 * and server/services/caddy.js (read-back at generation time — defense in
 * depth so a direct DB poke can't smuggle a malformed prefix into the live
 * Caddyfile).
 *
 * A bypass entry is a path PREFIX rooted at the per-app mount (e.g.
 * "/ws/local-runner" → matches "/agentclub-sandbox/ws/local-runner*" after
 * the app slug is prepended in the Caddy generator). Requests under that
 * prefix skip forward_auth on this app.
 */

// Reserved roots that NO bypass entry may target. The check is
// case-insensitive and segment-aware so /API/identity/verify and /Api/anything
// can't sneak past the lowercase startsWith check. Over-rejecting /apidocs is
// fine — it's a deliberate boundary, not a path-traversal hole.
const RESERVED_ROOTS = ['/api', '/admin', '/login', '/portal', '/health', '/__crashed'];

// Allowed character class. Excludes %, so percent-encoded traversal sequences
// like %2e%2e or %2f are rejected by the regex itself before string-level
// `..` / `//` checks ever need to run. Excludes whitespace, query strings,
// fragments, and regex/glob meta characters.
const PATH_RE = /^\/(?!\/)[A-Za-z0-9_\-./~]+$/;

/**
 * Validate one bypass-path string.
 * Throws Error with a user-facing message on rejection.
 * Returns the input unchanged on success.
 */
export function validateBypassPath(p) {
  if (typeof p !== 'string') throw new Error('Bypass path must be a string');
  if (p.length < 2 || p.length > 200) {
    throw new Error(`Bypass path "${p}" length must be 2-200 chars`);
  }
  if (!PATH_RE.test(p)) {
    throw new Error(`Bypass path "${p}" has invalid characters or shape (allowed: A-Z, a-z, 0-9, _, -, ., /, ~; must start with "/" and not "//")`);
  }
  if (p.includes('//') || p.includes('..')) {
    throw new Error(`Bypass path "${p}" must not contain "//" or ".."`);
  }
  // Reject degenerate dot-only segments (`/.`, `/foo/.`, `/./bar`). They
  // aren't a security hole — `/.` can only ever match its own prefix, never
  // `/api` — but they're useless entries that just confuse later readers.
  const segments = p.split('/');
  if (segments.some(seg => seg === '.' || seg === '..')) {
    throw new Error(`Bypass path "${p}" must not contain "." or ".." segments`);
  }

  // Reserved-namespace check — case-insensitive AND segment-aware. Catches
  // "/API", "/Api/foo", "/api/identity/verify" but lets "/apidocs" through
  // because the latter doesn't *match the boundary*.
  const lp = p.toLowerCase();
  for (const r of RESERVED_ROOTS) {
    if (lp === r || lp.startsWith(r + '/')) {
      throw new Error(`Bypass path "${p}" overlaps the reserved namespace "${r}" — these paths are owned by AppCrane and cannot be bypassed`);
    }
  }

  return p;
}

/**
 * Validate the full auth_bypass_paths array as it comes off the wire.
 *
 * Accepts: null, undefined, [], or an array of strings (1-10 entries).
 * Returns the validated array (or null for explicit clears).
 * Throws Error with a user-facing message on rejection.
 */
export function validateBypassPaths(input) {
  if (input == null) return null;
  if (Array.isArray(input) && input.length === 0) return null;
  if (!Array.isArray(input)) throw new Error('auth_bypass_paths must be an array of strings or null');
  if (input.length > 10) throw new Error('auth_bypass_paths must have at most 10 entries');

  const seen = new Set();
  const out = [];
  for (const raw of input) {
    const v = validateBypassPath(raw);
    if (seen.has(v)) throw new Error(`Duplicate bypass path "${v}"`);
    seen.add(v);
    out.push(v);
  }
  return out;
}

/**
 * Parse a stored DB value back into the in-memory array. Tolerates corrupt
 * rows (logs and treats as empty) so a bad write somewhere can't break the
 * Caddy generator for every app.
 */
export function parseBypassPaths(raw, onError) {
  if (raw == null || raw === '') return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      if (onError) onError(new Error('auth_bypass_paths column is not an array'));
      return [];
    }
    const out = [];
    for (const p of parsed) {
      try {
        out.push(validateBypassPath(p));
      } catch (e) {
        if (onError) onError(e);
      }
    }
    return out;
  } catch (e) {
    if (onError) onError(e);
    return [];
  }
}
