import { createHash } from 'crypto';

// Validation rules for AppCrane's MCP OAuth 2.1 authorization server. Pure
// functions: no database, no request state beyond what is passed in.

export const ACCESS_TOKEN_TTL_SECONDS = 3600;
export const REFRESH_TOKEN_TTL_DAYS = 30;
export const CODE_TTL_SECONDS = 300;
export const AUTH_REQUEST_TTL_SECONDS = 600;
export const CONSENT_FRESH_MINUTES = 10;

export const DCR_MODES = ['open', 'allowlist', 'approval'];
export const DCR_DEFAULT_MODE = 'allowlist';
export const DCR_DEFAULT_REDIRECT_HOSTS = ['claude.ai', 'claude.com'];

export const SCOPE_FULL = 'mcp';
export const SCOPE_READ = 'mcp:read';
export const SCOPES_SUPPORTED = [SCOPE_FULL, SCOPE_READ];

export const ACCESS_PREFIX = 'dhk_oat_';
export const REFRESH_PREFIX = 'dhk_ort_';

export const AUTH_METHODS = ['none', 'client_secret_post', 'client_secret_basic'];
export const GRANT_TYPES = ['authorization_code', 'refresh_token'];

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(description);
    this.oauthError = error;
    this.status = status;
  }
  toJSON() { return { error: this.oauthError, error_description: this.message }; }
}

/** The issuer: the dashboard's own origin. Same derivation as routes/a2a.js baseUrlOf. */
export function issuerOf(req) {
  const host = process.env.CRANE_DOMAIN;
  return host ? `https://${host}` : `${req.protocol}://${req.get('host')}`;
}

/** The one resource tokens are issued for: the MCP endpoint (RFC 8707 / RFC 9728). */
export function mcpResourceOf(req) {
  return `${issuerOf(req)}/api/mcp`;
}

export function resourceMetadataUrlOf(req) {
  return `${issuerOf(req)}/.well-known/oauth-protected-resource/api/mcp`;
}

/** Canonical form for comparison: lowercase scheme and host, no trailing slash, no fragment. */
export function canonicalResource(value) {
  if (typeof value !== 'string' || !value) return null;
  let u;
  try { u = new URL(value); } catch (_) { return null; }
  if (u.hash || u.search) return null;
  const path = u.pathname.replace(/\/+$/, '');
  return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${path}`;
}

/**
 * Redirect URIs: https anywhere, or http on a loopback host (any port, RFC 8252
 * section 7.3). No fragments, no credentials in the authority, no other scheme.
 */
export function redirectUriRefusal(uri) {
  if (typeof uri !== 'string' || !uri || uri.length > 2000) return 'redirect_uri must be a string of at most 2000 characters';
  let u;
  try { u = new URL(uri); } catch (_) { return `redirect_uri is not an absolute URL: ${uri.slice(0, 100)}`; }
  if (u.hash) return 'redirect_uri must not contain a fragment';
  if (u.username || u.password) return 'redirect_uri must not contain credentials';
  if (u.protocol === 'https:') return null;
  if (u.protocol === 'http:' && LOOPBACK_HOSTS.has(u.hostname.toLowerCase())) return null;
  return 'redirect_uri must use https, or http on localhost / 127.0.0.1 / [::1]';
}

const HOST_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:\d{1,5})?$/;

/** Normalise an allowlist entry (a bare host, optionally with a port) or null when it is not one. */
export function normalizeRedirectHost(v) {
  if (typeof v !== 'string') return null;
  const h = v.trim().toLowerCase();
  return HOST_RE.test(h) ? h : null;
}

/**
 * Allowlist mode: a loopback redirect (any port, RFC 8252 section 7.3) or an
 * https redirect whose host (with its port, when it has one) is listed exactly.
 */
export function redirectAllowedByHosts(uri, hosts) {
  if (redirectUriRefusal(uri)) return false;
  const u = new URL(uri);
  if (LOOPBACK_HOSTS.has(u.hostname.toLowerCase())) return true;
  return u.protocol === 'https:' && hosts.includes(u.host.toLowerCase());
}

/** Loopback redirect: shown with a warning on the consent page (any local program can listen there). */
export function isLoopbackRedirect(uri) {
  try { return LOOPBACK_HOSTS.has(new URL(uri).hostname.toLowerCase()); } catch (_) { return false; }
}

/**
 * Resolve a requested scope string to what is granted. Unknown scopes are
 * dropped (RFC 6749 section 3.3 lets the server issue less than asked); none
 * known means the default, full MCP. Read-only when only mcp:read is asked for.
 */
export function resolveScope(raw) {
  const asked = typeof raw === 'string' ? raw.split(/\s+/).filter(Boolean) : [];
  const known = asked.filter(s => SCOPES_SUPPORTED.includes(s));
  if (known.includes(SCOPE_FULL) || known.length === 0) return { scope: SCOPE_FULL, readOnly: false };
  return { scope: SCOPE_READ, readOnly: true };
}

export function scopeFor(readOnly) {
  return readOnly ? SCOPE_READ : SCOPE_FULL;
}

const PKCE_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

export function isValidCodeChallenge(v) {
  return typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v);
}

export function pkceMatches(verifier, challenge) {
  if (typeof verifier !== 'string' || !PKCE_RE.test(verifier)) return false;
  const computed = createHash('sha256').update(verifier).digest('base64url');
  return computed === challenge;
}

export function sanitizeClientName(v) {
  if (typeof v !== 'string') return 'Unnamed MCP client';
  const clean = v.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 100);
  return clean || 'Unnamed MCP client';
}

/**
 * Validate a dynamic client registration body (RFC 7591). Returns the stored
 * shape or throws OAuthError('invalid_redirect_uri' | 'invalid_client_metadata').
 */
export function validateRegistration(body) {
  const b = body && typeof body === 'object' ? body : {};
  if (JSON.stringify(b).length > 8192) throw new OAuthError('invalid_client_metadata', 'Registration metadata is larger than 8 KB');
  const uris = b.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10) {
    throw new OAuthError('invalid_redirect_uri', 'redirect_uris must be an array of 1 to 10 URIs');
  }
  for (const u of uris) {
    const why = redirectUriRefusal(u);
    if (why) throw new OAuthError('invalid_redirect_uri', why);
  }
  const method = b.token_endpoint_auth_method ?? 'client_secret_basic';
  if (!AUTH_METHODS.includes(method)) {
    throw new OAuthError('invalid_client_metadata', `token_endpoint_auth_method must be one of ${AUTH_METHODS.join(', ')}`);
  }
  const grantTypes = b.grant_types ?? GRANT_TYPES;
  if (!Array.isArray(grantTypes) || !grantTypes.length || grantTypes.some(g => !GRANT_TYPES.includes(g)) || !grantTypes.includes('authorization_code')) {
    throw new OAuthError('invalid_client_metadata', `grant_types must include authorization_code and only ${GRANT_TYPES.join(', ')}`);
  }
  const responseTypes = b.response_types ?? ['code'];
  if (!Array.isArray(responseTypes) || responseTypes.some(r => r !== 'code')) {
    throw new OAuthError('invalid_client_metadata', "response_types must be ['code']");
  }
  return {
    client_name: sanitizeClientName(b.client_name),
    redirect_uris: [...new Set(uris)],
    grant_types: [...new Set(grantTypes)],
    token_endpoint_auth_method: method,
  };
}
