// Each app's MCP URL is its own OAuth protected resource (RFC 9728, RFC 8707):
// a token approved for one app's tools is refused by every other app's
// endpoint and by POST /api/mcp, and an /api/mcp token is refused here.
//
// Production is /api/mcp/apps/<slug>; sandbox is /api/mcp/apps/<slug>-sandbox.
// A slug can never end in "-sandbox" (utils/slugPolicy.js), so the two never
// collide.

import { issuerOf, mcpResourceOf, canonicalResource } from '../oauthPolicy.js';

export const APP_MCP_BASE = '/api/mcp/apps';
const TARGET_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;

/** { slug, env } for a URL target, or null when it cannot be an app. */
export function parseTarget(target) {
  if (typeof target !== 'string' || !TARGET_RE.test(target)) return null;
  if (target.endsWith('-sandbox')) {
    const slug = target.slice(0, -'-sandbox'.length);
    return slug ? { slug, env: 'sandbox' } : null;
  }
  return { slug: target, env: 'production' };
}

export function targetOf(slug, env) {
  return env === 'sandbox' ? `${slug}-sandbox` : slug;
}

export function appMcpPathOf(slug, env) {
  return `${APP_MCP_BASE}/${targetOf(slug, env)}`;
}

export function appResourceOf(req, slug, env) {
  return `${issuerOf(req)}${appMcpPathOf(slug, env)}`;
}

export function appResourceMetadataUrlOf(req, slug, env) {
  return `${issuerOf(req)}/.well-known/oauth-protected-resource${appMcpPathOf(slug, env)}`;
}

/** Does a stored grant resource name exactly this app endpoint? */
export function resourceIsApp(req, resource, slug, env) {
  const c = canonicalResource(resource);
  return !!c && c === canonicalResource(appResourceOf(req, slug, env));
}

/**
 * The resource an authorization request is for, or null when the asked value
 * names nothing AppCrane protects. Absent → the platform MCP endpoint, as
 * before. `appExists(slug)` is the caller's lookup, so a resource for an app
 * that does not exist is refused at /oauth/authorize, not at first use.
 */
export function resolveRequestedResource(req, asked, appExists) {
  const platform = mcpResourceOf(req);
  if (asked === undefined) return platform;
  if (typeof asked !== 'string') return null;
  const c = canonicalResource(asked);
  if (!c) return null;
  if (c === canonicalResource(platform)) return platform;
  const prefix = canonicalResource(`${issuerOf(req)}${APP_MCP_BASE}`) + '/';
  if (!c.startsWith(prefix)) return null;
  const t = parseTarget(c.slice(prefix.length));
  if (!t || !appExists(t.slug)) return null;
  return appResourceOf(req, t.slug, t.env);
}
