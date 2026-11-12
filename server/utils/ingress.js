// Personal user API keys on the private API port only (APPCRANE_PRIVATE_API_PORT).
//
// Caddy stamps X-AppCrane-Ingress on every request it proxies to AppCrane:
// 'private' on the private-port site, 'public' on every other site (the
// platform host on 443, app hosts, custom domains, and the forward_auth
// subrequests to /api/identity/verify). It sets the header, so a client value
// never survives (services/caddy.js, craneIngress). A request that reaches
// Node's own port directly (loopback, app containers via host.docker.internal,
// the crane CLI on the box) carries no Caddy stamp and is not public.
//
// Unset: nothing here refuses anything, and Caddy stamps nothing.

import { logAudit } from '../middleware/audit.js';
import { AppError } from './errors.js';
import log from './logger.js';
import { assertUserKeyUsable, recordUserKeyUse } from '../services/userKeyUse.js';

export const PRIVATE_PORT_ENV = 'APPCRANE_PRIVATE_API_PORT';
export const INGRESS_HEADER = 'X-AppCrane-Ingress';
export const USER_KEY_REFUSED_CODE = 'USER_KEY_PRIVATE_PORT_ONLY';

let warned = '';

/** The private API port, or null when unset or unusable (logged once). */
export function privateApiPort(env = process.env) {
  const raw = String(env[PRIVATE_PORT_ENV] ?? '').trim();
  if (!raw) return null;
  const n = /^\d{1,5}$/.test(raw) ? Number(raw) : NaN;
  const nodePort = Number(env.PORT || 5001);
  if (!Number.isInteger(n) || n < 1 || n > 65535 || n === 80 || n === 443 || n === nodePort) {
    if (warned !== raw) {
      warned = raw;
      log.warn(`[ingress] ${PRIVATE_PORT_ENV}=${raw} is not a usable port (1-65535, not 80, 443 or PORT); treated as unset`);
    }
    return null;
  }
  return n;
}

export function isPublicIngress(req) {
  return String(req.headers?.['x-appcrane-ingress'] ?? '').trim().toLowerCase() === 'public';
}

export function userKeyRefusedMessage(port, env = process.env) {
  const host = env.CRANE_DOMAIN || 'your-crane-host';
  return `Personal API keys (dhk_user_*, dhk_admin_*) are accepted only on the private API port: use https://${host}:${port}. ` +
    'On this address sign in to the dashboard, or use an MCP key or MCP OAuth for MCP.';
}

// One audit row per user per hour, as for expired keys, so a client retrying a
// refused key in a loop cannot flood the audit log.
const auditedAt = new Map();
function auditRefusal(userId, req, via) {
  const last = auditedAt.get(userId);
  if (last && Date.now() - last < 3600_000) return;
  auditedAt.set(userId, Date.now());
  if (auditedAt.size > 5000) auditedAt.clear();
  try {
    const path = String(req.originalUrl || req.url || '').split('?')[0].slice(0, 200);
    logAudit(userId ?? null, null, 'user-key.public-refused', { via, path, ip: req.ip || null });
  } catch (e) {
    log.warn(`[ingress] audit row skipped: ${e.message}`);
  }
}

/**
 * The refusal for a request authenticated by a personal user key (a match on
 * users.api_key_hash), or null when the key may be used here. Callers that
 * work with next(err) pass it on; the rest throw it.
 */
export function userKeyIngressError(req, userId, via = 'rest') {
  const port = privateApiPort();
  if (!port || !isPublicIngress(req)) return null;
  auditRefusal(userId, req, via);
  return new AppError(userKeyRefusedMessage(port), 403, USER_KEY_REFUSED_CODE);
}

/**
 * For a route that matched a personal user key with its own lookup: throws if
 * the account is deactivated, the key expired or this ingress refuses it, and
 * otherwise records the use (a refusal is not a use).
 */
export function assertUserKeyIngress(req, userId, via) {
  assertUserKeyUsable(req, userId);
  const err = userKeyIngressError(req, userId, via);
  if (err) throw err;
  recordUserKeyUse(userId);
}

/** For a platform-admin status view. */
export function privateApiStatus(env = process.env) {
  const port = privateApiPort(env);
  return { configured: !!port, port, user_keys_public: !port };
}

export function _resetIngressAuditForTests() { auditedAt.clear(); }
