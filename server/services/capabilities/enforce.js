// The one check every write path calls before it turns a gated capability on.
//
// `needed` is only the part of the change that is NEW: a write that keeps what
// the app already has (a read-modify-write echo, a grandfathered setting) needs
// nothing, so callers compute it with the helpers below and pass null for "no
// new capability". With approval not required the caller's own rule (the one
// from before approvals) is all that applies.

import { capabilityDef } from './registry.js';
import { approvalRequired, activeScopes, pendingRequest, approvalRequiredError, recordImplicitGrant } from './store.js';
import { parseBypassPaths } from '../../utils/authBypassPaths.js';
import { logAudit } from '../../middleware/audit.js';

/**
 * Returns { ok: true, via: 'policy-off' | 'nothing-new' | 'grant' | 'implicit', capability, scope }
 * or throws a 403 CAPABILITY_APPROVAL_REQUIRED naming how to request it.
 *
 * user: the caller, or null for a deploy-time or runtime check (nobody to
 * record an implicit grant for). A human platform admin's direct setting is
 * allowed and comes back as via 'implicit': the caller records it with
 * recordImplicit() once its write has committed, so a write refused later in
 * the same request leaves no grant behind. An agent identity never gets one.
 */
export function checkCapability(db, { app, user = null, capability, needed }) {
  const c = capabilityDef(capability);
  if (!approvalRequired(db, capability)) return { ok: true, via: 'policy-off', capability };
  if (needed == null) return { ok: true, via: 'nothing-new', capability };
  if (c.covers(activeScopes(db, app.id, capability), needed)) return { ok: true, via: 'grant', capability };
  if (user && user.role === 'platform_admin' && user.kind !== 'agent') return { ok: true, via: 'implicit', capability, scope: needed };
  throw approvalRequiredError(app, capability, needed, pendingRequest(db, app.id, capability));
}

/**
 * Record the implicit grants among `checks` (results of checkCapability).
 * Returns their ids. Only a platform admin signed in to the dashboard leaves a
 * durable grant: the same rule as deciding a request (APPROVAL_REQUIRES_SESSION).
 * Over an API key, MCP key or OAuth token the write still goes ahead (platform
 * admins may set it) and is audited, but no grant is recorded, so a leaked key
 * cannot leave the owner an approval to reuse later. `channel` is the caller's
 * req.auth_kind; MCP tools carry it on user._stepUp.
 */
export function recordImplicit(db, { app, user, via, channel }, checks) {
  const ids = [];
  const kind = channel ?? user?._stepUp?.kind ?? null;
  for (const ch of checks) {
    if (ch?.via !== 'implicit') continue;
    if (kind !== 'session') {
      logAudit(user.id, app.id, 'capability-admin-direct', { capability: ch.capability, scope: ch.scope, via, channel: kind, grant_recorded: false });
      continue;
    }
    ids.push(recordImplicitGrant(db, { app, user, capability: ch.capability, scope: ch.scope, via }));
  }
  return ids;
}

/** checkCapability then, for a caller with no write of its own to wait for, recordImplicit. */
export function requireCapability(db, { app, user = null, capability, needed, via = 'api' }) {
  const out = checkCapability(db, { app, user, capability, needed });
  recordImplicit(db, { app, user, via }, [out]);
  return out;
}

export function neededBypassPaths(app, nextPaths) {
  if (!nextPaths || nextPaths.length === 0) return null;
  const current = new Set(parseBypassPaths(app.auth_bypass_paths, () => {}));
  const added = nextPaths.filter((p) => !current.has(p));
  return added.length ? { paths: [...new Set(added)].sort() } : null;
}

export function neededHeadless(app, nextMode) {
  return nextMode === 'headless' && app.auth_mode !== 'headless' ? {} : null;
}

export function neededPublic(app, nextVisibility) {
  return nextVisibility === 'public' && (app.visibility || 'private') !== 'public' ? {} : null;
}

/**
 * A custom domain served without AppCrane sign-in. `next` is the domain and
 * custom_domain_auth the app will have after the change. New when the
 * unprotected domain differs from the one the app already serves unprotected:
 * a new domain with sign-in off, or sign-in turned off on the current one.
 */
export function neededUnprotectedDomain(app, { domain, auth }) {
  const next = String(domain ?? '').trim().toLowerCase();
  if (!next || auth) return null;
  const cur = String(app?.domain ?? '').trim().toLowerCase();
  const curUnprotected = cur && !app?.custom_domain_auth ? cur : null;
  return next === curUnprotected ? null : { domains: [next] };
}

export function neededEngine(db, app, engine) {
  const has = db.prepare('SELECT 1 FROM managed_databases WHERE app_id = ? AND engine = ? LIMIT 1').get(app.id, engine);
  return has ? null : { engines: [engine] };
}

/** One recipient's domain, lower-cased; null for an address with none (the queue then refuses it). */
export function recipientDomain(to) {
  const s = String(to ?? '').trim().toLowerCase();
  const at = s.lastIndexOf('@');
  return at > 0 && at < s.length - 1 ? s.slice(at + 1) : null;
}

/**
 * The ingress an app will have after a change, in tcp_ports scope shape.
 * `next` carries the effective values the write path has already resolved;
 * a port left unnamed is the one the row holds, or null for "allocate one".
 */
export function portScopeOf({ ingress_type, public_port = null, sandbox_public_port = null, data_plane_port = null, data_plane_protocol = 'tcp' }) {
  return {
    ingress_type,
    public_port: Number.isInteger(public_port) ? public_port : null,
    sandbox_public_port: Number.isInteger(sandbox_public_port) ? sandbox_public_port : null,
    data_plane_port: ingress_type === 'dual' && Number.isInteger(data_plane_port) ? data_plane_port : null,
    data_plane_protocol: ingress_type === 'dual' ? (data_plane_protocol || 'tcp') : 'tcp',
  };
}

/**
 * App creation with a custom domain: a new app has no grants yet, and its
 * custom domain starts with sign-in off, so only a human platform admin may
 * name one at create (returned as a check to record once the row exists).
 * Anyone else creates the app first, then requests the domain.
 */
export function refuseDomainAtCreate(db, user, domain) {
  const d = String(domain ?? '').trim().toLowerCase();
  if (!d || !approvalRequired(db, 'custom_domain_unprotected')) return null;
  if (user && user.role === 'platform_admin' && user.kind !== 'agent') {
    return { ok: true, via: 'implicit', capability: 'custom_domain_unprotected', scope: { domains: [d] } };
  }
  const err = approvalRequiredError({ slug: '<slug>' }, 'custom_domain_unprotected', { domains: [d] }, null);
  err.message = `A custom domain is served without AppCrane sign-in until custom_domain_auth is on, and that needs platform admin approval on this platform. Create the app without a domain, then set it with custom_domain_auth on (self-service) or request it. ${err.message}`;
  throw err;
}
