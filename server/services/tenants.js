import { rmSync } from 'fs';
import { confinedHostPath } from './appDataWrite.js';
import { join, resolve, sep } from 'path';
import log from '../utils/logger.js';
import { orgFromEmail } from '../../packages/tenant/index.js';

// Cooperative per-tenant DB model. A tenant is (org, user); org is derived from
// the user's email domain. THIS DERIVATION IS THE PUBLIC CONTRACT — the
// app-side helper must compute the identical tenant path from the signed
// identity headers (X-AppCrane-User-Email + X-AppCrane-User-Id), or purge and
// the app would disagree on which file is whose.
//
// They no longer have to be kept in lockstep by hand: this module imports the
// derivation from packages/tenant and re-exports it, so there is one function.
// The direction matters — packages/tenant ships to the apps and must not import
// anything server-side, so the dependency only ever points this way.

export const TENANT_ROOT = 'tenants';

/**
 * org slug from an email address: the domain after the last '@', lowercased and
 * restricted to [a-z0-9.-]. Missing/malformed email → 'unknown'. Defined in
 * packages/tenant so the app side and this side cannot diverge; re-exported
 * here because callers have always imported it from this module.
 */
export { orgFromEmail };

/** Relative tenant dir under an app's /data, e.g. tenants/acme.com/u42 */
export function tenantDirRel(org, userId) {
  return join(TENANT_ROOT, orgSlug(org), `u${String(userId).replace(/[^0-9]/g, '')}`);
}

// org is already a slug from orgFromEmail, but re-sanitize defensively in case
// a caller passes a raw value — never trust an unslugged segment into a path.
function orgSlug(org) {
  const slug = String(org || '').toLowerCase().replace(/[^a-z0-9.-]/g, '');
  if (!slug || slug === '.' || slug === '..') return 'unknown';
  return slug;
}

/**
 * Delete a tenant's data dir for one app across every env. Best-effort and
 * idempotent — a non-existent dir (non-multitenant app, or a tenant that never
 * wrote anything) is a no-op. Never throws into the caller.
 */
export function purgeTenant(slug, email, userId) {
  const dataDir = resolve(process.env.DATA_DIR || './data');
  const org = orgFromEmail(email);
  const rel = tenantDirRel(org, userId);
  let removed = 0;
  for (const env of ['production', 'sandbox']) {
    const base = resolve(join(dataDir, 'apps', slug, env, 'shared', 'data'));
    const target = resolve(join(base, rel));
    // Path-traversal guard: target must stay strictly within the app's data root.
    if (target !== base && !target.startsWith(base + sep)) continue;
    // Security audit 2026-10-06, M3: the tenants/ tree is app-writable, so a
    // planted link at tenants/<org> redirected this delete into another app.
    // Walk it with lstat: any link on the way and nothing is deleted.
    let safe;
    try {
      safe = confinedHostPath(base, rel);
    } catch (e) {
      if (/symbolic link/.test(e.message)) log.warn(`purgeTenant: ${slug}/${env}: ${e.message}; nothing deleted`);
      continue;
    }
    try {
      rmSync(safe, { recursive: true, force: true });
      removed++;
    } catch (e) {
      log.warn(`purgeTenant: failed to remove ${target}: ${e.message}`);
    }
  }
  if (removed) log.info(`purgeTenant: purged ${rel} for app ${slug} (${removed} env(s))`);
}

/**
 * Purge a user's tenant data on each multitenant app in `appIds`, which the
 * caller has just removed their access to. Every path that removes access
 * calls this after its own writes: the dashboard's role 'none', deleting the
 * user, and SCIM group removal (the MCP revoke tool purges inline). An app
 * that never opted in is left alone. Never throws into the caller.
 */
export function purgeRevokedTenants(db, userId, email, appIds) {
  for (const appId of appIds) {
    try {
      const app = db.prepare('SELECT slug, multitenant FROM apps WHERE id = ?').get(appId);
      if (!app?.multitenant) continue;
      purgeTenant(app.slug, email, userId);
    } catch (e) {
      log.warn(`purgeRevokedTenants: app ${appId} user ${userId}: ${e.message}`);
    }
  }
}
