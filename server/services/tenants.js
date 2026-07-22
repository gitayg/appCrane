import { rmSync } from 'fs';
import { join, resolve, sep } from 'path';
import log from '../utils/logger.js';

// Cooperative per-tenant DB model. A tenant is (org, user); org is derived from
// the user's email domain. THIS DERIVATION IS THE PUBLIC CONTRACT — the
// app-side helper must compute the identical tenant path from the signed
// identity headers (X-AppCrane-User-Email + X-AppCrane-User-Id), or purge and
// the app would disagree on which file is whose. Keep the two in lockstep.

export const TENANT_ROOT = 'tenants';

/**
 * org slug from an email address: the domain after the last '@', lowercased and
 * restricted to [a-z0-9.-]. Missing/malformed email → 'unknown'.
 */
export function orgFromEmail(email) {
  const parts = String(email || '').toLowerCase().split('@');
  const domain = parts.length > 1 ? parts.pop() : '';
  const slug = domain.replace(/[^a-z0-9.-]/g, '');
  // '.' and '..' are path-traversal segments (a@.. → join(base,'..') escapes the
  // tenant root). No real domain is pure dots, so reject them.
  if (!slug || slug === '.' || slug === '..') return 'unknown';
  return slug;
}

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
    try {
      rmSync(target, { recursive: true, force: true });
      removed++;
    } catch (e) {
      log.warn(`purgeTenant: failed to remove ${target}: ${e.message}`);
    }
  }
  if (removed) log.info(`purgeTenant: purged ${rel} for app ${slug} (${removed} env(s))`);
}
