// appcrane-tenant — cooperative per-tenant DB helper for apps hosted on AppCrane.
//
// Derives an isolated SQLite DB path per (org, user) from the platform-signed
// identity headers AppCrane forwards to every request (see the AppCrane README,
// "Identity contract for deployed apps" §4). Enable it by setting
// `"multitenant": true` in your deployhub.json; AppCrane then injects
// APPCRANE_TENANT_ROOT and purges a tenant's dir when their access is revoked.
//
// IMPORTANT: the org + path derivation here MUST stay byte-identical to
// AppCrane server-side (server/services/tenants.js). If the two disagree,
// purge-on-revoke and the app would target different files. Keep them in sync.

import { mkdirSync } from 'fs';
import { join } from 'path';
import { createRequire } from 'module';

// Read a header from an Express req (req.get), a Node req (req.headers), or a
// plain headers object — so the helper works regardless of the app's framework.
function header(req, name) {
  if (!req) return '';
  if (typeof req.get === 'function') return req.get(name) || '';
  const h = req.headers || req;
  return (h[name] || h[name.toLowerCase()] || '');
}

/**
 * org slug from an email: the domain after the last '@', lowercased and
 * restricted to [a-z0-9.-]. Missing/malformed → 'unknown'. The sanitisation
 * also makes the value safe as a single path segment (no '/' or '..').
 */
export function orgFromEmail(email) {
  const parts = String(email || '').toLowerCase().split('@');
  const domain = parts.length > 1 ? parts.pop() : '';
  const slug = domain.replace(/[^a-z0-9.-]/g, '');
  // '.' and '..' are path-traversal segments (e.g. a@.. → join(root,'..') escapes
  // the tenant root). No real domain is pure dots, so reject them.
  if (!slug || slug === '.' || slug === '..') return 'unknown';
  return slug;
}

/** { org, userId } for the request. Throws if the request carries no identity. */
export function tenantKey(req) {
  const email = header(req, 'X-AppCrane-User-Email');
  const userId = String(header(req, 'X-AppCrane-User-Id')).replace(/[^0-9]/g, '');
  if (!userId) {
    throw new Error('appcrane-tenant: no tenant identity on request (missing X-AppCrane-User-Id)');
  }
  return { org: orgFromEmail(email), userId };
}

/** Absolute tenant dir, e.g. /data/tenants/acme.com/u42. Created unless create:false. */
export function tenantDir(req, { root = process.env.APPCRANE_TENANT_ROOT || '/data/tenants', create = true } = {}) {
  const { org, userId } = tenantKey(req);
  const dir = join(root, org, 'u' + userId);
  if (create) mkdirSync(dir, { recursive: true });
  return dir;
}

/** Absolute path to the tenant's db.sqlite (dependency-free — no better-sqlite3 needed). */
export function tenantDbPath(req, opts) {
  return join(tenantDir(req, opts), 'db.sqlite');
}

/**
 * Open the tenant's SQLite DB with better-sqlite3 (an optional peer dependency).
 * better-sqlite3 is required lazily, so apps that only need tenantDbPath() (or
 * use a different SQLite driver) don't have to install a native module.
 */
export function tenantDb(req, opts) {
  let Database;
  try {
    Database = createRequire(import.meta.url)('better-sqlite3');
  } catch {
    throw new Error(
      'appcrane-tenant: tenantDb() needs better-sqlite3 installed (optional peer dependency). ' +
      'Run `npm i better-sqlite3`, or call tenantDbPath() for a dependency-free path.'
    );
  }
  return new Database(tenantDbPath(req, opts));
}
