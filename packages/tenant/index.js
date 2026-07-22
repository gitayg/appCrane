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

import { mkdirSync, statSync, readdirSync } from 'fs';
import { join, basename } from 'path';
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

// ── Per-tenant file storage ────────────────────────────────────────────────

/** Absolute path to the tenant's storage dir (`<tenantDir>/storage/`), created unless create:false. */
export function tenantStorageDir(req, opts = {}) {
  const dir = join(tenantDir(req, opts), 'storage');
  if (opts.create !== false) mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Safe absolute path for a named file inside the tenant's storage dir. `name` is
 * reduced to its basename and rejected if it's empty, '.', '..', or contains a
 * NUL — so a caller can pass a user-supplied filename without traversal risk.
 */
export function tenantFile(req, name, opts) {
  const safe = basename(String(name || ''));
  if (!safe || safe === '.' || safe === '..' || safe.includes('\0')) {
    throw new Error('appcrane-tenant: invalid filename');
  }
  return join(tenantStorageDir(req, opts), safe);
}

// ── Per-tenant quota ───────────────────────────────────────────────────────

/** Total bytes used by the tenant (db + storage). Walks the dir tree; O(files). */
export function tenantUsage(req, opts = {}) {
  return dirSize(tenantDir(req, { ...opts, create: false }));
}

function dirSize(path) {
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch {
    return 0; // dir doesn't exist yet
  }
  let total = 0;
  for (const e of entries) {
    const p = join(path, e.name);
    if (e.isDirectory()) total += dirSize(p);
    else {
      try { total += statSync(p).size; } catch { /* raced away */ }
    }
  }
  return total;
}

/** Configured per-tenant quota in bytes from APPCRANE_TENANT_QUOTA_BYTES (0/unset = unlimited). */
export function tenantQuotaBytes() {
  const n = Number(process.env.APPCRANE_TENANT_QUOTA_BYTES || 0);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Throw a TENANT_QUOTA_EXCEEDED error if the tenant is at/over quota. No-op when
 * no quota is configured. Call before accepting a write in a multitenant app.
 */
export function assertTenantQuota(req, opts) {
  const quota = tenantQuotaBytes();
  if (!quota) return;
  const used = tenantUsage(req, opts);
  if (used >= quota) {
    const err = new Error(`appcrane-tenant: quota exceeded (${used} / ${quota} bytes)`);
    err.code = 'TENANT_QUOTA_EXCEEDED';
    throw err;
  }
}
