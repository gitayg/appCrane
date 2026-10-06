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
import { createHmac, timingSafeEqual } from 'crypto';

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

// ── Signed identity (1.2.0) ────────────────────────────────────────────────
//
// AppCrane's proxy strips client-sent X-AppCrane-* headers, but only traffic
// that goes THROUGH the proxy is covered: a raw tcp/dual port, or (measured on
// Docker Desktop) a sibling container reaching this app's loopback publish via
// host.docker.internal, arrives with whatever headers the sender chose. So
// /api/identity/verify signs what it issues with a secret only this app holds,
// injected as APPCRANE_IDENTITY_SECRET, and verifyIdentity() rejects anything
// it did not sign. AppCrane's server imports these same functions, so the two
// sides cannot disagree about what is signed.

/** The headers covered by the signature, in signing order. */
export const IDENTITY_SIGNED_HEADERS = Object.freeze([
  'X-AppCrane-User', 'X-AppCrane-User-Id', 'X-AppCrane-User-Email', 'X-AppCrane-User-Name',
  'X-AppCrane-User-Role', 'X-AppCrane-App-Role', 'X-AppCrane-Is-Admin', 'X-AppCrane-App-Roles',
]);
export const IDENTITY_MAX_AGE_SEC = 300;

/** base64url HMAC-SHA256 over the version, timestamp and every signed header (absent = empty). */
export function signIdentity(secret, ts, get) {
  const lines = ['appcrane-identity-v1', String(ts),
    ...IDENTITY_SIGNED_HEADERS.map((h) => `${h.toLowerCase()}:${get(h) ?? ''}`)];
  return createHmac('sha256', secret).update(lines.join('\n')).digest('base64url');
}

/**
 * Check the request's identity headers against APPCRANE_IDENTITY_SECRET (or
 * opts.secret) and return { userId, email, org }. Throws on a missing,
 * forged, altered or expired signature. A request whose headers came from
 * anywhere but this app's own /verify call cannot pass.
 */
export function verifyIdentity(req, { secret = process.env.APPCRANE_IDENTITY_SECRET, maxAgeSec = IDENTITY_MAX_AGE_SEC, now = Date.now() } = {}) {
  if (!secret) throw new Error('appcrane-tenant: no APPCRANE_IDENTITY_SECRET to verify the identity signature with');
  const get = (h) => { const v = header(req, h); return v === '' ? undefined : String(v); };
  const sig = get('X-AppCrane-Identity-Sig');
  const ts = get('X-AppCrane-Identity-Ts');
  if (!sig || !ts || !/^\d+$/.test(ts)) throw new Error('appcrane-tenant: identity signature missing');
  const expected = Buffer.from(signIdentity(secret, ts, get));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
    throw new Error('appcrane-tenant: identity signature does not match');
  }
  const age = Math.floor(now / 1000) - Number(ts);
  if (age > maxAgeSec || age < -60) throw new Error(`appcrane-tenant: identity signature expired (${age}s old)`);
  const email = get('X-AppCrane-User-Email') || '';
  return { userId: String(get('X-AppCrane-User-Id') || '').replace(/[^0-9]/g, ''), email, org: orgFromEmail(email) };
}

/**
 * { org, userId } for the request. Throws if the request carries no identity.
 * When APPCRANE_IDENTITY_SECRET is set (AppCrane 2.97.0+ injects it), the
 * identity must also carry a valid signature: forged headers throw.
 */
export function tenantKey(req) {
  if (process.env.APPCRANE_IDENTITY_SECRET) {
    const { org, userId } = verifyIdentity(req);
    if (!userId) throw new Error('appcrane-tenant: no tenant identity on request (missing X-AppCrane-User-Id)');
    return { org, userId };
  }
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
 *
 * `opts.migrations` (1.1.0): an ordered list of schema steps, each a SQL string
 * or a function given the open database. The file is upgraded lazily, on the
 * first open after a deploy, keyed on PRAGMA user_version: step i runs only if
 * user_version <= i, all pending steps run in one IMMEDIATE transaction, and
 * user_version is set to the list's length. So with thousands of tenant files
 * none is upgraded twice, none is left half-upgraded, and two requests opening
 * the same file at once upgrade it once. Append steps; never edit or remove one
 * that has shipped. A file whose user_version is ahead of the list (code rolled
 * back) is opened unchanged.
 */
export function tenantDb(req, opts = {}) {
  let Database;
  try {
    Database = createRequire(import.meta.url)('better-sqlite3');
  } catch {
    throw new Error(
      'appcrane-tenant: tenantDb() needs better-sqlite3 installed (optional peer dependency). ' +
      'Run `npm i better-sqlite3`, or call tenantDbPath() for a dependency-free path.'
    );
  }
  const db = new Database(tenantDbPath(req, opts));
  if (opts.migrations?.length) {
    try {
      migrate(db, opts.migrations);
    } catch (err) {
      db.close();
      throw err;
    }
  }
  return db;
}

function migrate(db, steps) {
  const version = () => db.pragma('user_version', { simple: true });
  if (version() >= steps.length) return;
  // Another connection may be upgrading this file right now: wait for its lock
  // rather than failing with SQLITE_BUSY.
  db.pragma('busy_timeout = 10000');
  db.transaction(() => {
    // Re-read under the write lock: whoever held it before us may have upgraded.
    for (let i = version(); i < steps.length; i++) {
      const step = steps[i];
      if (typeof step === 'function') step(db);
      else db.exec(step);
    }
    db.pragma(`user_version = ${steps.length}`);
  }).immediate();
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
