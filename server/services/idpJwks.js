// The configured IdP's signing keys, for verifying ID-JAG assertions
// (services/oauthIdJag.js). Cached for JWKS_TTL_MS. An assertion naming a kid
// the cache does not hold triggers ONE fresh fetch, so a key the IdP has just
// rotated in is accepted without waiting out the cache; that forced fetch is
// allowed at most once per FORCED_REFRESH_MIN_MS per JWKS URL, so a stream of
// assertions with made-up kids cannot make AppCrane hammer the IdP.

export const JWKS_TTL_MS = 10 * 60_000;
export const FORCED_REFRESH_MIN_MS = 60_000;
import { idpFetch } from './idpFetch.js';

const TIMEOUT_MS = 10_000;

const cache = new Map();
const inflight = new Map();

async function fetchKeys(jwksUri, trusted) {
  const r = await idpFetch(jwksUri, { trusted, timeoutMs: TIMEOUT_MS });
  if (!r.ok) throw new Error(`JWKS fetch failed (HTTP ${r.status})`);
  const body = await r.json();
  return Array.isArray(body?.keys) ? body.keys : [];
}

// One fetch per JWKS URL at a time: concurrent callers share it.
function refresh(jwksUri, trusted, stamps) {
  let p = inflight.get(jwksUri);
  if (!p) {
    p = fetchKeys(jwksUri, trusted)
      .then((keys) => { const e = { keys, ...stamps }; cache.set(jwksUri, e); return e; })
      .finally(() => inflight.delete(jwksUri));
    inflight.set(jwksUri, p);
  }
  return p;
}

/** The published key with this kid, or null. `now` is for tests; `trusted` is the configured discovery URL (services/idpFetch.js). */
export async function findSigningKey(jwksUri, kid, now = Date.now(), trusted = null) {
  let entry = cache.get(jwksUri);
  if (!entry || now - entry.fetchedAt >= JWKS_TTL_MS) {
    entry = await refresh(jwksUri, trusted, { fetchedAt: now, forcedAt: entry?.forcedAt ?? 0 });
  }
  let key = entry.keys.find((k) => k.kid === kid);
  if (!key) {
    const pending = inflight.get(jwksUri);
    if (pending) {
      entry = await pending;
      key = entry.keys.find((k) => k.kid === kid);
    } else if (now - entry.forcedAt >= FORCED_REFRESH_MIN_MS) {
      // Claimed before the await, so concurrent callers do not each force one.
      entry.forcedAt = now;
      entry = await refresh(jwksUri, trusted, { fetchedAt: now, forcedAt: now });
      key = entry.keys.find((k) => k.kid === kid);
    }
  }
  return key || null;
}

export function clearJwksCache() {
  cache.clear();
  inflight.clear();
}
