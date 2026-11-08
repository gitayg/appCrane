import { createHash } from 'crypto';
import { clientIp } from '../utils/clientIp.js';

/**
 * Global API rate limiter: 2000 req/min per credential that has authenticated,
 * 600/min per client address otherwise. The client address is req.ip, which is only the real
 * client when trust proxy is configured (see utils/clientIp.js).
 *
 * The admin SPA fans out ~40 requests per dashboard load and auto-refreshes
 * every 30s, so the limits need headroom for that plus normal navigation.
 *
 * /identity/verify gets its own per-client bucket. Caddy's forward_auth calls it
 * once for EVERY request into a hosted app (each asset, each XHR), so sharing
 * the 600/min API bucket let a busy app page starve the same browser's
 * dashboard and sign-in calls, and a looping page do the reverse. It needs no
 * tight limit: it only checks a presented session token, it takes no password,
 * and a 256-bit token cannot be guessed at any request rate. Password login
 * keeps both the generic bucket and its own 5/min throttle in routes/identity.js.
 *
 * This runs before any auth, so a credential header proves nothing yet, and keying
 * on it alone would let a made-up credential per request skip the address limit and
 * add a Map entry per request. So a credential gets a bucket only after a request
 * with it ended authenticated (req.user, set by requireAuth and the routes like it).
 * Until then it counts against a ceiling on its address: `ipAuthed`, or
 * API_RATE_LIMIT_IP_AUTHED, default the authed limit; that proving request moves
 * its count to the credential's own bucket. So valid keys behind one address (an
 * office NAT, containers behind one gateway) share nothing.
 *
 * Counting only 401s would not do: public routes ignore the header and never send
 * one, so made-up credentials on them would stay free. What pays for it: a key not
 * proven yet is refused while its address is over the ceiling, and credentials whose
 * routes do not set req.user stay on the ceiling unless they are also used on a route
 * that does. The address is clientIp's: X-Forwarded-For only counts from a trusted
 * hop, see utils/clientIp.js. /identity/verify has its own ceiling at the verify
 * limit, for the reason above.
 */
export const DEFAULT_LIMITS = Object.freeze({ authed: 2000, ip: 600, verify: 3000, windowMs: 60_000 });
// About 230 bytes an entry (46 MB for 200k), so this bounds the map near 25 MB.
export const MAX_BUCKETS = 100_000;
// Only credentials that authenticated get in here, about one per real key or session.
export const MAX_VERIFIED = 50_000;
const VERIFIED_TTL_MS = 60 * 60_000;

const credHash = (s) => createHash('sha256').update(s).digest('hex').slice(0, 32);

export function rateLimitKey(req) {
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const apiKey = req.headers['x-api-key'] || '';
  // X-API-Key first, as requireAuth reads them: a real key must not vouch for a
  // made-up Bearer sent beside it.
  if (apiKey) return { key: `k:${credHash(apiKey)}`, kind: 'authed' };
  if (bearer) return { key: `t:${credHash(bearer)}`, kind: 'authed' };
  const ip = clientIp(req);
  if (req.path === '/identity/verify') return { key: `v:${ip}`, kind: 'verify' };
  return { key: `ip:${ip}`, kind: 'ip' };
}

function credentialCeiling(req, verifyLimit, ipAuthed) {
  const ip = clientIp(req);
  return req.path === '/identity/verify'
    ? { key: `vauth:${ip}`, limit: verifyLimit }
    : { key: `ipauth:${ip}`, limit: ipAuthed };
}

export function createApiRateLimit(limits = DEFAULT_LIMITS) {
  const { windowMs } = limits;
  const ipAuthed = limits.ipAuthed ?? (parseInt(process.env.API_RATE_LIMIT_IP_AUTHED, 10) || limits.authed);
  const maxBuckets = limits.maxBuckets ?? MAX_BUCKETS;
  const maxVerified = limits.maxVerified ?? MAX_VERIFIED;
  const verifiedTtlMs = limits.verifiedTtlMs ?? VERIFIED_TTL_MS;
  const buckets = new Map();
  const verified = new Map(); // credential key -> proven until, oldest first
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [k, rec] of buckets) { if (now > rec.resetAt) buckets.delete(k); }
    for (const [k, until] of verified) { if (now <= until) break; verified.delete(k); }
  }, 5 * 60_000);
  sweeper.unref?.();

  // Every bucket lives windowMs and a renewed one re-enters at the end, so Map
  // order is expiry order: the front is what has expired, or what expires next.
  function makeRoom(now) {
    for (const [k, rec] of buckets) {
      if (now <= rec.resetAt && buckets.size < maxBuckets) break;
      buckets.delete(k);
    }
  }

  function admit(key, limit, now) {
    const rec = buckets.get(key);
    if (!rec || now > rec.resetAt) {
      buckets.delete(key);
      makeRoom(now);
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    if (rec.count >= limit) return false;
    rec.count++;
    return true;
  }

  function isVerified(key, now) {
    const until = verified.get(key);
    if (until === undefined) return false;
    if (now <= until) return true;
    verified.delete(key);
    return false;
  }

  function remember(key, now) {
    verified.delete(key);
    for (const k of verified.keys()) {
      if (verified.size < maxVerified) break;
      verified.delete(k);
    }
    verified.set(key, now + verifiedTtlMs);
  }

  // Runs when the response ends, once the route has decided about the credential.
  // A cookie can set req.user too, and says nothing about the header beside it.
  function settle(req, res, key, ceiling) {
    if (res.statusCode === 401) { verified.delete(key); return; }
    if (!req.user || req.authed_by_cookie) return;
    const now = Date.now();
    remember(key, now);
    if (!ceiling) return;
    const rec = buckets.get(ceiling.key);
    if (rec && now <= rec.resetAt && rec.count > 0) rec.count--;
    admit(key, limits.authed, now);
  }

  const tooMany = (res) => res.status(429).json({ error: { message: 'Too many requests', code: 'RATE_LIMITED' } });

  function apiRateLimit(req, res, next) {
    const { key, kind } = rateLimitKey(req);
    const now = Date.now();
    if (kind !== 'authed') return admit(key, limits[kind], now) ? next() : tooMany(res);
    const ceiling = isVerified(key, now) ? null : credentialCeiling(req, limits.verify, ipAuthed);
    if (!(ceiling ? admit(ceiling.key, ceiling.limit, now) : admit(key, limits.authed, now))) return tooMany(res);
    res.once('close', () => settle(req, res, key, ceiling));
    next();
  }
  apiRateLimit.buckets = buckets;
  apiRateLimit.verified = verified;
  return apiRateLimit;
}
