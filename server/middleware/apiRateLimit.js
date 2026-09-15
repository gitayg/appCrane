import { createHash } from 'crypto';
import { clientIp } from '../utils/clientIp.js';

/**
 * Global API rate limiter: 2000 req/min per credential, 600/min per client
 * address otherwise. The client address is req.ip, which is only the real
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
 */
export const DEFAULT_LIMITS = Object.freeze({ authed: 2000, ip: 600, verify: 3000, windowMs: 60_000 });

const credHash = (s) => createHash('sha256').update(s).digest('hex').slice(0, 32);

export function rateLimitKey(req) {
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const apiKey = req.headers['x-api-key'] || '';
  if (bearer) return { key: `t:${credHash(bearer)}`, kind: 'authed' };
  if (apiKey) return { key: `k:${credHash(apiKey)}`, kind: 'authed' };
  const ip = clientIp(req);
  if (req.path === '/identity/verify') return { key: `v:${ip}`, kind: 'verify' };
  return { key: `ip:${ip}`, kind: 'ip' };
}

export function createApiRateLimit(limits = DEFAULT_LIMITS) {
  const { windowMs } = limits;
  const buckets = new Map();
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [k, rec] of buckets) { if (now > rec.resetAt) buckets.delete(k); }
  }, 5 * 60_000);
  sweeper.unref?.();

  function apiRateLimit(req, res, next) {
    const { key, kind } = rateLimitKey(req);
    const limit = limits[kind];
    const now = Date.now();
    const rec = buckets.get(key);
    if (!rec || now > rec.resetAt) { buckets.set(key, { count: 1, resetAt: now + windowMs }); return next(); }
    if (rec.count >= limit) return res.status(429).json({ error: { message: 'Too many requests', code: 'RATE_LIMITED' } });
    rec.count++;
    next();
  }
  apiRateLimit.buckets = buckets;
  return apiRateLimit;
}
