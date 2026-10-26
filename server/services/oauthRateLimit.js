import { clientIp } from '../utils/clientIp.js';

// Fixed-window per-client-address limits for the public OAuth endpoints, which
// sit outside /api and so outside the global API limiter. In memory, one process.
// OAUTH_REGISTER_PER_HOUR raises the registration ceiling for an install whose
// clients all arrive from one address (a NAT, or a test run).
const registerPerHour = Math.max(1, parseInt(process.env.OAUTH_REGISTER_PER_HOUR, 10) || 20);
export const OAUTH_LIMITS = Object.freeze({
  register: { max: registerPerHour, windowMs: 60 * 60_000 },
  token: { max: 60, windowMs: 60_000 },
  authorize: { max: 60, windowMs: 60_000 },
});

export function createOAuthLimiter(name, limits = OAUTH_LIMITS[name]) {
  const buckets = new Map();
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [k, rec] of buckets) { if (now > rec.resetAt) buckets.delete(k); }
  }, 5 * 60_000);
  sweeper.unref?.();
  function limiter(req, res, next) {
    const key = clientIp(req);
    const now = Date.now();
    const rec = buckets.get(key);
    if (!rec || now > rec.resetAt) { buckets.set(key, { count: 1, resetAt: now + limits.windowMs }); return next(); }
    if (rec.count >= limits.max) {
      res.set('Retry-After', String(Math.ceil((rec.resetAt - now) / 1000)));
      return res.status(429).json({ error: 'slow_down', error_description: 'Too many requests' });
    }
    rec.count++;
    next();
  }
  limiter.buckets = buckets;
  return limiter;
}
