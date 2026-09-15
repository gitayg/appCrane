/**
 * Which proxy hops Express may believe about the client address.
 *
 * Every browser request reaches AppCrane through Caddy on the same host,
 * including the forward_auth calls to /api/identity/verify. Without a trust
 * setting req.ip is 127.0.0.1 for all of them, so every per-IP limit (the
 * generic API bucket, the login throttle) was one bucket shared by every user
 * of the instance, and one misbehaving browser could 429 everybody.
 *
 * Caddy sets X-Forwarded-For itself and, for a client not in its own
 * trusted_proxies, discards whatever XFF the client sent (measured against
 * caddy:2 v2.11.4 on both reverse_proxy and forward_auth). So the right-most
 * XFF entry written by a loopback peer is the real client.
 *
 * AppCrane listens on 0.0.0.0 by default, so a remote client can connect to
 * it directly and send any XFF it likes. Only peers named here are believed:
 * the default is `loopback`. `true` and hop counts are refused because they
 * believe XFF from ANY peer, which makes every per-IP limit spoofable.
 */
const UNSAFE = /^(true|\*|\d+)$/i;
const DISABLED = /^(false|off|none|0)$/i;

export function resolveTrustProxy(raw, warn = () => {}) {
  const value = (raw ?? '').toString().trim();
  if (!value) return 'loopback';
  if (DISABLED.test(value)) return false;
  const entries = value.split(',').map(s => s.trim()).filter(Boolean);
  if (!entries.length || entries.some(e => UNSAFE.test(e))) {
    warn(`TRUST_PROXY=${value} would trust X-Forwarded-For from any peer; using loopback instead`);
    return 'loopback';
  }
  return entries;
}

export function configureTrustProxy(app, raw = process.env.TRUST_PROXY, warn) {
  const setting = resolveTrustProxy(raw, warn);
  app.set('trust proxy', setting);
  return setting;
}

export function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}
