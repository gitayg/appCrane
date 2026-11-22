// Verified AppCrane identity.
//
// AppCrane's proxy checks every visitor and forwards who they are as
// X-AppCrane-* request headers. Those headers are only trustworthy when their
// signature checks out: a request that reaches this container any other way
// (a published TCP port, another container on the same host) can carry any
// headers it likes. So this module never reads an identity header until the
// v2 signature over all of them matches, using the per-app, per-environment
// secret AppCrane injects as APPCRANE_IDENTITY_SECRET.
//
// The signed text is, joined with "\n":
//   appcrane-identity-v2
//   <X-AppCrane-Identity-Ts>
//   one "name:value" line per header in SIGNED_HEADERS_V2 (absent = empty)
// HMAC-SHA256 with the secret, base64url, sent as X-AppCrane-Identity-Sig-V2.
//
// Framework-neutral: pass anything with a lowercase `headers` object (Node's
// http.IncomingMessage, an Express req).

import { createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNED_HEADERS_V2 = Object.freeze([
  'x-appcrane-user',
  'x-appcrane-user-id',
  'x-appcrane-user-email',
  'x-appcrane-user-name',
  'x-appcrane-user-role',
  'x-appcrane-app-role',
  'x-appcrane-is-admin',
  'x-appcrane-app-roles',
  'x-appcrane-auth-via',
]);

export const MAX_AGE_SEC = 300;
const MAX_CLOCK_SKEW_SEC = 60;

// Per-app role ladder. Compare with atLeast(), never with ===: an owner must
// pass an "admin" check.
export const ROLE_RANK = Object.freeze({ none: 0, viewer: 1, user: 2, admin: 3, owner: 4 });

export function atLeast(appRole, min) {
  return (ROLE_RANK[appRole] ?? 0) >= ROLE_RANK[min];
}

function headerValue(headers, name) {
  const v = headers?.[name];
  if (v === undefined || v === null) return '';
  return Array.isArray(v) ? v.join(', ') : String(v);
}

/** The base64url v2 signature over `headers` (a lowercase-keyed object). */
export function signIdentityV2(secret, ts, headers) {
  const lines = ['appcrane-identity-v2', String(ts), ...SIGNED_HEADERS_V2.map((h) => `${h}:${headerValue(headers, h)}`)];
  return createHmac('sha256', secret).update(lines.join('\n')).digest('base64url');
}

function sameString(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function decodeName(raw) {
  if (!raw) return '';
  try { return decodeURIComponent(raw); } catch { return raw; }
}

/**
 * Check the request's identity. Returns { ok: true, identity } or
 * { ok: false, code, message }. Never throws for a bad request, and never
 * echoes a header value back in its message.
 */
export function verifyRequest(req, { secret = process.env.APPCRANE_IDENTITY_SECRET, now = Date.now() } = {}) {
  if (!secret) {
    return { ok: false, code: 'IDENTITY_NOT_CONFIGURED', message: 'APPCRANE_IDENTITY_SECRET is not set, so no identity can be verified' };
  }
  const headers = req?.headers || {};
  const sig = headerValue(headers, 'x-appcrane-identity-sig-v2');
  const ts = headerValue(headers, 'x-appcrane-identity-ts');
  if (!sig || !/^\d{1,12}$/.test(ts)) {
    return { ok: false, code: 'IDENTITY_UNSIGNED', message: 'the request carries no signed AppCrane identity' };
  }
  if (!sameString(signIdentityV2(secret, ts, headers), sig)) {
    return { ok: false, code: 'IDENTITY_FORGED', message: 'the identity signature does not match' };
  }
  const age = Math.floor(now / 1000) - Number(ts);
  if (age > MAX_AGE_SEC || age < -MAX_CLOCK_SKEW_SEC) {
    return { ok: false, code: 'IDENTITY_EXPIRED', message: 'the identity signature is too old' };
  }
  const userId = headerValue(headers, 'x-appcrane-user-id');
  if (!/^\d+$/.test(userId)) {
    return { ok: false, code: 'IDENTITY_UNSIGNED', message: 'the signed identity names no user' };
  }
  const appRole = headerValue(headers, 'x-appcrane-app-role');
  return {
    ok: true,
    identity: {
      userId,
      email: headerValue(headers, 'x-appcrane-user-email') || headerValue(headers, 'x-appcrane-user'),
      name: decodeName(headerValue(headers, 'x-appcrane-user-name')),
      platformRole: headerValue(headers, 'x-appcrane-user-role'),
      appRole: Object.hasOwn(ROLE_RANK, appRole) ? appRole : 'none',
      isAppAdmin: atLeast(appRole, 'admin'),
      appRoles: headerValue(headers, 'x-appcrane-app-roles').split(',').map((s) => s.trim()).filter(Boolean),
      authVia: headerValue(headers, 'x-appcrane-auth-via') || 'session',
    },
  };
}
