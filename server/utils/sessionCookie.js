// v2.6.18: server-managed `cc_token` cookie.
//
// Pre-fix, the SPA wrote this cookie client-side after login (see
// studio-web/src/components/Login.tsx `setAuthCookie`). Any flow that
// reached a per-app route WITHOUT the SPA having run first — direct
// navigation, new tab, browser restart, link click after a long idle —
// hit a missing cookie at Caddy's `forward_auth`, which 302'd to /login,
// which the SPA's login page bounced to /applications because the
// dashboard session was valid but the app-side cookie wasn't reaching.
//
// This module is the single point where the cookie is set / cleared
// from the server, used by every endpoint that creates or invalidates
// an `identity_sessions` row: password login, set-password (issues a
// fresh session), OIDC callback, SAML callback, and logout.
//
// v2.7.8: now httpOnly. The SPA no longer reads or writes this cookie — the
// server owns it end to end. On load the SPA re-establishes it via
// POST /api/identity/refresh-cookie (Bearer the localStorage session token)
// rather than writing document.cookie, and logout deletes the session row
// server-side (so a lingering cookie is a dead token /verify rejects).
// httpOnly means an XSS payload can no longer read the session token out of
// the cookie.
//
// With per-app origins on (services/appOrigin.js) the cookie is
// `__Host-cc_token` instead: an app host under the platform's domain can set
// a `cc_token` cookie for that domain, never a __Host- one, so the legacy name
// is no longer read at all. Off, `cc_token` exactly as before.

import { getDb } from '../db.js';
import {
  isolationEnabled,
  PLATFORM_SESSION_COOKIE_ISOLATED,
  PLATFORM_SESSION_COOKIE_LEGACY,
} from '../services/appOrigin.js';

const SESSION_TTL_MS = (parseInt(process.env.SESSION_DURATION_HOURS, 10) || 24) * 60 * 60 * 1000;

function isolated() {
  return isolationEnabled(getDb());
}

/** The name the platform session cookie has right now. */
export function platformCookieName() {
  return isolated() ? PLATFORM_SESSION_COOKIE_ISOLATED : PLATFORM_SESSION_COOKIE_LEGACY;
}

export function readCookie(req, name) {
  const raw = req.headers?.cookie || '';
  const m = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  if (!m) return null;
  try { return decodeURIComponent(m[1]); } catch (_) { return m[1]; }
}

/** The platform session token from this request's cookie, or null. */
export function readSessionCookie(req) {
  return readCookie(req, platformCookieName());
}

export function setSessionCookie(res, token, req) {
  if (isolated()) {
    res.cookie(PLATFORM_SESSION_COOKIE_ISOLATED, token, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: SESSION_TTL_MS,
    });
    return;
  }
  res.cookie('cc_token', token, {
    httpOnly: true,
    secure: isHttps(req),
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_MS,
  });
}

export function clearSessionCookie(res) {
  if (isolated()) {
    res.clearCookie(PLATFORM_SESSION_COOKIE_ISOLATED, { path: '/', secure: true, httpOnly: true, sameSite: 'lax' });
  }
  res.clearCookie('cc_token', { path: '/' });
}

// App hosts are same-site with the platform once isolation is on, so SameSite
// no longer stops one of them from sending a write with the platform cookie.
// A cookie-authenticated write must come from the platform's own pages.
export function cookieWriteAllowed(req) {
  if (!isolated()) return true;
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
  const site = req.headers['sec-fetch-site'];
  if (site) return site === 'same-origin';
  const origin = req.headers.origin;
  const domain = String(process.env.CRANE_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
  return !!origin && !!domain && origin === `https://${domain}`;
}

function isHttps(req) {
  if (!req) return false;
  if (req.secure) return true;
  if (req.headers?.['x-forwarded-proto'] === 'https') return true;
  return false;
}
