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

const SESSION_TTL_MS = (parseInt(process.env.SESSION_DURATION_HOURS, 10) || 24) * 60 * 60 * 1000;

export function setSessionCookie(res, token, req) {
  res.cookie('cc_token', token, {
    httpOnly: true,
    secure: isHttps(req),
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_MS,
  });
}

export function clearSessionCookie(res) {
  res.clearCookie('cc_token', { path: '/' });
}

function isHttps(req) {
  if (!req) return false;
  if (req.secure) return true;
  if (req.headers?.['x-forwarded-proto'] === 'https') return true;
  return false;
}
