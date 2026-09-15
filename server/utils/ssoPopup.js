// Popup sign-in for AppCrane pages running inside an iframe.
//
// Identity providers refuse to be framed (X-Frame-Options / frame-ancestors),
// so a framed sign-in page cannot navigate its own frame to the IdP. Instead
// the SPA opens /api/auth/{oidc,saml}/start?mode=popup in a top-level popup.
// The callback then answers with a small completion page rather than the
// usual /login?oidc_token=… forward: the session cookie is set exactly as in
// the normal callback, and the page tells same-origin listeners "signed-in"
// over a BroadcastChannel and closes itself.
//
// Popup mode is decided ONLY from state AppCrane signed at /start — the OIDC
// `state` (HMAC-signed, already checked for CSRF) or, for SAML, a signed
// RelayState built here. A `mode` on the callback request is never read.
//
// Measured in Chrome 153: an IdP sending Cross-Origin-Opener-Policy:
// same-origin severs window.opener for the rest of the popup's life, so the
// completion page cannot postMessage its opener. BroadcastChannel between the
// popup and the frame (same origin, same top-level site) still delivers.
import crypto from 'crypto';

export const POPUP_MODE = 'popup';
export const SSO_CHANNEL = 'appcrane-sso';
const STATE_TTL_MS = 10 * 60 * 1000;
const RELAY_PREFIX = 'popup.';

/** The mode a /start request asked for: 'popup' or '' (the normal flow). */
export function requestedMode(query) {
  return query && query.mode === POPUP_MODE ? POPUP_MODE : '';
}

function relaySignature(body) {
  // Domain-separated from the OIDC state HMAC, and truncated to 128 bits so the
  // whole RelayState stays under SAML's 80-byte limit.
  return crypto.createHmac('sha256', process.env.ENCRYPTION_KEY)
    .update('saml-popup-relay|' + body).digest('base64url').slice(0, 22);
}

/** A signed SAML RelayState that marks the flow as popup mode (~46 bytes). */
export function makePopupRelayState() {
  const body = `${Date.now().toString(36)}.${crypto.randomBytes(4).toString('hex')}`;
  return `${RELAY_PREFIX}${body}.${relaySignature(body)}`;
}

/** True only for a RelayState made by makePopupRelayState that is under 10 minutes old. */
export function isPopupRelayState(value) {
  if (typeof value !== 'string' || !value.startsWith(RELAY_PREFIX)) return false;
  const parts = value.slice(RELAY_PREFIX.length).split('.');
  if (parts.length !== 3) return false;
  const [ts, nonce, sig] = parts;
  const expected = Buffer.from(relaySignature(`${ts}.${nonce}`));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return false;
  const t = parseInt(ts, 36);
  const age = Date.now() - t;
  return Number.isFinite(t) && age >= -60_000 && age <= STATE_TTL_MS;
}

export const POPUP_COMPLETE_SCRIPT = `(function () {
  try {
    var ch = new BroadcastChannel(${JSON.stringify(SSO_CHANNEL)});
    ch.postMessage({ type: 'signed-in' });
    ch.close();
  } catch (_) {}
  setTimeout(function () { window.close(); }, 300);
})();
`;

const POPUP_COMPLETE_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed in</title>
<style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1117;color:#e4e4e7;font:15px -apple-system,system-ui,sans-serif}</style>
</head><body><p>Signed in. You can close this window.</p>
<script src="/api/auth/popup/complete.js"></script>
</body></html>`;

/**
 * Answer a popup-mode callback. Top-level only: frame-ancestors 'none' and
 * X-Frame-Options DENY. Carries no token, user, or redirect.
 */
export function sendPopupComplete(res) {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.status(200).type('html').send(POPUP_COMPLETE_HTML);
}
