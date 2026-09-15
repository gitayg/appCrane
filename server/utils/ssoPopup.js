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

/**
 * True only for a RelayState made by makePopupRelayState that is under 10
 * minutes old. `allowExpired` drops the age check: a failure page may use an
 * expired but genuine RelayState to learn it is a popup, a session never may.
 */
export function isPopupRelayState(value, { allowExpired = false } = {}) {
  if (typeof value !== 'string' || !value.startsWith(RELAY_PREFIX)) return false;
  const parts = value.slice(RELAY_PREFIX.length).split('.');
  if (parts.length !== 3) return false;
  const [ts, nonce, sig] = parts;
  const expected = Buffer.from(relaySignature(`${ts}.${nonce}`));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return false;
  if (allowExpired) return true;
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

const POPUP_PAGE_STYLE = 'body{margin:0;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;background:#0f1117;color:#e4e4e7;font:15px -apple-system,system-ui,sans-serif;text-align:center;padding:0 24px;box-sizing:border-box}button{font:inherit;margin-top:12px;padding:8px 20px;border-radius:6px;border:1px solid #3f3f46;background:#27272a;color:#e4e4e7;cursor:pointer}';

const POPUP_COMPLETE_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed in</title>
<style>${POPUP_PAGE_STYLE}</style>
</head><body><p>Signed in. You can close this window.</p>
<script src="/api/auth/popup/complete.js"></script>
</body></html>`;

// ---- failure ----------------------------------------------------------------
//
// A popup-mode sign-in that fails tells the frame { type: 'sign-in-failed' } so
// it stops waiting, and shows a short reason with a Close button. It does not
// close itself: the user should see why. The reason comes from a fixed table
// keyed by code; no IdP text or exception message ever reaches the page.
//
// How a failing callback knows it is a popup. Measured in Chrome 153 against
// an IdP sending COOP same-origin: the window.name that window.open() set is
// "" on the IdP page and still "" once back on AppCrane, so the page cannot
// tell by itself. Only AppCrane-signed state decides: an OIDC `state` whose
// signature verifies (even if expired), or a SAML RelayState from
// makePopupRelayState (even if expired). A missing, garbled or modified state
// is not popup mode and gets the normal /login?sso_error redirect, and a
// `mode` on the callback request is never read.

export const POPUP_FAILURE_REASONS = Object.freeze({
  denied: 'The identity provider did not approve the sign-in.',
  no_account: 'There is no AppCrane account for this user. Ask an administrator for access.',
  expired: 'The sign-in took too long.',
  unavailable: 'The identity provider could not be reached.',
  failed: 'Sign-in could not be completed.',
});

/** A POPUP_FAILURE_REASONS code for an IdP `error` parameter (RFC 6749 4.1.2.1). */
export function idpErrorCode(error) {
  return error === 'access_denied' ? 'denied' : 'failed';
}

/** An Error that carries a popup failure code; the message stays server-side. */
export function popupFailure(code, message) {
  return Object.assign(new Error(message), { popupCode: code });
}

export const POPUP_FAILED_SCRIPT = `(function () {
  try {
    var ch = new BroadcastChannel(${JSON.stringify(SSO_CHANNEL)});
    ch.postMessage({ type: 'sign-in-failed' });
    ch.close();
  } catch (_) {}
  var btn = document.getElementById('close');
  if (btn) btn.addEventListener('click', function () { window.close(); });
})();
`;

function popupFailedHtml(code) {
  const reason = POPUP_FAILURE_REASONS[Object.hasOwn(POPUP_FAILURE_REASONS, code) ? code : 'failed'];
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in didn't complete</title>
<style>${POPUP_PAGE_STYLE}</style>
</head><body><p><strong>Sign-in didn't complete.</strong></p><p>${reason}</p>
<button type="button" id="close">Close</button>
<script src="/api/auth/popup/failed.js"></script>
</body></html>`;
}

function setPopupHeaders(res) {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

/**
 * Answer a popup-mode callback. Top-level only: frame-ancestors 'none' and
 * X-Frame-Options DENY. Carries no token, user, or redirect.
 */
export function sendPopupComplete(res) {
  setPopupHeaders(res);
  res.status(200).type('html').send(POPUP_COMPLETE_HTML);
}

/** Answer a failed popup-mode sign-in: same headers as success, no session, no error text. */
export function sendPopupFailed(res, code) {
  setPopupHeaders(res);
  res.status(200).type('html').send(popupFailedHtml(code));
}
