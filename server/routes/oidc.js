import { Router } from 'express';
import { auditLogin } from '../middleware/audit.js';
import { findOrLinkSsoUser } from '../services/ssoLink.js';
import crypto from 'crypto';
import { getDb } from '../db.js';
import { encrypt, decrypt, generateSessionToken, hashApiKey } from '../services/encryption.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { setSessionCookie, readCookie, platformCookieSecure } from '../utils/sessionCookie.js';
import { safeRedirectTarget } from '../utils/safeRedirect.js';
import { POPUP_MODE, requestedMode, sendPopupComplete, sendPopupFailed, popupFailure, idpErrorCode } from '../utils/ssoPopup.js';
import log from '../utils/logger.js';

const router = Router();
const SESSION_DURATION_HOURS = parseInt(process.env.SESSION_DURATION_HOURS) || 24;

// ---------------------------------------------------------------------------
// Discovery + JWKS caches (5 min / 10 min TTL)
// ---------------------------------------------------------------------------
const _discoveryCache = new Map();
const _jwksCache = new Map();

async function getDiscovery(baseUrl) {
  const now = Date.now();
  const cached = _discoveryCache.get(baseUrl);
  if (cached && now - cached.ts < 5 * 60 * 1000) return cached.doc;

  const url = baseUrl.endsWith('/.well-known/openid-configuration')
    ? baseUrl
    : baseUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';

  const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error(`OIDC discovery failed (${r.status}): ${url}`);
  const doc = await r.json();
  _discoveryCache.set(baseUrl, { doc, ts: now });
  return doc;
}

async function getJwks(jwksUri) {
  const now = Date.now();
  const cached = _jwksCache.get(jwksUri);
  if (cached && now - cached.ts < 10 * 60 * 1000) return cached.keys;
  const r = await fetch(jwksUri, { signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error(`JWKS fetch failed (${r.status})`);
  const { keys } = await r.json();
  _jwksCache.set(jwksUri, { keys, ts: now });
  return keys;
}

async function verifyIdToken(idToken, jwksUri, clientId, issuer) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed id_token');

  const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

  // Validate standard claims
  if (payload.iss !== issuer) throw new Error(`Token issuer mismatch: expected ${issuer}, got ${payload.iss}`);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(clientId)) throw new Error('Token audience does not include client_id');
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('id_token expired');

  // Find matching JWK (by kid, then by alg, then first key)
  const keys = await getJwks(jwksUri);
  const jwk = keys.find(k => k.kid === header.kid)
    || keys.find(k => k.alg === header.alg)
    || keys[0];
  if (!jwk) throw new Error('No matching JWK found for kid=' + header.kid);

  // Verify RS256 / RS384 / RS512 / PS256 / PS384 / PS512
  const alg = header.alg || 'RS256';
  const hashAlg = alg.includes('256') ? 'SHA256' : alg.includes('384') ? 'SHA384' : 'SHA512';
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const sigInput = Buffer.from(parts[0] + '.' + parts[1]);
  const sig = Buffer.from(parts[2], 'base64url');

  const valid = alg.startsWith('PS')
    ? crypto.verify(
        { name: 'RSA-PSS', saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
        sigInput,
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
        sig
      )
    : crypto.verify(hashAlg, sigInput, publicKey, sig);

  if (!valid) throw new Error('id_token signature verification failed');
  return payload;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getOidcConfig() {
  const db = getDb();
  const rows = db.prepare("SELECT key, value FROM settings WHERE key LIKE 'oidc_%'").all();
  const cfg = Object.fromEntries(rows.map(r => [r.key, r.value]));
  return {
    enabled:        cfg.oidc_enabled === '1',
    discovery_url:  cfg.oidc_discovery_url || '',
    client_id:      cfg.oidc_client_id || '',
    client_secret:  cfg.oidc_client_secret_enc ? (() => { try { return decrypt(cfg.oidc_client_secret_enc); } catch { return ''; } })() : '',
    client_secret_set: !!cfg.oidc_client_secret_enc,
    provider_name:  cfg.oidc_provider_name || 'SSO',
    auto_provision: cfg.oidc_auto_provision === '1',
  };
}

function craneBaseUrl() {
  return process.env.CRANE_DOMAIN
    ? 'https://' + process.env.CRANE_DOMAIN
    : 'http://localhost:' + (process.env.PORT || 5001);
}

// ---------------------------------------------------------------------------
// Browser binding: an SSO login finishes only in the browser that started it.
//
// A valid signature on the state or response only proves AppCrane or the IdP made
// it, not that this browser asked for it: an attacker can start a login, complete
// it as themselves and hand the victim the last step, signing the victim in as the
// attacker (login CSRF). So /start leaves a random value in an HttpOnly cookie and
// puts a hash of it in what comes back through the IdP.
//
// The value is reused while the cookie lives, so two sign-ins open in one browser
// (two tabs, a retried popup) both finish. Over https the name carries __Host-: an
// app host under the platform's domain could otherwise set the cookie for that
// domain and choose the value (see the note in utils/sessionCookie.js).
//
// Measured in Chrome 157 behind TLS, with the IdP on another site: SameSite=Lax is
// sent on the OIDC callback, a top-level GET, including in a popup opened from a
// cross-site iframe (a popup is first-party). It is not set or sent for an IdP step
// run inside a cross-site iframe; there the sign-in fails with the message below.
// ---------------------------------------------------------------------------
const BIND_TTL_MS = 10 * 60 * 1000;
const BIND_VALUE = /^[A-Za-z0-9_-]{32}$/;
const BROWSER_MISMATCH = 'Sign-in must finish in the browser that started it, with cookies allowed. Start again from the sign-in page.';

export function readBrowserBinding(req, name) {
  const value = readCookie(req, name);
  return value && BIND_VALUE.test(value) ? value : null;
}

export function ensureBrowserBinding(req, res, { name, secure, sameSite }) {
  const value = readBrowserBinding(req, name) || crypto.randomBytes(24).toString('base64url');
  res.cookie(name, value, { httpOnly: true, secure, sameSite, path: '/', maxAge: BIND_TTL_MS });
  return value;
}

export function browserMismatch() {
  return popupFailure('failed', BROWSER_MISMATCH);
}

// ---------------------------------------------------------------------------
// SSO handoff: how the SPA gets its session token.
//
// The API authenticates a Bearer, not the cookie, so the SPA still needs the token
// after the callback. A token in the redirect URL could be replayed by anyone:
// /login?oidc_token=<attacker's token> signed the victim in as the attacker. The
// URL now carries a code that is single-use, lives a minute, and only redeems in
// the browser holding the login's binding cookie. Kept in memory: a restart loses
// a code in flight, the cookie stays valid, and signing in again fixes it.
// ---------------------------------------------------------------------------
export const SSO_HANDOFF_TTL_MS = 60_000;
export const SSO_HANDOFF_MAX = 5000;
const ssoHandoffs = new Map(); // sha256(code) -> record, oldest first

export function issueSsoHandoff(token, cookieName, binding) {
  const now = Date.now();
  for (const [k, rec] of ssoHandoffs) {
    if (now <= rec.expiresAt && ssoHandoffs.size < SSO_HANDOFF_MAX) break;
    ssoHandoffs.delete(k);
  }
  const code = crypto.randomBytes(16).toString('base64url');
  ssoHandoffs.set(bindingHash(code), { token, cookieName, binding: bindingHash(binding), expiresAt: now + SSO_HANDOFF_TTL_MS });
  return code;
}

// The token, or null. A failed attempt does not use the code up: someone else
// trying it must not be able to spoil the real browser's sign-in.
export function redeemSsoHandoff(req, code) {
  if (typeof code !== 'string') return null;
  const key = bindingHash(code);
  const rec = ssoHandoffs.get(key);
  if (!rec) return null;
  if (Date.now() > rec.expiresAt) { ssoHandoffs.delete(key); return null; }
  const value = readBrowserBinding(req, rec.cookieName);
  if (!value || !safeEqual(bindingHash(value), rec.binding)) return null;
  ssoHandoffs.delete(key);
  return rec.token;
}

function oidcBindCookie(req) {
  const secure = platformCookieSecure(req) || craneBaseUrl().startsWith('https://');
  return { name: secure ? '__Host-cc_oidc_bind' : 'cc_oidc_bind', secure, sameSite: 'lax' };
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

const bindingHash = (value) => crypto.createHash('sha256').update(value).digest('base64url');

function stateIsThisBrowsers(req, stateData) {
  const value = readBrowserBinding(req, oidcBindCookie(req).name);
  return !!value && safeEqual(bindingHash(value), stateData.b);
}

// The HMAC proves AppCrane made the state; `b` ties it to the browser. Payload:
// { r: redirect, n: OIDC nonce, b: binding hash, t: timestamp, m?: 'popup' }
function makeState(redirect, mode, binding, nonce) {
  const payload = Buffer.from(JSON.stringify({ r: redirect || '', n: nonce, b: bindingHash(binding), t: Date.now(), ...(mode === POPUP_MODE && { m: POPUP_MODE }) })).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.ENCRYPTION_KEY).update(payload).digest('base64url');
  return payload + '.' + sig;
}

function parseState(state) {
  const dot = state.lastIndexOf('.');
  if (dot === -1) throw new Error('Invalid state format');
  const payload = state.slice(0, dot);
  const sig = state.slice(dot + 1);
  const expected = crypto.createHmac('sha256', process.env.ENCRYPTION_KEY).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) {
    throw new Error('State signature mismatch — possible CSRF');
  }
  const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
  if (Date.now() - data.t > 10 * 60 * 1000) throw popupFailure('expired', 'State expired (> 10 min)');
  return data;
}

// The mode inside a state whose signature verifies, ignoring its age: a failed
// callback uses it to answer a popup with the failure page. '' when the state
// is missing, garbled or not signed by this instance.
function signedStateMode(state) {
  try {
    if (typeof state !== 'string') return '';
    const dot = state.lastIndexOf('.');
    if (dot === -1) return '';
    const payload = state.slice(0, dot);
    const sig = Buffer.from(state.slice(dot + 1), 'base64url');
    const expected = crypto.createHmac('sha256', process.env.ENCRYPTION_KEY).update(payload).digest();
    if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) return '';
    return JSON.parse(Buffer.from(payload, 'base64url').toString()).m === POPUP_MODE ? POPUP_MODE : '';
  } catch {
    return '';
  }
}

function createIdentitySession(userId) {
  const db = getDb();
  const token = generateSessionToken();
  const tokenHash = hashApiKey(token);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 3600 * 1000).toISOString();
  db.prepare('INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at) VALUES (?, ?, ?, ?)').run(userId, tokenHash, null, expiresAt);
  db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(userId);
  return token;
}

function upsertSetting(db, key, value, adminId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(key, String(value ?? ''), adminId);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * GET /api/auth/oidc/config — public, returns only what the login page needs
 */
router.get('/config', (req, res) => {
  const cfg = getOidcConfig();
  res.json({ enabled: cfg.enabled, provider_name: cfg.provider_name });
});

/**
 * GET /api/auth/oidc/admin-config — admin: full config for settings page
 */
router.get('/admin-config', requireAuth, requirePlatformAdmin, (req, res) => {
  const cfg = getOidcConfig();
  res.json({
    enabled:           cfg.enabled,
    discovery_url:     cfg.discovery_url,
    client_id:         cfg.client_id,
    client_secret_set: cfg.client_secret_set,
    provider_name:     cfg.provider_name,
    auto_provision:    cfg.auto_provision,
  });
});

/**
 * PUT /api/auth/oidc/config — admin: save OIDC settings
 */
router.put('/config', requireAuth, requirePlatformAdmin, (req, res) => {
  const { enabled, discovery_url, client_id, client_secret, provider_name, auto_provision } = req.body || {};
  const db = getDb();
  const save = (k, v) => upsertSetting(db, k, v, req.user.id);

  save('oidc_enabled',        enabled ? '1' : '0');
  save('oidc_discovery_url',  discovery_url || '');
  save('oidc_client_id',      client_id || '');
  save('oidc_provider_name',  provider_name || 'SSO');
  save('oidc_auto_provision', auto_provision ? '1' : '0');
  if (client_secret) save('oidc_client_secret_enc', encrypt(client_secret));

  // Invalidate discovery cache when config changes
  _discoveryCache.clear();

  res.json({ message: 'OIDC settings saved' });
});

/**
 * POST /api/auth/oidc/test — admin: verify discovery URL is reachable
 */
router.post('/test', requireAuth, requirePlatformAdmin, async (req, res) => {
  const { discovery_url } = req.body || {};
  if (!discovery_url) return res.status(400).json({ error: { code: 'VALIDATION', message: 'discovery_url required' } });
  try {
    const doc = await getDiscovery(discovery_url);
    res.json({ ok: true, issuer: doc.issuer, authorization_endpoint: doc.authorization_endpoint });
  } catch (e) {
    res.status(400).json({ ok: false, error: { code: 'UNREACHABLE', message: e.message } });
  }
});

/**
 * GET /api/auth/oidc/start — redirect user to IdP
 */
router.get('/start', async (req, res) => {
  const cfg = getOidcConfig();
  if (!cfg.enabled || !cfg.discovery_url || !cfg.client_id) {
    return res.status(400).send('OIDC not configured');
  }
  try {
    const discovery = await getDiscovery(cfg.discovery_url);
    const redirectUri = craneBaseUrl() + '/api/auth/oidc/callback';
    // The old guard here was startsWith('/') && !startsWith('//'), which let
    // through '/\host' and '/<TAB>/host' — both cross-origin once a browser
    // normalizes them. '' means "no deep link", so the fallback is empty
    // rather than the module default. CWE-601.
    const safeRedirect = safeRedirectTarget(req.query.redirect, '');
    const binding = ensureBrowserBinding(req, res, oidcBindCookie(req));
    const nonce = crypto.randomBytes(16).toString('hex');
    const state = makeState(safeRedirect, requestedMode(req.query), binding, nonce);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id:     cfg.client_id,
      redirect_uri:  redirectUri,
      scope:         'openid email profile',
      state,
      nonce,
    });
    res.redirect(302, discovery.authorization_endpoint + '?' + params.toString());
  } catch (e) {
    log.error('OIDC start error: ' + e.message);
    if (requestedMode(req.query) === POPUP_MODE) return sendPopupFailed(res, 'unavailable');
    res.redirect(302, craneBaseUrl() + '/login?sso_error=' + encodeURIComponent(e.message));
  }
});

/**
 * GET /api/auth/oidc/callback — IdP posts back here with ?code=&state=
 */
router.get('/callback', async (req, res) => {
  const base = craneBaseUrl();
  // Decided before anything can fail, from the signed state only; see ssoPopup.js.
  const popup = signedStateMode(req.query.state) === POPUP_MODE;
  try {
    const { code, state, error, error_description } = req.query;
    if (error) throw popupFailure(idpErrorCode(error), error_description || error);
    if (!code || !state) throw new Error('Missing code or state in callback');

    const stateData = parseState(state);
    if (!stateIsThisBrowsers(req, stateData)) throw browserMismatch();
    const cfg = getOidcConfig();
    if (!cfg.enabled) throw new Error('OIDC is not enabled');

    const discovery   = await getDiscovery(cfg.discovery_url);
    const redirectUri = base + '/api/auth/oidc/callback';

    // Exchange authorization code for tokens
    const tokenRes = await fetch(discovery.token_endpoint, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  redirectUri,
        client_id:     cfg.client_id,
        client_secret: cfg.client_secret,
      }),
      signal: AbortSignal.timeout(15000),
    });

    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      throw new Error('Token exchange failed: ' + body.slice(0, 120));
    }

    const tokens = await tokenRes.json();
    if (!tokens.id_token) throw new Error('No id_token in token response');

    // Verify and decode the ID token
    const claims = await verifyIdToken(tokens.id_token, discovery.jwks_uri, cfg.client_id, discovery.issuer);
    if (!safeEqual(claims.nonce, stateData.n)) throw new Error('id_token nonce mismatch');
    const { sub, email, name, given_name, family_name } = claims;
    if (!sub) throw new Error('id_token missing sub claim');

    const displayName = name
      || [given_name, family_name].filter(Boolean).join(' ')
      || email
      || sub;

    // Find or create user
    const db = getDb();
    // Security audit 2026-10-06, M4: link by e-mail only when the IdP verified
    // it, and never move an account already bound to another sub.
    const emailVerified = claims.email_verified === true || claims.email_verified === 'true';
    let user = findOrLinkSsoUser(db, {
      column: 'sso_sub', subject: sub, email, emailVerified,
      allowUnverified: process.env.OIDC_ALLOW_UNVERIFIED_EMAIL_LINK === '1',
    });

    // Sync display name — and the email claim — from the IdP on every login,
    // so IdP-side corrections propagate automatically. `email` here is a real
    // OIDC claim (not a NameID fallback), so it's safe to sync. Guarded
    // against the email UNIQUE collision (another user already has it).
    if (user) {
      if (displayName && displayName !== user.name) {
        db.prepare('UPDATE users SET name = ? WHERE id = ?').run(displayName, user.id);
      }
      if (email && emailVerified && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) &&
          email.toLowerCase() !== (user.email || '').toLowerCase()) {
        try {
          db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, user.id);
          log.info(`OIDC: synced email for sub ${sub} → ${email}`);
        } catch (e) {
          log.warn(`OIDC: email sync skipped for sub ${sub} (${email}): ${e.message}`);
        }
      }
    }

    if (!user && cfg.auto_provision) {
      // No API key: a person gets one only by asking (Settings > Account).
      const result = db.prepare(
        "INSERT INTO users (name, email, role, sso_sub, created_at) VALUES (?, ?, 'user', ?, datetime('now'))"
      ).run(displayName, email || null, sub);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      log.info(`OIDC: auto-provisioned user "${displayName}" (${email || sub})`);
    }

    if (!user) {
      log.warn(`OIDC: no account for sub=${sub} email=${email}, auto-provision disabled`);
      auditLogin(null, 'failed', { method: 'oidc', reason: 'no_account', email: email || null, ip: req.ip });
      if (popup) return sendPopupFailed(res, 'no_account');
      return res.redirect(302, base + '/login?sso_error=no_account');
    }

    // Create session and hand token back to the browser via login page JS
    const token = createIdentitySession(user.id);
    auditLogin(user.id, 'ok', { method: 'oidc', ip: req.ip });
    log.info(`OIDC login: ${user.name} (${email || sub})`);

    // v2.6.18: set cc_token cookie server-side on the redirect response, so a
    // browser that goes straight into a per-app route after the callback, without
    // the SPA running, is signed in. The SPA's own Bearer comes from the handoff
    // code below; the cookie does not depend on it.
    setSessionCookie(res, token, req);

    // Popup mode comes from the signed state only, never from this request's query.
    if (stateData.m === POPUP_MODE) return sendPopupComplete(res);

    // Always go through /login so it sets the cookie, then forward to redirect target.
    // Re-validate rather than trusting `start`: the value round-trips through the
    // IdP inside `state`, and the deep link must be a same-origin path here too.
    // (This gate previously read startsWith('http'), which `start` never
    // produced — so the deep link was always dropped and SSO always landed on
    // the default page. Restoring it is only safe with the check below.)
    // '/login' is excluded so the forward can't bounce back into the login page.
    const target = safeRedirectTarget(stateData.r, '');
    const bindCookie = oidcBindCookie(req).name;
    const p = new URLSearchParams({ sso_code: issueSsoHandoff(token, bindCookie, readBrowserBinding(req, bindCookie)) });
    if (target && !target.includes('/login')) {
      p.set('redirect', target);
    }
    res.redirect(302, `${base}/login?${p.toString()}`);
  } catch (e) {
    log.error('OIDC callback error: ' + e.message);
    auditLogin(null, 'failed', { method: 'oidc', reason: e.popupCode || 'error', message: String(e.message).slice(0, 200), ip: req.ip });
    if (popup) return sendPopupFailed(res, e.popupCode || 'failed');
    res.redirect(302, base + '/login?sso_error=' + encodeURIComponent(e.message));
  }
});

/**
 * POST /api/auth/oidc/handoff — the SPA trades its sso_code for the session token.
 * Shared with SAML, whose callback issues the same code bound to its own cookie.
 */
router.post('/handoff', (req, res) => {
  const token = redeemSsoHandoff(req, req.body?.code);
  if (!token) return res.status(401).json({ error: { code: 'SSO_HANDOFF_REFUSED', message: BROWSER_MISMATCH } });
  res.json({ token });
});

export default router;
