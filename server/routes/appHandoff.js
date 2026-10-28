import { Router } from 'express';
import crypto from 'crypto';
import { getDb } from '../db.js';
import { generateSessionToken, hashApiKey } from '../services/encryption.js';
import {
  APP_SESSION_COOKIE,
  HANDOFF_CODE_TTL_SECONDS,
  HANDOFF_STATE_COOKIE,
  appOrigin,
  parseAppHost,
} from '../services/appOrigin.js';
import { readCookie, readSessionCookie } from '../utils/sessionCookie.js';
import { isSafeRedirect } from '../utils/safeRedirect.js';
import { AppError } from '../utils/errors.js';
import { resolveAppRole, refuseNoAccess } from './identity.js';

// Sign-in handoff from the platform host to an isolated app host
// (services/appOrigin.js). Owned by the server-auth workstream.
//
// Platform host:  GET /api/identity/handoff?app=<slug>&env=<sandbox|production>&return=<path>[&site=<host>]
//                 GET /api/identity/tls-ask?domain=<host>   (Caddy on-demand TLS, loopback only)
// App host:       GET /__appcrane/session?code=<code>
//                 GET /__appcrane/logout
//
// The platform cookie never reaches an app host, so the platform host turns
// the visitor's platform session into a one-time code, and the app host turns
// the code into a session for that one app and environment (scope 'app'),
// held in the app host's own __Host- cookie.
const router = Router();
export const appHostRouter = Router();

function stripHost(raw) {
  return String(raw || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
}

function craneDomain() {
  return stripHost(String(process.env.CRANE_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/+$/, ''));
}

/**
 * The app and environment a request's host serves: an app host under the
 * isolation domain, or an app's custom domain that uses AppCrane sign-in
 * (production). null for the platform host and anything else.
 */
export function resolveAppHost(db, rawHost) {
  const host = stripHost(rawHost);
  if (!host || host === craneDomain()) return null;
  const parsed = parseAppHost(db, host);
  if (parsed) {
    const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(parsed.slug);
    return app ? { app, env: parsed.env, host } : null;
  }
  const app = db.prepare('SELECT * FROM apps WHERE lower(trim(domain)) = ? AND custom_domain_auth = 1').get(host);
  return app ? { app, env: 'production', host } : null;
}

function noStore(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

// Relative, one leading slash, no backslash, no control characters.
function safeReturn(value) {
  if (typeof value !== 'string' || value.length > 2048) return '/';
  if (!isSafeRedirect(value) || value.includes('\\')) return '/';
  return value;
}

// Shown inside the dashboard's app tab too, so the platform may frame it;
// with the global X-Frame-Options SAMEORIGIN the browser would hide the
// message behind "refused to connect".
function page(res, status, title, message, retry) {
  res.removeHeader('X-Frame-Options');
  res.setHeader('Content-Security-Policy', `frame-ancestors https://${craneDomain()}`);
  const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  res.status(status).type('html').send(`<!doctype html><meta charset="utf-8"><title>${esc(title)}</title>`
    + `<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem">`
    + `<h1>${esc(title)}</h1><p>${esc(message)}</p>`
    + (retry ? `<p><a href="/">Open the app again</a></p>` : '')
    + `</body>`);
}

router.get('/handoff', (req, res) => {
  noStore(res);
  const db = getDb();
  const env = req.query.env === 'sandbox' || req.query.env === 'production' ? req.query.env : null;
  const app = env && typeof req.query.app === 'string'
    ? db.prepare('SELECT * FROM apps WHERE slug = ?').get(req.query.app)
    : null;
  if (!app) throw new AppError('Unknown app or environment', 404, 'NOT_FOUND');

  // Where the code goes: the app host the visitor came from when it really is
  // this app's (a custom domain with AppCrane sign-in), else the app's own host.
  const site = typeof req.query.site === 'string' ? resolveAppHost(db, req.query.site) : null;
  const origin = site && site.app.id === app.id && site.env === env
    ? `https://${site.host}`
    : appOrigin(db, app.slug, env);
  if (!origin) throw new AppError('This app is not served on its own host', 400, 'NOT_ISOLATED');

  const token = readSessionCookie(req);
  const session = token && db.prepare(`
    SELECT s.token_hash, u.id AS user_id, u.role FROM identity_sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.scope = 'platform' AND datetime(s.expires_at) > datetime('now') AND u.active = 1
  `).get(hashApiKey(token));
  if (!session) return res.redirect(302, `/login?redirect=${encodeURIComponent(req.originalUrl)}`);

  if (resolveAppRole(db, { user_id: session.user_id, crane_role: session.role }, app) === 'none') {
    return refuseNoAccess(req, res, app.name || app.slug);
  }

  // The hash of the app host's state cookie (set by verify's redirect). Only
  // the browser holding that cookie can use the code this issues.
  const state = typeof req.query.state === 'string' && /^[0-9a-f]{64}$/.test(req.query.state) ? req.query.state : null;
  if (!state) throw new AppError('Start signing in from the app', 400, 'NO_STATE');

  db.prepare("DELETE FROM app_handoff_codes WHERE expires_at < datetime('now')").run();
  const code = crypto.randomBytes(32).toString('base64url');
  db.prepare(`
    INSERT INTO app_handoff_codes (code_hash, user_id, app_id, app_env, parent_token_hash, state_hash, return_path, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+' || ? || ' seconds'))
  `).run(hashApiKey(code), session.user_id, app.id, env, session.token_hash, state, safeReturn(req.query.return), HANDOFF_CODE_TTL_SECONDS);

  res.redirect(302, `${origin}/__appcrane/session?code=${encodeURIComponent(code)}`);
});

// Caddy's on-demand TLS asks before it requests a certificate for a host.
// Only Caddy itself may ask: a loopback caller with no proxy headers, since a
// request Caddy proxies from the internet also arrives over loopback.
router.get('/tls-ask', (req, res) => {
  const addr = req.socket?.remoteAddress || '';
  const loopback = addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
  if (!loopback || req.headers['x-forwarded-for'] || req.headers['x-forwarded-host']) return res.status(404).end();
  const db = getDb();
  const parsed = parseAppHost(db, String(req.query.domain || ''));
  const known = parsed && db.prepare('SELECT 1 FROM apps WHERE slug = ?').get(parsed.slug);
  res.status(known ? 200 : 404).end();
});

appHostRouter.get('/session', (req, res) => {
  noStore(res);
  const db = getDb();
  const site = resolveAppHost(db, req.headers.host);
  if (!site) throw new AppError('Not found', 404, 'NOT_FOUND');

  const code = typeof req.query.code === 'string' ? req.query.code : '';
  const codeHash = hashApiKey(code);
  // Single use: whoever flips used_at owns the code, and a code shown on
  // another app's host is spent without being honoured.
  const row = code && db.transaction(() => {
    const won = db.prepare(`
      UPDATE app_handoff_codes SET used_at = datetime('now')
      WHERE code_hash = ? AND used_at IS NULL AND expires_at > datetime('now')
    `).run(codeHash).changes;
    return won ? db.prepare('SELECT * FROM app_handoff_codes WHERE code_hash = ?').get(codeHash) : null;
  })();
  if (!row || row.app_id !== site.app.id || row.app_env !== site.env) {
    return page(res, 403, 'Sign-in link not valid', 'This sign-in link has expired, was already used, or belongs to another app.', true);
  }
  // The code must come back to the browser that asked for it.
  const state = readCookie(req, HANDOFF_STATE_COOKIE);
  res.clearCookie(HANDOFF_STATE_COOKIE, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  const want = Buffer.from(row.state_hash, 'hex');
  const got = Buffer.from(state ? hashApiKey(state) : '', 'hex');
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
    return page(res, 403, 'Sign-in link not valid', 'This sign-in link was started in another browser. Open the app again to sign in.', true);
  }

  const parent = db.prepare(`
    SELECT s.expires_at, s.absolute_expires_at FROM identity_sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.user_id = ? AND s.scope = 'platform'
      AND datetime(s.expires_at) > datetime('now') AND u.active = 1
  `).get(row.parent_token_hash, row.user_id);
  if (!parent) return page(res, 403, 'Signed out', 'You signed out of AppCrane before this sign-in finished.', true);

  // Never outlives the platform session it came from: the policy trigger
  // caps the absolute deadline at the requested expiry, and the idle deadline
  // is capped at the parent's current one.
  const token = generateSessionToken();
  const tokenHash = hashApiKey(token);
  db.prepare(`
    INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at, scope, app_env, parent_token_hash)
    VALUES (?, ?, ?, strftime('%Y-%m-%d %H:%M:%SZ', ?), 'app', ?, ?)
  `).run(row.user_id, tokenHash, row.app_id, parent.absolute_expires_at || parent.expires_at, row.app_env, row.parent_token_hash);
  db.prepare(`
    UPDATE identity_sessions SET expires_at = strftime('%Y-%m-%d %H:%M:%SZ', min(datetime(expires_at), datetime(?)))
    WHERE token_hash = ?
  `).run(parent.expires_at, tokenHash);

  res.cookie(APP_SESSION_COOKIE, token, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  res.redirect(302, safeReturn(row.return_path));
});

appHostRouter.get('/logout', (req, res) => {
  noStore(res);
  const db = getDb();
  const site = resolveAppHost(db, req.headers.host);
  if (!site) throw new AppError('Not found', 404, 'NOT_FOUND');
  const token = readCookie(req, APP_SESSION_COOKIE);
  if (token) {
    db.prepare("DELETE FROM identity_sessions WHERE token_hash = ? AND scope = 'app' AND app_id = ? AND app_env = ?")
      .run(hashApiKey(token), site.app.id, site.env);
  }
  res.clearCookie(APP_SESSION_COOKIE, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  const domain = craneDomain();
  res.redirect(302, domain ? `https://${domain}/` : '/');
});

export default router;
