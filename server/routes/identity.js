import { Router } from 'express';
import { existsSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../db.js';
import { verifyPassword, generateSessionToken, hashApiKey, hashPassword } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';
import { setSessionCookie, clearSessionCookie } from '../utils/sessionCookie.js';
import { isSsoOnly } from '../services/authPolicy.js';
import { roleKeysForUser } from '../services/appDefinedRoles.js';
import log from '../utils/logger.js';

const ICON_DIR = resolve(process.env.DATA_DIR || './data', 'apps');
const ICON_EXTS = ['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg'];
const hasIcon = (slug) => ICON_EXTS.some(ext => existsSync(join(ICON_DIR, slug, `icon.${ext}`)));

const router = Router();

const SESSION_DURATION_HOURS = parseInt(process.env.SESSION_DURATION_HOURS) || 24;

// In-memory rate limiter for login attempts: 5 per minute per IP
const _loginAttempts = new Map();
// `now` is injectable so a test can prove the window closes and the sweep
// collects, without sleeping through a real 60 seconds.
export function checkLoginRateLimit(ip, now = Date.now()) {
  const rec = _loginAttempts.get(ip);
  if (!rec || now > rec.resetAt) {
    _loginAttempts.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (rec.count >= 5) return false;
  rec.count++;
  return true;
}

// v2.55.1: sweep expired buckets.
//
// An entry is only ever replaced when THAT IP comes back after its window
// closes, so an address that logs in once and never returns keeps its bucket
// for the life of the process. Every distinct source IP that ever touches
// /api/identity/login costs a permanent Map entry — and the endpoint an
// attacker hits from many addresses is exactly this one, so the growth is
// fastest under the attack the limiter exists to blunt.
//
// index.js already does this for _apiRateMap; the login limiter was written
// without it. Same 5-minute cadence, deliberately: a bucket lives 60s, so this
// only ever removes entries that are already expired and can never evict one
// that is still counting.
//
// Exported so a test can run the sweep on demand rather than waiting five
// minutes, and so the timer and the tested code are the same function — two
// copies of this loop would be free to drift apart.
export function _sweepLoginAttempts(now = Date.now()) {
  for (const [ip, rec] of _loginAttempts) {
    if (now > rec.resetAt) _loginAttempts.delete(ip);
  }
  return _loginAttempts.size;
}

// unref() so the timer does not hold the event loop open. This module is
// imported directly by route tests, and a bare setInterval would keep
// `node --test` running after the assertions finish.
const _loginSweeper = setInterval(_sweepLoginAttempts, 5 * 60_000);
_loginSweeper.unref?.();

/**
 * POST /api/identity/login
 * Login with (email OR username) + password → session token
 * Body: { login: "email or username", password: "xxx", app: "slug" (optional) }
 */
router.post('/login', (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  if (!checkLoginRateLimit(ip)) {
    log.warn(`Login rate limit hit from ${ip}`);
    throw new AppError('Too many login attempts. Try again in a minute.', 429, 'RATE_LIMITED');
  }

  const { login, password, app } = req.body || {};

  if (!login || !password) {
    throw new AppError('login (email or username) and password are required', 400, 'VALIDATION');
  }

  const db = getDb();

  // v2.7.0: SSO-only mode. When a platform admin has set auth_sso_only,
  // password sign-in is disabled for everyone — the IdP is the only browser
  // login path. OIDC/SAML callbacks issue sessions elsewhere and are
  // unaffected; X-API-Key auth stays open as the CLI/recovery path.
  if (isSsoOnly(db)) {
    throw new AppError('Password sign-in is disabled. Use single sign-on.', 403, 'SSO_REQUIRED');
  }

  // Find user by email or username
  const user = db.prepare(
    'SELECT * FROM users WHERE email = ? OR username = ?'
  ).get(login, login);

  if (!user) {
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  if (user.active === 0) {
    throw new AppError('Account is deactivated. Contact your administrator.', 403, 'DEACTIVATED');
  }

  if (!user.password_hash) {
    throw new AppError('Password not set for this user. Contact admin.', 401, 'NO_PASSWORD');
  }

  if (!verifyPassword(password, user.password_hash)) {
    log.warn(`Failed login for "${login}" from ${ip}`);
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  // Check app access if app specified
  let appId = null;
  let appRole = null;
  if (app) {
    const appRecord = db.prepare('SELECT * FROM apps WHERE slug = ?').get(app);
    if (appRecord) {
      appId = appRecord.id;
      // Check if user has access
      // Get app-specific role (defaults to 'none' = no access)
      const roleRecord = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, user.id);
      appRole = roleRecord?.app_role || 'none';
    }
  }

  // Create session token
  const token = generateSessionToken();
  const tokenHash = hashApiKey(token);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 60 * 60 * 1000).toISOString();

  db.prepare(
    'INSERT INTO identity_sessions (user_id, token_hash, app_id, expires_at) VALUES (?, ?, ?, ?)'
  ).run(user.id, tokenHash, appId, expiresAt);

  // Update last login
  db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(user.id);

  log.info(`Identity login: ${user.name} (${login})${app ? ' for app ' + app : ''}`);

  // Get all apps with this user's role, health state, and current version.
  // platform_admin counts as admin everywhere — same blast radius, same
  // capabilities. This block was the source of the v2.2.6 follow-up bug
  // where platform_admin saw the "request access" screen for private apps.
  const isAdmin = user.role === 'admin' || user.role === 'platform_admin';
  const apps = db.prepare(`
    SELECT a.slug, a.name, a.domain, a.description, a.public_access, a.visibility, a.category,
      -- v2.7.21: explicit per-app role wins; public-→-viewer is only the
      -- fallback for users WITHOUT an explicit row. Old shape returned
      -- 'viewer' for everyone on public apps, wiping owner/admin/user.
      COALESCE(aur.app_role, CASE WHEN a.visibility = 'public' THEN 'viewer' ELSE 'none' END) as app_role,
      CASE WHEN a.github_url IS NOT NULL AND a.github_url != '' THEN 1 ELSE 0 END as has_github,
      hp.is_down as prod_down, hp.last_status as prod_status,
      hs.is_down as sand_down, hs.last_status as sand_status,
      (SELECT version FROM deployments WHERE app_id = a.id AND env = 'production' AND status = 'live' ORDER BY finished_at DESC LIMIT 1) as prod_version,
      (SELECT version FROM deployments WHERE app_id = a.id AND env = 'sandbox'    AND status = 'live' ORDER BY finished_at DESC LIMIT 1) as sand_version
    FROM apps a
    LEFT JOIN app_user_roles aur ON a.id = aur.app_id AND aur.user_id = ?
    LEFT JOIN health_state hp ON a.id = hp.app_id AND hp.env = 'production'
    LEFT JOIN health_state hs ON a.id = hs.app_id AND hs.env = 'sandbox'
    ORDER BY a.name
  `).all(user.id).map(a => ({
    ...a,
    app_role: isAdmin && (a.app_role === 'none' || a.app_role === 'viewer') ? 'admin' : a.app_role,
    has_icon: hasIcon(a.slug),
    has_github: !!a.has_github,
  })).filter(a => isAdmin || a.visibility !== 'hidden');

  // v2.6.18: set cc_token cookie server-side. Eliminates the class
  // of bugs where the SPA's client-side cookie write was missing
  // (direct nav, new tab, browser restart) or had wrong attributes
  // (path / SameSite), which blocked Caddy forward_auth on per-app
  // routes and bounced users to /applications.
  setSessionCookie(res, token, req);

  res.json({
    token,
    expires_at: expiresAt,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      username: user.username,
      avatar_url: user.avatar_url,
      phone: user.phone,
      year_of_birth: user.year_of_birth,
    },
    ...(appRole && { app_role: appRole }),
    apps,
  });
});

/**
 * GET /api/identity/verify
 * App calls this to verify a session token and get user info + app role
 * Headers: Authorization: Bearer TOKEN
 * Query: ?app=slug (optional, to get role for specific app)
 */
router.get('/verify', (req, res) => {
  const authHeader = req.headers.authorization || '';
  let token = authHeader.replace('Bearer ', '').trim();
  // v2.6.18: also accept X-API-Key (matches the rest of the AppCrane
  // API surface and lets ops tools / MCP clients hit per-app URLs
  // without juggling browser cookies). Looked up against
  // users.api_key_hash, not identity_sessions — same as the rest of
  // the codebase's middleware/auth.js path.
  const apiKey = (req.headers['x-api-key'] || '').toString().trim();
  const isApiClient = !!(authHeader || apiKey); // browsers/Caddy don't send either header

  // Fallback: read cc_token cookie (forwarded by Caddy forward_auth from the browser)
  if (!token && !apiKey) {
    const cookies = req.headers.cookie || '';
    const match = cookies.match(/(?:^|;\s*)cc_token=([^;]+)/);
    if (match) token = decodeURIComponent(match[1]);
  }

  // v2.5.14: always build an absolute https://<crane-host>/login URL so a
  // Caddy forward_auth 302 can never produce a slug-prefixed relative
  // path. Tries CRANE_DOMAIN, then X-Forwarded-Host, then req.headers.host.
  // Strips any accidental scheme prefix on CRANE_DOMAIN (= "https://x.com"
  // would otherwise yield "https://https://x.com/login"). Falls back to
  // localhost only when no usable host is found anywhere — that means
  // we're not behind a proxy and the verify endpoint shouldn't have been
  // reachable from a browser anyway.
  function craneAbsBase() {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    let host = process.env.CRANE_DOMAIN
      || req.headers['x-forwarded-host']
      || req.headers.host
      || '';
    host = String(host).replace(/^https?:\/\//, '').replace(/\/+$/, '');
    if (!host) return `http://localhost:${process.env.PORT || 5001}`;
    return `${proto}://${host}`;
  }
  const craneUrl = craneAbsBase();

  // Reconstruct original URL from Caddy forward_auth headers for post-login redirect.
  //
  // Caddy's default directive ordering runs `uri strip_prefix /<slug>` BEFORE
  // forward_auth, so X-Forwarded-Uri arrives stripped (e.g. '/' for a /<slug>
  // root request, '/sub' for /<slug>/sub). Without compensation, the post-SSO
  // redirect lands on '/' instead of '/<slug>'.
  //
  // Caddyfile generator now passes ?prefix=/<slug-or-sandbox-prefix> on the
  // verify URL — we re-prepend it here. Falls back to ?app=<slug> if prefix
  // is missing (e.g. older Caddyfile from a pre-v1.25.2 deployment).
  //
  // v2.5.14: dedupe nested `?redirect=` chains. If a previous redirect
  // loop already wrapped the URL once (e.g. login → app → forward_auth
  // fail → login again with the previous /login?redirect=… as the new
  // redirect target), unwrap until we have the innermost concrete URL.
  // Caps at 5 levels so a malicious crafted chain can't pin a CPU.
  function unwrapNestedRedirect(url) {
    let cur = url;
    for (let i = 0; i < 5; i++) {
      try {
        const u = new URL(cur);
        // Only unwrap when the URL itself points at a /login route on
        // any host — that's the loop signature. Real apps with their
        // own ?redirect= params keep their value.
        if (!/\/login\/?$/.test(u.pathname)) return cur;
        const inner = u.searchParams.get('redirect');
        if (!inner) return cur;
        cur = inner;
      } catch (_) {
        return cur;
      }
    }
    return cur;
  }

  function originalUrl() {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const host  = req.headers['x-forwarded-host']  || process.env.CRANE_DOMAIN || '';
    let uri     = req.headers['x-forwarded-uri']   || '';
    const prefix = req.query.prefix || (req.query.app ? '/' + req.query.app : '');
    if (prefix) {
      if (!uri || uri === '/') uri = prefix;
      else if (!uri.startsWith(prefix)) uri = prefix + uri;
    }
    if (!host || !uri) return '';
    const rawUrl = `${proto}://${host}${uri}`;
    return unwrapNestedRedirect(rawUrl);
  }

  function loginRedirect(extra = {}) {
    const orig = originalUrl();
    const p = new URLSearchParams({ ...(orig && { redirect: orig }), ...extra });
    const qs = p.toString() ? '?' + p.toString() : '';
    return res.redirect(302, `${craneUrl}/login${qs}`);
  }

  if (!token && !apiKey) {
    if (!isApiClient) return loginRedirect();
    throw new AppError('Authorization: Bearer TOKEN, X-API-Key, or cc_token cookie required', 401, 'NO_TOKEN');
  }

  const db = getDb();

  // Resolve to a session-like row { user_id, name, email, username,
  // avatar_url, phone, year_of_birth, crane_role, user_active,
  // app_id, expires_at }. Two paths:
  //   (1) X-API-Key  → users.api_key_hash (no expiry, no app_id)
  //   (2) Bearer / cc_token → identity_sessions
  let session = null;
  if (apiKey) {
    const keyHash = hashApiKey(apiKey);
    const u = db.prepare(`
      SELECT id as user_id, name, email, username, avatar_url, phone, year_of_birth,
             role as crane_role, active as user_active
      FROM users WHERE api_key_hash = ?
    `).get(keyHash);
    if (u) {
      session = { ...u, app_id: null, expires_at: null };
    }
  } else {
    const tokenHash = hashApiKey(token);
    // SECURITY: pull u.active too so a deactivated user's lingering session
    // doesn't keep waving them through Caddy forward_auth into iframed apps
    // (security review v1.27.34 H6). Lookup remains a single query so the
    // existing redirect-when-cookie-only flow stays intact.
    session = db.prepare(`
      SELECT s.*, u.id as user_id, u.name, u.email, u.username, u.avatar_url, u.phone, u.year_of_birth, u.role as crane_role, u.active as user_active
      FROM identity_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ?
    `).get(tokenHash);

    if (session && session.expires_at && new Date(session.expires_at) < new Date()) {
      db.prepare('DELETE FROM identity_sessions WHERE token_hash = ?').run(tokenHash);
      if (!isApiClient) return loginRedirect();
      throw new AppError('Token expired', 401, 'TOKEN_EXPIRED');
    }
  }

  if (!session) {
    if (!isApiClient) return loginRedirect();
    throw new AppError('Invalid or expired token', 401, 'INVALID_TOKEN');
  }

  // Refuse the session if the user has been deactivated since login. The
  // session row stays (so they can't slip through during cleanup) but no
  // operation is performed on their behalf.
  if (session.user_active === 0) {
    if (!isApiClient) return loginRedirect();
    throw new AppError('Account is deactivated', 403, 'DEACTIVATED');
  }

  // Get app role
  const url = new URL(req.url, `http://${req.headers.host}`);
  const appSlug = url.searchParams.get('app');
  let appRole = null;
  let appName = null;
  // The app whose context this verify runs in, kept so the app-defined roles
  // below are read for THAT app and no other. Set alongside appRole so the two
  // can never disagree about which app was resolved.
  let appIdForRoles = null;

  // v2.7.21: correct role precedence is
  //   explicit per-app row > global-admin short-circuit > public→viewer > none
  // The old order put `visibility === 'public'` first and unconditionally set
  // appRole = 'viewer', wiping any explicit app_user_roles entry. That meant
  // an owner of a public app got 'viewer' on the wire (X-AppCrane-App-Role),
  // and any in-app role gate (e.g. Settings) wrongly denied them.
  const resolveAppRole = (appRecord, lookupAppId) => {
    const roleRecord = db.prepare(
      'SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?'
    ).get(lookupAppId, session.user_id);
    if (roleRecord?.app_role) return roleRecord.app_role;          // explicit wins
    if (session.crane_role === 'admin' || session.crane_role === 'platform_admin') return 'admin';
    if (appRecord.visibility === 'public') return 'viewer';        // public fallback
    return 'none';
  };

  if (appSlug) {
    const appRecord = db.prepare('SELECT * FROM apps WHERE slug = ?').get(appSlug);
    if (appRecord) {
      appName = appRecord.name;
      appIdForRoles = appRecord.id;
      appRole = resolveAppRole(appRecord, appRecord.id);
    }
  } else if (session.app_id) {
    const appRecord = db.prepare('SELECT * FROM apps WHERE id = ?').get(session.app_id);
    if (appRecord) {
      appName = appRecord.name;
      appIdForRoles = session.app_id;
      appRole = resolveAppRole(appRecord, session.app_id);
    }
  }

  // Deny access if user has no role for the requested app
  if (appRole === 'none') {
    if (!isApiClient) return loginRedirect({ denied: '1', app: appSlug || '', name: appName || '' });
    throw new AppError('You do not have access to this app', 403, 'FORBIDDEN');
  }

  // Record visit (one row per user/app/day via UPSERT — no-op if already exists)
  const visitAppId = appSlug
    ? db.prepare('SELECT id FROM apps WHERE slug = ?').get(appSlug)?.id
    : session.app_id;
  if (visitAppId) {
    const today = new Date().toISOString().slice(0, 10);
    db.prepare('INSERT OR IGNORE INTO app_visits (user_id, app_id, day) VALUES (?, ?, ?)').run(session.user_id, visitAppId, today);
  }

  // v2.7.19: emit X-AppCrane-* response headers so Caddy's per-app
  // forward_auth blocks can copy_headers them onto the upstream request,
  // and deployed apps read identity directly from the request — no callback
  // to /api/me needed. The matching `request_header -X-AppCrane-*` strip in
  // the Caddy generator kills client header-smuggling, so what the app
  // receives is guaranteed platform-issued. Match the documented contract:
  //   X-AppCrane-User       — email (backward-compat single identifier)
  //   X-AppCrane-User-Id    — numeric id as string
  //   X-AppCrane-User-Email — email
  //   X-AppCrane-User-Name  — display name (URL-encoded for non-Latin-1 safety)
  //   X-AppCrane-User-Role  — global role token (platform_admin / admin / user)
  //   X-AppCrane-App-Role   — per-app role (owner / admin / user / viewer)
  //   X-AppCrane-Is-Admin   — '1' / '0', see below
  //   X-AppCrane-App-Roles  — app-defined role keys, comma-separated; see below
  if (session.user_id !== undefined && session.user_id !== null) {
    res.setHeader('X-AppCrane-User-Id', String(session.user_id));
  }
  if (session.email) {
    res.setHeader('X-AppCrane-User', session.email);
    res.setHeader('X-AppCrane-User-Email', session.email);
  }
  if (session.name) {
    // HTTP headers are Latin-1; URL-encode so non-ASCII names round-trip
    // safely. App parsers should decodeURIComponent() on read.
    res.setHeader('X-AppCrane-User-Name', encodeURIComponent(session.name));
  }
  if (session.crane_role) {
    res.setHeader('X-AppCrane-User-Role', session.crane_role);
  }
  if (appRole) {
    res.setHeader('X-AppCrane-App-Role', appRole);
  }

  // v2.40.0: X-AppCrane-Is-Admin — the platform's own answer to "does this
  // person hold admin power here?", so an app never has to re-derive it from
  // two role strings whose ordering it can't see.
  //
  // The ordering is none < viewer < user < admin < owner, and 'owner' is where
  // apps kept getting it wrong: an app comparing App-Role === 'admin' denies the // role:platform-admin-skipped
  // OWNER of the app — the highest tier — from its own settings page. That is a
  // real bug we've now debugged more than once, and it is the reason this header
  // exists rather than more documentation about role ordering.
  //
  // When there IS an app context, App-Role is the whole answer — the global role
  // is deliberately NOT OR-ed in. resolveAppRole() above already folds the
  // global-admin short-circuit in as a FALLBACK, and lets an explicit
  // app_user_roles row beat it (v2.7.21). So a platform_admin an app owner has
  // deliberately seated as 'user' resolves to 'user', and this header must agree:
  // OR-ing crane_role back in would emit App-Role: user alongside Is-Admin: 1 —
  // two platform-issued headers contradicting each other about the one question
  // this header exists to settle, and it would re-grant the per-app power that
  // the explicit row was written to remove.
  //
  // Without an app context (a bare /verify with no ?app=) there is no App-Role
  // to defer to, and the global role is the only thing left to answer with.
  //
  // Always emitted on this path, '0' included: reaching this line means a
  // session WAS verified, so '0' honestly means "verified, not an admin". On the
  // headless and per-path-bypass routes /verify is never called at all, so no
  // value is emitted there — and Caddy strips any the client sent, so the header
  // is ABSENT rather than fabricated. A '0' would read as "verified, not an
  // admin" when nothing was verified, which is a worse ambiguity than the one
  // this fixes. Apps distinguish the two by reading X-AppCrane-Auth-Mode, which
  // Caddy stamps on every proxied request including those routes.
  const isPlatformAdmin = session.crane_role === 'admin' || session.crane_role === 'platform_admin';
  const isAppAdmin = appRole === 'admin' || appRole === 'owner';
  res.setHeader('X-AppCrane-Is-Admin', (appRole ? isAppAdmin : isPlatformAdmin) ? '1' : '0');

  // v2.41.0: X-AppCrane-App-Roles — the roles the APP defines for itself
  // (approver, auditor, reviewer...), comma-separated. AppCrane stores and
  // issues them; the app enforces them.
  //
  // They are CARRIED, never CONSULTED. Nothing above this line reads them:
  // resolveAppRole, the Is-Admin computation and every AppCrane authz check are
  // untouched by what an app owner types into a settings form. That separation
  // is the whole feature — if these keys could reach a platform decision, an app
  // owner would author their own escalation by naming a role.
  //
  // Read for the resolved app only, and only after the appRole === 'none' denial
  // above — a person who cannot enter the app is never told what they hold in it.
  //
  // OMITTED when the set is empty rather than sent as an empty value. The app's
  // natural test is `header?.split(',')`, and an empty string splits to [''] —
  // one phantom role named '' that no app defines. Absence is unambiguous.
  const appRoleKeys = appIdForRoles ? roleKeysForUser(appIdForRoles, session.user_id) : [];
  if (appRoleKeys.length > 0) {
    res.setHeader('X-AppCrane-App-Roles', appRoleKeys.join(','));
  }

  res.json({
    user: {
      id: session.user_id,
      name: session.name,
      email: session.email,
      username: session.username,
      avatar_url: session.avatar_url,
      phone: session.phone,
      year_of_birth: session.year_of_birth,
    },
    ...(appRole && { role: appRole, app: appSlug || appName }),
    expires_at: session.expires_at,
  });
});

/**
 * POST /api/identity/logout
 * Invalidate session token
 * Headers: Authorization: Bearer TOKEN
 */
router.post('/logout', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();

  // v2.6.18: clear the server-set cc_token cookie regardless of whether
  // a Bearer token was provided (e.g. user already cleared localStorage
  // but the cookie was lingering).
  clearSessionCookie(res);

  if (!token) {
    return res.json({ message: 'No token provided' });
  }

  const db = getDb();
  const tokenHash = hashApiKey(token);
  db.prepare('DELETE FROM identity_sessions WHERE token_hash = ?').run(tokenHash);

  res.json({ message: 'Logged out' });
});

/**
 * POST /api/identity/refresh-cookie
 * Re-establish the httpOnly cc_token cookie from a valid session Bearer.
 *
 * v2.7.8: the cookie is now httpOnly, so the SPA can no longer write it
 * itself. On load the SPA calls this with its localStorage session token so
 * Caddy's forward_auth on per-app routes has the cookie — covers sessions
 * created before the cookie was server-managed and any cookie loss. Only a
 * caller already holding a live session token can set the cookie (for that
 * same token), so there's no new auth surface.
 */
router.post('/refresh-cookie', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (!token) throw new AppError('Bearer session token required', 401, 'UNAUTHORIZED');

  const db = getDb();
  const row = db.prepare(`
    SELECT s.id FROM identity_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(hashApiKey(token));
  if (!row) throw new AppError('Invalid or expired session', 401, 'UNAUTHORIZED');

  setSessionCookie(res, token, req);
  res.json({ ok: true });
});

/**
 * POST /api/identity/logout-beacon
 * navigator.sendBeacon-compatible logout. The Beacon API can't set custom
 * headers (no Authorization), so the token rides in the request body. This
 * endpoint is otherwise identical to /logout and exists purely so the SPA
 * can fire-and-forget a session invalidation that survives the immediate
 * page navigation. Fail-open on parse error — the goal is best-effort
 * cleanup, not a hard auth surface.
 */
router.post('/logout-beacon', (req, res) => {
  const token = (req.body && typeof req.body.token === 'string' && req.body.token.trim()) || '';
  if (!token) return res.status(204).end();
  try {
    const db = getDb();
    db.prepare('DELETE FROM identity_sessions WHERE token_hash = ?').run(hashApiKey(token));
  } catch (_) {}
  res.status(204).end();
});

/**
 * GET /api/identity/me
 * Get current user profile from session token
 * Headers: Authorization: Bearer TOKEN
 */
router.get('/me', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();

  if (!token) throw new AppError('Authorization: Bearer TOKEN header required', 401, 'NO_TOKEN');

  const db = getDb();
  const tokenHash = hashApiKey(token);

  const session = db.prepare(`
    SELECT u.* FROM identity_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(tokenHash);

  if (!session) throw new AppError('Invalid or expired token', 401, 'INVALID_TOKEN');

  // Get all apps with roles, health state, and current version. Same
  // platform_admin treatment as above — global admins of either tier
  // bypass per-app role restrictions.
  const isAdmin = session.role === 'admin' || session.role === 'platform_admin';
  const apps = db.prepare(`
    SELECT a.slug, a.name, a.domain, a.description, a.public_access, a.visibility, a.category,
      -- v2.7.21: same precedence fix as above — explicit role wins.
      COALESCE(aur.app_role, CASE WHEN a.visibility = 'public' THEN 'viewer' ELSE 'none' END) as role,
      CASE WHEN a.github_url IS NOT NULL AND a.github_url != '' THEN 1 ELSE 0 END as has_github,
      hp.is_down as prod_down, hp.last_status as prod_status,
      hs.is_down as sand_down, hs.last_status as sand_status,
      (SELECT version FROM deployments WHERE app_id = a.id AND env = 'production' AND status = 'live' ORDER BY finished_at DESC LIMIT 1) as prod_version,
      (SELECT version FROM deployments WHERE app_id = a.id AND env = 'sandbox'    AND status = 'live' ORDER BY finished_at DESC LIMIT 1) as sand_version
    FROM apps a
    LEFT JOIN app_user_roles aur ON a.id = aur.app_id AND aur.user_id = ?
    LEFT JOIN health_state hp ON a.id = hp.app_id AND hp.env = 'production'
    LEFT JOIN health_state hs ON a.id = hs.app_id AND hs.env = 'sandbox'
    ORDER BY a.name
  `).all(session.id).map(a => ({
    ...a,
    role: isAdmin && (a.role === 'none' || a.role === 'viewer') ? 'admin' : a.role,
    has_icon: hasIcon(a.slug),
    has_github: !!a.has_github,
  })).filter(a => isAdmin || a.visibility !== 'hidden');

  res.json({
    user: {
      id: session.id,
      name: session.name,
      email: session.email,
      username: session.username,
      avatar_url: session.avatar_url,
      phone: session.phone,
      year_of_birth: session.year_of_birth,
    },
    apps,
  });
});

/**
 * POST /api/identity/set-password
 *
 * Self-service: the *currently authenticated user* sets THEIR own password
 * + receives a fresh Bearer session token. Accepts either Bearer
 * (cc_identity_token) or X-API-Key auth so an admin who currently signs
 * in via dhk_admin_* can set a password and migrate to the unified login
 * without needing a different admin's help.
 *
 * Wipes all of the user's existing identity_sessions on success — any
 * Bearer that may have leaked is invalidated; the new token returned
 * here is the only valid one.
 *
 * Bridges the v2.4.0 migration off `dhk_admin_*`-only login.
 */
router.post('/set-password', (req, res) => {
  const db = getDb();

  // Auth: prefer Bearer (matches /me), fall back to X-API-Key (lets a
  // dhk_admin_* / dhk_user_* paste-key user migrate themselves).
  let user = null;
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (bearer) {
    const tokenHash = hashApiKey(bearer);
    user = db.prepare(`
      SELECT u.* FROM identity_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
    `).get(tokenHash);
  }
  if (!user) {
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      const keyHash = hashApiKey(apiKey);
      user = db.prepare('SELECT * FROM users WHERE api_key_hash = ? AND active = 1').get(keyHash);
    }
  }
  if (!user) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');

  const { password } = req.body || {};
  if (!password || typeof password !== 'string' || password.length < 12) {
    throw new AppError('Password must be at least 12 characters', 400, 'VALIDATION');
  }

  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(password), user.id);
  db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(user.id);

  // Issue a fresh session so the caller can drop the API-key path
  // immediately and start using Bearer (cc_identity_token) right away.
  const token = generateSessionToken();
  const expiresAt = new Date(Date.now() + SESSION_DURATION_HOURS * 3600 * 1000)
    .toISOString().slice(0, 19).replace('T', ' ');
  db.prepare(`
    INSERT INTO identity_sessions (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `).run(user.id, hashApiKey(token), expiresAt);

  // v2.6.18: set cc_token cookie for the fresh session — same as
  // POST /login. Without this, the user logs in via /set-password
  // (the migration path off dhk_admin_* API keys), gets a Bearer
  // token, but per-app routes still 302 to /login because no cookie
  // was set.
  setSessionCookie(res, token, req);

  log.info(`User ${user.id} (${user.email || user.username}) set their own password`);
  res.json({
    ok: true,
    token,
    expires_at: expiresAt,
    user: { id: user.id, name: user.name, email: user.email, username: user.username },
  });
});

/**
 * GET /api/identity/preview-as/:userId
 * Admin-only: returns the portal view (apps + roles) as a specific user would see it.
 * Headers: Authorization: Bearer <admin-session-token>
 */
router.get('/preview-as/:userId', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) throw new AppError('Authorization: Bearer TOKEN header required', 401, 'NO_TOKEN');

  const db = getDb();
  const tokenHash = hashApiKey(token);

  const session = db.prepare(`
    SELECT u.role FROM identity_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(tokenHash);

  if (!session) throw new AppError('Invalid or expired token', 401, 'INVALID_TOKEN');
  if (session.role !== 'admin' && session.role !== 'platform_admin') throw new AppError('Admin only', 403, 'FORBIDDEN');

  const targetId = Number(req.params.userId);
  const target = db.prepare('SELECT id, name, email, username, avatar_url, role FROM users WHERE id = ?').get(targetId);
  if (!target) throw new AppError('User not found', 404, 'NOT_FOUND');

  const isTargetAdmin = target.role === 'admin' || target.role === 'platform_admin';
  const apps = db.prepare(`
    SELECT a.slug, a.name, a.domain, a.description, a.public_access, a.visibility, a.category,
      -- v2.7.21: explicit per-app role wins; public-→-viewer is only the
      -- fallback for users WITHOUT an explicit row. Old shape returned
      -- 'viewer' for everyone on public apps, wiping owner/admin/user.
      COALESCE(aur.app_role, CASE WHEN a.visibility = 'public' THEN 'viewer' ELSE 'none' END) as app_role,
      CASE WHEN a.github_url IS NOT NULL AND a.github_url != '' THEN 1 ELSE 0 END as has_github,
      hp.is_down as prod_down, hp.last_status as prod_status,
      hs.is_down as sand_down, hs.last_status as sand_status,
      (SELECT version FROM deployments WHERE app_id = a.id AND env = 'production' AND status = 'live' ORDER BY finished_at DESC LIMIT 1) as prod_version,
      (SELECT version FROM deployments WHERE app_id = a.id AND env = 'sandbox'    AND status = 'live' ORDER BY finished_at DESC LIMIT 1) as sand_version
    FROM apps a
    LEFT JOIN app_user_roles aur ON a.id = aur.app_id AND aur.user_id = ?
    LEFT JOIN health_state hp ON a.id = hp.app_id AND hp.env = 'production'
    LEFT JOIN health_state hs ON a.id = hs.app_id AND hs.env = 'sandbox'
    ORDER BY a.name
  `).all(targetId).map(a => ({
    ...a,
    has_icon: hasIcon(a.slug),
    has_github: !!a.has_github,
  })).filter(a => isTargetAdmin || a.visibility !== 'hidden');

  res.json({ user: target, apps });
});

/**
 * GET /api/identity/app-updates/:slug
 * Returns production deployments since the user's last visit to this app,
 * then bumps last_visit_at to now.
 * Auth: Authorization: Bearer TOKEN
 */
router.get('/app-updates/:slug', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) throw new AppError('Authorization required', 401, 'UNAUTHORIZED');

  const db = getDb();
  const session = db.prepare(`
    SELECT u.id as user_id FROM identity_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(hashApiKey(token));
  if (!session) throw new AppError('Invalid or expired token', 401, 'INVALID_TOKEN');

  const app = db.prepare('SELECT id, name FROM apps WHERE slug = ?').get(req.params.slug);
  if (!app) throw new AppError('App not found', 404, 'NOT_FOUND');

  // v2.27.0 SECURITY: a valid session proves WHO, not WHAT they may see.
  // Confirm this user is actually on this app before returning its update
  // history. Admins/platform admins see every app by design.
  const viewer = db.prepare('SELECT role FROM users WHERE id = ?').get(session.user_id);
  if (viewer?.role !== 'admin' && viewer?.role !== 'platform_admin') {
    const access = db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(app.id, session.user_id);
    if (!access) throw new AppError('Access denied', 403, 'FORBIDDEN');
  }

  const lastVisit = db.prepare(
    'SELECT last_visit_at FROM app_last_visit WHERE user_id = ? AND app_id = ?'
  ).get(session.user_id, app.id);

  const lastVisitAt = lastVisit ? lastVisit.last_visit_at : null;

  const updates = lastVisitAt ? db.prepare(`
    SELECT version, commit_hash, commit_message, finished_at
    FROM deployments
    WHERE app_id = ? AND env = 'production' AND status = 'live'
      AND finished_at > ?
    ORDER BY finished_at DESC
    LIMIT 10
  `).all(app.id, lastVisitAt) : [];

  db.prepare(`
    INSERT INTO app_last_visit (user_id, app_id, last_visit_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(user_id, app_id) DO UPDATE SET last_visit_at = datetime('now')
  `).run(session.user_id, app.id);

  res.json({ last_visit_at: lastVisitAt, is_first_visit: !lastVisitAt, updates });
});

export default router;
