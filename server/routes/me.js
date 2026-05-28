/**
 * GET /api/me — canonical "who is the caller" endpoint for proxied apps.
 *
 * Designed so an app running behind AppCrane's Caddy proxy can do:
 *
 *   const r = await fetch('/api/me');               // default same-origin
 *   if (r.ok) {
 *     const { user, app_role } = await r.json();
 *     // user.id, user.name, user.email, user.role (global)
 *   }
 *
 * Auth precedence (first match wins):
 *   1. `cc_token` cookie — what proxied apps actually have. Browser auto-sends
 *      it on same-origin requests; httpOnly so the app's JS can't read it
 *      directly, but it travels with fetch transparently.
 *   2. `Authorization: Bearer <token>` — for CLI / programmatic callers.
 *   3. `X-API-Key: dhk_*` — admin / agent keys.
 *
 * Optional query: `?app=<slug>` to get the caller's per-app role. Without it
 * the response includes the global role only.
 *
 * NEVER returns a session token, password hash, or any other secret. Just
 * identity + role so the app can decorate its UI ("Hi, Alice. You're an
 * admin on this app.") or branch its logic.
 */
import { Router } from 'express';
import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import { AppError } from '../utils/errors.js';

const router = Router();

function readCookieToken(req) {
  const raw = req.headers.cookie || '';
  const m = raw.match(/(?:^|;\s*)cc_token=([^;]+)/);
  if (!m) return null;
  try { return decodeURIComponent(m[1]); } catch (_) { return m[1]; }
}

function sessionUserFor(db, token) {
  if (!token) return null;
  return db.prepare(`
    SELECT u.* FROM identity_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(hashApiKey(token)) || null;
}

router.get('/me', (req, res) => {
  const db = getDb();

  // 1. Cookie (proxied-app default).
  let user = sessionUserFor(db, readCookieToken(req));
  // 2. Bearer fallback (CLI / programmatic).
  if (!user) {
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    if (bearer) user = sessionUserFor(db, bearer);
  }
  // 3. X-API-Key fallback (admin / agent).
  if (!user) {
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      user = db.prepare('SELECT * FROM users WHERE api_key_hash = ? AND active = 1').get(hashApiKey(apiKey)) || null;
    }
  }
  if (!user) throw new AppError('Authentication required', 401, 'UNAUTHORIZED');

  // Per-app role. Resolution order for the app context:
  //   1. Explicit `?app=<slug>` query (caller knows exactly what it wants).
  //   2. Referer fallback — the app's frontend at /<slug>/... or
  //      /<slug>-sandbox/... fetches /api/me, and the browser auto-sends
  //      Referer on same-origin requests. We extract the first path segment
  //      and use it as the slug. SECURITY: this is a pure look-up — the
  //      user's role is computed from THEIR per-app row, not derived from
  //      the slug, so a spoofed Referer can only ask "what's my role on
  //      app X", never escalate. If no Referer / malformed / no match, the
  //      response omits the per-app fields (lean global-only payload).
  let appSlug = req.query.app ? String(req.query.app) : null;
  if (!appSlug) {
    const ref = req.headers.referer || '';
    if (ref) {
      try {
        const seg = new URL(ref).pathname.split('/').filter(Boolean)[0];
        if (seg && /^[a-z0-9][a-z0-9-]*$/.test(seg)) appSlug = seg;
      } catch (_) { /* malformed referer — ignore */ }
    }
  }

  // Global admins/platform_admins are 'admin' on every app (matches /verify).
  // Public apps grant 'viewer' to any authenticated user without an explicit
  // per-app role. Sandbox URLs run at /<slug>-sandbox/* but app_user_roles
  // is keyed to the base slug — try the exact slug first, then strip the
  // suffix as a fallback.
  let appRole = null;
  let appSlugOut = null;
  if (appSlug) {
    let app = db.prepare('SELECT id, slug, visibility FROM apps WHERE slug = ?').get(appSlug);
    if (!app && appSlug.endsWith('-sandbox')) {
      app = db.prepare('SELECT id, slug, visibility FROM apps WHERE slug = ?')
        .get(appSlug.slice(0, -'-sandbox'.length));
    }
    if (app) {
      appSlugOut = app.slug;
      if (user.role === 'admin' || user.role === 'platform_admin') {
        appRole = 'admin';
      } else {
        const r = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(app.id, user.id);
        appRole = r?.app_role || (app.visibility === 'public' ? 'viewer' : 'none');
      }
    }
  }

  res.json({
    user: {
      id:       user.id,
      name:     user.name,
      email:    user.email,
      username: user.username,
      role:     user.role,
    },
    ...(appSlugOut !== null && { app: appSlugOut, app_role: appRole }),
  });
});

export default router;
