// Widget tokens (migration 215): what the drop-in widgets on an app's own host
// authenticate with.
//
// Issued from the host's app-session cookie by POST /__appcrane/widgets/token
// and returned to the page's script, which sends it back as
// `Authorization: Bearer cwt_...` to /__appcrane/widgets/api/*. A header, not
// a cookie, so a cross-site form or image can never carry it, and a request
// that does carry it from another origin needs a CORS preflight no AppCrane
// route answers.
//
// What it is good for, all checked at every use:
//   - one app and one environment: the row's (app_id, app_env) must be the
//     Host's, so a token issued on app A's host is refused on app B's;
//   - the widget endpoints only (nothing else reads this table);
//   - its scopes, and for 'members' and 'app-keys' the app's opt-in
//     (migration 216) at issue time and again at every use;
//   - at most an hour, and never past its app session: the parent row is
//     joined live, so signing out or revoking the session ends the token.

import crypto from 'crypto';
import { hashApiKey } from './encryption.js';
import { resolveAppRole } from '../routes/identity.js';
import { scopeEnabled } from './widgetScopeOptIn.js';

export const WIDGET_TOKEN_PREFIX = 'cwt_';
export const WIDGET_TOKEN_TTL_SECONDS = 3600;
export const WIDGET_SCOPES = ['me', 'sessions', 'members', 'access', 'app-keys'];
// Someone with no role on the app may still ask for one.
const NO_ROLE_SCOPES = ['me', 'access'];
const MAX_PER_SESSION = 20;

/** The live app session behind an app host's cookie, with its user, or null. */
export function appSessionFor(db, site, cookieToken) {
  if (!cookieToken) return null;
  return db.prepare(`
    SELECT s.token_hash, s.expires_at, u.id AS user_id, u.role AS crane_role
    FROM identity_sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.scope = 'app' AND s.app_id = ? AND s.app_env = ?
      AND datetime(s.expires_at) > datetime('now') AND u.active = 1
  `).get(hashApiKey(cookieToken), site.app.id, site.env) || null;
}

export function grantableScopes(db, session, app) {
  const role = resolveAppRole(db, { user_id: session.user_id, crane_role: session.crane_role }, app);
  return (role === 'none' ? NO_ROLE_SCOPES : WIDGET_SCOPES).filter((s) => scopeEnabled(db, app.id, s));
}

/** Issue a token for the session; requested: a scope list or null for all it may have. */
export function issueWidgetToken(db, site, session, requested = null) {
  const allowed = grantableScopes(db, session, site.app);
  const scopes = Array.isArray(requested) ? allowed.filter((s) => requested.includes(s)) : allowed;
  const token = WIDGET_TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
  db.transaction(() => {
    db.prepare("DELETE FROM widget_tokens WHERE datetime(expires_at) <= datetime('now')").run();
    db.prepare(`
      DELETE FROM widget_tokens WHERE parent_token_hash = ? AND token_hash NOT IN (
        SELECT token_hash FROM widget_tokens WHERE parent_token_hash = ? ORDER BY created_at DESC, rowid DESC LIMIT ?)
    `).run(session.token_hash, session.token_hash, MAX_PER_SESSION - 1);
    db.prepare(`
      INSERT INTO widget_tokens (token_hash, user_id, app_id, app_env, parent_token_hash, scopes, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%SZ', min(datetime('now', '+' || ? || ' seconds'), datetime(?))))
    `).run(hashApiKey(token), session.user_id, site.app.id, site.env, session.token_hash, scopes.join(' '), WIDGET_TOKEN_TTL_SECONDS, session.expires_at);
  })();
  const row = db.prepare('SELECT expires_at FROM widget_tokens WHERE token_hash = ?').get(hashApiKey(token));
  return { token, scopes, expires_at: row.expires_at };
}

/**
 * The caller behind a widget token presented on this site, or null: the
 * token must be live, issued for this host's app and environment, and its app
 * session and user must still be live too.
 */
export function resolveWidgetToken(db, site, bearer) {
  if (typeof bearer !== 'string' || !bearer.startsWith(WIDGET_TOKEN_PREFIX)) return null;
  const row = db.prepare(`
    SELECT w.scopes, w.parent_token_hash, w.expires_at AS token_expires_at, u.*
    FROM widget_tokens w
    JOIN identity_sessions s ON s.token_hash = w.parent_token_hash AND s.scope = 'app'
      AND s.app_id = w.app_id AND s.app_env = w.app_env AND datetime(s.expires_at) > datetime('now')
    JOIN users u ON u.id = w.user_id AND u.id = s.user_id AND u.active = 1
    WHERE w.token_hash = ? AND w.app_id = ? AND w.app_env = ? AND datetime(w.expires_at) > datetime('now')
  `).get(hashApiKey(bearer), site.app.id, site.env);
  if (!row) return null;
  const { scopes, parent_token_hash, token_expires_at, ...user } = row;
  return { user, scopes: scopes.split(' ').filter(Boolean), parentHash: parent_token_hash, expiresAt: token_expires_at };
}
