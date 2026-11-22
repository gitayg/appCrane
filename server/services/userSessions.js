// A user's own sign-in sessions (identity_sessions): list and revoke.
//
// The handle a caller sees is derived from the session's token hash and is
// one-way, so it names a session without being usable as one, and a list
// never carries anything a request could authenticate with. Every lookup is
// by user first and handle second: a handle from someone else's list matches
// nothing.

import crypto from 'crypto';

export function sessionHandle(tokenHash) {
  return crypto.createHash('sha256').update(`appcrane-session-handle:${tokenHash}`).digest('base64url').slice(0, 32);
}

function liveRows(db, userId) {
  return db.prepare(`
    SELECT s.token_hash, s.scope, s.app_env, s.parent_token_hash, s.created_at, s.last_seen_at,
           s.expires_at, s.absolute_expires_at, a.slug AS app_slug, a.name AS app_name, s.app_id
    FROM identity_sessions s LEFT JOIN apps a ON a.id = s.app_id
    WHERE s.user_id = ? AND datetime(s.expires_at) > datetime('now')
    ORDER BY s.id DESC
  `).all(userId);
}

/**
 * The user's live sessions. currentHash: the token hash the request itself
 * signed in with, so the caller can tell which row is "this browser".
 */
export function listSessions(db, userId, currentHash = null) {
  const rows = liveRows(db, userId);
  const handles = new Map(rows.map((r) => [r.token_hash, sessionHandle(r.token_hash)]));
  return rows.map((r) => ({
    id: handles.get(r.token_hash),
    scope: r.scope,
    app: r.scope === 'app' && r.app_slug ? { slug: r.app_slug, name: r.app_name, env: r.app_env } : null,
    parent_id: r.parent_token_hash && handles.get(r.parent_token_hash) || null,
    created_at: r.created_at,
    last_seen_at: r.last_seen_at,
    expires_at: r.expires_at,
    current: !!currentHash && r.token_hash === currentHash,
    _app_id: r.app_id,
  }));
}

export function publicSession(s) {
  const { _app_id, ...rest } = s;
  return rest;
}

/** The live session with this handle, owned by userId, or null. */
export function findSession(db, userId, handle) {
  if (typeof handle !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(handle)) return null;
  return liveRows(db, userId).find((r) => sessionHandle(r.token_hash) === handle) || null;
}

/**
 * End one session. A platform session takes the app sessions it handed off
 * with it (as sign-out does); widget tokens end with their app session because
 * every use joins it. Returns the number of sessions removed.
 */
export function revokeSession(db, userId, tokenHash) {
  return db.transaction(() => {
    let n = db.prepare('DELETE FROM identity_sessions WHERE token_hash = ? AND user_id = ?').run(tokenHash, userId).changes;
    if (n) n += db.prepare("DELETE FROM identity_sessions WHERE parent_token_hash = ? AND scope = 'app' AND user_id = ?").run(tokenHash, userId).changes;
    return n;
  })();
}

export function revokeAllSessions(db, userId) {
  return db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(userId).changes;
}
