import { randomBytes, timingSafeEqual } from 'crypto';
import { getDb } from '../db.js';
import { hashApiKey } from './encryption.js';
import {
  OAuthError, ACCESS_PREFIX, REFRESH_PREFIX, ACCESS_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_DAYS,
  CODE_TTL_SECONDS, AUTH_REQUEST_TTL_SECONDS, pkceMatches, canonicalResource, scopeFor,
} from './oauthPolicy.js';

// Persistence for the MCP OAuth authorization server. Every secret is stored
// as its SHA-256 (hashApiKey) and returned in plaintext exactly once.

const rand = (n = 32) => randomBytes(n).toString('base64url');

function sameHash(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// A registration nobody ever approved is garbage after a day: DCR is open to
// anyone, so unused rows must not pile up.
export function pruneStale() {
  const db = getDb();
  db.prepare("DELETE FROM oauth_auth_requests WHERE expires_at <= datetime('now')").run();
  db.prepare("DELETE FROM oauth_codes WHERE expires_at <= datetime('now', '-1 day')").run();
  db.prepare(`
    DELETE FROM oauth_clients
    WHERE created_at <= datetime('now', '-1 day')
      AND client_id NOT IN (SELECT client_id FROM oauth_grants)
      AND client_id NOT IN (SELECT client_id FROM oauth_codes)
  `).run();
  db.prepare("DELETE FROM oauth_tokens WHERE expires_at <= datetime('now', '-1 day')").run();
}

export function registerClient(meta) {
  const db = getDb();
  const clientId = `mcpc_${rand(16)}`;
  const secret = meta.token_endpoint_auth_method === 'none' ? null : `dhk_ocs_${rand(24)}`;
  db.prepare(`
    INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, token_endpoint_auth_method)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(clientId, secret ? hashApiKey(secret) : null, meta.client_name,
    JSON.stringify(meta.redirect_uris), JSON.stringify(meta.grant_types), meta.token_endpoint_auth_method);
  const row = getClient(clientId);
  return { client: row, clientSecret: secret };
}

export function getClient(clientId) {
  if (typeof clientId !== 'string' || !clientId) return null;
  const row = getDb().prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(clientId);
  if (!row) return null;
  return { ...row, redirect_uris: JSON.parse(row.redirect_uris), grant_types: JSON.parse(row.grant_types) };
}

/**
 * Client authentication at the token and revocation endpoints. `presented` is
 * { method, clientId, secret } as parsed from the request; the registered
 * method must be the one used.
 */
export function authenticateClient(presented) {
  const client = getClient(presented.clientId);
  if (!client) throw new OAuthError('invalid_client', 'Unknown client', 401);
  if (client.token_endpoint_auth_method === 'none') {
    if (presented.method !== 'none') throw new OAuthError('invalid_client', 'This client is public and has no secret', 401);
    return client;
  }
  if (presented.method !== client.token_endpoint_auth_method) {
    throw new OAuthError('invalid_client', `This client authenticates with ${client.token_endpoint_auth_method}`, 401);
  }
  if (!presented.secret || !sameHash(hashApiKey(presented.secret), client.client_secret_hash)) {
    throw new OAuthError('invalid_client', 'Client authentication failed', 401);
  }
  return client;
}

export function createAuthRequest({ clientId, redirectUri, codeChallenge, scope, resource, state }) {
  const id = rand(16);
  getDb().prepare(`
    INSERT INTO oauth_auth_requests (id, client_id, redirect_uri, code_challenge, scope, resource, state, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+' || ? || ' seconds'))
  `).run(id, clientId, redirectUri, codeChallenge, scope, resource, state ?? null, AUTH_REQUEST_TTL_SECONDS);
  return id;
}

export function getAuthRequest(id) {
  if (typeof id !== 'string' || !id) return null;
  return getDb().prepare(`
    SELECT r.*, c.client_name FROM oauth_auth_requests r
    JOIN oauth_clients c ON c.client_id = r.client_id
    WHERE r.id = ? AND r.expires_at > datetime('now')
  `).get(id) || null;
}

/** Consume a pending request (one decision per request). Null when already decided or expired. */
export function takeAuthRequest(id) {
  const db = getDb();
  return db.transaction(() => {
    const row = getAuthRequest(id);
    if (!row) return null;
    db.prepare('DELETE FROM oauth_auth_requests WHERE id = ?').run(id);
    return row;
  })();
}

export function createCode({ clientId, userId, redirectUri, codeChallenge, scope, resource, readOnly }) {
  const code = rand(32);
  getDb().prepare(`
    INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scope, resource, read_only, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+' || ? || ' seconds'))
  `).run(hashApiKey(code), clientId, userId, redirectUri, codeChallenge, scope, resource, readOnly ? 1 : 0, CODE_TTL_SECONDS);
  return code;
}

function issueTokens(db, grantId) {
  const access = `${ACCESS_PREFIX}${rand(32)}`;
  const refresh = `${REFRESH_PREFIX}${rand(32)}`;
  db.prepare(`INSERT INTO oauth_tokens (token_hash, grant_id, kind, expires_at)
              VALUES (?, ?, 'access', datetime('now', '+' || ? || ' seconds'))`).run(hashApiKey(access), grantId, ACCESS_TOKEN_TTL_SECONDS);
  db.prepare(`INSERT INTO oauth_tokens (token_hash, grant_id, kind, expires_at)
              VALUES (?, ?, 'refresh', datetime('now', '+' || ? || ' days'))`).run(hashApiKey(refresh), grantId, REFRESH_TOKEN_TTL_DAYS);
  return { access, refresh };
}

export function revokeGrantById(grantId) {
  const db = getDb();
  db.prepare("UPDATE oauth_grants SET revoked_at = COALESCE(revoked_at, datetime('now')) WHERE id = ?").run(grantId);
  db.prepare("UPDATE oauth_tokens SET revoked_at = COALESCE(revoked_at, datetime('now')) WHERE grant_id = ?").run(grantId);
}

function tokenResponse(grant, pair) {
  return {
    access_token: pair.access,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: pair.refresh,
    scope: scopeFor(!!grant.read_only),
  };
}

/**
 * authorization_code grant. A code is single-use: presenting it a second time
 * revokes everything issued from it (OAuth 2.1 section 4.1.3).
 */
export function redeemCode({ code, client, redirectUri, verifier, resource }) {
  if (typeof code !== 'string' || !code) throw new OAuthError('invalid_request', 'code is required');
  const db = getDb();
  const out = db.transaction(() => {
    const hash = hashApiKey(code);
    const row = db.prepare('SELECT * FROM oauth_codes WHERE code_hash = ?').get(hash);
    if (!row || row.client_id !== client.client_id) throw new OAuthError('invalid_grant', 'Unknown authorization code');
    if (row.used_at) {
      if (row.grant_id) revokeGrantById(row.grant_id);
      return { err: new OAuthError('invalid_grant', 'Authorization code was already used; tokens issued from it are revoked') };
    }
    if (Date.parse(row.expires_at.replace(' ', 'T') + 'Z') <= Date.now()) throw new OAuthError('invalid_grant', 'Authorization code expired');
    if (redirectUri !== row.redirect_uri) throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request');
    if (!pkceMatches(verifier, row.code_challenge)) throw new OAuthError('invalid_grant', 'code_verifier does not match the code_challenge');
    if (resource != null && canonicalResource(resource) !== canonicalResource(row.resource)) {
      throw new OAuthError('invalid_target', 'resource does not match the authorization request');
    }
    const user = db.prepare('SELECT active FROM users WHERE id = ?').get(row.user_id);
    if (!user?.active) throw new OAuthError('invalid_grant', 'The approving account is deactivated');
    const grantId = db.prepare(`
      INSERT INTO oauth_grants (user_id, client_id, scope, resource, read_only) VALUES (?, ?, ?, ?, ?)
    `).run(row.user_id, row.client_id, row.scope, row.resource, row.read_only).lastInsertRowid;
    db.prepare("UPDATE oauth_codes SET used_at = datetime('now'), grant_id = ? WHERE code_hash = ?").run(grantId, hash);
    return { ok: tokenResponse(row, issueTokens(db, grantId)) };
  })();
  if (out.err) throw out.err;
  return out.ok;
}

/**
 * refresh_token grant with rotation. The presented refresh token is spent; a
 * spent one presented again means it leaked, so the whole grant is revoked
 * (OAuth 2.1 section 4.3.1).
 */
export function refreshTokens({ refreshToken, client, resource }) {
  if (typeof refreshToken !== 'string' || !refreshToken.startsWith(REFRESH_PREFIX)) {
    throw new OAuthError('invalid_grant', 'Unknown refresh token');
  }
  if (!client.grant_types.includes('refresh_token')) throw new OAuthError('unauthorized_client', 'This client did not register the refresh_token grant');
  const db = getDb();
  const out = db.transaction(() => {
    const hash = hashApiKey(refreshToken);
    const row = db.prepare(`
      SELECT t.*, g.client_id, g.user_id, g.read_only, g.resource, g.revoked_at AS grant_revoked_at
      FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
      WHERE t.token_hash = ? AND t.kind = 'refresh'
    `).get(hash);
    if (!row || row.client_id !== client.client_id) throw new OAuthError('invalid_grant', 'Unknown refresh token');
    if (row.revoked_at || row.grant_revoked_at) {
      revokeGrantById(row.grant_id);
      return { err: new OAuthError('invalid_grant', 'Refresh token was already used or revoked; the connection is revoked') };
    }
    if (Date.parse(row.expires_at.replace(' ', 'T') + 'Z') <= Date.now()) throw new OAuthError('invalid_grant', 'Refresh token expired');
    if (resource != null && canonicalResource(resource) !== canonicalResource(row.resource)) {
      throw new OAuthError('invalid_target', 'resource does not match the grant');
    }
    const user = db.prepare('SELECT active FROM users WHERE id = ?').get(row.user_id);
    if (!user?.active) throw new OAuthError('invalid_grant', 'The approving account is deactivated');
    db.prepare("UPDATE oauth_tokens SET revoked_at = datetime('now') WHERE token_hash = ?").run(hash);
    return { ok: tokenResponse(row, issueTokens(db, row.grant_id)) };
  })();
  if (out.err) throw out.err;
  return out.ok;
}

/** RFC 7009. Revoking a refresh token ends the grant; an access token ends just itself. */
export function revokeToken({ token, client }) {
  if (typeof token !== 'string' || !token) return;
  const db = getDb();
  const row = db.prepare(`
    SELECT t.token_hash, t.kind, t.grant_id, g.client_id FROM oauth_tokens t
    JOIN oauth_grants g ON g.id = t.grant_id WHERE t.token_hash = ?
  `).get(hashApiKey(token));
  if (!row || row.client_id !== client.client_id) return;
  if (row.kind === 'refresh') revokeGrantById(row.grant_id);
  else db.prepare("UPDATE oauth_tokens SET revoked_at = COALESCE(revoked_at, datetime('now')) WHERE token_hash = ?").run(row.token_hash);
}

/** Resolve a presented access token to its grant and user, or null (invalid, expired, revoked). */
export function lookupAccessToken(token) {
  if (typeof token !== 'string' || !token.startsWith(ACCESS_PREFIX)) return null;
  const db = getDb();
  const row = db.prepare(`
    SELECT g.id AS grant_id, g.client_id, g.resource, g.read_only, c.client_name,
           u.id AS uid, u.name, u.email, u.role, u.active, u.kind, u.username, u.mcp_app_scope
    FROM oauth_tokens t
    JOIN oauth_grants g ON g.id = t.grant_id
    JOIN oauth_clients c ON c.client_id = g.client_id
    JOIN users u ON u.id = g.user_id
    WHERE t.token_hash = ? AND t.kind = 'access'
      AND t.revoked_at IS NULL AND t.expires_at > datetime('now')
      AND g.revoked_at IS NULL
  `).get(hashApiKey(token));
  if (!row) return null;
  try { db.prepare("UPDATE oauth_grants SET last_used_at = datetime('now') WHERE id = ?").run(row.grant_id); } catch (_) {}
  return row;
}

export function listGrantsForUser(userId) {
  return getDb().prepare(`
    SELECT g.id, g.scope, g.read_only, g.created_at, g.last_used_at, c.client_name, c.redirect_uris
    FROM oauth_grants g JOIN oauth_clients c ON c.client_id = g.client_id
    WHERE g.user_id = ? AND g.revoked_at IS NULL
    ORDER BY g.id DESC
  `).all(userId).map(g => {
    let hosts = [];
    try { hosts = [...new Set(JSON.parse(g.redirect_uris).map(u => new URL(u).host))]; } catch (_) {}
    return {
      id: g.id, client_name: g.client_name, redirect_hosts: hosts, scope: g.scope,
      read_only: !!g.read_only, created_at: g.created_at, last_used_at: g.last_used_at,
    };
  });
}

export function revokeGrantForUser(userId, grantId) {
  const row = getDb().prepare('SELECT id, revoked_at FROM oauth_grants WHERE id = ? AND user_id = ?').get(grantId, userId);
  if (!row) return null;
  if (!row.revoked_at) revokeGrantById(row.id);
  return row.id;
}
