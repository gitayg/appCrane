import { Router } from 'express';
import { getDb } from '../db.js';
import { hashApiKey } from '../services/encryption.js';
import log from '../utils/logger.js';
import {
  OAuthError, issuerOf, mcpResourceOf, canonicalResource, resolveScope, isValidCodeChallenge,
  validateRegistration, SCOPES_SUPPORTED, SCOPE_FULL, AUTH_METHODS, GRANT_TYPES,
} from '../services/oauthPolicy.js';
import {
  pruneStale, registerClient, getClient, authenticateClient, createAuthRequest,
  redeemCode, refreshTokens, revokeToken,
} from '../services/oauthStore.js';
import { createOAuthLimiter } from '../services/oauthRateLimit.js';

// AppCrane as the OAuth 2.1 authorization server for its own MCP endpoint
// (MCP authorization spec 2025-11-25): RFC 9728 protected-resource metadata,
// RFC 8414 server metadata, RFC 7591 registration, authorization code + PKCE
// S256, refresh rotation, RFC 7009 revocation. The consent screen is the SPA
// at /mcp/authorize, backed by routes/oauthConsent.js.

const router = Router();
export const wellKnownRouter = Router();

const registerLimit = createOAuthLimiter('register');
const tokenLimit = createOAuthLimiter('token');
const authorizeLimit = createOAuthLimiter('authorize');

// Metadata and the token/registration/revocation endpoints carry no ambient
// credential (no cookie is read), so any origin may call them.
function openCors(req, res, next) {
  res.set('Access-Control-Allow-Origin', '*');
  next();
}

function noStore(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
}

function protectedResourceMetadata(req, res) {
  const issuer = issuerOf(req);
  res.json({
    resource: mcpResourceOf(req),
    authorization_servers: [issuer],
    scopes_supported: [SCOPE_FULL],
    bearer_methods_supported: ['header'],
    resource_name: 'AppCrane MCP',
  });
}

wellKnownRouter.get('/oauth-protected-resource', openCors, protectedResourceMetadata);
wellKnownRouter.get('/oauth-protected-resource/api/mcp', openCors, protectedResourceMetadata);
wellKnownRouter.get('/oauth-authorization-server', openCors, (req, res) => {
  const issuer = issuerOf(req);
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: GRANT_TYPES,
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: AUTH_METHODS,
    revocation_endpoint_auth_methods_supported: AUTH_METHODS,
    scopes_supported: SCOPES_SUPPORTED,
    authorization_response_iss_parameter_supported: true,
  });
});

function oauthFail(res, err) {
  if (err instanceof OAuthError) {
    if (err.oauthError === 'invalid_client' && err.status === 401) res.set('WWW-Authenticate', 'Basic realm="AppCrane OAuth"');
    return res.status(err.status).json(err.toJSON());
  }
  log.warn(`OAuth: unexpected error: ${err.message}`);
  return res.status(500).json({ error: 'server_error', error_description: 'Internal error' });
}

router.post('/register', openCors, registerLimit, (req, res) => {
  noStore(res);
  try {
    pruneStale();
    const meta = validateRegistration(req.body);
    const { client, clientSecret } = registerClient(meta);
    log.info(`OAuth: registered client ${client.client_id} auth=${client.token_endpoint_auth_method}`);
    res.status(201).json({
      client_id: client.client_id,
      ...(clientSecret ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
      client_id_issued_at: Math.floor(Date.parse(client.created_at.replace(' ', 'T') + 'Z') / 1000),
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      grant_types: client.grant_types,
      response_types: ['code'],
      token_endpoint_auth_method: client.token_endpoint_auth_method,
    });
  } catch (err) {
    oauthFail(res, err);
  }
});

const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function errorPage(res, status, message) {
  res.status(status).type('html').set('Cache-Control', 'no-store').send(
    `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>AppCrane - Authorization error</title></head>` +
    `<body style="font-family:-apple-system,sans-serif;max-width:560px;margin:60px auto;padding:0 16px">` +
    `<h1 style="font-size:20px">This connection request cannot be completed</h1><p>${esc(message)}</p>` +
    `<p style="color:#666">Start the connection again from the app that sent you here.</p></body></html>`);
}

function sessionFromCookie(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)cc_token=([^;]+)/);
  if (!m) return false;
  let token;
  try { token = decodeURIComponent(m[1]); } catch (_) { token = m[1]; }
  return !!getDb().prepare(`
    SELECT 1 FROM identity_sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(hashApiKey(token));
}

const str = (v) => (typeof v === 'string' ? v : undefined);

// GET /oauth/authorize. An unknown client or a redirect_uri that is not an
// exact registered match gets an error page and NO redirect (OAuth 2.1
// section 4.1.2.1); every other problem is reported to the redirect_uri.
router.get('/authorize', authorizeLimit, (req, res) => {
  const q = req.query;
  const client = getClient(str(q.client_id));
  if (!client) return errorPage(res, 400, 'Unknown client_id. The app must register with AppCrane first.');
  let redirectUri = str(q.redirect_uri);
  if (!redirectUri && client.redirect_uris.length === 1) redirectUri = client.redirect_uris[0];
  if (!redirectUri || !client.redirect_uris.includes(redirectUri)) {
    return errorPage(res, 400, 'redirect_uri is missing or does not exactly match a URI this app registered.');
  }
  const state = str(q.state);
  const issuer = issuerOf(req);
  const fail = (error, description) => {
    const u = new URL(redirectUri);
    u.searchParams.set('error', error);
    u.searchParams.set('error_description', description);
    if (state !== undefined) u.searchParams.set('state', state);
    u.searchParams.set('iss', issuer);
    return res.redirect(302, u.toString());
  };
  if (state !== undefined && state.length > 1024) return fail('invalid_request', 'state is longer than 1024 characters');
  if (str(q.response_type) !== 'code') return fail('unsupported_response_type', "response_type must be 'code'");
  if (str(q.code_challenge_method) !== 'S256') return fail('invalid_request', 'PKCE is required: code_challenge_method must be S256');
  if (!isValidCodeChallenge(str(q.code_challenge))) return fail('invalid_request', 'code_challenge must be a base64url SHA-256 (43 characters)');
  const resource = mcpResourceOf(req);
  const asked = q.resource;
  if (asked !== undefined && (typeof asked !== 'string' || canonicalResource(asked) !== canonicalResource(resource))) {
    return fail('invalid_target', `resource must be ${resource}`);
  }
  const { scope } = resolveScope(str(q.scope));
  const id = createAuthRequest({
    clientId: client.client_id, redirectUri, codeChallenge: q.code_challenge, scope, resource, state,
  });
  const consent = `/mcp/authorize?request=${encodeURIComponent(id)}`;
  return res.redirect(302, sessionFromCookie(req) ? consent : `/login?redirect=${encodeURIComponent(consent)}`);
});

// Client credentials from the request: HTTP Basic (RFC 6749 section 2.3.1,
// form-urlencoded parts), client_secret in the body, or a public client_id.
function presentedClient(req) {
  const body = req.body || {};
  const auth = req.headers.authorization || '';
  if (/^Basic\s+/i.test(auth)) {
    const raw = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
    const i = raw.indexOf(':');
    const dec = (s) => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch (_) { return s; } };
    return { method: 'client_secret_basic', clientId: dec(i < 0 ? raw : raw.slice(0, i)), secret: i < 0 ? '' : dec(raw.slice(i + 1)) };
  }
  if (typeof body.client_secret === 'string' && body.client_secret) {
    return { method: 'client_secret_post', clientId: str(body.client_id), secret: body.client_secret };
  }
  return { method: 'none', clientId: str(body.client_id) };
}

router.post('/token', openCors, tokenLimit, (req, res) => {
  noStore(res);
  try {
    const body = req.body || {};
    const client = authenticateClient(presentedClient(req));
    const grantType = str(body.grant_type);
    if (!grantType) throw new OAuthError('invalid_request', 'grant_type is required');
    if (!client.grant_types.includes(grantType) || !GRANT_TYPES.includes(grantType)) {
      throw new OAuthError(GRANT_TYPES.includes(grantType) ? 'unauthorized_client' : 'unsupported_grant_type', `grant_type ${grantType} is not allowed for this client`);
    }
    const resource = body.resource === undefined ? null : str(body.resource) ?? '';
    const out = grantType === 'authorization_code'
      ? redeemCode({ code: str(body.code), client, redirectUri: str(body.redirect_uri), verifier: str(body.code_verifier), resource })
      : refreshTokens({ refreshToken: str(body.refresh_token), client, resource });
    res.json(out);
  } catch (err) {
    oauthFail(res, err);
  }
});

router.post('/revoke', openCors, tokenLimit, (req, res) => {
  noStore(res);
  try {
    const client = authenticateClient(presentedClient(req));
    revokeToken({ token: str((req.body || {}).token), client });
    res.status(200).json({});
  } catch (err) {
    oauthFail(res, err);
  }
});

export default router;
