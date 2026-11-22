import crypto from 'crypto';
import { getDb } from '../db.js';
import { getDiscovery, getOidcConfig } from '../routes/oidc.js';
import { findSigningKey } from './idpJwks.js';
import { OAuthError, issuerOf, canonicalResource, resolveScope } from './oauthPolicy.js';
import { getDcrPolicy } from './oauthClientPolicy.js';
import { resolveRequestedResource } from './appMcp/oauthResource.js';
import { issueAssertionGrant } from './oauthStore.js';
import { isEnrolled } from './mfa.js';
import { idpDidMfa } from './ssoMfa.js';
import { parseScopeString } from './mcpScopes.js';

// Identity Assertion JWT Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant-06;
// MCP ext-auth "Enterprise-Managed Authorization"). The enterprise IdP, through
// an RFC 8693 token exchange, gives the MCP client a short JWT (typ
// oauth-id-jag+jwt) naming the user, AppCrane as audience and the client; the
// client presents it at /oauth/token with the RFC 7523 jwt-bearer grant and
// gets an access token without a browser consent.
//
// Trusted only from the OIDC IdP AppCrane already signs people in with:
// issuer and keys come from that IdP's discovery document and JWKS. Off unless a
// platform admin turns it on. A client may use it only when it is confidential
// (authenticates with its secret), a platform admin approved it, and a platform
// admin pinned a blueprint to it: the blueprint is the consent nobody clicks.

export const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
export const ID_JAG_PROFILE = 'urn:ietf:params:oauth:grant-profile:id-jag';
const ID_JAG_TYPES = new Set(['oauth-id-jag+jwt', 'application/oauth-id-jag+jwt']);
export const ID_JAG_MAX_LIFETIME_SECONDS = 600;
const SKEW_SECONDS = 60;

const ALGS = {
  RS256: { hash: 'sha256' }, RS384: { hash: 'sha384' }, RS512: { hash: 'sha512' },
  PS256: { hash: 'sha256', pss: true }, PS384: { hash: 'sha384', pss: true }, PS512: { hash: 'sha512', pss: true },
  ES256: { hash: 'sha256', ec: true }, ES384: { hash: 'sha384', ec: true },
};

const grantError = (why) => new OAuthError('invalid_grant', `ID-JAG refused: ${why}`);

function decodePart(part) {
  try { return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')); } catch (_) { return null; }
}

/** Verify the assertion's signature and claims. Returns its claims or throws OAuthError('invalid_grant'). */
export async function verifyIdJag(assertion, { issuer, jwksUri, audience, clientId, trusted = null, now = Math.floor(Date.now() / 1000) }) {
  if (typeof assertion !== 'string' || assertion.length > 16384) throw new OAuthError('invalid_request', 'assertion is required');
  const parts = assertion.split('.');
  if (parts.length !== 3) throw grantError('not a signed JWT');
  const header = decodePart(parts[0]);
  const claims = decodePart(parts[1]);
  if (!header || !claims || typeof claims !== 'object') throw grantError('not a signed JWT');
  if (!ID_JAG_TYPES.has(String(header.typ || '').toLowerCase())) throw grantError('typ is not oauth-id-jag+jwt');
  const alg = ALGS[header.alg];
  if (!alg) throw grantError(`alg ${JSON.stringify(String(header.alg)).slice(0, 20)} is not accepted`);
  if (typeof header.kid !== 'string' || !header.kid) throw grantError('the header has no kid');
  const jwk = await findSigningKey(jwksUri, header.kid, Date.now(), trusted);
  if (!jwk) throw grantError('it is signed with a key the IdP does not publish');
  if (jwk.use && jwk.use !== 'sig') throw grantError('the key is published for encryption, not signing');
  if (jwk.alg && jwk.alg !== header.alg) throw grantError('the key is published for a different alg');
  let key;
  try { key = crypto.createPublicKey({ key: jwk, format: 'jwk' }); } catch (_) { throw grantError('the IdP key could not be read'); }
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = Buffer.from(parts[2], 'base64url');
  let valid = false;
  try {
    valid = alg.pss
      ? crypto.verify(alg.hash, data, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, sig)
      : alg.ec
        ? crypto.verify(alg.hash, data, { key, dsaEncoding: 'ieee-p1363' }, sig)
        : crypto.verify(alg.hash, data, key, sig);
  } catch (_) { valid = false; }
  if (!valid) throw grantError('the signature does not verify');

  if (claims.iss !== issuer) throw grantError('iss is not the IdP AppCrane trusts');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (aud.length !== 1 || aud[0] !== audience) throw grantError('aud is not this AppCrane');
  if (claims.client_id !== clientId) throw grantError('client_id is not the client presenting it');
  if (typeof claims.sub !== 'string' || !claims.sub) throw grantError('sub is missing');
  if (typeof claims.jti !== 'string' || !claims.jti || claims.jti.length > 256) throw grantError('jti is missing');
  if (!Number.isFinite(claims.exp) || claims.exp <= now) throw grantError('it has expired');
  if (!Number.isFinite(claims.iat) || claims.iat > now + SKEW_SECONDS) throw grantError('iat is in the future');
  if (claims.exp - claims.iat > ID_JAG_MAX_LIFETIME_SECONDS) throw grantError(`it is valid for longer than ${ID_JAG_MAX_LIFETIME_SECONDS} seconds`);
  return claims;
}

function spendJti(db, iss, jti, exp) {
  db.prepare("DELETE FROM oauth_id_jag_jti WHERE expires_at <= datetime('now')").run();
  const r = db.prepare("INSERT OR IGNORE INTO oauth_id_jag_jti (iss, jti, expires_at) VALUES (?, ?, datetime(?, 'unixepoch'))").run(iss, jti, exp);
  if (r.changes !== 1) throw grantError('it was already used');
}

function grantedScope(requested, inAssertion) {
  const fromReq = parseScopeString(requested);
  const fromJag = parseScopeString(inAssertion);
  const list = fromReq.length && fromJag.length ? fromReq.filter((s) => fromJag.includes(s)) : (fromReq.length ? fromReq : fromJag);
  return resolveScope(list.join(' ')).scope;
}

/** /oauth/token with grant_type jwt-bearer: the token response, or throws OAuthError. */
export async function redeemIdJag({ req, client, assertion, resource, scope }) {
  const db = getDb();
  if (!getDcrPolicy(db).id_jag_enabled) throw new OAuthError('unsupported_grant_type', 'This AppCrane does not accept ID-JAG assertions; a platform admin can turn them on under MCP OAuth settings');
  // The audience an assertion must name is this server's issuer. Without
  // CRANE_DOMAIN that comes from the request's Host header, which the caller
  // chooses, so an assertion made for another server could be matched to it.
  if (!process.env.CRANE_DOMAIN) throw new OAuthError('unsupported_grant_type', 'ID-JAG assertions need CRANE_DOMAIN set, so the audience they must name is fixed');
  if (client.token_endpoint_auth_method === 'none') throw new OAuthError('unauthorized_client', 'Only a confidential client (one that authenticates with its secret) may present an ID-JAG');
  if (!client.approved_at) throw new OAuthError('unauthorized_client', 'A platform admin must approve this client before it may present an ID-JAG');
  if (client.blueprint_id == null) throw new OAuthError('unauthorized_client', 'A platform admin must pin a blueprint to this client before it may present an ID-JAG');
  const cfg = getOidcConfig();
  if (!cfg.enabled || !cfg.discovery_url) throw grantError('no OIDC identity provider is configured');
  let disc;
  try { disc = await getDiscovery(cfg.discovery_url); } catch (_) { throw new OAuthError('temporarily_unavailable', 'The identity provider could not be reached', 503); }
  if (typeof disc?.issuer !== 'string' || typeof disc?.jwks_uri !== 'string') throw new OAuthError('temporarily_unavailable', 'The identity provider metadata has no issuer or jwks_uri', 503);
  let claims;
  try {
    claims = await verifyIdJag(assertion, { issuer: disc.issuer, jwksUri: disc.jwks_uri, audience: issuerOf(req), clientId: client.client_id, trusted: cfg.discovery_url });
  } catch (e) {
    if (e instanceof OAuthError) throw e;
    throw new OAuthError('temporarily_unavailable', 'The identity provider keys could not be fetched', 503);
  }
  const jagResource = Array.isArray(claims.resource) ? (claims.resource.length === 1 ? claims.resource[0] : null) : claims.resource;
  if (jagResource === null) throw new OAuthError('invalid_target', 'The assertion must name exactly one resource');
  if (jagResource !== undefined && resource !== undefined && canonicalResource(String(jagResource)) !== canonicalResource(resource)) {
    throw new OAuthError('invalid_target', 'resource does not match the resource in the assertion');
  }
  const target = resolveRequestedResource(req, jagResource ?? resource, (slug) => !!db.prepare('SELECT 1 FROM apps WHERE slug = ?').get(slug));
  if (!target) throw new OAuthError('invalid_target', 'The assertion names a resource AppCrane does not protect');
  const user = db.prepare('SELECT id, active FROM users WHERE sso_sub = ?').get(claims.sub);
  if (!user) throw grantError('no AppCrane account is linked to this IdP subject; the person signs in with SSO once first');
  if (!user.active) throw grantError('the account is deactivated');
  if (isEnrolled(db, user.id) && !idpDidMfa(claims.amr)) throw grantError('the account uses AppCrane MFA and the assertion does not say the IdP did MFA (amr)');
  spendJti(db, claims.iss, claims.jti, claims.exp);
  return issueAssertionGrant({
    userId: user.id, clientId: client.client_id, scope: grantedScope(scope, claims.scope),
    resource: target, blueprintId: client.blueprint_id, via: 'id-jag',
  });
}
