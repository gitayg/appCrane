import https from 'node:https';
import { getDb } from '../db.js';
import { assertHostNotBlocked, isBlockedAddress, makeGuardedLookup } from './remoteFetch.js';
import { OAuthError, GRANT_TYPES, redirectUriRefusal, sanitizeClientName } from './oauthPolicy.js';

// OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-03;
// MCP authorization, Client Registration): a client_id that is an https URL
// names a JSON document the client hosts. AppCrane fetches it on /oauth/authorize,
// checks it, and keeps it as an oauth_clients row keyed by that URL, so the
// rest of the flow (codes, grants, tokens, revocation) is the one dynamic
// registration already uses.
//
// The fetch is an SSRF surface reachable without signing in, so: https only, the
// address actually dialled is checked (no private, loopback or link-local
// destinations, no DNS rebinding between check and connect), no redirects
// (section 6: MUST NOT follow), at most 5 KB read (section 10.7's recommended
// cap), 5 s, and errors are never cached (section 6.2).

export const CIMD_MAX_BYTES = 5 * 1024;
export const CIMD_TIMEOUT_MS = 5000;
export const CIMD_DEFAULT_TTL_SECONDS = 3600;
export const CIMD_MAX_TTL_SECONDS = 86400;

let fetchOptions = {};

/** Tests: point names at chosen addresses, trust a test CA, or relax the address check. */
export function configureCimdFetch(opts = {}) {
  fetchOptions = { ...opts };
}

export function isCimdClientId(v) {
  return typeof v === 'string' && /^https:\/\//i.test(v);
}

/** Section 3: why this string cannot be a client identifier URL, or null. */
export function clientIdUrlRefusal(raw) {
  if (typeof raw !== 'string' || raw.length > 2000) return 'client_id URL must be at most 2000 characters';
  let u;
  try { u = new URL(raw); } catch (_) { return 'client_id is not a valid URL'; }
  if (u.protocol !== 'https:') return 'client_id URL must use https';
  if (u.username || u.password) return 'client_id URL must not contain credentials';
  if (raw.includes('#')) return 'client_id URL must not contain a fragment';
  const path = raw.replace(/^https:\/\/[^/?#]*/i, '').split('?')[0];
  if (!path || path === '/') return 'client_id URL must have a path, such as /client.json';
  if (path.split('/').some((seg) => seg === '.' || seg === '..' || /^%2e(%2e)?$/i.test(seg) || /^\.%2e$|^%2e\.$/i.test(seg))) {
    return 'client_id URL must not contain . or .. path segments';
  }
  if (u.href !== raw) return 'client_id URL must be in normalised form';
  return null;
}

function ttlFrom(cacheControl) {
  const cc = String(cacheControl || '').toLowerCase();
  if (/\bno-store\b|\bno-cache\b/.test(cc)) return 0;
  const m = cc.match(/\bmax-age=(\d+)/);
  if (!m) return CIMD_DEFAULT_TTL_SECONDS;
  return Math.min(Number(m[1]), CIMD_MAX_TTL_SECONDS);
}

const refuse = (why) => new OAuthError('invalid_client', `Client metadata document refused: ${why}`, 400);

/** GET the document. Resolves { doc, ttl } or rejects with an OAuthError; never returns the body in an error. */
export function fetchClientMetadata(rawUrl) {
  const isBlocked = fetchOptions.isBlocked || isBlockedAddress;
  return new Promise((resolve, reject) => {
    const url = new URL(rawUrl);
    try { assertHostNotBlocked(url, isBlocked); } catch (_) { return reject(refuse('its host is a private, loopback or link-local address')); }
    let settled = false;
    const fail = (e) => { if (!settled) { settled = true; reject(e); } };
    const req = https.request(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'AppCrane-OAuth-CIMD/1' },
      lookup: makeGuardedLookup({ isBlocked, ...(fetchOptions.resolve ? { resolve: fetchOptions.resolve } : {}) }),
      ...(fetchOptions.ca ? { ca: fetchOptions.ca } : {}),
      agent: false,
      timeout: CIMD_TIMEOUT_MS,
    }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400) { res.destroy(); return fail(refuse(`it redirected (HTTP ${status}); redirects are not followed`)); }
      if (status !== 200) { res.destroy(); return fail(refuse(`HTTP ${status}`)); }
      if (Number(res.headers['content-length'] || 0) > CIMD_MAX_BYTES) { res.destroy(); return fail(refuse(`it is larger than ${CIMD_MAX_BYTES} bytes`)); }
      const chunks = [];
      let seen = 0;
      res.on('data', (c) => {
        seen += c.length;
        if (seen > CIMD_MAX_BYTES) { res.destroy(); fail(refuse(`it is larger than ${CIMD_MAX_BYTES} bytes`)); return; }
        chunks.push(c);
      });
      res.on('error', () => fail(refuse('the connection dropped')));
      res.on('end', () => {
        if (settled) return;
        let doc;
        try { doc = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { return fail(refuse('it is not valid JSON')); }
        settled = true;
        resolve({ doc, ttl: ttlFrom(res.headers['cache-control']) });
      });
    });
    req.on('timeout', () => { req.destroy(); fail(refuse(`no answer within ${CIMD_TIMEOUT_MS} ms`)); });
    // The idle timeout restarts on every byte; this bounds the whole fetch.
    const deadlineMs = fetchOptions.deadlineMs || CIMD_TIMEOUT_MS;
    const deadline = setTimeout(() => { req.destroy(); fail(refuse(`no answer within ${deadlineMs} ms`)); }, deadlineMs);
    req.on('close', () => clearTimeout(deadline));
    req.on('error', (e) => fail(refuse(e.code === 'EBLOCKEDADDRESS'
      ? 'its host resolves to a private, loopback or link-local address'
      : `it could not be fetched (${e.code || 'network error'})`)));
    req.end();
  });
}

function optionalHttpsUri(v) {
  if (typeof v !== 'string' || v.length > 2000) return null;
  try { return new URL(v).protocol === 'https:' ? v : null; } catch (_) { return null; }
}

/** Sections 4 and 4.1: the stored shape of a valid document, or an OAuthError. */
export function validateClientMetadata(doc, clientIdUrl) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw refuse('it is not a JSON object');
  if (doc.client_id !== clientIdUrl) throw refuse('its client_id is not exactly the URL it was fetched from');
  if (typeof doc.client_name !== 'string' || !doc.client_name.trim()) throw refuse('client_name is required');
  if ('client_secret' in doc || 'client_secret_expires_at' in doc) throw refuse('it must not contain a client_secret');
  const method = doc.token_endpoint_auth_method ?? 'none';
  if (method !== 'none') throw refuse(`token_endpoint_auth_method ${JSON.stringify(String(method)).slice(0, 40)} is not supported; AppCrane accepts metadata-document clients as public clients (none) with PKCE`);
  const uris = doc.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10) throw refuse('redirect_uris must be an array of 1 to 10 URIs');
  for (const u of uris) {
    const why = redirectUriRefusal(u);
    if (why) throw refuse(why);
  }
  const grantTypes = doc.grant_types ?? ['authorization_code'];
  if (!Array.isArray(grantTypes) || !grantTypes.includes('authorization_code') || grantTypes.some((g) => !GRANT_TYPES.includes(g))) {
    throw refuse(`grant_types must include authorization_code and only ${GRANT_TYPES.join(', ')}`);
  }
  const responseTypes = doc.response_types ?? ['code'];
  if (!Array.isArray(responseTypes) || responseTypes.some((r) => r !== 'code')) throw refuse("response_types must be ['code']");
  return {
    client_name: sanitizeClientName(doc.client_name),
    redirect_uris: [...new Set(uris)],
    grant_types: [...new Set(grantTypes)],
    client_uri: optionalHttpsUri(doc.client_uri),
    logo_uri: optionalHttpsUri(doc.logo_uri),
  };
}

function cachedRow(db, clientId) {
  return db.prepare(`
    SELECT * FROM oauth_clients WHERE client_id = ? AND is_cimd = 1 AND metadata_expires_at > datetime('now')
  `).get(clientId);
}

/**
 * The oauth_clients row for a metadata-document client, fetched when there is
 * no fresh cached copy. Rejects with OAuthError when the URL or the document
 * is refused; a refusal is not cached, so the next attempt fetches again.
 */
export async function resolveCimdClient(clientId, db = getDb()) {
  const why = clientIdUrlRefusal(clientId);
  if (why) throw new OAuthError('invalid_client', why, 400);
  if (cachedRow(db, clientId)) return { cached: true };
  const { doc, ttl } = await fetchClientMetadata(clientId);
  const m = validateClientMetadata(doc, clientId);
  db.prepare(`
    INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, token_endpoint_auth_method,
                               is_cimd, client_uri, logo_uri, metadata_fetched_at, metadata_expires_at)
    VALUES (?, NULL, ?, ?, ?, 'none', 1, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds'))
    ON CONFLICT(client_id) DO UPDATE SET
      client_name = excluded.client_name, redirect_uris = excluded.redirect_uris, grant_types = excluded.grant_types,
      client_uri = excluded.client_uri, logo_uri = excluded.logo_uri,
      metadata_fetched_at = excluded.metadata_fetched_at, metadata_expires_at = excluded.metadata_expires_at
    WHERE oauth_clients.is_cimd = 1
  `).run(clientId, m.client_name, JSON.stringify(m.redirect_uris), JSON.stringify(m.grant_types), m.client_uri, m.logo_uri, ttl);
  return { cached: false };
}

/**
 * What the consent screen shows about where the client's identity comes from.
 * The host of the client_id URL is the one fact the client cannot choose freely
 * (section 10.6). A logo is offered only from that same host, and is never
 * fetched by AppCrane.
 */
export function cimdConsentView(r) {
  const host = new URL(r.client_id).host;
  const sameHost = (v) => { try { return v && new URL(v).host === host ? v : null; } catch (_) { return null; } };
  return { url: r.client_id, host, client_uri: r.client_uri || null, logo_uri: sameHost(r.logo_uri) };
}
