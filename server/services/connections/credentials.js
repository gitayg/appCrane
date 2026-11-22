// Turning a stored credential into the upstream auth header, plus every string
// that must never reach the app (the gateway scrubs responses for them).
//
// Google service accounts: a signed JWT (RS256) is exchanged at Google's token
// endpoint for an access token, cached until a minute before it expires.

import { createSign } from 'crypto';
import { upstreamRequest, UpstreamError } from './upstream.js';

const GOOGLE_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const googleTokens = new Map();
let googleTokenUri = GOOGLE_TOKEN_URI;
/** Test seam: the token endpoint (still dialled through the guarded upstream). */
export function _setGoogleTokenUriForTests(uri) { googleTokenUri = uri || GOOGLE_TOKEN_URI; googleTokens.clear(); }

const b64url = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

export function googleAssertion(creds, settings, nowSec = Math.floor(Date.now() / 1000)) {
  const header = { alg: 'RS256', typ: 'JWT', ...(creds.private_key_id ? { kid: creds.private_key_id } : {}) };
  const claims = {
    iss: creds.client_email, scope: settings.scopes.join(' '), aud: googleTokenUri, iat: nowSec, exp: nowSec + 3600,
    ...(settings.subject ? { sub: settings.subject } : {}),
  };
  const unsigned = `${b64url(header)}.${b64url(claims)}`;
  const sig = createSign('RSA-SHA256').update(unsigned).sign(creds.private_key).toString('base64url');
  return `${unsigned}.${sig}`;
}

async function googleAccessToken(conn, creds, settings) {
  const key = `${conn.id}:${conn.updated_at}`;
  const hit = googleTokens.get(key);
  if (hit && hit.expiresAt > Date.now() + 60_000) return hit.token;
  const form = new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: googleAssertion(creds, settings) }).toString();
  const res = await upstreamRequest(new URL(googleTokenUri), {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: Buffer.from(form), timeoutMs: 15000, maxResponseBytes: 64 * 1024,
  });
  let json = null;
  try { json = JSON.parse(res.body.toString('utf8')); } catch (_) {}
  if (res.status !== 200 || typeof json?.access_token !== 'string') {
    throw new UpstreamError('UPSTREAM_AUTH', `Google refused the service account (HTTP ${res.status})`);
  }
  for (const k of googleTokens.keys()) if (k.startsWith(`${conn.id}:`)) googleTokens.delete(k);
  googleTokens.set(key, { token: json.access_token, expiresAt: Date.now() + (Number(json.expires_in) || 3600) * 1000 });
  return json.access_token;
}

/** { headers, secrets }: the auth header(s) to add upstream, and the strings to scrub from anything sent back. */
export async function authFor(conn, creds, settings) {
  switch (conn.auth_type) {
    case 'bearer':
      return { headers: { authorization: `Bearer ${creds.token}` }, secrets: [creds.token] };
    case 'header':
      return { headers: { [conn.auth_header.toLowerCase()]: creds.value }, secrets: [creds.value] };
    case 'basic': {
      const encoded = Buffer.from(`${creds.username}:${creds.password}`).toString('base64');
      return { headers: { authorization: `Basic ${encoded}` }, secrets: [creds.password, encoded] };
    }
    case 'google_service_account': {
      const token = await googleAccessToken(conn, creds, settings);
      return { headers: { authorization: `Bearer ${token}` }, secrets: [token, creds.private_key] };
    }
    default:
      throw new UpstreamError('UPSTREAM_AUTH', 'unknown auth type');
  }
}

/** Replace every secret in `text` (at least 4 characters long) with [redacted]. */
export function scrubSecrets(text, secrets) {
  let out = text;
  for (const s of secrets) if (typeof s === 'string' && s.length >= 4) out = out.split(s).join('[redacted]');
  return out;
}

/** scrubSecrets on raw bytes, so a binary body is not re-encoded. */
export function scrubBuffer(buf, secrets) {
  let out = buf;
  const mark = Buffer.from('[redacted]');
  for (const s of secrets) {
    if (typeof s !== 'string' || s.length < 4) continue;
    const needle = Buffer.from(s);
    let i = out.indexOf(needle);
    if (i < 0) continue;
    const parts = [];
    let from = 0;
    while (i >= 0) { parts.push(out.subarray(from, i), mark); from = i + needle.length; i = out.indexOf(needle, from); }
    parts.push(out.subarray(from));
    out = Buffer.concat(parts);
  }
  return out;
}
