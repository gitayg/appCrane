import http from 'http';
import https from 'https';
import { isIP } from 'net';
import { makeGuardedLookup, assertHostNotBlocked } from './remoteFetch.js';

// Fetches AppCrane makes to the OIDC identity provider: discovery, JWKS and the
// token exchange. The discovery URL is chosen by a platform admin (or checked
// by the IT setup connection test) and keeps working on any address, so an
// on-prem IdP still works. Every OTHER URL comes out of the discovery
// document, which the IdP's host writes: a token_endpoint or jwks_uri on a
// different origin must be https on a public address (checked on the address
// dialled). Link-local (cloud metadata), "this host" and multicast are refused
// everywhere. No redirect is followed, and the whole request has a deadline.

export const IDP_TIMEOUT_MS = 10_000;
const MAX_BYTES = 1024 * 1024;

function neverAllowed(ip) {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || (a === 169 && b === 254) || a >= 224;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === '::' || /^fe[89ab]/.test(s) || s.startsWith('ff')) return true;
    const m = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return m ? neverAllowed(m[1]) : false;
  }
  return true;
}

const refused = (msg) => Object.assign(new Error(msg), { code: 'EBLOCKEDADDRESS' });

/**
 * { status, ok, text(), json() } for `rawUrl`. `trusted` is the configured
 * discovery URL: its origin may be any address and http or https.
 */
export function idpFetch(rawUrl, { trusted, method = 'GET', headers = {}, body = null, timeoutMs = IDP_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    let trustedOrigin = null;
    try { url = new URL(String(rawUrl)); } catch { return reject(new Error('not a valid URL')); }
    try { trustedOrigin = new URL(String(trusted)).origin; } catch { /* nothing trusted */ }
    const sameOrigin = url.origin === trustedOrigin;
    if (!['http:', 'https:'].includes(url.protocol)) return reject(new Error('the URL must be http or https'));
    if (!sameOrigin && url.protocol !== 'https:') return reject(refused(`${url.host} is not the configured identity provider, so it must be https`));
    const isBlocked = sameOrigin ? neverAllowed : undefined;
    try { assertHostNotBlocked(url, isBlocked); } catch (e) { return reject(e); }
    const lib = url.protocol === 'https:' ? https : http;
    let done = false;
    const finish = (fn, v) => { if (!done) { done = true; clearTimeout(timer); fn(v); } };
    const req = lib.request(url, {
      method,
      headers: { Accept: 'application/json', ...headers, ...(body != null && { 'Content-Length': Buffer.byteLength(body) }) },
      lookup: makeGuardedLookup(isBlocked ? { isBlocked } : {}),
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.resume();
        return finish(reject, new Error(`${url.host} answered HTTP ${res.statusCode}; redirects are not followed`));
      }
      let size = 0;
      const chunks = [];
      res.on('data', (c) => { size += c.length; if (size > MAX_BYTES) req.destroy(new Error('response too large')); else chunks.push(c); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        finish(resolve, {
          status: res.statusCode,
          ok: res.statusCode >= 200 && res.statusCode < 300,
          text: async () => text,
          json: async () => JSON.parse(text),
        });
      });
      res.on('error', (e) => finish(reject, e));
    });
    const timer = setTimeout(() => req.destroy(new Error(`${url.host} did not answer within ${timeoutMs / 1000}s`)), timeoutMs);
    req.on('error', (e) => finish(reject, e));
    if (body != null) req.write(body);
    req.end();
  });
}
