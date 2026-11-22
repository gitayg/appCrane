// The outbound leg of the connections gateway. The host is the connection's
// own base_url, never anything the app sends; https only; the address actually
// dialled is checked (a name that resolves to a private, loopback or
// link-local address is refused at connect time, so DNS rebinding gains
// nothing); redirects are never followed here; the body is capped and the
// whole exchange has a deadline.
//
// APPCRANE_CONNECTIONS_PRIVATE_HOSTS (comma-separated host names, operator
// environment only, never an API field) lets a named on-prem upstream resolve
// to a private address.

import https from 'https';
import zlib from 'zlib';
import { makeGuardedLookup, assertHostNotBlocked } from '../remoteFetch.js';

export class UpstreamError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

let seams = { resolve: undefined, ca: undefined };
/** Test seam: { resolve(host, opts) -> [{address, family}], ca } */
export function _setUpstreamForTests(s) { seams = { resolve: undefined, ca: undefined, ...(s || {}) }; }

function privateHosts() {
  return new Set(String(process.env.APPCRANE_CONNECTIONS_PRIVATE_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean));
}

function lookupFor(host) {
  if (privateHosts().has(host)) {
    if (!seams.resolve) return undefined;
    return makeGuardedLookup({ resolve: seams.resolve, isBlocked: () => false });
  }
  return makeGuardedLookup(seams.resolve ? { resolve: seams.resolve } : {});
}

function decode(buf, encoding) {
  const e = String(encoding || 'identity').toLowerCase().trim();
  if (e === 'identity' || e === '') return buf;
  if (e === 'gzip' || e === 'x-gzip') return zlib.gunzipSync(buf);
  if (e === 'deflate') return zlib.inflateSync(buf);
  if (e === 'br') return zlib.brotliDecompressSync(buf);
  throw new UpstreamError('UPSTREAM_ENCODING', `the upstream answered with content-encoding ${e}`);
}

/**
 * One request. Resolves { status, headers, body (Buffer, decoded) }; rejects
 * UpstreamError with code UPSTREAM_BLOCKED | UPSTREAM_TIMEOUT | UPSTREAM_TOO_LARGE |
 * UPSTREAM_UNREACHABLE | UPSTREAM_ENCODING.
 */
export function upstreamRequest(url, { method, headers, body, timeoutMs, maxResponseBytes }) {
  return new Promise((resolve, reject) => {
    if (url.protocol !== 'https:') return reject(new UpstreamError('UPSTREAM_BLOCKED', 'the upstream is not https'));
    let host;
    try { host = assertHostNotBlocked(url).toLowerCase(); } catch (e) { return reject(new UpstreamError('UPSTREAM_BLOCKED', e.message)); }
    let settled = false;
    const fail = (e) => { if (!settled) { settled = true; reject(e); } };
    const lookup = lookupFor(host);
    const req = https.request({
      method,
      hostname: host,
      port: url.port || 443,
      path: url.pathname + url.search,
      headers: { ...headers, 'content-length': body ? body.length : 0 },
      agent: false,
      servername: host,
      ...(lookup ? { lookup } : {}),
      ...(seams.ca ? { ca: seams.ca } : {}),
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxResponseBytes) { res.destroy(); fail(new UpstreamError('UPSTREAM_TOO_LARGE', 'the upstream response is over the connection\'s size limit')); return; }
        chunks.push(c);
      });
      res.on('error', () => fail(new UpstreamError('UPSTREAM_UNREACHABLE', 'the upstream connection dropped')));
      res.on('end', () => {
        if (settled) return;
        let out;
        try { out = decode(Buffer.concat(chunks), res.headers['content-encoding']); } catch (e) { return fail(e instanceof UpstreamError ? e : new UpstreamError('UPSTREAM_ENCODING', 'the upstream body could not be decoded')); }
        if (out.length > maxResponseBytes) return fail(new UpstreamError('UPSTREAM_TOO_LARGE', 'the upstream response is over the connection\'s size limit'));
        settled = true;
        clearTimeout(deadline);
        resolve({ status: res.statusCode || 502, headers: res.headers, body: out });
      });
    });
    const deadline = setTimeout(() => { req.destroy(); fail(new UpstreamError('UPSTREAM_TIMEOUT', `the upstream did not answer within ${timeoutMs} ms`)); }, timeoutMs);
    req.on('error', (e) => {
      clearTimeout(deadline);
      fail(e.code === 'EBLOCKEDADDRESS'
        ? new UpstreamError('UPSTREAM_BLOCKED', 'the upstream resolves to a private, loopback or link-local address')
        : new UpstreamError('UPSTREAM_UNREACHABLE', `could not reach the upstream (${e.code || 'network error'})`));
    });
    req.end(body || undefined);
  });
}
