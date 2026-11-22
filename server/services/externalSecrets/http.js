// One HTTP call to a secret store. Errors carry a status or a short code, never
// a response body, a header or the URL's path: any of those can hold a secret.
//
// A platform connection reaches whatever the platform admin pointed it at. An
// app connection is set by an app owner, so it gets https only and the
// private/loopback/link-local refusal remoteFetch uses, checked on the address
// actually dialled. APPCRANE_SECRET_CONNECTIONS_PRIVATE_OK=1 lifts that for a
// host whose stores live on its private network.
import http from 'node:http';
import https from 'node:https';
import { assertHostNotBlocked, makeGuardedLookup } from '../remoteFetch.js';

const TIMEOUT_MS = 15000;
const MAX_BYTES = 1024 * 1024;

export class StoreError extends Error {
  constructor(reason, status = null) {
    super(reason);
    this.name = 'StoreError';
    this.status = status;
  }
}

export const privateAllowed = () => process.env.APPCRANE_SECRET_CONNECTIONS_PRIVATE_OK === '1';

/** { status, json } for a 2xx; StoreError otherwise. `guarded` for app connections. */
export function requestJson(rawUrl, { method = 'GET', headers = {}, body = null, guarded = false, timeoutMs = TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(rawUrl); } catch (_) { return reject(new StoreError('the connection address is not a valid URL')); }
    const strict = guarded && !privateAllowed();
    if (strict) {
      if (url.protocol !== 'https:') return reject(new StoreError('an app connection must use https'));
      try { assertHostNotBlocked(url); } catch (_) { return reject(new StoreError('the connection address is a private, loopback or link-local address')); }
    }
    const lib = url.protocol === 'https:' ? https : http;
    const payload = body === null ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
    let settled = false;
    const fail = (e) => { if (!settled) { settled = true; reject(e); } };
    const typed = Object.keys(headers).some((h) => h.toLowerCase() === 'content-type');
    const req = lib.request(url, {
      method,
      headers: {
        Accept: 'application/json',
        ...(payload && { 'Content-Length': payload.length, ...(!typed && { 'Content-Type': 'application/json' }) }),
        ...headers,
      },
      ...(strict && { lookup: makeGuardedLookup() }),
      agent: false,
      timeout: timeoutMs,
    }, (res) => {
      const status = res.statusCode || 0;
      const chunks = [];
      let seen = 0;
      res.on('data', (c) => {
        seen += c.length;
        if (seen > MAX_BYTES) { res.destroy(); fail(new StoreError('the response was too large', status)); return; }
        chunks.push(c);
      });
      res.on('error', () => fail(new StoreError('the connection dropped', status)));
      res.on('end', () => {
        if (settled) return;
        if (status >= 300 && status < 400) return fail(new StoreError(`redirect refused (HTTP ${status})`, status));
        if (status < 200 || status >= 300) return fail(new StoreError(`HTTP ${status}`, status));
        let json = null;
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null'); } catch (_) { return fail(new StoreError('the response could not be parsed', status)); }
        settled = true;
        resolve({ status, json });
      });
    });
    req.on('timeout', () => { req.destroy(); fail(new StoreError('timed out')); });
    req.on('error', (e) => fail(new StoreError(e.code === 'EBLOCKEDADDRESS' ? 'the connection address is a private, loopback or link-local address' : `could not connect (${e.code || 'network error'})`)));
    if (payload) req.write(payload);
    req.end();
  });
}

/** Join a base URL and an already-encoded path without losing the base's own path. */
export function joinUrl(base, path) {
  return `${String(base).replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}

export const enc = (segments) => segments.map((s) => encodeURIComponent(s)).join('/');
