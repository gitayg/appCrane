import http from 'http';
import https from 'https';
import { makeGuardedLookup, assertHostNotBlocked } from '../remoteFetch.js';
import { DEFAULT_BASE_URLS } from './config.js';

// The outbound leg. The target is the provider's configured base URL plus one
// path from the gateway's fixed allowlist; nothing the app sends picks the
// host or the path. A host the platform admin listed in private_hosts may
// resolve anywhere and use plain http (an on-prem OpenAI-compatible server);
// every other host must be https and is refused at connect time when it
// resolves to a private, loopback or link-local address.

export class UpstreamBlocked extends Error {}

const FORWARD_REQUEST_HEADERS = ['anthropic-version', 'anthropic-beta', 'openai-beta', 'accept'];
export const FORWARD_RESPONSE_HEADERS = [
  'content-type', 'retry-after', 'request-id', 'x-request-id', 'anthropic-request-id', 'openai-processing-ms',
];

const IDLE_TIMEOUT_MS = 10 * 60_000;

export function targetUrl(cfg, provider, path) {
  const base = cfg.providers?.[provider]?.base_url || DEFAULT_BASE_URLS[provider];
  const u = new URL(base);
  u.pathname = `${u.pathname.replace(/\/+$/, '')}${path}`;
  return u;
}

function guardFor(cfg, url) {
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  if ((cfg.private_hosts || []).includes(host)) return { lookup: undefined };
  if (url.protocol !== 'https:') throw new UpstreamBlocked(`${host} is not https and is not in the gateway's private hosts`);
  try { assertHostNotBlocked(url); } catch (e) { throw new UpstreamBlocked(e.message); }
  return { lookup: makeGuardedLookup() };
}

/**
 * Start the upstream request. Returns the ClientRequest; the caller wires
 * 'response' and 'error'. `key` goes into the auth header only.
 */
export function startUpstream({ cfg, provider, path, key, incomingHeaders, body }) {
  const url = targetUrl(cfg, provider, path);
  const { lookup } = guardFor(cfg, url);
  const headers = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'user-agent': 'AppCrane-LLM-Gateway' };
  for (const h of FORWARD_REQUEST_HEADERS) if (incomingHeaders[h]) headers[h] = String(incomingHeaders[h]);
  if (provider === 'anthropic') {
    headers['x-api-key'] = key;
    if (!headers['anthropic-version']) headers['anthropic-version'] = '2023-06-01';
  } else if (cfg.providers.openai.auth_header === 'api-key') {
    headers['api-key'] = key;
  } else {
    headers.authorization = `Bearer ${key}`;
  }
  const mod = url.protocol === 'https:' ? https : http;
  const req = mod.request({
    method: 'POST',
    hostname: url.hostname.replace(/^\[(.*)\]$/, '$1'),
    port: url.port || undefined,
    path: url.pathname + url.search,
    headers,
    ...(lookup ? { lookup } : {}),
  });
  req.setTimeout(IDLE_TIMEOUT_MS, () => req.destroy(Object.assign(new Error('upstream idle timeout'), { code: 'ETIMEDOUT' })));
  req.end(body);
  return req;
}

/** Remove the provider key, and anything shaped like a provider key, from text going back to the app. */
export function scrubKey(text, key) {
  let out = String(text);
  if (key) out = out.split(key).join('[redacted]');
  return out.replace(/\b(sk-(?:ant-|proj-)?)[A-Za-z0-9*_\-]{6,}/g, '$1[redacted]');
}
