// The hop from AppCrane to the app: the app's own backend port on loopback,
// the same upstream Caddy proxies /<slug> to, with a deadline and a response
// size cap. Plain http.request rather than fetch, so no proxy environment
// variable can send an app's traffic anywhere but 127.0.0.1.

import http from 'node:http';
import { getPortsForSlot } from '../portAllocator.js';

export const LIMITS = {
  timeoutMs: Math.max(1000, parseInt(process.env.APP_MCP_TIMEOUT_MS, 10) || 15000),
  maxRequestBytes: Math.max(1024, parseInt(process.env.APP_MCP_MAX_REQUEST_BYTES, 10) || 256 * 1024),
  maxResponseBytes: Math.max(1024, parseInt(process.env.APP_MCP_MAX_RESPONSE_BYTES, 10) || 256 * 1024),
  callsPerMinute: Math.max(1, parseInt(process.env.APP_MCP_CALLS_PER_MIN, 10) || 60),
};

export function __setLimitsForTests(over) {
  Object.assign(LIMITS, over);
}

export class UpstreamError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

export function upstreamPort(app, env) {
  const ports = getPortsForSlot(app.slot);
  return env === 'sandbox' ? ports.sand_be : ports.prod_be;
}

/**
 * Send one request. Resolves { status, contentType, headers, text, truncated }.
 * Rejects UpstreamError('timeout' | 'unreachable').
 */
export function callApp(app, env, { method, path, headers, body }) {
  const port = upstreamPort(app, env);
  return new Promise((resolve, reject) => {
    const payload = body == null ? null : Buffer.from(body);
    const req = http.request({
      host: '127.0.0.1', port, method, path,
      headers: {
        ...headers,
        Host: `127.0.0.1:${port}`,
        Accept: headers.Accept || 'application/json, text/plain;q=0.9, */*;q=0.1',
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': String(payload.length) } : {}),
      },
    });
    const timer = setTimeout(() => {
      req.destroy(new UpstreamError(`the app did not answer within ${LIMITS.timeoutMs} ms`, 'timeout'));
    }, LIMITS.timeoutMs);
    req.on('response', (res) => {
      const chunks = [];
      let size = 0;
      let truncated = false;
      res.on('data', (c) => {
        if (truncated) return;
        const room = LIMITS.maxResponseBytes - size;
        if (c.length > room) {
          chunks.push(c.subarray(0, room));
          size += room;
          truncated = true;
          res.destroy();
          finish();
          return;
        }
        chunks.push(c);
        size += c.length;
      });
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve({
          status: res.statusCode,
          contentType: String(res.headers['content-type'] || ''),
          headers: res.headers,
          text: new TextDecoder('utf-8', { fatal: false }).decode(Buffer.concat(chunks)).replace(/�$/, ''),
          truncated,
        });
      };
      res.on('end', finish);
      res.on('error', (e) => { if (!truncated) { clearTimeout(timer); reject(e instanceof UpstreamError ? e : new UpstreamError(`the app's response failed: ${e.message}`, 'unreachable')); } });
    });
    req.on('error', (e) => {
      clearTimeout(timer);
      reject(e instanceof UpstreamError ? e : new UpstreamError(`the app is not reachable (${e.code || e.message})`, 'unreachable'));
    });
    if (payload) req.write(payload);
    req.end();
  });
}

// Fixed-window calls per caller and app, in memory, one process.
const buckets = new Map();
const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [k, rec] of buckets) if (now > rec.resetAt) buckets.delete(k);
}, 5 * 60_000);
sweeper.unref?.();

/** null when allowed, or the seconds until the window resets. */
export function takeCall(callerKey, appId, env) {
  const key = `${callerKey}|${appId}|${env}`;
  const now = Date.now();
  const rec = buckets.get(key);
  if (!rec || now > rec.resetAt) {
    buckets.set(key, { count: 1, resetAt: now + 60_000 });
    return null;
  }
  if (rec.count >= LIMITS.callsPerMinute) return Math.ceil((rec.resetAt - now) / 1000);
  rec.count++;
  return null;
}

export function __resetRateLimitForTests() {
  buckets.clear();
}
