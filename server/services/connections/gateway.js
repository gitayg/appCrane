// The connections gateway: /api/service/connections/<name>/<path>.
//
// An app's server calls it with its APPCRANE_SERVICE_TOKEN. AppCrane checks the
// app holds an active 'connection:<name>' grant covering the method and path,
// strips the app's own auth, cookie, hop-by-hop and X-AppCrane-* headers, adds
// the connection's credential, forwards to the connection's fixed upstream, and
// returns the answer with every credential string scrubbed out. Each call is
// one event-store row (usage.js). Mounted before the global JSON parser: the
// body is read raw, with the connection's own size cap.

import { createHmac } from 'crypto';
import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { appForServiceToken } from '../appServiceToken.js';
import { identitySecretFor } from '../identitySignature.js';
import { verifyIdentity } from '../../../packages/tenant/index.js';
import { activeScopes, approvalRequiredError, pendingRequest } from '../capabilities/store.js';
import { capabilityOf, CONNECTION_PREFIX } from '../capabilities/registry.js';
import { getConnectionRow, credentialsFor, identitySecretOf } from './store.js';
import { PRESETS } from './presets.js';
import { authFor, scrubBuffer, scrubSecrets } from './credentials.js';
import { upstreamRequest, UpstreamError } from './upstream.js';
import { takeSlot, recordCall } from './usage.js';

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const DROP_REQUEST = new Set([...HOP_BY_HOP, 'host', 'content-length', 'authorization', 'cookie', 'x-api-key', 'api-key',
  'forwarded', 'via', 'x-real-ip', 'accept-encoding', 'expect', 'origin', 'referer',
  // An upstream that honours these would run another method than the one the grant allowed.
  'x-http-method-override', 'x-http-method', 'x-method-override']);
const DROP_RESPONSE = new Set([...HOP_BY_HOP, 'content-length', 'content-encoding', 'set-cookie', 'set-cookie2', 'location',
  'strict-transport-security', 'alt-svc']);
const IDENTITY_SIGNED = ['X-AppCrane-Identity-Sig', 'X-AppCrane-Identity-Sig-V2'];

function send(res, status, code, message, extra = {}) {
  if (res.headersSent) return res.destroy();
  res.status(status).json({ error: { code, message, ...extra } });
}

/** The path after /<name>, decoded for the grant check; null when it could step outside a prefix. */
export function splitPath(url) {
  const q = url.indexOf('?');
  const raw = (q < 0 ? url : url.slice(0, q)) || '/';
  const search = q < 0 ? '' : url.slice(q);
  if (!raw.startsWith('/') || raw.includes('//') || raw.includes('\\') || raw.length > 4096) return null;
  const decoded = [];
  for (const seg of raw.split('/').slice(1)) {
    let d;
    try { d = decodeURIComponent(seg); } catch (_) { return null; }
    if (d === '.' || d === '..' || /[/\\\u0000-\u001f\u007f]/.test(d)) return null;
    decoded.push(d);
  }
  return { raw, search, decoded: `/${decoded.join('/')}` };
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) return reject(Object.assign(new Error('too large'), { tooLarge: true }));
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { reject(Object.assign(new Error('too large'), { tooLarge: true })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function forwardHeaders(incoming, conn) {
  const listed = new Set(String(incoming.connection || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean));
  const out = {};
  for (const [k, v] of Object.entries(incoming)) {
    const h = k.toLowerCase();
    if (DROP_REQUEST.has(h) || listed.has(h) || h.startsWith('x-appcrane-') || h.startsWith('x-forwarded-') || h.startsWith('proxy-')) continue;
    if (conn.auth_header && h === conn.auth_header.toLowerCase()) continue;
    out[h] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

/** The acting user, when the app passed on the identity AppCrane signed for it; null when it passed none. */
function actingUser(db, app, headers) {
  if (!IDENTITY_SIGNED.some((h) => headers[h.toLowerCase()])) return null;
  for (const env of ['production', 'sandbox']) {
    try {
      const who = verifyIdentity({ headers }, { secret: identitySecretFor(db, app.id, env) });
      if (who.userId) return { ...who, env };
    } catch (_) { /* try the other environment's secret */ }
  }
  return false;
}

export function signActing(secret, { ts, app, userId, email }) {
  return createHmac('sha256', secret).update(['appcrane-acting-v1', ts, app, userId, email].join('\n')).digest('base64url');
}

/** Same-origin redirect under the base path: rewritten to the gateway path. Anything else: null (refused). */
function rewriteLocation(location, upstreamUrl, conn) {
  let target;
  try { target = new URL(location, upstreamUrl); } catch (_) { return null; }
  const base = new URL(conn.base_url);
  if (target.origin !== base.origin) return null;
  const basePath = base.pathname.replace(/\/+$/, '');
  if (basePath && !(target.pathname === basePath || target.pathname.startsWith(`${basePath}/`))) return null;
  return `/api/service/connections/${conn.name}${target.pathname.slice(basePath.length) || '/'}${target.search}`;
}

export async function connectionHandler(req, res) {
  const started = Date.now();
  if (req.headers.via || req.headers['x-forwarded-host'] || req.headers['x-forwarded-for']) {
    return send(res, 403, 'NOT_INTERNAL', 'This endpoint is reachable only from an app container, not the public domain.');
  }
  const app = appForServiceToken(String(req.headers['x-appcrane-service-token'] || '').trim());
  if (!app) return send(res, 401, 'BAD_SERVICE_TOKEN', 'Invalid or missing X-AppCrane-Service-Token');
  const db = getDb();
  const name = req.params.name;
  const conn = getConnectionRow(name, db);
  if (!conn || !conn.enabled) return send(res, 404, 'CONNECTION_NOT_FOUND', `There is no enabled platform connection named ${String(name).slice(0, 64)}.`);
  const method = String(req.method).toUpperCase();
  const parts = splitPath(req.url);
  const logged = parts ? parts.decoded.slice(0, 512) : '/<invalid>';
  const done = (status, outcome, extra = {}) => recordCall({ app, conn, method, path: logged, status, outcome, latencyMs: Date.now() - started, ...extra });

  if (!METHODS.has(method)) { done(405, 'refused'); return send(res, 405, 'METHOD_NOT_ALLOWED', `${method} is not forwarded by the connections gateway.`); }
  if (!parts) { done(400, 'refused'); return send(res, 400, 'BAD_PATH', 'The path has an empty, dot or encoded-slash segment, which a grant cannot be checked against.'); }

  const capability = CONNECTION_PREFIX + conn.name;
  const needed = { methods: [method], path_prefixes: [parts.decoded] };
  if (!capabilityOf(capability).covers(activeScopes(db, app.id, capability), needed)) {
    done(403, 'refused');
    const err = approvalRequiredError(app, capability, needed, pendingRequest(db, app.id, capability));
    return send(res, 403, err.code, err.message, { capability });
  }
  if (!takeSlot(app.id, conn.name, conn.rate_per_minute)) {
    done(429, 'rate_limited');
    res.setHeader('retry-after', '60');
    return send(res, 429, 'CONNECTION_RATE_LIMITED', `This app is over ${conn.rate_per_minute} calls per minute to ${conn.name}.`);
  }

  let acting = null;
  if (conn.forward_identity) {
    acting = actingUser(db, app, req.headers);
    if (acting === false) { done(403, 'refused'); return send(res, 403, 'IDENTITY_INVALID', 'The X-AppCrane identity headers passed on are not ones AppCrane signed for this app, or are older than five minutes.'); }
  }

  let body;
  try { body = await readBody(req, conn.max_request_kb * 1024); } catch (e) {
    if (e.tooLarge) { done(413, 'refused'); return send(res, 413, 'REQUEST_TOO_LARGE', `The request body is over ${conn.max_request_kb} KB.`); }
    done(400, 'aborted');
    return send(res, 400, 'REQUEST_ABORTED', 'The request body could not be read.');
  }

  let settings = {};
  try { settings = JSON.parse(conn.settings_json || '{}'); } catch (_) {}
  let secrets = [];
  try {
    const creds = credentialsFor(conn);
    const auth = await authFor(conn, creds, settings);
    secrets = auth.secrets;
    const base = new URL(conn.base_url);
    const url = new URL(`${base.origin}${base.pathname.replace(/\/+$/, '')}${parts.raw}${parts.search}`);
    const headers = { ...PRESETS[conn.provider].headers, ...forwardHeaders(req.headers, conn), 'accept-encoding': 'gzip, deflate, br', 'user-agent': req.headers['user-agent'] || 'AppCrane-Connections' };
    if (acting) {
      const ts = String(Math.floor(Date.now() / 1000));
      const fields = { ts, app: app.slug, userId: acting.userId, email: acting.email || '' };
      Object.assign(headers, {
        'x-appcrane-acting-app': app.slug, 'x-appcrane-acting-user-id': acting.userId, 'x-appcrane-acting-user-email': fields.email,
        'x-appcrane-acting-ts': ts, 'x-appcrane-acting-sig': signActing(identitySecretOf(conn), fields),
      });
    }
    Object.assign(headers, auth.headers);
    const up = await upstreamRequest(url, { method, headers, body: body.length ? body : null, timeoutMs: conn.timeout_ms, maxResponseBytes: conn.max_response_kb * 1024 });

    if (up.status >= 300 && up.status < 400 && up.headers.location) {
      const local = rewriteLocation(String(up.headers.location), url, conn);
      if (!local) {
        done(502, 'redirect_refused', { bytesIn: body.length, actingUserId: acting?.userId });
        return send(res, 502, 'CONNECTION_REDIRECT_REFUSED', `The upstream redirected outside ${conn.base_url}; the gateway does not follow it.`);
      }
      res.setHeader('location', local);
    }
    for (const [k, v] of Object.entries(up.headers)) {
      if (DROP_RESPONSE.has(k)) continue;
      res.setHeader(k, Array.isArray(v) ? v.map((x) => scrubSecrets(String(x), secrets)) : scrubSecrets(String(v), secrets));
    }
    const out = scrubBuffer(up.body, secrets);
    done(up.status, up.status >= 400 ? 'upstream_error' : 'ok', { bytesIn: body.length, bytesOut: out.length, actingUserId: acting?.userId });
    res.status(up.status);
    return res.end(method === 'HEAD' ? undefined : out);
  } catch (e) {
    const known = e instanceof UpstreamError;
    const status = !known ? 502 : e.code === 'UPSTREAM_TIMEOUT' ? 504 : 502;
    const outcome = known ? e.code.toLowerCase() : 'error';
    done(status, outcome, { bytesIn: body.length });
    if (!known) log.warn(`[connections] ${app.slug} -> ${conn.name}: ${scrubSecrets(e.message, secrets)}`);
    return send(res, status, known ? `CONNECTION_${e.code}` : 'CONNECTION_ERROR', known ? scrubSecrets(e.message, secrets) : 'The connection failed.');
  }
}
