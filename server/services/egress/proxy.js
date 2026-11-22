// The egress proxy: the only way out of an enforced app's container.
//
// HTTP CONNECT (https and any other TCP protocol) and absolute-form plain-http
// requests. The container authenticates with its per-app, per-environment
// token (Proxy-Authorization: Basic, any user name); the target must be a DNS
// name (no IP literals: that is the direct-IP bypass), on the app's allow-list
// at connection time, and must resolve to a public address (checked on the
// address actually dialled, so an allowed name pointed at 10.x gains nothing).
// Refusals and first use of a host are written to the event store.
//
// APPCRANE_EGRESS_PRIVATE_HOSTS (comma-separated names, operator environment
// only) lets a named on-prem host resolve to a private address.

import http from 'http';
import net from 'net';
import { lookup as dnsLookup } from 'dns/promises';
import log from '../../utils/logger.js';
import { makeGuardedLookup } from '../remoteFetch.js';
import { recordEvent } from '../eventStore.js';
import { resolveEgressToken, allowedHosts, hostAllowed } from './policy.js';

const IDLE_MS = 10 * 60_000;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade'];

let resolveSeam = null;
/** Test seam: resolve(host, opts) -> [{ address, family }]. */
export function _setEgressResolverForTests(fn) { resolveSeam = fn || null; }

function privateHosts() {
  return new Set(String(process.env.APPCRANE_EGRESS_PRIVATE_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean));
}

function lookupFor(host) {
  const resolve = resolveSeam || dnsLookup;
  return makeGuardedLookup(privateHosts().has(host) ? { resolve, isBlocked: () => false } : { resolve });
}

function tokenOf(req) {
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(String(req.headers['proxy-authorization'] || '').trim());
  if (!m) return null;
  const decoded = Buffer.from(m[1], 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  return i < 0 ? decoded : decoded.slice(i + 1);
}

/** { host, port } from 'host:port' or an absolute URL; null when malformed. */
export function parseTarget(hostPort) {
  const m = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(String(hostPort || ''));
  if (!m) return null;
  const port = Number(m[2]);
  if (port < 1 || port > 65535) return null;
  return { host: m[1].toLowerCase().replace(/\.$/, ''), port };
}

const recent = new Map();
function note(app, kind, host, port, reason) {
  const key = `${kind}:${app.id}:${host}:${port}`;
  const ttl = kind === 'egress.allowed' ? 10 * 60_000 : 60_000;
  const last = recent.get(key);
  if (last && Date.now() - last < ttl) return;
  recent.set(key, Date.now());
  recordEvent({
    kind, severity: kind === 'egress.refused' ? 'warning' : 'info', appId: app.id, appSlug: app.slug,
    summary: `${app.slug} egress ${kind === 'egress.refused' ? 'refused' : 'allowed'}: ${host}:${port}${reason ? ` (${reason})` : ''}`,
    data: { host, port, reason: reason || null },
  });
}

export function _resetEgressNotesForTests() { recent.clear(); }

/** null when allowed, else the refusal reason. */
function decide(who, target) {
  if (!target) return 'malformed target';
  if (net.isIP(target.host)) return 'IP address targets are refused: name the host';
  if (!HOST_RE.test(target.host)) return 'malformed host';
  if (!hostAllowed(allowedHosts(who.app.id), target.host, target.port)) return 'not on this app\'s egress allow-list';
  return null;
}

function refuseSocket(socket, status, text, extra = '') {
  socket.end(`HTTP/1.1 ${status}\r\nContent-Type: text/plain\r\nConnection: close\r\n${extra}\r\n${text}\n`);
}

function onConnect(req, socket, head) {
  socket.on('error', () => {});
  const who = resolveEgressToken(tokenOf(req));
  if (!who) return refuseSocket(socket, '407 Proxy Authentication Required', 'AppCrane egress proxy: missing or invalid token', 'Proxy-Authenticate: Basic realm="appcrane-egress"\r\n');
  const target = parseTarget(req.url);
  const why = decide(who, target);
  if (why) {
    note(who.app, 'egress.refused', target?.host || String(req.url).slice(0, 100), target?.port || 0, why);
    return refuseSocket(socket, '403 Forbidden', `AppCrane egress proxy: ${target?.host || 'target'} refused: ${why}`);
  }
  const upstream = net.connect({ host: target.host, port: target.port, lookup: lookupFor(target.host) });
  upstream.setTimeout(IDLE_MS, () => upstream.destroy());
  socket.setTimeout(IDLE_MS, () => socket.destroy());
  upstream.once('connect', () => {
    note(who.app, 'egress.allowed', target.host, target.port);
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head?.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on('error', (e) => {
    if (upstream.connecting || !socket.writableEnded) {
      const blocked = e.code === 'EBLOCKEDADDRESS';
      if (blocked) note(who.app, 'egress.refused', target.host, target.port, 'resolves to a private address');
      if (!socket.destroyed && socket.bytesWritten === 0) {
        return refuseSocket(socket, blocked ? '403 Forbidden' : '502 Bad Gateway', `AppCrane egress proxy: ${blocked ? `${target.host} resolves to a private, loopback or link-local address` : `could not reach ${target.host} (${e.code || 'error'})`}`);
      }
    }
    socket.destroy();
  });
  socket.on('close', () => upstream.destroy());
}

function onRequest(req, res) {
  const who = resolveEgressToken(tokenOf(req));
  if (!who) {
    res.writeHead(407, { 'proxy-authenticate': 'Basic realm="appcrane-egress"', 'content-type': 'text/plain' });
    return res.end('AppCrane egress proxy: missing or invalid token\n');
  }
  let url;
  try { url = new URL(req.url); } catch (_) { url = null; }
  if (!url || url.protocol !== 'http:') {
    res.writeHead(400, { 'content-type': 'text/plain' });
    return res.end('AppCrane egress proxy: send an absolute http:// URL, or CONNECT for https\n');
  }
  const target = { host: url.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase(), port: Number(url.port) || 80 };
  const why = decide(who, target);
  if (why) {
    note(who.app, 'egress.refused', target.host, target.port, why);
    res.writeHead(403, { 'content-type': 'text/plain' });
    return res.end(`AppCrane egress proxy: ${target.host} refused: ${why}\n`);
  }
  const headers = { ...req.headers };
  for (const h of HOP_BY_HOP) delete headers[h];
  const up = http.request({ host: target.host, port: target.port, method: req.method, path: url.pathname + url.search, headers, lookup: lookupFor(target.host), agent: false }, (r) => {
    note(who.app, 'egress.allowed', target.host, target.port);
    const out = { ...r.headers };
    for (const h of HOP_BY_HOP) delete out[h];
    res.writeHead(r.statusCode || 502, out);
    r.pipe(res);
  });
  up.setTimeout(IDLE_MS, () => up.destroy());
  up.on('error', (e) => {
    const blocked = e.code === 'EBLOCKEDADDRESS';
    if (blocked) note(who.app, 'egress.refused', target.host, target.port, 'resolves to a private address');
    if (res.headersSent) return res.destroy();
    res.writeHead(blocked ? 403 : 502, { 'content-type': 'text/plain' });
    res.end(`AppCrane egress proxy: ${blocked ? `${target.host} resolves to a private, loopback or link-local address` : `could not reach ${target.host}`}\n`);
  });
  req.pipe(up);
}

export function createEgressProxyServer() {
  const server = http.createServer(onRequest);
  server.on('connect', onConnect);
  server.on('clientError', (_e, socket) => socket.destroy());
  return server;
}

let running = null;   // { host, port, server }

/** Listen on host:port once; a second call with the same address is a no-op. Throws when it cannot bind. */
export async function ensureEgressProxy(host, port) {
  if (running && running.host === host && running.port === port) return running;
  if (running) await new Promise((r) => running.server.close(() => r()));
  const server = createEgressProxyServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { server.off('error', reject); resolve(); });
  });
  running = { host, port, server };
  log.info(`[egress] proxy listening on ${host}:${port}`);
  return running;
}

export async function stopEgressProxy() {
  if (!running) return;
  const s = running.server;
  running = null;
  s.closeAllConnections?.();
  await new Promise((r) => s.close(() => r()));
}
