import { readFileSync } from 'node:fs';

// The host's own addresses and the interface of its default route, and host
// hardening's state file. A binding counts as public only when it is a
// wildcard or an address on that interface: a managed database published on
// the bridge gateway (172.17.0.1) is reachable from containers, not from the
// internet.

export const ROUTE_ARGS = Object.freeze({ v4: ['route', 'show', 'default'], v6: ['-6', 'route', 'show', 'default'] });
export const ADDR_ARGS = Object.freeze(['-o', 'addr', 'show']);
export const HOST_NETWORK_STATE = '/var/lib/appcrane/host-network.state';

export function parseDefaultIface(text) {
  return /^default\b.*\bdev (\S+)/m.exec(String(text || ''))?.[1] || null;
}

/** Map of interface -> [addresses] from `ip -o addr show`. */
export function parseAddrs(text) {
  const out = new Map();
  for (const line of String(text || '').split('\n')) {
    const m = /^\d+:\s+([^\s@:]+)(?:@\S+)?:?\s+inet6?\s+([^\s/]+)/.exec(line.trim());
    if (!m) continue;
    if (!out.has(m[1])) out.set(m[1], []);
    out.get(m[1]).push(m[2]);
  }
  return out;
}

/** { ext: {v4, v6}, addrs: Map|null, extAddrs: Set } */
export async function readHostNet(run) {
  const ext = {};
  for (const fam of ['v4', 'v6']) {
    const r = await run('ip', [...ROUTE_ARGS[fam]]);
    ext[fam] = r.code === 0 ? parseDefaultIface(r.stdout) : null;
  }
  const a = await run('ip', [...ADDR_ARGS]);
  const addrs = a.code === 0 ? parseAddrs(a.stdout) : null;
  const extAddrs = new Set();
  if (addrs) for (const i of new Set([ext.v4, ext.v6])) for (const ip of addrs.get(i) || []) extAddrs.add(ip);
  return { ext, addrs, extAddrs };
}

export const isWildcard = (ip) => ip === '' || ip === '*' || ip === '0.0.0.0' || ip === '::';
export const isLoopback = (ip) => ip === '::1' || /^127\./.test(ip) || /^::ffff:127\./.test(ip);
const PRIVATE = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^169\.254\./, /^f[cd][0-9a-f]{2}:/i, /^fe80:/i];

/**
 * Public: a wildcard, or an address on the default route's interface. When the
 * host's addresses could not be read, any address outside the private and
 * link-local ranges counts as public.
 */
export function isPublicAddr(ip, net) {
  if (isWildcard(ip)) return true;
  if (isLoopback(ip)) return false;
  if (net?.addrs && (net.ext?.v4 || net.ext?.v6)) return net.extAddrs.has(ip);
  return !PRIVATE.some(re => re.test(ip));
}

/** Host hardening's key=value state file; the last value of a key wins. null when absent. */
export function parseState(text) {
  if (text === null || text === undefined) return null;
  const out = {};
  for (const line of String(text).split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
  }
  return out;
}

export function defaultReadFile(path) {
  try { return readFileSync(path, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}

export function readHostNetworkState(readFile = defaultReadFile) {
  try { return parseState(readFile(HOST_NETWORK_STATE)); } catch (_) { return null; }
}

// Host hardening records publish_drop=no when it installed DOCKER-USER
// without the `-i EXT -j DROP` (AppCrane could not keep APPCRANE-PUBLISH up to
// date), and docker_user=interim while the hand-installed interim unit still
// owns DOCKER-USER (nothing jumps to APPCRANE-PUBLISH then).
export const STATE_DROP_KEY = 'publish_drop';

/**
 * Does host hardening's last run say the DOCKER-USER skeleton drops what
 * APPCRANE-PUBLISH does not accept? Used only when the rules cannot be read.
 * A failed run that knew the public interface may still have left an earlier
 * skeleton in place (its boot unit re-applies it), so it counts as enforcing.
 */
export function stateSaysEnforcing(state) {
  if (!state || !state.ext || state.docker_user === 'interim') return false;
  return state[STATE_DROP_KEY] !== 'no';
}
