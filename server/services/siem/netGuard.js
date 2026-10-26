import { isIP, BlockList } from 'net';
import { lookup } from 'dns/promises';
import { getDb } from '../../db.js';
import { isBlockedAddress, makeGuardedLookup, assertHostNotBlocked } from '../remoteFetch.js';

// Where a SIEM sink may connect. Public addresses are allowed. Private,
// loopback and CGNAT addresses are refused (remoteFetch.isBlockedAddress)
// UNLESS a platform admin listed them in the private allowlist: on-prem SIEMs
// usually live on a private network. Link-local (cloud metadata), "this host"
// 0.0.0.0/8 and multicast are refused even when listed. The check runs inside
// the socket's own DNS lookup (makeGuardedLookup), so the address checked is
// the address dialled; IP literals are checked before connecting.

export const ALLOWLIST_KEY = 'siem_private_allowlist';
const MAX_ENTRIES = 64;

function neverAllowed(ip) {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || (a === 169 && b === 254) || a >= 224;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === '::') return true;
    if (/^fe[89ab]/.test(s) || s.startsWith('ff')) return true;
    const m = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return m ? neverAllowed(m[1]) : false;
  }
  return true;
}

/** Validate and normalise allowlist entries: IPs, CIDRs, or host names. Throws on a bad entry. */
export function normalizeAllowlist(list) {
  if (!Array.isArray(list)) throw new Error('private_allowlist must be an array');
  if (list.length > MAX_ENTRIES) throw new Error(`private_allowlist holds at most ${MAX_ENTRIES} entries`);
  return [...new Set(list.map(e => String(e || '').trim().toLowerCase()).filter(Boolean))].map((e) => {
    const [addr, bits] = e.split('/');
    if (bits !== undefined) {
      const v = isIP(addr);
      const n = Number(bits);
      if (!v || !Number.isInteger(n) || n < 0 || n > (v === 4 ? 32 : 128)) throw new Error(`not a valid CIDR: ${e}`);
      if (n < (v === 4 ? 8 : 16)) throw new Error(`CIDR ${e} is too wide; list the SIEM's own network`);
      return e;
    }
    if (isIP(e)) return e;
    if (!/^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$/.test(e)) throw new Error(`not an IP, CIDR or host name: ${e}`);
    return e;
  });
}

export function getAllowlist(db = getDb()) {
  const raw = db.prepare('SELECT value FROM settings WHERE key = ?').get(ALLOWLIST_KEY)?.value;
  if (!raw) return [];
  try { return normalizeAllowlist(JSON.parse(raw)); } catch { return []; }
}

export function setAllowlist(list, userId, db = getDb()) {
  const clean = normalizeAllowlist(list);
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(ALLOWLIST_KEY, JSON.stringify(clean), userId ?? null);
  return clean;
}

/**
 * The policy for one destination host. Returns isBlocked(ip). A host name on
 * the allowlist allows whatever private address that name resolves to.
 */
export function policyFor(host, allowlist = getAllowlist()) {
  const bl = new BlockList();
  let hostAllowed = false;
  for (const e of allowlist) {
    const [addr, bits] = e.split('/');
    const v = isIP(addr);
    if (v && bits !== undefined) bl.addSubnet(addr, Number(bits), v === 4 ? 'ipv4' : 'ipv6');
    else if (v) bl.addAddress(addr, v === 4 ? 'ipv4' : 'ipv6');
    else if (e === String(host || '').toLowerCase()) hostAllowed = true;
  }
  return (ip) => {
    if (neverAllowed(ip)) return true;
    if (!isBlockedAddress(ip)) return false;
    if (hostAllowed) return false;
    const v = isIP(ip);
    return !(v && bl.check(ip, v === 4 ? 'ipv4' : 'ipv6'));
  };
}

/** A guarded DNS lookup for net/tls/https/dgram, plus an up-front literal check. */
export function guardFor(host, allowlist) {
  const isBlocked = policyFor(host, allowlist);
  const bare = String(host).replace(/^\[(.*)\]$/, '$1');
  assertHostNotBlocked({ hostname: bare }, isBlocked);
  return { lookup: makeGuardedLookup({ isBlocked }), isBlocked };
}

/** Resolve-and-check for clients that do their own DNS (the S3 export's fetch). */
export async function assertResolvable(host, allowlist) {
  const { isBlocked } = guardFor(host, allowlist);
  if (isIP(host)) return;
  const addrs = await lookup(host, { all: true });
  const bad = addrs.find(a => isBlocked(a.address));
  if (bad) throw Object.assign(new Error(`${host} resolves to ${bad.address}, a private, loopback or link-local address that is not on the SIEM private allowlist`), { code: 'EBLOCKEDADDRESS' });
}
