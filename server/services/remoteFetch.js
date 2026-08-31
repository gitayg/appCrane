import { lookup } from 'dns/promises';
import { isIP } from 'net';

// Fetching bytes the server was told to fetch, without becoming a proxy into
// the private network it lives on.
//
// This exists so an artifact can reach AppCrane without passing through an
// agent's context. Chunking a bundle over JSON-RPC makes the MODEL the data
// pipe: a 600KB archive is ~800KB of base64 that the model has to emit
// character by character, which costs output tokens per character, and a single
// wrong character fails the digest. Handing the server a URL costs a few dozen
// tokens regardless of file size.
//
// The obvious hazard is the obvious one. A server that fetches URLs on request
// is an SSRF primitive: AppCrane sits next to Docker's socket, Caddy's admin
// API on 2019, its own API on 5001, and on a cloud host the metadata service on
// 169.254.169.254. So the destination is resolved and checked BEFORE the
// request, and redirects are refused rather than followed — a public URL that
// 302s to 169.254.169.254 would otherwise walk straight through a check done
// only on the original.

const MAX_BYTES = 200 * 1024 * 1024; // matches the multipart upload limit
const TIMEOUT_MS = 120_000;

/** Is this address one AppCrane must never be talked into fetching from? */
export function isBlockedAddress(ip) {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;                 // this-host, private, loopback
    if (a === 169 && b === 254) return true;                            // link-local — cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;                   // private
    if (a === 192 && b === 168) return true;                            // private
    if (a === 100 && b >= 64 && b <= 127) return true;                  // carrier-grade NAT
    if (a === 192 && b === 0) return true;                              // protocol assignments
    if (a === 198 && (b === 18 || b === 19)) return true;               // benchmarking
    if (a >= 224) return true;                                          // multicast and reserved
    return false;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === '::' || s === '::1') return true;
    if (s.startsWith('fc') || s.startsWith('fd')) return true;          // unique-local
    if (s.startsWith('fe8') || s.startsWith('fe9') || s.startsWith('fea') || s.startsWith('feb')) return true; // link-local
    if (s.startsWith('ff')) return true;                                // multicast
    // ::ffff:10.0.0.1 and friends — an IPv4 address wearing an IPv6 hat.
    const m = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return isBlockedAddress(m[1]);
    return false;
  }
  return true; // not an IP at all
}

/**
 * Check a URL is safe to fetch, resolving its hostname first.
 * Throws with the reason; returns the parsed URL.
 */
export async function assertFetchable(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch { throw new Error(`not a valid URL: ${rawUrl}`); }
  if (url.protocol !== 'https:') {
    throw new Error(`only https:// URLs are fetched (got ${url.protocol}//) — plain HTTP would expose the bytes and any token in the URL`);
  }
  const addrs = await lookup(url.hostname, { all: true }).catch(() => {
    throw new Error(`cannot resolve ${url.hostname}`);
  });
  if (!addrs.length) throw new Error(`cannot resolve ${url.hostname}`);
  for (const { address } of addrs) {
    if (isBlockedAddress(address)) {
      throw new Error(
        `${url.hostname} resolves to ${address}, which is a private or link-local address. `
        + 'AppCrane will not fetch from its own network — that is the path to the Docker socket, '
        + "Caddy's admin API and the cloud metadata service.",
      );
    }
  }
  return url;
}

/**
 * Download a URL to a Buffer, refusing private destinations, redirects, and
 * anything over the size cap.
 */
export async function fetchToBuffer(rawUrl) {
  const url = await assertFetchable(rawUrl);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { redirect: 'error', signal: ac.signal });
    if (!res.ok) throw new Error(`fetch failed: HTTP ${res.status} ${res.statusText}`);

    const declared = Number(res.headers.get('content-length') || 0);
    if (declared > MAX_BYTES) {
      throw new Error(`file is ${declared} bytes, over the ${MAX_BYTES} byte limit`);
    }
    const buf = Buffer.from(await res.arrayBuffer());
    // Checked again against the body: content-length is a claim, not a fact.
    if (buf.length > MAX_BYTES) {
      throw new Error(`file is ${buf.length} bytes, over the ${MAX_BYTES} byte limit`);
    }
    return buf;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`fetch timed out after ${TIMEOUT_MS}ms`);
    if (/redirect/i.test(e.message)) {
      throw new Error(
        'the URL redirected, and redirects are not followed — the destination check runs on the '
        + 'URL you gave, so a redirect could point anywhere. Use the final URL directly.',
      );
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
