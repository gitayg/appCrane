/**
 * WHATWG fetch-spec "bad ports" list (v2.6.10).
 *
 * Node's built-in fetch (via undici) refuses connections to ports on
 * this list — fetch() throws "bad port undefined" with no `cause`
 * detail surfaced to most catch blocks. AppCrane's port allocator,
 * before this module, could hand out any of these (e.g. slot 23 →
 * prod_be 4045 = NFS lockd, blocked) and every deploy would die in the
 * health probe with no diagnostic. curl works fine against the same
 * port — the enforcement is purely client-side in undici.
 *
 * Source: https://fetch.spec.whatwg.org/#port-blocking
 * Mirror in code: undici/lib/web/fetch/util.js
 *
 * Kept inline so we don't depend on undici's internal export. Update
 * when the spec changes (rare).
 */
const WHATWG_BAD_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69,
  77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119,
  123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515,
  526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990,
  993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000,
  6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]);

/**
 * Return true when this port is safe to bind / fetch against.
 * Anything outside 1024..65535 (privileged + invalid) and anything on
 * the WHATWG block list returns false.
 */
export function isPortSafe(port) {
  if (!Number.isFinite(port)) return false;
  if (port < 1024 || port > 65535) return false;
  return !WHATWG_BAD_PORTS.has(port);
}

/**
 * Convenience for the typical case in AppCrane: check every port a
 * slot is about to receive. Returns true when ALL four ports
 * (prod_fe, prod_be, sand_fe, sand_be) are safe.
 */
export function arePortsSafe(ports) {
  return ['prod_fe', 'prod_be', 'sand_fe', 'sand_be']
    .every(k => isPortSafe(ports[k]));
}

/**
 * For diagnostics: which ports of this set are blocked, and why?
 * Returns [{ key, port, reason }] for any blocked port; [] when safe.
 */
export function describeBlockedPorts(ports) {
  const out = [];
  for (const key of ['prod_fe', 'prod_be', 'sand_fe', 'sand_be']) {
    const port = ports[key];
    if (!isPortSafe(port)) {
      out.push({
        key,
        port,
        reason: WHATWG_BAD_PORTS.has(port)
          ? `WHATWG fetch-spec blocks this port`
          : `out of allowed range (1024-65535)`,
      });
    }
  }
  return out;
}

export { WHATWG_BAD_PORTS };
