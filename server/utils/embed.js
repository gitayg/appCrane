// Platform-default iframe embedding (v2.25.0).
//
// By default AppCrane lets any host under the platform's OWN registrable domain
// (the eTLD+1 of CRANE_DOMAIN, e.g. app.opswat.com → opswat.com) embed apps —
// a same-org trust boundary. It's emitted as a `frame-ancestors` allowlist and
// merged with any per-app `frame_ancestors`. A platform admin can turn it off
// or override the domain in Settings → Security.
//
// SECURITY: the wildcard base is derived via the Public Suffix List (`psl`), so
// it is always a real registrable domain and NEVER a bare public suffix — an
// apex CRANE_DOMAIN like `opswat.com` yields `*.opswat.com`, not `*.com`, and a
// value psl can't resolve to an eTLD+1 disables the default rather than
// emitting an over-broad allowlist.
import psl from 'psl';

/** Registrable domain (eTLD+1) of CRANE_DOMAIN, or null if it can't be derived. */
export function platformRegistrableDomain() {
  const crane = (process.env.CRANE_DOMAIN || '').trim().toLowerCase();
  if (!crane) return null;
  try {
    const parsed = psl.parse(crane);
    return parsed && parsed.domain ? parsed.domain : null;
  } catch (_) { return null; }
}

/**
 * The platform-default frame-ancestors token string when same-site embedding is
 * enabled, else null. Enabled unless an admin set it 'off'; the domain is the
 * admin override if present, otherwise the derived registrable domain.
 */
export function platformEmbedAncestors(db) {
  const get = (k) => db.prepare('SELECT value FROM settings WHERE key = ?').get(k)?.value;
  if ((get('platform_embed_same_site') ?? 'on') === 'off') return null;
  const override = (get('platform_embed_domain') || '').trim().toLowerCase();
  const domain = override || platformRegistrableDomain();
  if (!domain) return null;
  return `'self' https://*.${domain} https://${domain}`;
}

/** Union of two frame-ancestors token strings (dedupe, order-preserving). Either may be null. */
export function mergeAncestors(a, b) {
  const toks = [];
  for (const s of [a, b]) {
    if (!s) continue;
    for (const t of String(s).trim().split(/\s+/)) {
      if (t && !toks.includes(t)) toks.push(t);
    }
  }
  return toks.length ? toks.join(' ') : null;
}
