/**
 * The first path segment of a same-origin Referer, or null.
 *
 * The slug fallback (server/index.js) 307s a root-path request into the app
 * whose page sent it. Only a page on THIS host can be one of our apps: a link
 * from another site whose path happens to start with an app's slug (e.g.
 * https://blog.example.org/<slug>/post linking to /crew, sent with a full
 * Referer) used to bounce the visitor into that app instead of the page they
 * clicked. Behind Caddy the Host header is the client's own (reverse_proxy
 * passes it through unchanged), so it is what the Referer must match.
 */
export function refererSlug(referer, host) {
  if (!referer || !host) return null;
  let url;
  try { url = new URL(referer); } catch { return null; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  if (url.host.toLowerCase() !== String(host).toLowerCase()) return null;
  const seg = url.pathname.split('/')[1];
  return seg || null;
}
