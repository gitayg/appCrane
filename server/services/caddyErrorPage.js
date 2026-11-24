import { readFileSync } from 'fs';

// The page Caddy serves itself, with no upstream, when the upstream that should
// have answered is gone: AppCrane for the platform host (so its own crash page
// cannot render either), or an app on a site that has no AppCrane crash route.
// Embedded in the Caddyfile as a heredoc, not served from a file: the caddy
// user may not be able to read the repository, and a missing file would turn
// the error page itself into an error.
//
// Nothing about the failed upstream is in it: no address, no port, no
// {err.*} or {http.reverse_proxy.*} placeholder. Values are fixed when the
// Caddyfile is generated and escaped there, braces included, so no request
// value or Caddy placeholder can reach the body.

export const HEREDOC_MARKER = 'APPCRANE_UNAVAILABLE_PAGE';

const TEMPLATE = readFileSync(new URL('../assets/caddy-unavailable.html', import.meta.url), 'utf8');

const esc = (s) => String(s ?? '')
  .replace(/[\u0000-\u001f\u007f]/g, ' ')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
  .replace(/\{/g, '&#123;').replace(/\}/g, '&#125;');

const ENV_LABELS = { production: 'Production', sandbox: 'Sandbox', platform: 'Platform' };

/**
 * The page's HTML. `link` is an absolute or root-relative dashboard URL, or
 * null for a site whose visitors must not be pointed at the platform host.
 */
export function unavailablePage({ name, env, link }) {
  const envLabel = ENV_LABELS[env] || 'Production';
  const title = env === 'platform' ? 'AppCrane is unavailable' : `${name} is unavailable`;
  const detail = env === 'platform'
    ? 'AppCrane is not answering right now, so the apps it serves cannot be opened either.'
    : `The ${envLabel.toLowerCase()} environment of this app is not answering right now.`;
  const linkHtml = link ? `<a class="btn" href="${esc(link)}">Open the AppCrane dashboard</a>` : '';
  return TEMPLATE
    .replaceAll('__APPCRANE_TITLE__', esc(title))
    .replaceAll('__APPCRANE_ENV__', esc(envLabel))
    .replaceAll('__APPCRANE_DETAIL__', esc(detail))
    .replaceAll('__APPCRANE_LINK__', linkHtml)
    .replace(/\n+$/, '');
}

/** Caddyfile lines that answer the request with the page and a 503. */
export function unavailableRespond(indent, page) {
  return `${indent}header Content-Type "text/html; charset=utf-8"\n` +
    `${indent}header Cache-Control "no-store"\n` +
    `${indent}respond <<${HEREDOC_MARKER}\n${page}\n${HEREDOC_MARKER} 503\n`;
}

/**
 * A whole handle_errors block that serves the page for 502/503/504. `crane`
 * (optional) is the Caddyfile text of the existing AppCrane crash-page handler:
 * it keeps handling app failures, and the page takes over only when the
 * upstream that failed was AppCrane itself, which that handler would proxy to.
 */
export function unavailableErrors(indent, { page, cranePort = null, crane = '' }) {
  const i2 = indent + '    ';
  const i3 = i2 + '    ';
  let s = `${indent}handle_errors {\n`;
  s += `${i2}@appdown expression \`{err.status_code} in [502, 503, 504]\`\n`;
  if (crane && cranePort) {
    s += `${i2}@cranedown expression \`{err.status_code} in [502, 503, 504] && {http.reverse_proxy.upstream.port} == "${cranePort}"\`\n`;
    s += `${i2}handle @cranedown {\n`;
    s += unavailableRespond(i3, page);
    s += `${i2}}\n`;
    s += crane;
  } else {
    s += `${i2}handle @appdown {\n`;
    s += unavailableRespond(i3, page);
    s += `${i2}}\n`;
  }
  s += `${indent}}\n`;
  return s;
}
