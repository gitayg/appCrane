// AppCrane's e-mail layout: one shared frame for platform mail.
//
// Colours are the dashboard's own tokens (studio-web/src/admin.css, public/favicon.svg):
// the dark header is the favicon's tile and the dark theme's --surface, the
// wordmark is the login page's "App<span>Crane</span>" in --text and --accent,
// and the body uses the light theme's tokens, which read well on white.
//
// E-mail-safe on purpose: nested tables, inline styles and bgcolor attributes,
// six-digit hex only, no web fonts and no images (the wordmark is text, so a
// dark-mode client has nothing to invert into an unreadable logo).

export const BRAND = {
  header: '#1a1d27',
  headerText: '#e4e4e7',
  accent: '#3b82f6',
  accentStrong: '#2563eb',
  green: '#22c55e',
  page: '#f1f5f9',
  card: '#ffffff',
  text: '#0f172a',
  dim: '#64748b',
  border: '#e2e8f0',
};

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";

export const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/** A version label, e.g. "v2.110.0", outlined in the accent colour. */
export function versionPill(version) {
  return `<span style="display:inline-block;border:1px solid ${BRAND.accentStrong};color:${BRAND.accentStrong};`
    + `border-radius:10px;padding:1px 8px;font-size:12px;font-weight:600;line-height:18px;">v${esc(version)}</span>`;
}

/** A bulleted list of plain-text lines (escaped here). */
export function bulletList(lines) {
  const items = lines.map((l) => `<li style="margin:0 0 6px;">${esc(l)}</li>`).join('');
  return `<ul style="margin:6px 0 0;padding-left:20px;font-size:14px;line-height:21px;color:${BRAND.text};">${items}</ul>`;
}

function button(label, url) {
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:22px 0 4px;"><tr>`
    + `<td bgcolor="${BRAND.accentStrong}" style="background:${BRAND.accentStrong};border-radius:6px;">`
    + `<a href="${esc(url)}" style="display:inline-block;padding:10px 18px;font-family:${FONT};font-size:14px;`
    + `font-weight:600;color:#ffffff;text-decoration:none;">${esc(label)}</a></td></tr></table>`;
}

/**
 * The full HTML body. Everything passed as text is escaped here; `bodyHtml` is
 * trusted markup the caller built (with esc/bulletList/versionPill).
 * @param {{ preheader?: string, greeting?: string, intro?: string, bodyHtml?: string,
 *           cta?: { label: string, url: string }, footer: string }} p
 */
export function renderBrandedEmail({ preheader = '', greeting = '', intro = '', bodyHtml = '', cta = null, footer }) {
  return `<div style="margin:0;padding:0;background:${BRAND.page};">`
    + (preheader ? `<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${esc(preheader)}</div>` : '')
    + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="${BRAND.page}" style="background:${BRAND.page};">`
    + `<tr><td align="center" style="padding:24px 12px;">`
    + `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;border-collapse:separate;">`
    + `<tr><td bgcolor="${BRAND.header}" style="background:${BRAND.header};padding:16px 24px;border-radius:8px 8px 0 0;border-bottom:3px solid ${BRAND.accent};">`
    + `<span style="font-family:${FONT};font-size:20px;font-weight:800;letter-spacing:-0.2px;color:${BRAND.headerText};">App</span>`
    + `<span style="font-family:${FONT};font-size:20px;font-weight:800;letter-spacing:-0.2px;color:${BRAND.accent};">Crane</span>`
    + `<span style="display:inline-block;width:6px;height:6px;border-radius:3px;background:${BRAND.green};margin-left:3px;"></span>`
    + `</td></tr>`
    + `<tr><td bgcolor="${BRAND.card}" style="background:${BRAND.card};padding:24px;font-family:${FONT};color:${BRAND.text};`
    + `border-left:1px solid ${BRAND.border};border-right:1px solid ${BRAND.border};">`
    + (greeting ? `<p style="margin:0 0 8px;font-size:15px;line-height:22px;color:${BRAND.text};">${esc(greeting)}</p>` : '')
    + (intro ? `<p style="margin:0 0 4px;font-size:14px;line-height:21px;color:${BRAND.text};">${esc(intro)}</p>` : '')
    + bodyHtml
    + (cta ? button(cta.label, cta.url) : '')
    + `</td></tr>`
    + `<tr><td bgcolor="${BRAND.card}" style="background:${BRAND.card};padding:14px 24px 20px;border:1px solid ${BRAND.border};`
    + `border-top:1px solid ${BRAND.border};border-radius:0 0 8px 8px;font-family:${FONT};font-size:12px;line-height:18px;color:${BRAND.dim};">`
    + esc(footer)
    + `</td></tr>`
    + `</table></td></tr></table></div>`;
}
