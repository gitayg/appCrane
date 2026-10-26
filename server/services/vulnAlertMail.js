// The immediate vulnerability alert (vulnAlerts.js): one mail per recipient per
// scan, listing every finding that scan was the first to report.

import { BRAND, esc, renderBrandedEmail } from './mail/brandedLayout.js';
import { dashboardBaseUrl, requestUrl } from './vulnRequests.js';

export function advisoryUrl(id, app) {
  if (/^GHSA-/i.test(id)) return `https://github.com/advisories/${encodeURIComponent(id)}`;
  if (app.source_type === 'image') return null;
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

function fixLine(f) {
  return f.fixed ? `Fixed in ${f.fixed}` : 'No fixed version published yet';
}

function nextSteps(f) {
  const lines = [];
  const reqs = f.advisories.filter((a) => a.requestId);
  if (reqs.length) {
    const open = reqs.filter((a) => a.requestOpen).map((a) => `#${a.requestId}`);
    const closed = reqs.filter((a) => !a.requestOpen).map((a) => `#${a.requestId}`);
    if (open.length) lines.push(`A request is open in the app's queue (${open.join(', ')}).`);
    if (closed.length) lines.push(`The earlier request (${closed.join(', ')}) was already closed; it is not reopened, so check it or open a new one.`);
  }
  if (f.autoPatch.will) {
    lines.push('RCE auto-patch will try this fix by itself: sandbox first, then the release check, then production, with automatic rollback. You will get an e-mail with the outcome. If any of its checks fails, the request comes back to a person.');
  } else if (f.rce) {
    lines.push(`This advisory allows remote code execution, but auto-patch will not handle it (${f.autoPatch.why}). A person needs to act.`);
  } else {
    lines.push('A person needs to act: upgrade the package, or decide in the request why not.');
  }
  const rc = {
    blocks: `The release check will block production releases until ${f.name} is upgraded (or an exception is recorded).`,
    not_enforced: 'The release check reports this but does not block production on this platform.',
    excepted: 'The release check has an active exception for dependencies on this app, so production releases are not blocked.',
    warn: 'The release check shows this as a warning; it does not block production while no fix exists.',
    off: "The release check is off for this app's data classification.",
  }[f.releaseCheck];
  if (rc) lines.push(rc);
  return lines;
}

/**
 * @param {{ app: object, env: string, source: string, findings: Array<object>,
 *           person: { name?: string, roles: string[] } }} p
 */
export function renderVulnAlert({ app, env, source, findings, person }) {
  const appName = app.name || app.slug;
  const n = findings.length;
  const pkgWord = n === 1 ? 'package' : 'packages';
  const subject = `[AppCrane] ${appName} (${env}): ${n} newly found vulnerable ${pkgWord}`;
  const intro = `A ${source} scan of ${appName} (${env}) found ${n} vulnerable ${pkgWord} that had not been reported before.`;
  const why = person.roles.includes('owner') && person.roles.includes('platform_admin')
    ? 'an owner of this app and a platform admin'
    : person.roles.includes('owner') ? 'an owner of this app' : 'a platform admin';
  const footer = `You receive this as ${why}. Each finding is mailed once; the daily digest lists everything still open. A platform admin can turn these immediate e-mails off in Settings > Security.`;
  const listUrl = `${dashboardBaseUrl()}/requests`;

  const advLabel = (a) => [a.id, a.severity ? `severity ${a.severity.toLowerCase()}` : null, a.rce ? 'remote code execution' : null]
    .filter(Boolean).join(', ');

  let text = `${intro}\n\n`;
  for (const f of findings) {
    text += `${f.name}@${f.version} (${f.ecosystem}): ${fixLine(f)}\n`;
    for (const a of f.advisories) {
      const url = advisoryUrl(a.id, app);
      text += `  - ${advLabel(a)}${url ? ` ${url}` : ''}${a.requestId ? ` (request: ${requestUrl(a.requestId)})` : ''}\n`;
    }
    for (const l of nextSteps(f)) text += `  ${l}\n`;
    text += '\n';
  }
  text += `Requests: ${listUrl}\n\n${footer}\n`;

  const blocks = findings.map((f) => {
    const advs = f.advisories.map((a) => {
      const url = advisoryUrl(a.id, app);
      const id = url ? `<a href="${esc(url)}" style="color:${BRAND.accentStrong};">${esc(a.id)}</a>` : esc(a.id);
      const extra = [a.severity ? `severity ${esc(a.severity.toLowerCase())}` : null, a.rce ? '<strong>remote code execution</strong>' : null]
        .filter(Boolean).join(', ');
      const req = a.requestId ? ` &middot; <a href="${esc(requestUrl(a.requestId))}" style="color:${BRAND.accentStrong};">request #${a.requestId}</a>` : '';
      return `<li style="margin:0 0 4px;">${id}${extra ? ` (${extra})` : ''}${req}</li>`;
    }).join('');
    const steps = nextSteps(f).map((l) => `<li style="margin:0 0 4px;">${esc(l)}</li>`).join('');
    return `<div style="margin:18px 0 0;padding:12px 14px;border:1px solid ${BRAND.border};border-radius:6px;">`
      + `<div style="font-family:ui-monospace,Menlo,monospace;font-size:13px;font-weight:600;color:${BRAND.text};">${esc(f.name)}@${esc(f.version)}`
      + ` <span style="font-family:inherit;font-weight:400;color:${BRAND.dim};">(${esc(f.ecosystem)})</span></div>`
      + `<div style="font-size:13px;color:${BRAND.text};margin:4px 0 0;">${esc(fixLine(f))}</div>`
      + `<ul style="margin:6px 0 0;padding-left:20px;font-size:13px;line-height:19px;color:${BRAND.text};">${advs}</ul>`
      + `<div style="font-size:12px;font-weight:600;color:${BRAND.dim};margin:8px 0 0;">What happens next</div>`
      + `<ul style="margin:4px 0 0;padding-left:20px;font-size:13px;line-height:19px;color:${BRAND.text};">${steps}</ul>`
      + `</div>`;
  }).join('');

  const html = renderBrandedEmail({
    preheader: intro,
    greeting: `Hi${person.name ? ` ${person.name}` : ''},`,
    intro,
    bodyHtml: blocks,
    cta: { label: 'Open requests', url: listUrl },
    footer,
  });
  return { subject, text, html };
}
