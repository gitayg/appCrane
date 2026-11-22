// The e-mails of the required-owner workflow: an app lost its last owner, a
// person is asked to own an app, and the nominator hears the answer.

import { BRAND, esc, renderBrandedEmail } from './mail/brandedLayout.js';
import { dashboardBaseUrl } from './vulnRequests.js';

export const REASON_TEXT = {
  'owner-deactivated': 'its owner was deactivated',
  'owner-deleted': 'its owner was deleted',
  'owner-removed': 'its owner lost the owner role',
  'no-owner': 'nobody holds the owner role',
};

export function appManageUrl(slug) {
  return `${dashboardBaseUrl()}/app?slug=${encodeURIComponent(slug)}`;
}

export function transfersUrl() {
  return `${dashboardBaseUrl()}/owner-transfers`;
}

const p = (s) => `<p style="margin:12px 0 0;font-size:14px;line-height:21px;color:${BRAND.text};">${esc(s)}</p>`;

function build({ subject, greeting, intro, lines, cta, footer }) {
  const html = renderBrandedEmail({ preheader: intro, greeting, intro, bodyHtml: lines.map(p).join(''), cta, footer });
  const text = [greeting, '', intro, '', ...lines, ...(cta ? ['', `${cta.label}: ${cta.url}`] : []), '', footer, ''].join('\n');
  return { subject, text, html };
}

const hi = (user) => `Hi${user?.name ? ` ${user.name}` : ''},`;

export function renderOrphaned({ app, user, reason, cause, recipientRole }) {
  const appName = app.name || app.slug;
  const why = REASON_TEXT[reason] || REASON_TEXT['no-owner'];
  const next = recipientRole === 'platform_admin'
    ? 'Nominate a new owner, or assign one directly, from the app page.'
    : 'As an app admin you can nominate a new owner from the app page; a platform admin can also assign one.';
  return build({
    subject: `[AppCrane] ${appName} has no owner`,
    greeting: hi(user),
    intro: `${appName} has no active owner: ${why}.`,
    lines: [`Detected by: ${cause}`, 'The app keeps running. Every app needs a named owner who is responsible for it and for who has access.', next],
    cta: { label: `Open ${appName}`, url: appManageUrl(app.slug) },
    footer: 'You get this because you are a platform admin or an admin of this app on AppCrane.',
  });
}

export function renderNomination({ app, nominee, nominator, kind, note, expiresAt }) {
  const appName = app.name || app.slug;
  const by = nominator?.name || nominator?.email || 'A platform admin';
  const intro = kind === 'orphan'
    ? `${by} asked you to become the owner of ${appName}, which has no owner.`
    : `${by} asked you to take over as owner of ${appName}.`;
  return build({
    subject: `[AppCrane] You were asked to own ${appName}`,
    greeting: hi(nominee),
    intro,
    lines: [
      'An owner has full control of the app, including who has access to it.',
      ...(note ? [`Note: ${note}`] : []),
      `Accept or decline in the dashboard before ${expiresAt} UTC.`,
    ],
    cta: { label: 'Review the request', url: transfersUrl() },
    footer: 'You get this because someone nominated you as an app owner on AppCrane. If you did not expect it, decline it or ask a platform admin.',
  });
}

export function renderDecision({ app, nominator, nominee, accepted }) {
  const appName = app.name || app.slug;
  const who = nominee?.name || nominee?.email || 'The nominee';
  const intro = accepted ? `${who} accepted and is now an owner of ${appName}.` : `${who} declined to own ${appName}.`;
  return build({
    subject: accepted ? `[AppCrane] ${appName} has a new owner` : `[AppCrane] Ownership of ${appName} was declined`,
    greeting: hi(nominator),
    intro,
    lines: accepted ? [] : ['Nominate someone else from the app page.'],
    cta: { label: `Open ${appName}`, url: appManageUrl(app.slug) },
    footer: 'You get this because you nominated a new owner for this app on AppCrane.',
  });
}
