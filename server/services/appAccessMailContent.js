// The e-mail a person gets when their access to an app changes.

import { BRAND, esc, renderBrandedEmail } from './mail/brandedLayout.js';
import { appUrl } from './appWhatsNewMail.js';

const ROLE_WORD = { none: 'no access', user: 'user', admin: 'admin', owner: 'owner' };

export const ROLE_CAN = {
  user: 'A user can open and use the app.',
  admin: 'An admin can use the app and help run it: deploys, logs and settings, as the app\'s permissions allow.',
  owner: 'An owner has full control of the app, including who has access to it.',
  none: 'You can no longer open the app.',
};

const RANK = { none: 0, user: 1, admin: 2, owner: 3 };

function headline(appName, from, to) {
  if (from === 'none') return `You now have ${to} access to ${appName}.`;
  if (to === 'none') return `Your access to ${appName} was removed.`;
  const dir = RANK[to] > RANK[from] ? 'raised' : 'changed';
  return `Your access to ${appName} was ${dir} from ${ROLE_WORD[from]} to ${ROLE_WORD[to]}.`;
}

function subjectFor(appName, from, to) {
  if (from === 'none') return `[AppCrane] You have been given access to ${appName}`;
  if (to === 'none') return `[AppCrane] Your access to ${appName} was removed`;
  return `[AppCrane] Your role on ${appName} is now ${ROLE_WORD[to]}`;
}

/**
 * @param {{ app: { name: string, slug: string }, user: { name?: string }, from: string, to: string, actor?: string|null }} p
 * from/to are 'none' | 'user' | 'admin' | 'owner'. actor is a display name, or null when unknown.
 */
export function renderAccessChange({ app, user, from, to, actor = null }) {
  const appName = app.name || app.slug;
  const greeting = `Hi${user.name ? ` ${user.name}` : ''},`;
  const intro = headline(appName, from, to);
  const change = `Your role: ${ROLE_WORD[from]} -> ${ROLE_WORD[to]}`;
  const can = ROLE_CAN[to];
  const by = actor ? `Changed by: ${actor}` : null;
  const url = to === 'none' ? null : appUrl(app.slug);
  const footer = 'You get this because your access to an app on AppCrane changed. '
    + 'If you did not expect it, ask the app\'s owner or a platform admin.';

  const p = (s) => `<p style="margin:12px 0 0;font-size:14px;line-height:21px;color:${BRAND.text};">${esc(s)}</p>`;
  const html = renderBrandedEmail({
    preheader: intro,
    greeting,
    intro,
    bodyHtml: p(change) + p(can) + (by ? p(by) : ''),
    cta: url ? { label: `Open ${appName}`, url } : null,
    footer,
  });
  const text = [greeting, '', intro, '', change, can, ...(by ? [by] : []), ...(url ? ['', `Open the app: ${url}`] : []), '', footer, '']
    .join('\n');
  return { subject: subjectFor(appName, from, to), text, html };
}
