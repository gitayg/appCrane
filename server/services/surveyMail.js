// "New survey response": every answer is mailed to the app's owners and the
// platform admins -- active humans with an e-mail, one mail per address --
// with who answered and every question with its answer. Members are not mailed.
//
// One mail per (response, recipient): app_id plus the idempotency key
// `survey-response:<id>:<email>` (email_queue, migration 060). A mail fault
// never reaches the person who answered: queueSurveyResponseMail catches
// per recipient, and the route guards the whole call.

import { enqueueEmail } from './emailQueue.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, esc, renderBrandedEmail } from './mail/brandedLayout.js';
import log from '../utils/logger.js';

export const SURVEY_RESPONSE_SOURCE = 'survey-response';

export function surveyMailRecipients(db, appId) {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.email FROM users u
    WHERE u.active = 1 AND u.email IS NOT NULL AND trim(u.email) != ''
      AND COALESCE(u.kind, 'human') = 'human'
      AND (u.role = 'platform_admin'
        OR EXISTS (SELECT 1 FROM app_user_roles r WHERE r.user_id = u.id AND r.app_id = ? AND r.app_role = 'owner'))
    ORDER BY u.id
  `).all(appId);
  const seen = new Set();
  return rows.filter((u) => {
    const k = u.email.trim().toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function shown(a) {
  if (a.kind === 'nps') return `${a.value} / 10`;
  return String(a.value);
}

export function renderSurveyResponse({ app, survey, respondent, answers, nps, name }) {
  const who = respondent?.name || respondent?.email || 'Someone';
  const whoFull = respondent?.email && respondent.email !== who ? `${who} (${respondent.email})` : who;
  const subject = `[AppCrane] ${app.name} survey: ${nps !== null && nps !== undefined ? `NPS ${nps} from ` : 'new answer from '}${who}`;
  const intro = `${whoFull} answered "${survey.name}" in ${app.name}.`;
  const url = `${dashboardBaseUrl()}/surveys?app=${encodeURIComponent(app.slug)}`;
  const footer = `You get this because you own ${app.name} or administer this AppCrane. `
    + 'Platform admins choose which surveys run, and where, on the NPS & surveys page.';

  let text = `Hi${name ? ' ' + name : ''},\n\n${intro}\n\n`;
  for (const a of answers) text += `${a.prompt}\n  ${shown(a)}\n\n`;
  text += `All answers: ${url}\n\n${footer}\n`;

  const rows = answers.map((a) => `<tr><td style="padding:10px 0;border-top:1px solid ${BRAND.border};">`
    + `<div style="font-size:13px;line-height:19px;color:${BRAND.dim};">${esc(a.prompt)}</div>`
    + `<div style="margin-top:3px;font-size:14px;line-height:21px;color:${BRAND.text};white-space:pre-wrap;">${esc(shown(a))}</div>`
    + `</td></tr>`).join('');
  const html = renderBrandedEmail({
    preheader: intro,
    greeting: `Hi${name ? ' ' + name : ''},`,
    intro,
    bodyHtml: `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:16px 0 0;">${rows}</table>`,
    cta: { label: 'See all answers', url },
    footer,
  });
  return { subject, text, html };
}

/**
 * Queue the mail for one stored response. Never throws for a recipient's
 * fault; a database fault can still throw, so the caller guards the call.
 */
export function queueSurveyResponseMail({ db, app, survey, respondent, responseId, answers, nps, enqueue = enqueueEmail }) {
  let sent = 0, skipped = 0;
  for (const u of surveyMailRecipients(db, app.id)) {
    const idempotencyKey = `survey-response:${responseId}:${u.email.trim().toLowerCase()}`;
    try {
      const { subject, text, html } = renderSurveyResponse({ app, survey, respondent, answers, nps, name: u.name });
      const r = enqueue({ to: u.email, subject, text, html, appId: app.id, env: 'production', idempotencyKey, source: SURVEY_RESPONSE_SOURCE });
      if (r?.deduped) skipped++; else sent++;
    } catch (e) {
      skipped++;
      log.warn(`[survey-mail] ${app.slug} response ${responseId}: skipped ${u.email}: ${e.message}`);
    }
  }
  return { sent, skipped };
}
