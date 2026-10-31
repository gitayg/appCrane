// Platform admins hear about AppCrane feedback at most once an hour each:
// the first item in an hour sends, the rest wait in Requests. Platform mail
// (app_id NULL), deduped by the idempotency key, which migration 162 makes
// unique for source 'feedback'.

import { enqueueEmail } from '../emailQueue.js';
import { requestUrl, dashboardBaseUrl } from '../vulnRequests.js';
import { BRAND, esc, renderBrandedEmail } from '../mail/brandedLayout.js';
import { platformAdmins } from '../memoryAdmissionMail.js';
import log from '../../utils/logger.js';

export const FEEDBACK_MAIL_SOURCE = 'feedback';
const PREVIEW_MAX = 500;

export function hourBucket(now = new Date()) {
  return now.toISOString().slice(0, 13);
}

function send(m) {
  try {
    const r = enqueueEmail({ ...m, appId: null, source: FEEDBACK_MAIL_SOURCE });
    return !r?.deduped;
  } catch (e) {
    if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[feedback] mail to ${m.to} skipped: ${e.message}`);
    return false;
  }
}

export function notifyAdminsOfFeedback(db, { id, kind, who, message, now = new Date() }) {
  const hour = hourBucket(now);
  const preview = message.length > PREVIEW_MAX ? `${message.slice(0, PREVIEW_MAX)}...` : message;
  const link = requestUrl(id);
  const sent = [];
  for (const a of platformAdmins(db)) {
    const ok = send({
      to: a.email,
      subject: `[AppCrane] New feedback about AppCrane (${kind})`,
      text: `Hi${a.name ? ` ${a.name}` : ''},\n\n${who} sent feedback about AppCrane (${kind}):\n\n  "${preview}"\n\n`
        + `Open it: ${link}\n\nYou get at most one of these an hour; later feedback this hour is in Requests.\n`,
      html: renderBrandedEmail({
        preheader: `${who} sent feedback about AppCrane (${kind})`,
        greeting: `Hi${a.name ? ` ${a.name}` : ''},`,
        intro: `${who} sent feedback about AppCrane (${kind}):`,
        bodyHtml: `<p style="margin:12px 0 0;font-size:14px;line-height:21px;color:${BRAND.text};white-space:pre-wrap;">${esc(preview)}</p>`
          + `<p style="margin:12px 0 0;font-size:13px;line-height:20px;color:${BRAND.dim};">${esc('You get at most one of these an hour; later feedback this hour is in Requests.')}</p>`,
        cta: { label: 'Open feedback', url: link },
        footer: `You get this because you are a platform admin of this AppCrane (${dashboardBaseUrl()}).`,
      }),
      idempotencyKey: `feedback:admin:${hour}:${a.email.trim().toLowerCase()}`,
    });
    if (ok) sent.push(a.email);
  }
  return sent;
}
