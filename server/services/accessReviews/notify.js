import log from '../../utils/logger.js';
import { enqueueEmail } from '../emailQueue.js';
import { bulletList, renderBrandedEmail } from '../mail/brandedLayout.js';
import { dashboardBaseUrl } from '../vulnRequests.js';

// Access-review mail. Every message carries an idempotency key that the unique
// index from migration 146 enforces, so a key that was queued once is never
// queued again, however often the scheduler runs.

export const MAIL_SOURCE = 'access-review';
export const myReviewsPath = '/access-reviews';
export const campaignPath = (id) => `/access-reviews/campaigns/${Number(id)}`;

/** Queue one message; false when it was queued before (or the recipient is not a mailable user). */
export function queueOnce({ to, subject, intro, lines = [], cta, greeting, footer, key }) {
  const base = dashboardBaseUrl();
  const url = `${base}${cta.path}`;
  try {
    enqueueEmail({
      to,
      subject,
      text: `${greeting}\n\n${intro}\n\n${lines.map(l => `- ${l}`).join('\n')}${lines.length ? '\n\n' : ''}${url}\n`,
      html: renderBrandedEmail({
        preheader: intro,
        greeting,
        intro,
        bodyHtml: lines.length ? bulletList(lines) : '',
        cta: { label: cta.label, url },
        footer,
      }),
      appId: null,
      source: MAIL_SOURCE,
      idempotencyKey: `${MAIL_SOURCE}:${key}`,
    });
    return true;
  } catch (e) {
    if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[access-reviews] mail ${key} skipped: ${e.message}`);
    return false;
  }
}

const day = (ts) => String(ts || '').slice(0, 10);
const greet = (u) => `Hi${u.name ? ` ${u.name}` : ''},`;

function pendingByReviewer(db, campaignId) {
  const rows = db.prepare(`SELECT rv.user_id, u.name, u.email, r.id AS review_id, r.app_name, r.kind,
                                  (SELECT COUNT(*) FROM access_review_items i WHERE i.review_id = r.id AND i.decision IS NULL) AS left_n
                             FROM access_reviews r
                             JOIN access_review_reviewers rv ON rv.review_id = r.id
                             JOIN users u ON u.id = rv.user_id
                            WHERE r.campaign_id = ? AND r.status = 'pending' AND u.active = 1 AND u.email IS NOT NULL
                            ORDER BY rv.user_id, r.id`).all(campaignId);
  const by = new Map();
  for (const r of rows) {
    if (!by.has(r.user_id)) by.set(r.user_id, { user: { id: r.user_id, name: r.name, email: r.email }, reviews: [] });
    by.get(r.user_id).reviews.push(r);
  }
  return [...by.values()];
}

const reviewLine = (r) => `${r.kind === 'platform' ? 'Platform admins' : r.app_name}: ${r.left_n} access(es) to review`;

export function sendStartMails(db, campaignId) {
  const c = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(campaignId);
  let n = 0;
  for (const { user, reviews } of pendingByReviewer(db, campaignId)) {
    if (queueOnce({
      to: user.email, key: `start:${campaignId}:${user.id}`, greeting: greet(user),
      subject: `[AppCrane] Access review: please review who has access, due ${day(c.due_at)}`,
      intro: `${c.name} has started. Confirm, remove or change each person's access by ${day(c.due_at)}.`,
      lines: reviews.map(reviewLine), cta: { label: 'Open my reviews', path: myReviewsPath },
      footer: 'You get this because you own an app (or are a platform admin) in this access review.',
    })) n++;
  }
  return n;
}

export function sendReminderMails(db, campaignId) {
  const c = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(campaignId);
  let n = 0;
  for (const { user, reviews } of pendingByReviewer(db, campaignId)) {
    if (queueOnce({
      to: user.email, key: `reminder:${campaignId}:${user.id}`, greeting: greet(user),
      subject: `[AppCrane] Reminder: access review due ${day(c.due_at)}`,
      intro: `${c.name} is due on ${day(c.due_at)} and you still have access to review.`,
      lines: reviews.map(reviewLine), cta: { label: 'Open my reviews', path: myReviewsPath },
      footer: 'You get this because a review assigned to you is not finished.',
    })) n++;
  }
  return n;
}

function platformAdmins(db) {
  return db.prepare("SELECT id, name, email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL ORDER BY id").all();
}

function pendingReviewLines(db, campaignId) {
  return db.prepare(`SELECT r.app_name, r.kind,
                            (SELECT COUNT(*) FROM access_review_items i WHERE i.review_id = r.id AND i.decision IS NULL) AS left_n,
                            (SELECT group_concat(u.name, ', ') FROM access_review_reviewers rv JOIN users u ON u.id = rv.user_id WHERE rv.review_id = r.id) AS reviewers
                       FROM access_reviews r WHERE r.campaign_id = ? AND r.status = 'pending' ORDER BY r.id LIMIT 25`).all(campaignId)
    .map(r => `${r.kind === 'platform' ? 'Platform admins' : r.app_name}: ${r.left_n} unreviewed (reviewers: ${r.reviewers || 'none'})`);
}

export function sendEscalationMails(db, campaignId) {
  const c = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(campaignId);
  const lines = pendingReviewLines(db, campaignId);
  let n = 0;
  for (const a of platformAdmins(db)) {
    if (queueOnce({
      to: a.email, key: `overdue:${campaignId}:${a.id}`, greeting: greet(a),
      subject: `[AppCrane] Access review overdue: ${c.name}`,
      intro: `${c.name} was due on ${day(c.due_at)} and ${lines.length} review(s) are not finished.`,
      lines, cta: { label: 'Open the campaign', path: campaignPath(campaignId) },
      footer: 'You get this because you are a platform admin. Overdue reviews are escalated once per campaign.',
    })) n++;
  }
  return n;
}

export function sendUnreviewedReport(db, campaignId) {
  const c = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(campaignId);
  const lines = pendingReviewLines(db, campaignId);
  let n = 0;
  for (const a of platformAdmins(db)) {
    if (queueOnce({
      to: a.email, key: `unreviewed:${campaignId}:${a.id}`, greeting: greet(a),
      subject: `[AppCrane] Access review closed with unreviewed access: ${c.name}`,
      intro: `The grace period for ${c.name} ended on ${day(c.grace_until)}. This access was never reviewed and was left unchanged.`,
      lines, cta: { label: 'Open the report', path: campaignPath(campaignId) },
      footer: 'You get this because you are a platform admin and the access-review policy reports unreviewed access.',
    })) n++;
  }
  return n;
}
