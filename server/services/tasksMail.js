// Tasks e-mail: the assignee hears about a new task, and the other party hears
// about a reply or a status change. One mail per (event, recipient): app_id
// plus the idempotency key `task-event:<eventId>:<userId>` is unique in
// email_queue (migration 060), so a retried notify cannot send twice.
//
// Recipients are active humans with an e-mail who still have access to the
// task's app, never the person who caused the event. An app-side comment or
// status change (no acting person) goes to the assignee. Deletions send nothing.

import { enqueueEmail } from './emailQueue.js';
import { dashboardBaseUrl } from './vulnRequests.js';
import { BRAND, esc, renderBrandedEmail } from './mail/brandedLayout.js';
import { STATUS_LABELS } from './tasksEvents.js';
import log from '../utils/logger.js';

export const TASK_MAIL_SOURCE = 'tasks';

export function taskUrl(taskId) {
  return `${dashboardBaseUrl()}/tasks?task=${encodeURIComponent(taskId)}`;
}

function recipientIds(task, ev) {
  if (ev.kind === 'created') return task.assignee_user_id === task.requester_user_id ? [] : [task.assignee_user_id];
  if (ev.kind === 'comment' || ev.kind === 'status') {
    if (ev.actor_user_id == null) return [task.assignee_user_id];
    return [...new Set([task.requester_user_id, task.assignee_user_id])].filter((id) => id !== ev.actor_user_id);
  }
  return [];
}

function render({ app, task, ev, actorName, comment, name }) {
  const who = actorName || app.name;
  const subj = task.subject.length > 120 ? `${task.subject.slice(0, 117)}...` : task.subject;
  let lead, subject, detailText = '';
  if (ev.kind === 'created') {
    subject = `[AppCrane] ${app.name}: new task "${subj}"`;
    lead = `${who} assigned you a task in ${app.name}.`;
    detailText = task.body || '';
  } else if (ev.kind === 'comment') {
    subject = `[AppCrane] ${app.name}: reply on "${subj}"`;
    lead = `${who} replied on a task in ${app.name}.`;
    detailText = comment || '';
  } else {
    subject = `[AppCrane] ${app.name}: "${subj}" is now ${STATUS_LABELS[ev.to_status] || ev.to_status}`;
    lead = `${who} moved a task in ${app.name} from ${STATUS_LABELS[ev.from_status] || ev.from_status} to ${STATUS_LABELS[ev.to_status] || ev.to_status}.`;
  }
  const url = taskUrl(task.id);
  const footer = `You get this because you are a party to this task in ${app.name} on AppCrane.`;
  const greeting = `Hi${name ? ' ' + name : ''},`;

  let text = `${greeting}\n\n${lead}\n\nTask: ${task.subject}\n`;
  if (detailText) text += `\n${detailText}\n`;
  text += `\nOpen it in My tasks: ${url}\n\n${footer}\n`;

  const detailHtml = detailText
    ? `<div style="margin:10px 0 0;padding:12px 14px;border-left:3px solid ${BRAND.accent};background:${BRAND.page};`
      + `font-size:14px;line-height:21px;color:${BRAND.text};white-space:pre-wrap;">${esc(detailText)}</div>`
    : '';
  const html = renderBrandedEmail({
    preheader: lead,
    greeting,
    intro: lead,
    bodyHtml: `<p style="margin:16px 0 0;font-size:15px;font-weight:600;color:${BRAND.text};">${esc(task.subject)}</p>${detailHtml}`,
    cta: { label: 'Open in My tasks', url },
    footer,
  });
  return { subject, text, html };
}

/** Queue the mails for one event. Returns how many were queued. */
export function queueTaskMail(db, eventId, enqueue = enqueueEmail) {
  const ev = db.prepare('SELECT * FROM task_events WHERE id = ?').get(eventId);
  if (!ev) return 0;
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(ev.task_id);
  if (!task || task.deleted_at) return 0;
  const app = db.prepare('SELECT id, name, slug FROM apps WHERE id = ?').get(task.app_id);
  if (!app) return 0;
  const actor = ev.actor_user_id != null && ev.kind !== 'created'
    ? db.prepare('SELECT name FROM users WHERE id = ?').get(ev.actor_user_id)
    : (ev.kind === 'created' ? db.prepare('SELECT name FROM users WHERE id = ?').get(task.requester_user_id) : null);
  const comment = ev.comment_id != null ? db.prepare('SELECT body FROM task_comments WHERE id = ?').get(ev.comment_id)?.body : null;

  let queued = 0;
  for (const uid of recipientIds(task, ev)) {
    const u = db.prepare(`
      SELECT u.id, u.name, u.email FROM users u
      WHERE u.id = ? AND u.active = 1 AND u.email IS NOT NULL AND trim(u.email) != ''
        AND COALESCE(u.kind, 'human') = 'human'
        AND EXISTS (SELECT 1 FROM app_users m WHERE m.app_id = ? AND m.user_id = u.id)
    `).get(uid, app.id);
    if (!u) continue;
    const { subject, text, html } = render({ app, task, ev, actorName: actor?.name, comment, name: u.name });
    try {
      const r = enqueue({
        to: u.email, subject, text, html, appId: app.id, env: 'production',
        idempotencyKey: `task-event:${ev.id}:${u.id}`, source: TASK_MAIL_SOURCE,
      });
      if (!r?.deduped) queued++;
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[tasks] mail for event ${ev.id} to user ${u.id} skipped: ${e.message}`);
    }
  }
  return queued;
}
