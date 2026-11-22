// E-mail for capability requests. The platform e-mail service only sends to
// registered users, and every recipient here is one: platform admins hear about
// a new request, the requester hears the decision, owners hear that a grant
// ended. Best-effort: a mail failure never fails the action that caused it.

import { enqueueEmail } from '../emailQueue.js';
import { dashboardBaseUrl } from '../vulnRequests.js';
import log from '../../utils/logger.js';
import { capabilityDef } from './registry.js';

export const CAPABILITY_MAIL_SOURCE = 'capability-request';

const label = (cap) => capabilityDef(cap)?.label || cap;
const queueUrl = () => `${dashboardBaseUrl()}/capability-approvals`;

function send(to, subject, text, key) {
  try { enqueueEmail({ to, subject, text, appId: null, source: CAPABILITY_MAIL_SOURCE, idempotencyKey: key }); }
  catch (e) { log.warn(`[capabilities] mail to a recipient skipped: ${e.message}`); }
}

export function mailNewRequest(db, app, capability, id, requester, reason, scope) {
  try {
    const admins = db.prepare("SELECT id, email, name FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL AND COALESCE(kind, 'human') != 'agent'").all();
    const who = requester.name || requester.email || `user ${requester.id}`;
    for (const a of admins) {
      if (a.id === requester.id) continue;
      send(a.email, `[AppCrane] ${app.name || app.slug} asks for: ${label(capability)}`,
        `Hi${a.name ? ` ${a.name}` : ''},\n\n${who}${requester.kind === 'agent' ? ' (an agent identity)' : ''} asked for "${label(capability)}" on ${app.name || app.slug}.\n\n`
        + `Scope: ${JSON.stringify(scope)}\nReason: ${reason}\n\nApprove, narrow or deny it in AppCrane: ${queueUrl()}\n\n- AppCrane`,
        `capability:${id}:new:${a.id}`);
    }
  } catch (e) { log.warn(`[capabilities] new-request mail failed: ${e.message}`); }
}

export function mailDecision(db, app, row, approved) {
  try {
    if (!row.requested_by) return;
    const u = db.prepare('SELECT email, name FROM users WHERE id = ? AND active = 1').get(row.requested_by);
    if (!u?.email) return;
    const scope = row.scope ? `\nApproved scope: ${row.scope}` : '';
    const until = row.expires_at ? `\nUntil: ${row.expires_at} UTC` : '';
    const note = row.decision_note ? `\nNote: ${row.decision_note}` : '';
    send(u.email, `[AppCrane] ${label(row.capability)} for ${app?.name || 'your app'}: ${approved ? 'approved' : 'denied'}`,
      `Hi${u.name ? ` ${u.name}` : ''},\n\nYour request #${row.id} for "${label(row.capability)}" was ${approved ? 'approved' : 'denied'}.${scope}${until}${note}\n\n- AppCrane`,
      `capability:${row.id}:decision`);
  } catch (e) { log.warn(`[capabilities] decision mail failed: ${e.message}`); }
}

export function mailEnded(db, row, how, effect) {
  try {
    const app = db.prepare('SELECT id, name, slug FROM apps WHERE id = ?').get(row.app_id);
    if (!app) return;
    const owners = db.prepare(`SELECT DISTINCT u.id, u.email, u.name FROM app_user_roles r JOIN users u ON u.id = r.user_id
      WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 1 AND u.email IS NOT NULL`).all(app.id);
    for (const o of owners) {
      send(o.email, `[AppCrane] ${label(row.capability)} on ${app.name || app.slug} ${how}`,
        `Hi${o.name ? ` ${o.name}` : ''},\n\nThe grant #${row.id} for "${label(row.capability)}" on ${app.name || app.slug} was ${how}: ${effect}.\n\nRequest it again from the app's Capabilities card if it is still needed.\n\n- AppCrane`,
        `capability:${row.id}:${how}:${o.id}`);
    }
  } catch (e) { log.warn(`[capabilities] end mail failed: ${e.message}`); }
}
