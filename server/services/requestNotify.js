/**
 * v2.14.1: email the requester when their enhancement request is fulfilled
 * (status → 'done'). Uses the platform email service, which only ever sends to
 * registered AppCrane users — the requester is one (they have a user_id), so
 * no new recipient surface. Best-effort: never throws into the caller.
 */
import { getDb } from '../db.js';
import { enqueueEmail } from './emailQueue.js';
import log from '../utils/logger.js';

export function notifyRequesterFulfilled(enhancementId) {
  try {
    const db = getDb();
    const row = db.prepare(
      'SELECT id, app_slug, user_id, message, fix_version, status FROM enhancement_requests WHERE id = ?'
    ).get(enhancementId);
    if (!row || !row.user_id) return;

    const user = db.prepare('SELECT email, name FROM users WHERE id = ? AND active = 1').get(row.user_id);
    if (!user?.email) return;

    let appName = row.app_slug || 'your app';
    const app = db.prepare('SELECT name FROM apps WHERE slug = ?').get(row.app_slug);
    if (app?.name) appName = app.name;

    const wontDo = row.status === 'no_changes_needed';
    const verPart = row.fix_version ? ` in v${row.fix_version}` : '';
    const requestText = String(row.message || '').slice(0, 500);
    const subject = wontDo
      ? `Update on your request for ${appName}`
      : `Your request for ${appName} was completed`;

    // Requester gets a personal note; platform admins get a copy for visibility.
    const recipients = new Set([user.email]);
    for (const a of db.prepare("SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL").all()) {
      recipients.add(a.email);
    }

    for (const to of recipients) {
      const forRequester = to === user.email;
      let text;
      if (forRequester) {
        text = wontDo
          ? `Hi${user.name ? ' ' + user.name : ''},\n\n` +
            `After review, this request won't be actioned (no change needed / out of scope):\n\n` +
            `  "${requestText}"\n\n` +
            `If you think that's a mistake, reply to your app admin.\n\n— AppCrane`
          : `Hi${user.name ? ' ' + user.name : ''},\n\n` +
            `Good news — a request you submitted for ${appName} has been completed${verPart}:\n\n` +
            `  "${requestText}"\n\n` +
            `You'll see it the next time you open the app.\n\n— AppCrane`;
      } else {
        text =
          `Request #${row.id} from ${user.name || user.email} for ${appName} was ` +
          `${wontDo ? "closed as won't-do" : 'completed'}.\n\n  "${requestText}"\n\n— AppCrane`;
      }
      try { enqueueEmail({ to, subject, text, source: 'request-fulfilled' }); } catch (_) { /* skip bad recipient */ }
    }
    log.info(`[request-notify] queued ${wontDo ? "won't-do" : 'fulfillment'} email for request ${row.id} → ${recipients.size} recipient(s)`);
  } catch (e) {
    log.warn(`[request-notify] could not notify for enhancement ${enhancementId}: ${e.message}`);
  }
}

/**
 * v2.14.1: email an app's owners/admins when someone requests access to it, so
 * they can approve/deny without waiting to notice it in the dashboard.
 */
export function notifyAppAdminsOfAccessRequest(appSlug, requesterName) {
  try {
    if (!appSlug) return;
    const db = getDb();
    const app = db.prepare('SELECT id, name FROM apps WHERE slug = ?').get(appSlug);
    if (!app) return;

    const admins = db.prepare(`
      SELECT DISTINCT u.email, u.name
      FROM app_user_roles aur
      JOIN users u ON u.id = aur.user_id
      WHERE aur.app_id = ? AND aur.app_role IN ('owner', 'admin') AND u.active = 1 AND u.email IS NOT NULL
    `).all(app.id);
    if (!admins.length) return;

    const appName = app.name || appSlug;
    const subject = `Access request for ${appName}`;
    for (const a of admins) {
      const text =
        `Hi${a.name ? ' ' + a.name : ''},\n\n` +
        `${requesterName || 'A user'} has requested access to ${appName}.\n\n` +
        `Approve or deny it from AppCrane (it appears in the app's requests), or an agent ` +
        `can handle it via appcrane_list_access_requests.\n\n` +
        `— AppCrane`;
      try { enqueueEmail({ to: a.email, subject, text, source: 'access-request' }); } catch (_) { /* skip bad recipient */ }
    }
    log.info(`[access-request] notified ${admins.length} admin(s) of ${appName}`);
  } catch (e) {
    log.warn(`[access-request] could not notify app admins for ${appSlug}: ${e.message}`);
  }
}
