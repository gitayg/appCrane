// The one place an intake request row is written and announced. POST
// /api/enhancements (the intake form) and appcrane_submit_feedback both come
// through here, so a request filed by an agent lands in the same queue, with
// the same GitHub mirror and app-admin mail, as one typed into the form.

import { mirrorRequest, getAppForMirror } from './github/issuesMirror.js';
import { notifyAppAdminsOfNewRequest, notifyPlatformAdminsOfPlatformRequest } from './requestNotify.js';

// v2.21.5: '_platform' is a reserved slug for requests against AppCrane
// itself, visible only to platform admins.
export const PLATFORM_SLUG = '_platform';

export function insertRequest(db, { appSlug, userId, userName, message, kind = null }) {
  const { lastInsertRowid } = db.prepare(`
    INSERT INTO enhancement_requests (app_slug, user_id, user_name, message, status, kind)
    VALUES (?, ?, ?, ?, 'new', ?)
  `).run(appSlug || null, userId, userName, message, kind);
  return Number(lastInsertRowid);
}

/**
 * Tell the right people about a new request. platformMail: false lets a
 * caller with its own throttled platform-admin mail (feedback) skip the
 * one-mail-per-request notice.
 */
export function announceRequest(db, id, appSlug, { platformMail = true } = {}) {
  if (appSlug === PLATFORM_SLUG) {
    if (platformMail) notifyPlatformAdminsOfPlatformRequest(id);
    return;
  }
  if (!appSlug) return;
  const app = getAppForMirror(appSlug);
  if (app?.github_url) {
    const row = db.prepare('SELECT id, message, user_name, status, created_at FROM enhancement_requests WHERE id = ?').get(id);
    mirrorRequest(app, row).catch(() => {});
  }
  // v2.14.1/3: email the app's owners/admins on any new request (access or feature).
  notifyAppAdminsOfNewRequest(id);
}
