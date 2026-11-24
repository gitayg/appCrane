// What verify-before-run did when an image was not verified, kept per app, env,
// image and outcome (migration 285). warn mode: one server log line per image
// per day instead of one per restart, and the census lists the image while it is
// unsigned. enforce mode: every refusal is audited, mailed to the app's owners
// and the platform admins (once per image per day) and shown on the app, so a
// refused auto-restart is never a silent outage.

import { getDb } from '../../db.js';
import log from '../../utils/logger.js';
import { signedRowFor } from './store.js';

export const THROTTLE_HOURS = 24;
const due = (t) => `(${t} IS NULL OR ${t} <= datetime('now', '-${THROTTLE_HOURS} hours'))`;

/**
 * Count one event and say whether this one should be logged / mailed.
 * @returns {{ id: number, count: number, log: boolean, notify: boolean }}
 */
export function recordTrustEvent(db, { appId, env, imageId, imageRef, kind, what, reason }) {
  const id = imageId || '';
  db.prepare(`INSERT INTO image_trust_events (app_id, env, image_id, image_ref, kind, what, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(app_id, env, image_id, kind) DO NOTHING`).run(appId, env, id, imageRef ?? null, kind, what ?? null, reason ?? null);
  const row = db.prepare(`SELECT id, count, ${due('last_logged_at')} AS log_due, ${due('last_notified_at')} AS notify_due
    FROM image_trust_events WHERE app_id = ? AND env = ? AND image_id = ? AND kind = ?`).get(appId, env, id, kind);
  db.prepare(`UPDATE image_trust_events SET count = count + 1, last_at = datetime('now'), image_ref = COALESCE(?, image_ref),
      what = COALESCE(?, what), reason = COALESCE(?, reason),
      last_logged_at = CASE WHEN ? THEN datetime('now') ELSE last_logged_at END
    WHERE id = ?`).run(imageRef ?? null, what ?? null, reason ?? null, row.log_due ? 1 : 0, row.id);
  return { id: row.id, count: row.count + 1, log: !!row.log_due, notify: !!row.notify_due };
}

function markNotified(db, id) {
  db.prepare("UPDATE image_trust_events SET last_notified_at = datetime('now') WHERE id = ?").run(id);
}

export function recipientsFor(db, appId) {
  return db.prepare(`SELECT DISTINCT email FROM (
      SELECT u.email FROM app_user_roles r JOIN users u ON u.id = r.user_id
        WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 1
      UNION
      SELECT email FROM users WHERE role = 'platform_admin' AND active = 1
    ) WHERE email IS NOT NULL AND trim(email) != '' ORDER BY email`).all(appId).map((r) => r.email);
}

/**
 * The enforce-mode refusal: counted, audited every time, mailed once per image per day.
 * Never throws: the caller is already on its way to throw IMAGE_UNTRUSTED.
 */
export async function recordRefusal(q) {
  const db = q.db || getDb();
  try {
    const app = db.prepare('SELECT id, slug, name FROM apps WHERE slug = ?').get(q.slug);
    if (!app) return null;
    const ev = recordTrustEvent(db, { appId: app.id, env: q.env, imageId: q.imageId, imageRef: q.image, kind: 'refused', what: q.what, reason: q.reason });
    const { logAudit } = await import('../../middleware/audit.js');
    logAudit(null, app.id, 'image-trust-refused', { env: q.env, what: q.what || null, image_ref: q.image || null, image_id: q.imageId || null, reason: q.reason, count: ev.count });
    if (!ev.notify) return { ...ev, mailed: [] };
    const { enqueueEmail } = await import('../emailQueue.js');
    const day = new Date().toISOString().slice(0, 10);
    const mailed = [];
    const text = `AppCrane refused to ${q.what === 'restart' ? 'restart' : 'start'} ${app.slug} ${q.env}.\n\n`
      + `Image: ${q.image || '(unknown)'}\nImage id: ${q.imageId || '(unknown)'}\nReason: ${q.reason}\nTime: ${new Date().toISOString()}\n\n`
      + `Image trust is in enforce mode, so a container whose image this instance has not signed is not started or restarted. `
      + `The container was left as it was: if it was unhealthy or stopped, it still is.\n\n`
      + `To fix it: redeploy ${app.slug} ${q.env} (a deploy signs its image), or have a platform admin sign the running images `
      + `(Settings > Security > Image signing, "Sign running unsigned images"), or switch image trust to warn.\n`;
    for (const to of recipientsFor(db, app.id)) {
      try {
        enqueueEmail({
          to, appId: app.id, env: q.env, source: 'image-trust', fromName: 'AppCrane Security',
          subject: `[AppCrane] IMAGE REFUSED - ${app.slug} ${q.env} ${q.what || 'start'} (enforce mode)`,
          text, idempotencyKey: `image-trust-refused:${q.env}:${q.imageId || q.image || ''}:${day}:${to.trim().toLowerCase()}`,
        });
        mailed.push(to);
      } catch (e) {
        log.warn(`[image-trust] refusal mail to ${to} skipped: ${e.message}`);
      }
    }
    markNotified(db, ev.id);
    return { ...ev, mailed };
  } catch (e) {
    log.error(`[image-trust] could not record a refusal for ${q.slug}/${q.env}: ${e.message}`);
    return null;
  }
}

/**
 * Events whose image is still not signed for its app/env (a later signature
 * resolves them). Newest first.
 * @param {{ appId?: number, sinceDays?: number }} [f]
 */
export function openTrustEvents(db, f = {}) {
  const rows = db.prepare(`SELECT e.*, a.slug AS app FROM image_trust_events e JOIN apps a ON a.id = e.app_id
    WHERE (? IS NULL OR e.app_id = ?) AND e.last_at >= datetime('now', ?)
    ORDER BY e.last_at DESC, e.id DESC LIMIT 200`).all(f.appId ?? null, f.appId ?? null, `-${f.sinceDays ?? 30} days`);
  return rows
    .filter((r) => !r.image_id || !signedRowFor(db, r.app_id, r.env, r.image_id))
    .map((r) => ({
      app: r.app, env: r.env, kind: r.kind, what: r.what, image_ref: r.image_ref, image_id: r.image_id || null,
      reason: r.reason, count: r.count, first_at: r.first_at, last_at: r.last_at,
    }));
}
