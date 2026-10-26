import { AppError } from '../../utils/errors.js';
import { logAudit } from '../../middleware/audit.js';
import { recordEvent } from '../eventStore.js';
import { getPolicy, classificationOf, inScope, LEVELS } from './policy.js';
import { sendStartMails } from './notify.js';

const DAY = 86_400_000;
export const sqlTime = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
export const sqlMs = (ts) => Date.parse(String(ts).replace(' ', 'T') + 'Z');

function lastAccess(db, userId, appId) {
  let best = null;
  try {
    const v = db.prepare('SELECT MAX(day) AS d FROM app_visits WHERE user_id = ? AND app_id = ?').get(userId, appId)?.d;
    if (v) best = `${v} 00:00:00`;
  } catch (_) {}
  try {
    const a = db.prepare('SELECT MAX(created_at) AS t FROM audit_log WHERE user_id = ? AND app_id = ?').get(userId, appId)?.t;
    if (a && (!best || a > best)) best = a;
  } catch (_) {}
  return best;
}

function scimManaged(db, appId, userId) {
  try { return !!db.prepare('SELECT 1 FROM scim_group_access WHERE app_id = ? AND user_id = ?').get(appId, userId); } catch (_) { return false; }
}

function activePlatformAdmins(db) {
  return db.prepare("SELECT id FROM users WHERE role = 'platform_admin' AND active = 1 ORDER BY id").all().map(r => r.id);
}

/** Everyone with a role on the app, as review items. */
export function appItems(db, appId) {
  return db.prepare(`SELECT aur.user_id, aur.app_role, u.name, u.email
                       FROM app_user_roles aur JOIN users u ON u.id = aur.user_id
                      WHERE aur.app_id = ? AND aur.app_role <> 'none' ORDER BY aur.user_id`).all(appId)
    .map(r => ({
      user_id: r.user_id, user_name: r.name, user_email: r.email, role: r.app_role,
      granted_via: scimManaged(db, appId, r.user_id) ? 'scim' : 'direct',
      last_access_at: lastAccess(db, r.user_id, appId),
    }));
}

export function platformItems(db) {
  return db.prepare("SELECT id, name, email, last_login_at FROM users WHERE role = 'platform_admin' ORDER BY id").all()
    .map(u => ({ user_id: u.id, user_name: u.name, user_email: u.email, role: 'platform_admin', granted_via: 'direct', last_access_at: u.last_login_at || null }));
}

/**
 * Start a campaign: one review per app in scope (reviewers: its owners, or the
 * platform admins when it has none) and, for the default scope, one review of
 * the platform admins. Refuses when the scope already has an open campaign.
 */
export function createCampaign(db, { scope = 'default', createdBy = null, now = Date.now(), dueDays = null, notify = true } = {}) {
  if (scope !== 'default' && !LEVELS.includes(scope)) throw new AppError(`scope must be 'default' or a classification level`, 400, 'VALIDATION');
  const policy = getPolicy(db);
  if (scope !== 'default' && policy.by_classification[scope] == null) {
    throw new AppError(`No cadence is set for '${scope}' apps; they are reviewed in the default campaign`, 400, 'VALIDATION');
  }
  if (db.prepare("SELECT 1 FROM access_review_campaigns WHERE scope = ? AND status = 'open'").get(scope)) {
    throw new AppError('A campaign for this scope is already open', 409, 'CAMPAIGN_OPEN');
  }
  const due = Number.isInteger(dueDays) && dueDays >= 1 && dueDays <= 90 ? dueDays : policy.due_days;
  const dueAt = now + due * DAY;
  const name = `Access review ${sqlTime(now).slice(0, 10)}${scope === 'default' ? '' : ` (${scope} apps)`}`;
  const admins = activePlatformAdmins(db);

  const insReview = db.prepare(`INSERT INTO access_reviews (campaign_id, kind, app_id, app_slug, app_name, data_classification)
                                VALUES (?, ?, ?, ?, ?, ?)`);
  const insReviewer = db.prepare('INSERT OR IGNORE INTO access_review_reviewers (review_id, user_id) VALUES (?, ?)');
  const insItem = db.prepare(`INSERT INTO access_review_items (review_id, user_id, user_name, user_email, role, granted_via, last_access_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?)`);
  const owners = db.prepare("SELECT aur.user_id FROM app_user_roles aur JOIN users u ON u.id = aur.user_id WHERE aur.app_id = ? AND aur.app_role = 'owner' AND u.active = 1 ORDER BY aur.user_id");

  const id = db.transaction(() => {
    const campaignId = Number(db.prepare(`INSERT INTO access_review_campaigns (name, scope, started_at, due_at, grace_until, created_by, overdue_action)
                                          VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(name, scope, sqlTime(now), sqlTime(dueAt), sqlTime(dueAt + policy.grace_days * DAY), createdBy, policy.overdue_action).lastInsertRowid);
    for (const app of db.prepare('SELECT id, slug, name FROM apps ORDER BY id').all()) {
      const level = classificationOf(db, app.id);
      if (!inScope(policy, scope, level)) continue;
      const items = appItems(db, app.id);
      if (!items.length) continue;
      const reviewId = Number(insReview.run(campaignId, 'app', app.id, app.slug, app.name, level).lastInsertRowid);
      const reviewers = owners.all(app.id).map(r => r.user_id);
      for (const uid of reviewers.length ? reviewers : admins) insReviewer.run(reviewId, uid);
      for (const it of items) insItem.run(reviewId, it.user_id, it.user_name, it.user_email, it.role, it.granted_via, it.last_access_at);
    }
    if (scope === 'default') {
      const items = platformItems(db);
      if (items.length) {
        const reviewId = Number(insReview.run(campaignId, 'platform', null, null, 'Platform admins', null).lastInsertRowid);
        for (const uid of admins) insReviewer.run(reviewId, uid);
        for (const it of items) insItem.run(reviewId, it.user_id, it.user_name, it.user_email, it.role, it.granted_via, it.last_access_at);
      }
    }
    return campaignId;
  })();

  const counts = db.prepare(`SELECT COUNT(DISTINCT r.id) AS reviews, COUNT(i.id) AS items FROM access_reviews r
                               LEFT JOIN access_review_items i ON i.review_id = r.id WHERE r.campaign_id = ?`).get(id);
  logAudit(createdBy, null, 'access-review-campaign-start', { campaign_id: id, scope, reviews: counts.reviews, items: counts.items });
  recordEvent({ kind: 'access_review.started', severity: 'info', userId: createdBy, summary: `${name} started: ${counts.reviews} review(s), ${counts.items} access(es)`,
    refTable: 'access_review_campaigns', refId: id, data: { scope, due_at: sqlTime(dueAt), ...counts } });
  if (notify) sendStartMails(db, id);
  return getCampaign(db, id);
}

export function getCampaign(db, id) {
  const c = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(id);
  if (!c) return null;
  const p = db.prepare(`SELECT COUNT(*) AS reviews, SUM(status = 'completed') AS completed FROM access_reviews WHERE campaign_id = ?`).get(id);
  const it = db.prepare(`SELECT COUNT(*) AS items, SUM(i.decision IS NOT NULL) AS decided,
                                SUM(i.decision = 'remove') AS removed, SUM(i.decision = 'change') AS changed
                           FROM access_review_items i JOIN access_reviews r ON r.id = i.review_id WHERE r.campaign_id = ?`).get(id);
  return { ...c, reviews: p.reviews, reviews_completed: p.completed || 0, items: it.items, decided: it.decided || 0, removed: it.removed || 0, changed: it.changed || 0 };
}

export function listCampaigns(db, limit = 50) {
  return db.prepare('SELECT id FROM access_review_campaigns ORDER BY id DESC LIMIT ?').all(limit).map(r => getCampaign(db, r.id));
}

export function closeCampaign(db, id, { userId = null, reason = 'manual' } = {}) {
  const c = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(id);
  if (!c) throw new AppError('Campaign not found', 404, 'NOT_FOUND');
  if (c.status === 'closed') return getCampaign(db, id);
  db.prepare("UPDATE access_review_campaigns SET status = 'closed', closed_at = datetime('now') WHERE id = ?").run(id);
  const out = getCampaign(db, id);
  const unreviewed = out.items - out.decided;
  logAudit(userId, null, 'access-review-campaign-close', { campaign_id: id, reason, unreviewed });
  recordEvent({ kind: 'access_review.closed', severity: unreviewed ? 'warning' : 'info', userId, summary: `${c.name} closed (${reason}): ${unreviewed} access(es) left unreviewed`,
    refTable: 'access_review_campaigns', refId: id, data: { reason, unreviewed, removed: out.removed, changed: out.changed } });
  return out;
}
