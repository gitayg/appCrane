import { AppError } from '../../utils/errors.js';
import { isPlatformAdmin } from '../../utils/roles.js';
import { logAudit } from '../../middleware/audit.js';
import { recordEvent } from '../eventStore.js';
import { clearUserRoleGrants } from '../appDefinedRoles.js';
import { purgeRevokedTenants } from '../tenants.js';
import { closeCampaign } from './campaigns.js';

export const DECISIONS = Object.freeze(['keep', 'remove', 'change']);
export const APP_ROLES = Object.freeze(['owner', 'admin', 'user']);
export const SCIM_MESSAGE = 'Managed by your identity provider: this access comes from an IdP group, so change the group membership there.';

/**
 * Apply an app role the way PUT /api/apps/:slug/roles does (routes/users.js):
 * the last owner cannot be demoted, 'none' deletes the row and the app-defined
 * role grants and purges the person's tenant data, anything else upserts.
 */
export async function setAppRole(db, appId, userId, role) {
  if (role !== 'owner') {
    const target = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, userId);
    if (target?.app_role === 'owner') {
      const owners = db.prepare("SELECT COUNT(*) AS n FROM app_user_roles WHERE app_id = ? AND app_role = 'owner'").get(appId);
      if (owners.n <= 1) throw new AppError('Cannot remove the last owner of the app. Assign another owner first.', 400, 'LAST_OWNER');
    }
  }
  if (role === 'none') {
    db.transaction(() => {
      db.prepare('DELETE FROM app_user_roles WHERE app_id = ? AND user_id = ?').run(appId, userId);
      clearUserRoleGrants(appId, userId);
    })();
    const target = db.prepare('SELECT email FROM users WHERE id = ?').get(userId);
    await purgeRevokedTenants(db, userId, target?.email, [appId]);
  } else {
    db.prepare(`INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, ?)
                ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = excluded.app_role`).run(appId, userId, role);
  }
}

/** Demote a platform admin the way PUT /api/users/:id/role does: never yourself, never the last one. */
function demotePlatformAdmin(db, userId, actorId) {
  const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(userId);
  if (!user || user.role !== 'platform_admin') return;
  if (userId === actorId) throw new AppError('Cannot demote yourself. Have another platform admin do it.', 400, 'SELF_DEMOTE');
  const others = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'platform_admin' AND id != ?").get(userId);
  if (others.n === 0) throw new AppError('Cannot demote the only platform admin', 400, 'LAST_PLATFORM_ADMIN');
  db.prepare("UPDATE users SET role = 'user' WHERE id = ?").run(userId);
}

/**
 * Whether `user` may decide on `review` now: a listed reviewer who still holds
 * the reviewing role (an owner of the app, or a platform admin for the
 * platform review and for apps that had no owner).
 */
export function canDecide(db, user, review) {
  if (!user) return false;
  if (!db.prepare('SELECT 1 FROM access_review_reviewers WHERE review_id = ? AND user_id = ?').get(review.id, user.id)) return false;
  if (review.kind === 'platform') return isPlatformAdmin(user);
  const owner = db.prepare("SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ? AND app_role = 'owner'").get(review.app_id, user.id);
  return !!owner || isPlatformAdmin(user);
}

export function canView(db, user, review) {
  return isPlatformAdmin(user) || canDecide(db, user, review);
}

function otherDeciders(db, review, userId) {
  return db.prepare('SELECT user_id FROM access_review_reviewers WHERE review_id = ? AND user_id != ?').all(review.id, userId)
    .some(r => {
      const u = db.prepare('SELECT id, role, active FROM users WHERE id = ?').get(r.user_id);
      return u && u.active === 1 && canDecide(db, u, review);
    });
}

/**
 * Record one decision and apply it at once. Keep records only; Remove takes
 * the role away; Change sets a new app role. SCIM-granted access cannot be
 * removed or changed here. Every decision is audited and recorded as an event.
 */
export async function decide(db, { itemId, user, decision, newRole = null, note = null }) {
  const item = db.prepare('SELECT * FROM access_review_items WHERE id = ?').get(itemId);
  const review = item && db.prepare('SELECT * FROM access_reviews WHERE id = ?').get(item.review_id);
  if (!item || !review || !canView(db, user, review)) throw new AppError('Review item not found', 404, 'NOT_FOUND');
  if (!canDecide(db, user, review)) throw new AppError('Only the reviewers of this review can decide on it', 403, 'FORBIDDEN');
  const campaign = db.prepare('SELECT * FROM access_review_campaigns WHERE id = ?').get(review.campaign_id);
  if (campaign.status !== 'open') throw new AppError('This campaign is closed', 409, 'CAMPAIGN_CLOSED');
  if (item.decision) throw new AppError('This access was already reviewed', 409, 'ALREADY_DECIDED');
  if (!DECISIONS.includes(decision)) throw new AppError('decision must be keep, remove or change', 400, 'VALIDATION');
  if (decision === 'change') {
    if (review.kind === 'platform') throw new AppError('A platform admin can be kept or removed, not changed', 400, 'VALIDATION');
    if (!APP_ROLES.includes(newRole)) throw new AppError('new_role must be owner, admin or user', 400, 'VALIDATION');
    if (newRole === item.role) throw new AppError('new_role is the role the person already has', 400, 'VALIDATION');
  }
  if (item.user_id === user.id) {
    if (decision !== 'keep') throw new AppError('You cannot remove or change your own access in a review', 403, 'SELF_REVIEW');
    if (otherDeciders(db, review, user.id)) throw new AppError('Another reviewer must review your own access', 403, 'SELF_REVIEW');
  }
  const scim = item.granted_via === 'scim' || (review.kind === 'app'
    && !!db.prepare('SELECT 1 FROM scim_group_access WHERE app_id = ? AND user_id = ?').get(review.app_id, item.user_id));
  if (scim && decision !== 'keep') throw new AppError(SCIM_MESSAGE, 409, 'SCIM_MANAGED');

  const cleanNote = note == null ? null : String(note).slice(0, 500);
  const previous = review.kind === 'app'
    ? db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(review.app_id, item.user_id)?.app_role ?? null
    : db.prepare('SELECT role FROM users WHERE id = ?').get(item.user_id)?.role ?? null;

  if (decision === 'remove') {
    if (review.kind === 'app') await setAppRole(db, review.app_id, item.user_id, 'none');
    else demotePlatformAdmin(db, item.user_id, user.id);
  } else if (decision === 'change') {
    await setAppRole(db, review.app_id, item.user_id, newRole);
  }

  db.prepare(`UPDATE access_review_items SET decision = ?, new_role = ?, note = ?, decided_by = ?, decided_at = datetime('now') WHERE id = ?`)
    .run(decision, decision === 'change' ? newRole : null, cleanNote, user.id, item.id);

  const detail = { campaign_id: campaign.id, review_id: review.id, item_id: item.id, target_user_id: item.user_id, decision,
    role: item.role, previous_role: previous, new_role: decision === 'change' ? newRole : decision === 'remove' ? (review.kind === 'app' ? 'none' : 'user') : previous };
  logAudit(user.id, review.app_id ?? null, 'access-review-decision', detail);
  const what = decision === 'keep' ? 'kept' : decision === 'remove' ? 'removed' : `changed to ${newRole}`;
  recordEvent({ kind: 'access_review.decision', severity: decision === 'keep' ? 'info' : 'warning', appId: review.app_id, appSlug: review.app_slug,
    userId: user.id, subjectUserId: item.user_id, summary: `Access review: ${item.role} access ${what}${review.kind === 'platform' ? ' (platform admin)' : ''}`,
    refTable: 'access_review_items', refId: item.id, data: detail });

  const left = db.prepare('SELECT COUNT(*) AS n FROM access_review_items WHERE review_id = ? AND decision IS NULL').get(review.id).n;
  if (!left) {
    db.prepare("UPDATE access_reviews SET status = 'completed', completed_at = datetime('now') WHERE id = ?").run(review.id);
    const open = db.prepare("SELECT COUNT(*) AS n FROM access_reviews WHERE campaign_id = ? AND status = 'pending'").get(campaign.id).n;
    if (!open) closeCampaign(db, campaign.id, { userId: user.id, reason: 'complete' });
  }
  return db.prepare('SELECT * FROM access_review_items WHERE id = ?').get(item.id);
}
