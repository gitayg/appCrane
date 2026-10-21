import { AppError } from '../../utils/errors.js';
import { canView, canDecide, SCIM_MESSAGE } from './decisions.js';

function shape(db, user, r) {
  const items = db.prepare(`SELECT i.*, d.name AS decided_by_name FROM access_review_items i LEFT JOIN users d ON d.id = i.decided_by
                             WHERE i.review_id = ? ORDER BY i.id`).all(r.id)
    .map(i => ({ ...i, scim_managed: i.granted_via === 'scim', scim_message: i.granted_via === 'scim' ? SCIM_MESSAGE : null }));
  const reviewers = db.prepare(`SELECT rv.user_id, u.name FROM access_review_reviewers rv LEFT JOIN users u ON u.id = rv.user_id
                                 WHERE rv.review_id = ? ORDER BY rv.user_id`).all(r.id);
  return {
    id: r.id, kind: r.kind, app_id: r.app_id, app_slug: r.app_slug, app_name: r.app_name, data_classification: r.data_classification,
    status: r.status, completed_at: r.completed_at,
    campaign: { id: r.campaign_id, name: r.c_name, status: r.c_status, started_at: r.c_started, due_at: r.c_due },
    can_decide: r.c_status === 'open' && canDecide(db, user, r),
    reviewers, items,
  };
}

const SELECT = `SELECT r.*, c.name AS c_name, c.status AS c_status, c.started_at AS c_started, c.due_at AS c_due
                  FROM access_reviews r JOIN access_review_campaigns c ON c.id = r.campaign_id`;

/** Reviews assigned to the caller: open campaigns first, then the most recent closed ones. */
export function reviewsForUser(db, user, limit = 30) {
  return db.prepare(`${SELECT} JOIN access_review_reviewers rv ON rv.review_id = r.id
                      WHERE rv.user_id = ? ORDER BY (c.status = 'open') DESC, r.id DESC LIMIT ?`).all(user.id, limit)
    .map(r => shape(db, user, r));
}

export function reviewDetail(db, id, user) {
  const r = db.prepare(`${SELECT} WHERE r.id = ?`).get(id);
  if (!r || !canView(db, user, r)) throw new AppError('Review not found', 404, 'NOT_FOUND');
  return shape(db, user, r);
}

export function campaignReviews(db, campaignId, user) {
  return db.prepare(`${SELECT} WHERE r.campaign_id = ? ORDER BY r.id`).all(campaignId).map(r => shape(db, user, r));
}
