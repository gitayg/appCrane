/**
 * 4-bucket lifecycle for enhancement requests:
 *   triage → in_progress → shipped → validated
 *
 * The `status` column on enhancement_requests still carries detailed AppStudio
 * states (planning, coding, sandbox_ready, …) for backward compat with the
 * legacy worker. This helper collapses them into the 4 user-facing buckets.
 *
 * `validated_at` (column added in 039-request-validation.sql) is the only
 * way a row reaches the `validated` bucket — the requester or admin marks it
 * after confirming the shipped change actually works.
 */

import { notifyRequesterFulfilled } from './requestNotify.js';

const SHIPPED_STATUSES = new Set([
  'merged', 'done', 'sandbox_ready', 'no_changes_needed',
]);

const IN_PROGRESS_STATUSES = new Set([
  'selected', 'planning', 'pending_user_review_plan', 'plan_approved',
  'coding', 'pushing', 'building', 'in_progress',
]);

export const BUCKETS = ['triage', 'in_progress', 'shipped', 'validated'];

/**
 * Collapse a (status, validated_at) tuple to one of the 4 buckets.
 */
export function bucketize(status, validated_at) {
  if (validated_at) return 'validated';
  if (SHIPPED_STATUSES.has(status)) return 'shipped';
  if (IN_PROGRESS_STATUSES.has(status)) return 'in_progress';
  return 'triage';
}

/**
 * Map a target bucket back to the underlying detailed status used by writes.
 * Bucket transitions:
 *   triage      → 'new'
 *   in_progress → 'in_progress'
 *   shipped     → 'done'
 *   validated   → leave status alone, set validated_at
 */
export function bucketToStatus(bucket) {
  switch (bucket) {
    case 'triage':       return { status: 'new',         clearValidated: true  };
    case 'in_progress':  return { status: 'in_progress', clearValidated: true  };
    case 'shipped':      return { status: 'done',        clearValidated: true  };
    case 'validated':    return { status: null,          clearValidated: false };
    default: throw new Error(`Unknown bucket: ${bucket}`);
  }
}

/**
 * Apply a bucket transition to a single row. Caller must ensure auth.
 * Returns the new bucket label (or throws on bad input).
 */
export function applyBucket(db, id, bucket, userId) {
  if (!BUCKETS.includes(bucket)) throw new Error(`Invalid bucket: ${bucket}`);
  const { status, clearValidated } = bucketToStatus(bucket);
  const prev = db.prepare('SELECT status FROM enhancement_requests WHERE id = ?').get(id);

  if (bucket === 'validated') {
    db.prepare(
      "UPDATE enhancement_requests SET validated_at = datetime('now'), validated_by = ? WHERE id = ?"
    ).run(userId || null, id);
  } else {
    if (clearValidated) {
      db.prepare(
        'UPDATE enhancement_requests SET status = ?, validated_at = NULL, validated_by = NULL WHERE id = ?'
      ).run(status, id);
    } else {
      db.prepare('UPDATE enhancement_requests SET status = ? WHERE id = ?').run(status, id);
    }
  }

  // v2.14.1: first time a request reaches the shipped bucket, email the requester.
  if (bucket === 'shipped' && prev?.status !== 'done') {
    notifyRequesterFulfilled(id);
  }
  return bucket;
}
