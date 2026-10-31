// An app's requests as the coder panel sees and sends them
// (GET /api/coder/:slug/requests, POST .../requests/dispatch, and the
// request references on POST .../session/:id/dispatch).
//
// The caller has already passed the coder's owner-or-platform-admin gate for
// THIS app; every query here is also scoped to the app's slug, so an id from
// another app reads exactly like one that does not exist.

import { AppError } from '../../utils/errors.js';
import { bucketize, applyBucket } from '../requestStatus.js';
import { MAX_DISPATCH_REQUESTS } from './requestsPrompt.js';

const OPEN_BUCKETS = ['triage', 'in_progress'];
const EXCERPT_CHARS = 400;
const LIST_LIMIT = 200;

/** 'vulnerability' (opened by the dependency scan) or 'request' (filed by a person). */
function kindOf(row) {
  return row.vuln_key ? 'vulnerability' : 'request';
}

/**
 * This app's requests, newest first. Open ones only unless includeClosed.
 * Access requests are left out: they are a membership decision, not a change
 * to the code, so there is nothing in them for the coder to do.
 */
export function listCoderRequests(db, slug, { includeClosed = false } = {}) {
  const rows = db.prepare(`
    SELECT id, user_name, message, created_at, status, validated_at, vuln_key, coder_session_id
    FROM enhancement_requests
    WHERE app_slug = ? AND (kind IS NULL OR kind != 'access')
    ORDER BY created_at DESC, id DESC
    LIMIT ${LIST_LIMIT}
  `).all(slug);
  return rows
    .map((r) => ({
      id: r.id,
      user_name: r.user_name || null,
      excerpt: String(r.message || '').slice(0, EXCERPT_CHARS),
      truncated: String(r.message || '').length > EXCERPT_CHARS,
      created_at: r.created_at,
      status: r.status,
      bucket: bucketize(r.status, r.validated_at),
      kind: kindOf(r),
      coder_session_id: r.coder_session_id || null,
    }))
    .filter((r) => includeClosed || OPEN_BUCKETS.includes(r.bucket));
}

/**
 * The open requests `ids` names on this app, in the order given — or a refusal
 * that changes nothing. `field` names the body field in the messages.
 */
export function loadOpenRequests(db, slug, ids, { field = 'request_ids' } = {}) {
  if (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => !Number.isInteger(id) || id <= 0)) {
    throw new AppError(`${field} must be a non-empty array of request ids`, 400, 'VALIDATION');
  }
  if (new Set(ids).size !== ids.length) throw new AppError(`${field} lists a request twice`, 400, 'VALIDATION');
  if (ids.length > MAX_DISPATCH_REQUESTS) {
    throw new AppError(
      `At most ${MAX_DISPATCH_REQUESTS} requests go to the coder at once: they run as one turn and are reviewed and released together. Send the rest in another batch.`,
      400,
      'TOO_MANY_REQUESTS',
    );
  }

  const found = db.prepare(
    `SELECT id, user_name, message, created_at, status, validated_at FROM enhancement_requests
     WHERE app_slug = ? AND id IN (${ids.map(() => '?').join(', ')})`,
  ).all(slug, ...ids);
  if (found.length !== ids.length) {
    throw new AppError(`One or more of these requests is not a request on '${slug}'. Nothing was sent.`, 404, 'NOT_FOUND');
  }
  const byId = new Map(found.map((r) => [r.id, r]));
  const rows = ids.map((id) => byId.get(id));

  const closed = rows.filter((r) => !OPEN_BUCKETS.includes(bucketize(r.status, r.validated_at)));
  if (closed.length) {
    throw new AppError(
      `Already shipped or validated: ${closed.map((r) => `#${r.id}`).join(', ')}. Nothing was sent.`,
      409,
      'REQUEST_CLOSED',
    );
  }
  return rows;
}

/** Once the prompt is in: the requests are in progress and point at the session. */
export function markSentToCoder(db, rows, sessionId, userId) {
  const stamp = db.prepare('UPDATE enhancement_requests SET coder_session_id = ? WHERE id = ?');
  db.transaction(() => {
    for (const row of rows) {
      if (bucketize(row.status, row.validated_at) !== 'in_progress') applyBucket(db, row.id, 'in_progress', userId);
      stamp.run(sessionId, row.id);
    }
  })();
}
