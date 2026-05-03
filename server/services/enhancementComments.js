// Bugs / notes / reviews on enhancement requests.
//
// Storage layer for the enhancement_comments table. Routes consume
// these helpers; the planner + coder also consume them to inject
// open feedback into agent prompts on every run.

import { getDb } from '../db.js';
import log from '../utils/logger.js';

const VALID_TYPES   = new Set(['bug', 'note', 'review']);
const VALID_STATUS  = new Set(['open', 'resolved']);
const MAX_BODY      = 8000;   // generous cap; refuse anything pathological

function rowToPublic(r) {
  return {
    id: r.id,
    type: r.type,
    body: r.body,
    status: r.status,
    author_user_id: r.author_user_id,
    author_name:    r.author_name,
    created_at:     r.created_at,
    resolved_at:    r.resolved_at,
    resolved_by:    r.resolved_by,
  };
}

/** All comments on an enhancement, oldest first (chronological thread). */
export function listComments(enhancementId) {
  return getDb()
    .prepare('SELECT * FROM enhancement_comments WHERE enhancement_id = ? ORDER BY id ASC')
    .all(enhancementId)
    .map(rowToPublic);
}

/**
 * Open comments only — what the agent should be told about.
 * Used by planner/coder prompt assembly so every re-run sees outstanding
 * feedback without the operator having to re-type it into the request.
 */
export function listOpenComments(enhancementId) {
  return getDb()
    .prepare(`SELECT * FROM enhancement_comments
              WHERE enhancement_id = ? AND status = 'open'
              ORDER BY id ASC`)
    .all(enhancementId)
    .map(rowToPublic);
}

/** Tiny count helper — used to badge the Feedback tab without a full fetch. */
export function openCommentCount(enhancementId) {
  const row = getDb()
    .prepare(`SELECT COUNT(*) AS n FROM enhancement_comments
              WHERE enhancement_id = ? AND status = 'open'`)
    .get(enhancementId);
  return row?.n || 0;
}

export function getComment(enhancementId, commentId) {
  return getDb()
    .prepare('SELECT * FROM enhancement_comments WHERE id = ? AND enhancement_id = ?')
    .get(commentId, enhancementId);
}

export function createComment(enhancementId, { type, body, authorUserId, authorName }) {
  if (!VALID_TYPES.has(type)) throw new Error(`type must be one of ${[...VALID_TYPES].join(', ')}`);
  const trimmed = (body || '').trim();
  if (!trimmed) throw new Error('body is required');
  if (trimmed.length > MAX_BODY) throw new Error(`body exceeds ${MAX_BODY} chars`);

  const result = getDb()
    .prepare(`INSERT INTO enhancement_comments
              (enhancement_id, type, body, author_user_id, author_name)
              VALUES (?, ?, ?, ?, ?)`)
    .run(enhancementId, type, trimmed, authorUserId || null, authorName || null);
  log.info(`Comments: added ${type} on enh #${enhancementId} by ${authorName || authorUserId || 'unknown'}`);
  return getComment(enhancementId, result.lastInsertRowid);
}

export function setStatus(enhancementId, commentId, status, resolverUserId) {
  if (!VALID_STATUS.has(status)) throw new Error(`status must be one of ${[...VALID_STATUS].join(', ')}`);
  const existing = getComment(enhancementId, commentId);
  if (!existing) throw new Error('comment not found');
  if (existing.status === status) return rowToPublic(existing);

  if (status === 'resolved') {
    getDb().prepare(`UPDATE enhancement_comments
                     SET status = 'resolved', resolved_at = datetime('now'), resolved_by = ?
                     WHERE id = ?`).run(resolverUserId || null, commentId);
  } else {
    getDb().prepare(`UPDATE enhancement_comments
                     SET status = 'open', resolved_at = NULL, resolved_by = NULL
                     WHERE id = ?`).run(commentId);
  }
  return getComment(enhancementId, commentId);
}

export function deleteComment(enhancementId, commentId) {
  const result = getDb()
    .prepare('DELETE FROM enhancement_comments WHERE id = ? AND enhancement_id = ?')
    .run(commentId, enhancementId);
  return result.changes > 0;
}

/**
 * Build the markdown section the planner / coder appends to its prompt
 * when an enhancement has open comments. Returns '' when nothing's open
 * so callers can blindly concatenate without an extra null check.
 *
 * Format is deliberately simple — agents parse it like any other section.
 */
export function renderOpenCommentsSection(enhancementId) {
  const open = listOpenComments(enhancementId);
  if (!open.length) return '';
  const lines = ['## Open feedback to address',
    '',
    `${open.length} item${open.length === 1 ? '' : 's'} the operator added since the last run. Address each one in your plan / code:`,
    ''];
  for (const c of open) {
    const tag = c.type === 'bug' ? '🐛 BUG' : c.type === 'review' ? '👀 REVIEW' : '📝 NOTE';
    const author = c.author_name ? ` — ${c.author_name}` : '';
    lines.push(`- **${tag}**${author} (${c.created_at}): ${c.body}`);
  }
  return lines.join('\n');
}
