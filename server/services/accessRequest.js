// File an access request for one app as a signed-in person: the same
// enhancement_requests row (kind 'access', message 'Access request for app
// "<name>"') the portal's Request-access button posts to /api/enhancements, so
// it lands in the same queue, mail and MCP approve/deny tools.

import { AppError } from '../utils/errors.js';
import { insertRequest, announceRequest } from './requestCreate.js';

const MAX_NOTE = 1000;

function openRequest(db, userId, slug) {
  return db.prepare(`
    SELECT id FROM enhancement_requests
    WHERE user_id = ? AND app_slug = ? AND kind = 'access' AND status != 'done'
  `).get(userId, slug);
}

export function pendingAccessRequest(db, userId, slug) {
  return openRequest(db, userId, slug)?.id ?? null;
}

/** Returns the new request id; 409 DUPLICATE_ACCESS_REQUEST when one is already open. */
export function fileAccessRequest(db, user, app, note = '') {
  if (note != null && typeof note !== 'string') throw new AppError('note must be a string', 400, 'VALIDATION');
  const text = (note || '').trim();
  if (text.length > MAX_NOTE) throw new AppError(`note must be at most ${MAX_NOTE} characters`, 400, 'VALIDATION');
  const duplicate = () => new AppError('You already have an open access request for this app.', 409, 'DUPLICATE_ACCESS_REQUEST');
  if (openRequest(db, user.id, app.slug)) throw duplicate();
  const message = `Access request for app “${app.name || app.slug}”` + (text ? `:\n${text}` : '');
  let id;
  try {
    id = insertRequest(db, { appSlug: app.slug, userId: user.id, userName: user.name, message, kind: 'access' });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE' && openRequest(db, user.id, app.slug)) throw duplicate();
    throw e;
  }
  announceRequest(db, id, app.slug);
  return id;
}
