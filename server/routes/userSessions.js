import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { auditMiddleware } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { clearSessionCookie } from '../utils/sessionCookie.js';
import { listSessions, publicSession, findSession, revokeSession, revokeAllSessions } from '../services/userSessions.js';

// Mounted at /api/me/sessions: the caller's own sign-in sessions.
//   GET    /api/me/sessions       list (current: true marks the one this request used)
//   DELETE /api/me/sessions/:id   revoke one; revoking the current one signs out
// Every lookup is the caller's own user id plus the handle, so another
// person's handle answers 404 exactly like one that never existed.
export const meSessionsRouter = Router();
meSessionsRouter.use(requireAuth);

const self = (req) => req.real_user || req.user;

meSessionsRouter.get('/', (req, res) => {
  const sessions = listSessions(getDb(), self(req).id, req.auth_credential_hash || null).map(publicSession);
  res.json({ sessions });
});

meSessionsRouter.delete('/:id', auditMiddleware('user-session-revoke'), (req, res) => {
  const db = getDb();
  const row = findSession(db, self(req).id, req.params.id);
  if (!row) throw new AppError('No such session', 404, 'NOT_FOUND');
  const current = row.token_hash === req.auth_credential_hash;
  const revoked = revokeSession(db, self(req).id, row.token_hash);
  if (current) clearSessionCookie(res);
  res.json({ revoked, signed_out: current });
});

// Mounted at /api/users: a platform admin ends someone's sessions.
//   GET    /api/users/:id/sessions
//   DELETE /api/users/:id/sessions/:sid
//   DELETE /api/users/:id/sessions        every session of that user
export const adminUserSessionsRouter = Router();

function targetUser(db, raw) {
  const id = Number(raw);
  const user = Number.isInteger(id) && id > 0 ? db.prepare('SELECT id FROM users WHERE id = ?').get(id) : null;
  if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');
  return user.id;
}

adminUserSessionsRouter.get('/:id/sessions', requireAuth, requirePlatformAdmin, (req, res) => {
  const db = getDb();
  const userId = targetUser(db, req.params.id);
  res.json({ sessions: listSessions(db, userId, req.auth_credential_hash || null).map(publicSession) });
});

adminUserSessionsRouter.delete('/:id/sessions/:sid', requireAuth, requirePlatformAdmin, auditMiddleware('admin-user-session-revoke'), (req, res) => {
  const db = getDb();
  const userId = targetUser(db, req.params.id);
  const row = findSession(db, userId, req.params.sid);
  if (!row) throw new AppError('No such session', 404, 'NOT_FOUND');
  res.json({ revoked: revokeSession(db, userId, row.token_hash) });
});

adminUserSessionsRouter.delete('/:id/sessions', requireAuth, requirePlatformAdmin, auditMiddleware('admin-user-sessions-revoke-all'), (req, res) => {
  const db = getDb();
  const userId = targetUser(db, req.params.id);
  res.json({ revoked: revokeAllSessions(db, userId) });
});
