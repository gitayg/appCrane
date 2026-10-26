import { Router } from 'express';
import { getDb } from '../db.js';
import { requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import {
  listAllGrants, revokeGrantAsAdmin, revokeAllGrantsForUser, listClients, setClientApproval, grantLifetimeDays,
} from '../services/oauthStore.js';
import { getDcrPolicy, updateDcrPolicy } from '../services/oauthClientPolicy.js';

// Platform admin side of MCP OAuth, mounted at /api/oauth/admin by
// oauthConsent.js (so behind its requireAuth and its refusal of MCP
// credentials): every user's connections with revoke, the registered clients
// with approve, and the registration policy.
const router = Router();
router.use(requirePlatformAdmin);

const audit = (req, action, detail) => { try { logAudit(req.user.id, null, action, detail); } catch (_) {} };
const intParam = (v, what) => {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n) || n <= 0 || String(n) !== String(v)) throw new AppError(`Invalid ${what}`, 400, 'VALIDATION');
  return n;
};

router.get('/grants', (req, res) => {
  const userId = req.query.user_id === undefined ? null : intParam(req.query.user_id, 'user_id');
  res.json({ grants: listAllGrants({ userId }), lifetime_days: grantLifetimeDays() });
});

router.delete('/grants/:id', (req, res) => {
  const id = intParam(req.params.id, 'connection id');
  const row = revokeGrantAsAdmin(id);
  if (!row) throw new AppError('Connection not found', 404, 'NOT_FOUND');
  audit(req, 'oauth-grant-revoked-by-admin', { grant_id: id, user_id: row.user_id });
  res.json({ message: 'Connection revoked', id });
});

router.post('/users/:id/revoke-all', (req, res) => {
  const userId = intParam(req.params.id, 'user id');
  if (!getDb().prepare('SELECT 1 FROM users WHERE id = ?').get(userId)) throw new AppError('User not found', 404, 'NOT_FOUND');
  const revoked = revokeAllGrantsForUser(userId);
  audit(req, 'oauth-grants-revoked-by-admin', { user_id: userId, revoked });
  res.json({ revoked });
});

router.get('/clients', (req, res) => {
  res.json({ clients: listClients() });
});

router.post('/clients/:clientId/approval', (req, res) => {
  const { approved } = req.body || {};
  if (typeof approved !== 'boolean') throw new AppError('approved must be a boolean', 400, 'VALIDATION');
  if (!setClientApproval(String(req.params.clientId), req.user.id, approved)) throw new AppError('Client not found', 404, 'NOT_FOUND');
  audit(req, approved ? 'oauth-client-approved' : 'oauth-client-unapproved', { client_id: String(req.params.clientId) });
  res.json({ client_id: String(req.params.clientId), approved });
});

router.get('/policy', (req, res) => {
  res.json(getDcrPolicy());
});

router.put('/policy', (req, res) => {
  try {
    const out = updateDcrPolicy(getDb(), req.body || {}, req.user.id);
    audit(req, 'oauth-dcr-policy-update', { mode: out.mode, redirect_hosts: out.redirect_hosts });
    res.json(out);
  } catch (e) {
    if (e.status === 400) throw new AppError(e.message, 400, 'VALIDATION');
    throw e;
  }
});

export default router;
