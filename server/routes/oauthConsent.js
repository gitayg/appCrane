import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { issuerOf, isLoopbackRedirect, resolveScope, scopeFor, SCOPE_READ } from '../services/oauthPolicy.js';
import {
  getAuthRequest, takeAuthRequest, createCode, listGrantsForUser, revokeGrantForUser,
} from '../services/oauthStore.js';

// The signed-in half of MCP OAuth: the consent screen's data and decision
// (/mcp/authorize in the SPA), and the user's list of connected OAuth clients.
// Session or user-API-key callers only: an MCP key or OAuth token can never
// approve a client or manage connections.
const router = Router();
router.use(requireAuth, (req, res, next) => {
  if (req.user_mcp_key) return next(new AppError('Manage MCP connections from the dashboard, not via an MCP credential', 403, 'KEY_FORBIDDEN'));
  next();
});

function hostOf(uri) {
  try { return new URL(uri).host; } catch (_) { return null; }
}

router.get('/authorize-requests/:id', (req, res) => {
  const r = getAuthRequest(req.params.id);
  if (!r) throw new AppError('This connection request expired or was already answered. Start again from the app.', 404, 'NOT_FOUND');
  res.json({
    client_name: r.client_name,
    redirect_uri: r.redirect_uri,
    redirect_host: hostOf(r.redirect_uri),
    loopback: isLoopbackRedirect(r.redirect_uri),
    scope: r.scope,
    read_only_requested: r.scope === SCOPE_READ,
    expires_at: r.expires_at,
  });
});

router.post('/authorize-requests/:id', (req, res) => {
  const { decision, read_only } = req.body || {};
  if (decision !== 'approve' && decision !== 'deny') throw new AppError("decision must be 'approve' or 'deny'", 400, 'VALIDATION');
  if (read_only != null && typeof read_only !== 'boolean') throw new AppError('read_only must be a boolean', 400, 'VALIDATION');
  const r = takeAuthRequest(req.params.id);
  if (!r) throw new AppError('This connection request expired or was already answered. Start again from the app.', 404, 'NOT_FOUND');
  const back = new URL(r.redirect_uri);
  if (r.state != null) back.searchParams.set('state', r.state);
  back.searchParams.set('iss', issuerOf(req));
  if (decision === 'deny') {
    back.searchParams.set('error', 'access_denied');
    back.searchParams.set('error_description', 'The user denied the request');
    return res.json({ redirect_to: back.toString() });
  }
  const readOnly = resolveScope(r.scope).readOnly || read_only === true;
  const code = createCode({
    clientId: r.client_id, userId: req.user.id, redirectUri: r.redirect_uri,
    codeChallenge: r.code_challenge, scope: scopeFor(readOnly), resource: r.resource, readOnly,
  });
  try {
    logAudit(req.user.id, null, 'oauth-client-authorized', {
      client_name: r.client_name, client_id: r.client_id, redirect_host: hostOf(r.redirect_uri), scope: scopeFor(readOnly),
    });
  } catch (_) { /* best effort, as auditMiddleware */ }
  back.searchParams.set('code', code);
  res.json({ redirect_to: back.toString() });
});

router.get('/connections', (req, res) => {
  res.json({ connections: listGrantsForUser(req.user.id) });
});

router.delete('/connections/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id) || id <= 0) throw new AppError('Invalid connection id', 400, 'VALIDATION');
  const revoked = revokeGrantForUser(req.user.id, id);
  if (!revoked) throw new AppError('Connection not found', 404, 'NOT_FOUND');
  try { logAudit(req.user.id, null, 'oauth-grant-revoked', { grant_id: id }); } catch (_) {}
  res.json({ message: 'Connection revoked', id });
});

export default router;
