import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { hashApiKey, verifyPassword } from '../services/encryption.js';
import { guardPasswordAttempt, onPasswordFailure } from '../services/signinRisk/index.js';
import { issuerOf, isLoopbackRedirect, resolveScope, scopeFor, SCOPE_READ, CONSENT_FRESH_MINUTES } from '../services/oauthPolicy.js';
import {
  getAuthRequest, takeAuthRequest, createCode, listGrantsForUser, revokeGrantForUser, getClient,
} from '../services/oauthStore.js';
import { clientRefusal } from '../services/oauthClientPolicy.js';
import { consentScope } from '../services/oauthScopeSummary.js';
import { listBlueprints, getBlueprint } from '../services/mcpBlueprints.js';
import { cimdConsentView } from '../services/oauthCimd.js';
import adminRouter from './oauthAdmin.js';

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

// Approving a client turns whoever holds this browser session into a
// long-lived credential, so it takes a FRESH sign-in: a dashboard session
// younger than CONSENT_FRESH_MINUTES, or the account password typed on the
// consent screen. An API key can never approve: it is the credential most
// likely to have leaked into a log or a CI run. A view-as session is refused
// too (it acts as someone else's role).
function freshness(req) {
  if (req.headers['x-api-key']) return { fresh: false, why: 'api_key' };
  if (req.view_as) return { fresh: false, why: 'view_as' };
  const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const row = bearer && getDb().prepare(`
    SELECT created_at >= datetime('now', '-' || ? || ' minutes') AS fresh FROM identity_sessions WHERE token_hash = ? AND scope = 'platform'
  `).get(CONSENT_FRESH_MINUTES, hashApiKey(bearer));
  return row?.fresh ? { fresh: true } : { fresh: false, why: 'stale_session' };
}

const REAUTH_MAX_FAILURES = 5;
const REAUTH_WINDOW_MS = 15 * 60_000;
const reauthFailures = new Map();
function reauthBlocked(userId, now = Date.now()) {
  const rec = reauthFailures.get(userId);
  return !!rec && now < rec.resetAt && rec.count >= REAUTH_MAX_FAILURES;
}
function recordReauthFailure(userId, now = Date.now()) {
  const rec = reauthFailures.get(userId);
  if (!rec || now >= rec.resetAt) reauthFailures.set(userId, { count: 1, resetAt: now + REAUTH_WINDOW_MS });
  else rec.count++;
}

function hasPassword(userId) {
  return !!getDb().prepare('SELECT password_hash FROM users WHERE id = ?').get(userId)?.password_hash;
}

router.get('/authorize-requests/:id', (req, res) => {
  const r = getAuthRequest(req.params.id);
  if (!r) throw new AppError('This connection request expired or was already answered. Start again from the app.', 404, 'NOT_FOUND');
  const f = freshness(req);
  const resolved = resolveScope(r.scope);
  res.json({
    client_name: r.client_name,
    client_verified: !!r.client_approved_at,
    client_id_document: r.is_cimd ? cimdConsentView(r) : null,
    requested_scopes: resolved.scoped ? r.scope.split(' ') : null,
    blueprints: listBlueprints().map(({ id, name, description, scopes, apps }) => ({ id, name, description, scopes, apps })),
    client_blueprint: r.client_blueprint_id == null ? null : (getBlueprint(r.client_blueprint_id)?.name ?? 'deleted'),
    redirect_uri: r.redirect_uri,
    redirect_host: hostOf(r.redirect_uri),
    loopback: isLoopbackRedirect(r.redirect_uri),
    scope: r.scope,
    read_only_requested: r.scope === SCOPE_READ,
    expires_at: r.expires_at,
    access: consentScope((req.real_user || req.user).id),
    reauth: { required: !f.fresh, reason: f.why || null, has_password: hasPassword((req.real_user || req.user).id), fresh_minutes: CONSENT_FRESH_MINUTES },
  });
});

router.post('/authorize-requests/:id', (req, res) => {
  const { decision, read_only, blueprint_id } = req.body || {};
  if (decision !== 'approve' && decision !== 'deny') throw new AppError("decision must be 'approve' or 'deny'", 400, 'VALIDATION');
  if (read_only != null && typeof read_only !== 'boolean') throw new AppError('read_only must be a boolean', 400, 'VALIDATION');
  if (blueprint_id != null && (!Number.isInteger(blueprint_id) || !getBlueprint(blueprint_id))) throw new AppError('blueprint_id must be the id of an existing blueprint', 400, 'VALIDATION');
  if (decision === 'approve') {
    const f = freshness(req);
    if (f.why === 'api_key') throw new AppError('An API key cannot approve an MCP connection. Sign in to the dashboard and approve it there.', 403, 'REAUTH_REQUIRED');
    if (f.why === 'view_as') throw new AppError('Stop viewing as another role before approving an MCP connection.', 403, 'REAUTH_REQUIRED');
    if (!f.fresh) {
      const { password } = req.body || {};
      if (typeof password !== 'string' || !password) {
        throw new AppError(`Confirm it is you: enter your password, or sign in again (approval needs a sign-in from the last ${CONSENT_FRESH_MINUTES} minutes).`, 403, 'REAUTH_REQUIRED');
      }
      if (reauthBlocked(req.user.id)) throw new AppError('Too many wrong passwords. Sign in again, or try again in 15 minutes.', 429, 'RATE_LIMITED');
      const risk = guardPasswordAttempt(getDb(), req, res, { user: req.user, login: null, ip: req.ip });
      const row = getDb().prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
      if (!row?.password_hash || !verifyPassword(password, row.password_hash)) {
        recordReauthFailure(req.user.id);
        onPasswordFailure(getDb(), risk, { user: req.user, login: null, ip: req.ip, method: 'oauth-consent' });
        try { logAudit(req.user.id, null, 'oauth-consent-reauth-failed', {}); } catch (_) {}
        throw new AppError('That password is not correct.', 403, 'REAUTH_FAILED');
      }
      reauthFailures.delete(req.user.id);
    }
  }
  const r = takeAuthRequest(req.params.id);
  if (!r) throw new AppError('This connection request expired or was already answered. Start again from the app.', 404, 'NOT_FOUND');
  const client = getClient(r.client_id);
  const refusal = decision === 'approve' && client ? clientRefusal(client, r.redirect_uri) : null;
  if (refusal) throw new AppError(refusal, 403, 'CLIENT_NOT_ALLOWED');
  const back = new URL(r.redirect_uri);
  if (r.state != null) back.searchParams.set('state', r.state);
  back.searchParams.set('iss', issuerOf(req));
  if (decision === 'deny') {
    back.searchParams.set('error', 'access_denied');
    back.searchParams.set('error_description', 'The user denied the request');
    return res.json({ redirect_to: back.toString() });
  }
  const resolved = resolveScope(r.scope);
  const readOnly = resolved.readOnly || read_only === true;
  const scope = resolved.scoped ? r.scope : scopeFor(readOnly);
  // A blueprint a platform admin pinned to the client wins over the user's pick.
  const blueprintId = client?.blueprint_id ?? blueprint_id ?? null;
  const code = createCode({
    clientId: r.client_id, userId: req.user.id, redirectUri: r.redirect_uri,
    codeChallenge: r.code_challenge, scope, resource: r.resource, readOnly, blueprintId,
  });
  try {
    logAudit(req.user.id, null, 'oauth-client-authorized', {
      client_name: r.client_name, client_id: r.client_id, redirect_host: hostOf(r.redirect_uri), scope, blueprint_id: blueprintId,
    });
  } catch (_) { /* best effort, as auditMiddleware */ }
  back.searchParams.set('code', code);
  res.json({ redirect_to: back.toString() });
});

router.get('/blueprints', (req, res) => {
  res.json({ blueprints: listBlueprints().map(({ id, name, description, scopes, apps }) => ({ id, name, description, scopes, apps })) });
});

router.get('/connections', (req, res) => {
  res.json({ connections: listGrantsForUser(req.user.id) });
});

router.use('/admin', adminRouter);

router.delete('/connections/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id) || id <= 0) throw new AppError('Invalid connection id', 400, 'VALIDATION');
  const revoked = revokeGrantForUser(req.user.id, id);
  if (!revoked) throw new AppError('Connection not found', 404, 'NOT_FOUND');
  try { logAudit(req.user.id, null, 'oauth-grant-revoked', { grant_id: id }); } catch (_) {}
  res.json({ message: 'Connection revoked', id });
});

export default router;
