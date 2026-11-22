import { Router } from 'express';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { hashApiKey, verifyPassword } from '../services/encryption.js';
import { verifyCode } from '../services/mfa.js';
import { parseUtc } from '../services/sessionPolicy.js';
import { isAppOwnerOrPlatformAdmin } from '../services/permissions.js';
import { readSessionCookie } from '../utils/sessionCookie.js';
import { safeRedirectTarget } from '../utils/safeRedirect.js';
import { sendPopupFailed } from '../utils/ssoPopup.js';
import {
  ACTIONS, WINDOW_BOUNDS, WINDOW_DEFAULT, browserHoldsRequestSession, clearPasswordFailures, consumeRequest, createGrant, createRequest, isFresh,
  listGrants, liveRequest, methodsFor, notePasswordFailure, passwordLimited, recordStepUp, requireStepUp, revokeGrant,
  sessionAuth, setWindowMinutes, validateAppReturn, windowMinutes,
} from '../services/stepUp.js';

// Mounted at /api/identity/step-up. See services/stepUp.js for the model.
// Wrong codes and passwords answer 400, never 401, so the SPA's expired-session
// handler does not sign the person out over a typo.

const router = Router();
const ipOf = (req) => req.ip || req.socket?.remoteAddress || 'unknown';

// Only a dashboard session steps up: a key cannot re-authenticate.
function requireSessionCaller(req, res, next) {
  if (req.auth_kind !== 'session') {
    return next(new AppError('Step-up needs a dashboard sign-in; an API key, MCP key or OAuth token cannot step up', 403, 'STEP_UP_SESSION_ONLY'));
  }
  next();
}

const realUserId = (req) => (req.real_user || req.user).id;

function statusBody(db, req) {
  const a = sessionAuth(db, req.auth_credential_hash);
  const minutes = windowMinutes(db);
  const authTime = a && Number.isFinite(a.authTimeMs) ? a.authTimeMs : null;
  return {
    fresh: isFresh(db, req.auth_credential_hash),
    auth_time: authTime ? Math.floor(authTime / 1000) : null,
    fresh_until: authTime ? Math.floor((authTime + minutes * 60_000) / 1000) : null,
    mfa: a?.mfa || null,
    window_minutes: minutes,
    methods: methodsFor(db, realUserId(req)),
  };
}

function done(db, req, res, method, mfa) {
  recordStepUp(db, req.auth_credential_hash, method, mfa);
  logAudit(realUserId(req), null, 'step-up', { method, ip: ipOf(req) });
  res.json({ ok: true, ...statusBody(db, req) });
}

function assertMethod(db, req, method) {
  if (!methodsFor(db, realUserId(req)).includes(method)) {
    throw new AppError(`Step-up with ${method} is not available for your account`, 400, 'STEP_UP_METHOD_UNAVAILABLE');
  }
}

router.get('/', requireAuth, requireSessionCaller, (req, res) => {
  res.json(statusBody(getDb(), req));
});

router.post('/totp', requireAuth, requireSessionCaller, (req, res) => {
  const db = getDb();
  assertMethod(db, req, 'totp');
  const code = req.body?.code;
  if (!code || typeof code !== 'string') throw new AppError('code is required', 400, 'VALIDATION');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(realUserId(req));
  const r = verifyCode(db, user, code, { ip: ipOf(req) });
  if (!r.ok) {
    if (r.reason === 'rate_limited') throw new AppError(`Too many wrong codes. Try again in ${Math.ceil(r.retry_after_s / 60)} minute(s).`, 429, 'RATE_LIMITED');
    if (r.reason === 'replayed') throw new AppError('That code was already used. Wait for the next one.', 400, 'CODE_REPLAYED');
    throw new AppError('That code is not valid.', 400, 'INVALID_CODE');
  }
  done(db, req, res, r.method, r.method);
});

router.post('/password', requireAuth, requireSessionCaller, (req, res) => {
  const db = getDb();
  assertMethod(db, req, 'password');
  const userId = realUserId(req);
  const wait = passwordLimited(userId);
  if (wait) throw new AppError(`Too many wrong passwords. Try again in ${Math.ceil(wait / 60)} minute(s).`, 429, 'RATE_LIMITED');
  const password = req.body?.password;
  const user = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(userId);
  if (typeof password !== 'string' || !password || !verifyPassword(password, user.password_hash)) {
    notePasswordFailure(userId);
    logAudit(userId, null, 'step-up-refused', { method: 'password', reason: 'bad_password', ip: ipOf(req) });
    throw new AppError('That password is not correct.', 400, 'INVALID_PASSWORD');
  }
  clearPasswordFailures(userId);
  done(db, req, res, 'password', null);
});

// IdP re-login. The SPA opens `url` in a popup; the callback answers with the
// SSO popup completion page (BroadcastChannel 'appcrane-sso', 'signed-in').
router.post('/sso', requireAuth, requireSessionCaller, (req, res) => {
  const db = getDb();
  const [method] = methodsFor(db, realUserId(req));
  if (method !== 'oidc' && method !== 'saml') throw new AppError('Your account does not step up through an identity provider', 400, 'STEP_UP_METHOD_UNAVAILABLE');
  const handle = createRequest(db, { kind: method, userId: realUserId(req), sessionHash: req.auth_credential_hash });
  res.json({ method, url: `/api/identity/step-up/sso/go?${new URLSearchParams({ h: handle })}` });
});

router.get('/sso/go', async (req, res) => {
  const db = getDb();
  const handle = new URL(req.originalUrl, 'http://x').searchParams.get('h');
  const request = liveRequest(db, handle, ['oidc', 'saml']);
  if (!request || request.idp_request_id) return sendPopupFailed(res, 'step_up_expired');
  if (!browserHoldsRequestSession(readSessionCookie(req), request)) return sendPopupFailed(res, 'step_up_wrong_browser');
  try {
    if (request.kind === 'oidc') return await (await import('./oidc.js')).startOidcStepUp(req, res, handle);
    return await (await import('./saml.js')).startSamlStepUp(req, res, request);
  } catch (_) {
    return sendPopupFailed(res, 'unavailable');
  }
});

// ── hosted apps ─────────────────────────────────────────────────────────────
// GET /api/identity/step-up/app?app=<slug>&return=<url on that app's host>
// A top-level navigation from the app. The return URL must be on the app's own
// host (or, without per-app origins, under its mount here); the step-up happens
// on /step-up in the dashboard, which then sends the person back.

router.get('/app', (req, res) => {
  const db = getDb();
  const q = new URL(req.originalUrl, 'http://x').searchParams;
  const target = validateAppReturn(db, q.get('app'), q.get('return'));
  if (!target) throw new AppError('return must be a URL on this app\'s own host', 400, 'INVALID_RETURN_URL');
  const token = readSessionCookie(req);
  const session = token && db.prepare(`SELECT s.user_id FROM identity_sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.scope = 'platform' AND datetime(s.expires_at) > datetime('now') AND u.active = 1`).get(hashApiKey(token));
  if (!session) {
    const self = safeRedirectTarget(`/api/identity/step-up/app?${q}`, '');
    return res.redirect(302, `/login${self ? `?${new URLSearchParams({ redirect: self })}` : ''}`);
  }
  const handle = createRequest(db, {
    kind: 'app_return', userId: session.user_id, sessionHash: hashApiKey(token), appId: target.app.id, appEnv: target.env, returnUrl: target.url,
  });
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.redirect(302, `/step-up?${new URLSearchParams({ h: handle })}`);
});

// What the /step-up page shows for a handle, without consuming it.
router.post('/app/describe', requireAuth, requireSessionCaller, (req, res) => {
  const db = getDb();
  const request = liveRequest(db, req.body?.h, ['app_return']);
  if (!request || request.user_id !== realUserId(req)) throw new AppError('This confirmation link expired. Go back to the app and try again.', 404, 'STEP_UP_REQUEST_INVALID');
  const app = db.prepare('SELECT slug, name FROM apps WHERE id = ?').get(request.app_id);
  res.json({ app: app?.slug, name: app?.name, env: request.app_env, return_url: request.return_url });
});

// The person stepped up after the app asked: hand back the validated return URL.
router.post('/app/complete', requireAuth, requireSessionCaller, (req, res) => {
  const db = getDb();
  const request = liveRequest(db, req.body?.h, ['app_return']);
  if (!request || request.user_id !== realUserId(req)) throw new AppError('This confirmation link expired. Go back to the app and try again.', 404, 'STEP_UP_REQUEST_INVALID');
  const a = sessionAuth(db, req.auth_credential_hash);
  if (!a || !(a.authTimeMs >= parseUtc(request.started_at))) {
    const err = new AppError('Confirm it\'s you to go back to the app.', 401, 'STEP_UP_REQUIRED');
    err.publicDetails = { step_up: { action: 'app_return', mode: 'reauth', methods: methodsFor(db, realUserId(req)), window_minutes: windowMinutes(db), endpoint: '/api/identity/step-up' } };
    throw err;
  }
  if (!consumeRequest(db, request.id)) throw new AppError('This confirmation link was already used.', 404, 'STEP_UP_REQUEST_INVALID');
  logAudit(realUserId(req), request.app_id, 'step-up-app-return', { env: request.app_env });
  res.json({ return_url: request.return_url });
});

// ── grants for keys and agents ──────────────────────────────────────────────

router.get('/grants', requireAuth, requireSessionCaller, (req, res) => {
  res.json({ grants: listGrants(getDb(), realUserId(req)), window_minutes: windowMinutes(getDb()) });
});

function grantAction(req, res, next) {
  const action = req.body?.action;
  const def = typeof action === 'string' && Object.hasOwn(ACTIONS, action) ? ACTIONS[action] : null;
  if (!def || def.keys !== 'grant') return next(new AppError('action is not one an API key or agent needs a grant for', 400, 'VALIDATION'));
  req.step_up_action = action;
  next();
}

// The grant is itself a dangerous act: it needs a fresh step-up of its own.
router.post('/grants', requireAuth, requireSessionCaller, grantAction, (req, res, next) => requireStepUp(req.step_up_action)(req, res, next), (req, res) => {
  const db = getDb();
  const def = ACTIONS[req.step_up_action];
  let app = null;
  if (def.perApp) {
    const slug = req.body?.slug;
    app = typeof slug === 'string' ? db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug) : null;
    if (!app) throw new AppError('slug names no app', 404, 'NOT_FOUND');
    if (!isAppOwnerOrPlatformAdmin(req.user, app)) throw new AppError('Only the app owner or a platform admin can grant this', 403, 'FORBIDDEN');
  } else if ((req.real_user || req.user).role !== 'platform_admin') {
    throw new AppError('Only a platform admin can grant this', 403, 'FORBIDDEN');
  }
  const g = createGrant(db, realUserId(req), req.step_up_action, app?.id ?? null);
  logAudit(realUserId(req), app?.id ?? null, 'step-up-grant', { action: req.step_up_action, expires_at: g.expires_at, ip: ipOf(req) });
  res.json({ ...g, app: app?.slug ?? null });
});

router.delete('/grants/:id', requireAuth, requireSessionCaller, (req, res) => {
  if (!revokeGrant(getDb(), realUserId(req), req.params.id)) throw new AppError('Grant not found', 404, 'NOT_FOUND');
  res.json({ ok: true });
});

// ── platform policy ─────────────────────────────────────────────────────────

router.get('/policy', requireAuth, requirePlatformAdmin, (req, res) => {
  res.json({ window_minutes: windowMinutes(getDb()), default: WINDOW_DEFAULT, bounds: WINDOW_BOUNDS, actions: ACTIONS });
});

router.put('/policy', requireAuth, requirePlatformAdmin, requireStepUp('security_settings'), (req, res) => {
  const db = getDb();
  const before = windowMinutes(db);
  const after = setWindowMinutes(db, req.body?.window_minutes, req.user.id);
  logAudit(req.user.id, null, 'platform-policy-change', { policy: 'step-up', before: { window_minutes: before }, after: { window_minutes: after } });
  res.json({ window_minutes: after, default: WINDOW_DEFAULT, bounds: WINDOW_BOUNDS, actions: ACTIONS });
});

export default router;
