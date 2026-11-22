import { Router } from 'express';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { readCookie } from '../utils/sessionCookie.js';
import { logAudit } from '../middleware/audit.js';
import { APP_SESSION_COOKIE } from '../services/appOrigin.js';
import { craneDomain, resolveAppHost } from './appHandoff.js';
import { resolveAppRole, accessRequestUrl } from './identity.js';
import { appSessionFor, issueWidgetToken, resolveWidgetToken, WIDGET_SCOPES } from '../services/widgetTokens.js';
import { listSessions, publicSession, findSession, revokeSession } from '../services/userSessions.js';
import { canManageAppRoles, setAppRole, SETTABLE_APP_ROLES } from '../services/appRoleChange.js';
import { fileAccessRequest, pendingAccessRequest } from '../services/accessRequest.js';
import { listKeys, issueKey, revokeKey } from '../services/userAppKeys.js';
import { scopeEnabled } from '../services/widgetScopeOptIn.js';
import { createOAuthLimiter } from '../services/oauthRateLimit.js';
import { hashApiKey } from '../services/encryption.js';
import { stepUpRefusal } from '../services/stepUp.js';

// Drop-in widgets on an app's own host (per-app origins, services/appOrigin.js).
// Caddy sends /__appcrane/* on an app host to AppCrane with the Host header
// unchanged, so everything here knows which app and environment is asking
// from the Host alone, and answers 404 on any other host.
//
//   GET    /__appcrane/widgets.js               the script, latest (revalidated)
//   GET    /__appcrane/widgets/<hash>.js        the same bytes at a content address (immutable, for SRI)
//   GET    /__appcrane/widgets/manifest.json    { version, src, integrity }
//   POST   /__appcrane/widgets/token            app-session cookie -> widget token (services/widgetTokens.js)
//   *      /__appcrane/widgets/api/*            widget token only (Authorization: Bearer cwt_...)
//
// The page's script never sees the app-session cookie (httpOnly) or anything
// from the platform host: only a token for this app, this environment and
// these endpoints, for an hour at most.
export const widgetsRouter = Router();

const SCRIPT = readFileSync(new URL('../assets/widgets.js', import.meta.url), 'utf8');
const SCRIPT_HASH = crypto.createHash('sha256').update(SCRIPT).digest('hex').slice(0, 16);
const SCRIPT_INTEGRITY = `sha384-${crypto.createHash('sha384').update(SCRIPT).digest('base64')}`;
const VERSION = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version;
const WIDGET_KEY_MAX_DAYS = 90;

function siteOf(req) {
  const site = resolveAppHost(getDb(), req.headers.host);
  if (!site) throw new AppError('Not found', 404, 'NOT_FOUND');
  return site;
}

function platformUrl() {
  const domain = craneDomain();
  return /^[a-z0-9.-]+$/.test(domain) ? `https://${domain}` : null;
}

function sendScript(res, cache) {
  res.setHeader('Cache-Control', cache);
  res.setHeader('ETag', `"${SCRIPT_HASH}"`);
  res.type('application/javascript; charset=utf-8').send(SCRIPT);
}

widgetsRouter.get('/widgets.js', (req, res) => {
  siteOf(req);
  if (req.headers['if-none-match'] === `"${SCRIPT_HASH}"`) return res.status(304).end();
  sendScript(res, 'no-cache');
});

widgetsRouter.get('/widgets/manifest.json', (req, res) => {
  const site = siteOf(req);
  res.setHeader('Cache-Control', 'no-cache');
  // request_access: the platform's access-request page for this app, for a
  // visitor who cannot sign in here because they have no role on it. Names the
  // slug only, which the host already shows; never the app's name.
  res.json({ version: VERSION, src: `/__appcrane/widgets/${SCRIPT_HASH}.js`, integrity: SCRIPT_INTEGRITY, request_access: accessRequestUrl(site.app.slug) });
});

widgetsRouter.get('/widgets/:file', (req, res) => {
  siteOf(req);
  if (req.params.file !== `${SCRIPT_HASH}.js`) throw new AppError('Not found', 404, 'NOT_FOUND');
  sendScript(res, 'public, max-age=31536000, immutable');
});

// A page needs one token an hour per tab; these leave room for many tabs and
// reloads while bounding rows written and lookups made. Per address first,
// then per app-session cookie (keyed by its hash; no cookie, no bucket).
export const WIDGET_TOKEN_LIMITS = Object.freeze({ perIp: { max: 120, windowMs: 60_000 }, perSession: { max: 20, windowMs: 60_000 } });
const tooMany = (res) => res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many widget token requests; try again shortly' } });
const tokenPerIp = createOAuthLimiter('widget-token-ip', WIDGET_TOKEN_LIMITS.perIp, { refuse: tooMany });
const tokenPerSession = createOAuthLimiter('widget-token-session', WIDGET_TOKEN_LIMITS.perSession, {
  refuse: tooMany,
  key: (req) => {
    const c = readCookie(req, APP_SESSION_COOKIE);
    return c ? `s:${hashApiKey(c)}` : null;
  },
});

// Only this host's own pages may ask: the custom header makes any
// cross-origin attempt a CORS preflight that nothing here answers, and the
// fetch metadata, when the browser sends it, has to say same-origin.
widgetsRouter.post('/widgets/token', tokenPerIp, tokenPerSession, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const site = siteOf(req);
  if (req.headers['x-appcrane-widget'] !== '1') throw new AppError('X-AppCrane-Widget: 1 required', 400, 'WIDGET_HEADER');
  const fetchSite = req.headers['sec-fetch-site'];
  if (fetchSite && fetchSite !== 'same-origin') throw new AppError('Cross-site request refused', 403, 'CSRF_REFUSED');
  if (req.headers.origin && req.headers.origin !== `https://${site.host}`) throw new AppError('Cross-site request refused', 403, 'CSRF_REFUSED');

  const db = getDb();
  const session = appSessionFor(db, site, readCookie(req, APP_SESSION_COOKIE));
  if (!session) throw new AppError('Not signed in to this app', 401, 'SIGNED_OUT');
  const requested = req.body?.scopes;
  if (requested != null && (!Array.isArray(requested) || requested.some((s) => !WIDGET_SCOPES.includes(s)))) {
    throw new AppError(`scopes must be a list of: ${WIDGET_SCOPES.join(', ')}`, 400, 'VALIDATION');
  }
  res.json(issueWidgetToken(db, site, session, requested ?? null));
});

function widgetAuth(scope) {
  return (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    const site = siteOf(req);
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    const caller = resolveWidgetToken(getDb(), site, bearer);
    if (!caller) throw new AppError('Widget token missing, expired or not for this app', 401, 'WIDGET_TOKEN_INVALID');
    if (!caller.scopes.includes(scope)) throw new AppError(`This widget token does not carry the '${scope}' scope`, 403, 'WIDGET_SCOPE');
    if (!scopeEnabled(getDb(), site.app.id, scope)) throw new AppError(`The '${scope}' widget is not turned on for this app`, 403, 'WIDGET_SCOPE_OFF');
    req.widget = { site, ...caller };
    next();
  };
}

const roleOf = (db, w) => resolveAppRole(db, { user_id: w.user.id, crane_role: w.user.role }, w.site.app);

widgetsRouter.get('/widgets/api/me', widgetAuth('me'), (req, res) => {
  const db = getDb();
  const { user, site } = req.widget;
  const platform = platformUrl();
  res.json({
    user: { id: user.id, name: user.name, email: user.email, username: user.username, avatar_url: user.avatar_url || null },
    app: { slug: site.app.slug, name: site.app.name || site.app.slug, env: site.env },
    app_role: roleOf(db, req.widget),
    can_manage_members: canManageAppRoles(user, site.app),
    access_requested: pendingAccessRequest(db, user.id, site.app.slug) !== null,
    scopes: req.widget.scopes,
    platform_url: platform,
    links: {
      sign_out: '/__appcrane/logout',
      account: platform ? `${platform}/settings#account` : null,
      request_access: platform ? `${platform}/launch` : null,
    },
  });
});

// Only this app's sessions are listed; the visitor's platform sign-ins and
// other apps are a count, so a page on this app learns nothing about them.
widgetsRouter.get('/widgets/api/sessions', widgetAuth('sessions'), (req, res) => {
  const { user, site, parentHash } = req.widget;
  const all = listSessions(getDb(), user.id, parentHash);
  const here = all.filter((s) => s.scope === 'app' && s._app_id === site.app.id);
  const sessions = here.map((s) => ({ ...publicSession(s), parent_id: undefined, revocable_here: true }));
  res.json({ sessions, other_sessions: all.length - here.length });
});

// Only this app's sessions: a page on an app host must not be able to sign its
// visitor out of AppCrane or out of another app. Those are revoked from the
// platform (GET/DELETE /api/me/sessions).
widgetsRouter.delete('/widgets/api/sessions/:id', widgetAuth('sessions'), (req, res) => {
  const db = getDb();
  const { user, site, parentHash } = req.widget;
  const row = findSession(db, user.id, req.params.id);
  if (!row) throw new AppError('No such session', 404, 'NOT_FOUND');
  if (row.scope !== 'app' || row.app_id !== site.app.id) {
    throw new AppError('Revoke this session from AppCrane itself', 403, 'NOT_REVOCABLE_HERE');
  }
  const current = row.token_hash === parentHash;
  const revoked = revokeSession(db, user.id, row.token_hash);
  logAudit(user.id, site.app.id, 'user-session-revoke', { via: 'widget', env: site.env, current });
  if (current) res.clearCookie(APP_SESSION_COOKIE, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  res.json({ revoked, signed_out: current });
});

function requireManager(req) {
  const { user, site } = req.widget;
  if (!canManageAppRoles(user, site.app)) throw new AppError('Only the app owner can manage users on this app.', 403, 'FORBIDDEN');
}

widgetsRouter.get('/widgets/api/members', widgetAuth('members'), (req, res) => {
  requireManager(req);
  const { user, site } = req.widget;
  const members = getDb().prepare(`
    SELECT u.id, u.name, u.email, u.avatar_url, u.active, r.app_role
    FROM app_user_roles r JOIN users u ON u.id = r.user_id
    WHERE r.app_id = ? AND r.app_role != 'none'
    ORDER BY CASE r.app_role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.name
  `).all(site.app.id).map((m) => ({ ...m, active: !!m.active, you: m.id === user.id }));
  res.json({ app: site.app.slug, roles: SETTABLE_APP_ROLES, members });
});

widgetsRouter.put('/widgets/api/members/:userId', widgetAuth('members'), async (req, res) => {
  const { user, site } = req.widget;
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId) || userId <= 0) throw new AppError('Invalid user id', 400, 'VALIDATION');
  const appRole = req.body?.app_role;
  await setAppRole(getDb(), user, site.app, userId, appRole);
  logAudit(user.id, site.app.id, 'app-set-role', { via: 'widget', user_id: userId, app_role: appRole });
  res.json({ user_id: userId, app_role: appRole });
});

// Invite: give an existing AppCrane user a role here. Creating accounts stays
// with platform admins.
widgetsRouter.post('/widgets/api/members', widgetAuth('members'), async (req, res) => {
  requireManager(req);
  const db = getDb();
  const { user, site } = req.widget;
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const appRole = req.body?.app_role ?? 'user';
  if (!email) throw new AppError('email required', 400, 'VALIDATION');
  if (appRole === 'none' || !SETTABLE_APP_ROLES.includes(appRole)) throw new AppError('app_role must be owner, admin or user', 400, 'VALIDATION');
  const target = db.prepare("SELECT id, name FROM users WHERE lower(trim(email)) = ? AND active = 1 AND COALESCE(kind, 'human') = 'human'").get(email);
  if (!target) throw new AppError('No active AppCrane user has that email', 404, 'USER_NOT_FOUND');
  if (db.prepare("SELECT 1 FROM app_user_roles WHERE app_id = ? AND user_id = ? AND app_role != 'none'").get(site.app.id, target.id)) {
    throw new AppError('That person is already a member; change their role instead', 409, 'ALREADY_MEMBER');
  }
  await setAppRole(db, user, site.app, target.id, appRole);
  logAudit(user.id, site.app.id, 'app-set-role', { via: 'widget-invite', user_id: target.id, app_role: appRole });
  res.status(201).json({ user_id: target.id, name: target.name, app_role: appRole });
});

widgetsRouter.post('/widgets/api/access-request', widgetAuth('access'), (req, res) => {
  const db = getDb();
  const { user, site } = req.widget;
  if (['owner', 'admin', 'user'].includes(roleOf(db, req.widget))) {
    throw new AppError('You already have access to this app', 409, 'ALREADY_MEMBER');
  }
  const id = fileAccessRequest(db, user, site.app, req.body?.note);
  res.status(201).json({ request_id: id });
});

widgetsRouter.get('/widgets/api/app-keys', widgetAuth('app-keys'), (req, res) => {
  const { user, site } = req.widget;
  res.json({ keys: listKeys(getDb(), user.id, site.app.id), max_days: WIDGET_KEY_MAX_DAYS });
});

// Issuing a key is the same gated action as POST /api/me/app-keys: the
// platform session behind this widget must have signed in or stepped up
// recently. If not, the widget sends the person through the hosted-app
// step-up (step_up.url, plus &return=<this page>) and back.
widgetsRouter.post('/widgets/api/app-keys', widgetAuth('app-keys'), (req, res) => {
  const { user, site, parentHash } = req.widget;
  const refusal = stepUpRefusal(getDb(), { kind: 'session', credentialHash: parentHash, userId: user.id }, 'manage_api_keys');
  if (refusal) {
    const platform = platformUrl();
    refusal.publicDetails.step_up.url = `${platform || ''}/api/identity/step-up/app?${new URLSearchParams({ app: site.app.slug })}`;
    throw refusal;
  }
  const { key, api_key } = issueKey(getDb(), user, {
    app: site.app.slug, label: req.body?.label, expiresInDays: req.body?.expires_in_days ?? 30, maxDays: WIDGET_KEY_MAX_DAYS,
  });
  logAudit(user.id, site.app.id, 'user-app-key-create', { via: 'widget', key_id: key.id });
  res.status(201).json({ key, api_key });
});

widgetsRouter.delete('/widgets/api/app-keys/:id', widgetAuth('app-keys'), (req, res) => {
  const { user, site } = req.widget;
  revokeKey(getDb(), user.id, req.params.id, site.app.id);
  logAudit(user.id, site.app.id, 'user-app-key-revoke', { via: 'widget', key_id: Number(req.params.id) });
  res.json({ revoked: true });
});
