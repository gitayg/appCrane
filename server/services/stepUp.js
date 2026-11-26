import crypto from 'crypto';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { hashApiKey } from './encryption.js';
import { isEnrolled } from './mfa.js';
import { parseUtc, sqlUtc } from './sessionPolicy.js';
import { ssoRequired } from './authPolicy.js';
import { appOrigin, isolationEnabled, normalizeDomain } from './appOrigin.js';
import { isSafeRedirect } from '../utils/safeRedirect.js';

// Step-up authentication: a dangerous action needs the person behind the
// request to have authenticated within the last few minutes (WorkOS-style
// re-authentication; OIDC max_age / prompt=login; auth_time).
//
// Who can satisfy it, and how:
//  - a dashboard session (Bearer identity token): its authentication time is the
//    later of its sign-in and its last step-up. It steps up with the strongest
//    factor the person has: their TOTP code if enrolled, else a fresh IdP login
//    (OIDC prompt=login + max_age=0, SAML ForceAuthn), else their password.
//  - a credential that cannot step up interactively: per action and kind.
//    `keys` is for agent credentials (personal MCP keys, MCP OAuth tokens, and
//    internal callers with no credential); `apiKey` for a user API key (the
//    operator's REST/CLI key, also what the admin SPA signs in with by key),
//    defaulting to `keys`. 'grant' needs a time-boxed grant its person made
//    from a freshly stepped-up dashboard session, for that one action and app,
//    so no key or agent reveals a production secret, and no agent deletes an
//    app, without a human having just authenticated. 'allow' keeps flows that are
//    legitimate and reversible working: promote is health-checked with
//    auto-revert, and a key rotating itself is the documented way a key-only
//    account survives expiry. Deleting an app and security settings stay 'allow' for a user API
//    key (deletion over REST also needs ?confirm=true): it is already the full-power credential (it can rotate itself and
//    issue MCP keys), agents' MCP keys cannot reach those routes at all
//    (KEY_SCOPE_RESTRICTED in requireAuth), and refusing it would strand
//    key-only operators. Set apiKey: 'grant' to tighten that.

export const WINDOW_SETTING = 'step_up_window_minutes';
export const WINDOW_DEFAULT = 10;
export const WINDOW_BOUNDS = Object.freeze({ min: 1, max: 60 });
export const REQUEST_TTL_MS = 10 * 60_000;
// An IdP clock a little behind ours must not turn a genuine re-login into a refusal.
export const IDP_SKEW_MS = 30_000;
const PASSWORD_FAILS = Object.freeze({ max: 5, windowMs: 15 * 60_000 });

export const ACTIONS = Object.freeze({
  reveal_production_secret: Object.freeze({ label: 'reveal a production secret', keys: 'grant', perApp: true }),
  promote_production: Object.freeze({ label: 'promote to production', keys: 'allow', perApp: true }),
  delete_app: Object.freeze({ label: 'delete an app', keys: 'grant', apiKey: 'allow', perApp: true }),
  manage_api_keys: Object.freeze({ label: 'create or rotate API keys', keys: 'allow', perApp: false }),
  security_settings: Object.freeze({ label: 'change sign-in, SSO, SCIM or security settings', keys: 'grant', apiKey: 'allow', perApp: false }),
  grant_platform_admin: Object.freeze({ label: 'grant platform admin', keys: 'grant', apiKey: 'allow', perApp: false }),
  // routes/capabilities.js: approve, deny, confirm and revoke.
  approve_capability_request: Object.freeze({ label: 'approve a capability request', keys: 'grant', apiKey: 'allow', perApp: false }),
  disable_mfa: Object.freeze({ label: "turn off a user's two-factor sign-in", keys: 'grant', apiKey: 'allow', perApp: false }),
  // Whole-platform archives and restores (v2.147.0). The archive routes also
  // refuse every credential but a session (configArchiveGuard.js); the image
  // load and the production managed-DB restore take a key holding a grant.
  platform_archive: Object.freeze({ label: 'export, import or restore a platform backup, or weaken a protected setting', keys: 'grant', apiKey: 'grant', perApp: false }),
});

export const INTERACTIVE_KINDS = Object.freeze(['session']);

export function craneBaseUrl() {
  return process.env.CRANE_DOMAIN
    ? 'https://' + String(process.env.CRANE_DOMAIN).replace(/^https?:\/\//, '').replace(/\/+$/, '')
    : 'http://localhost:' + (process.env.PORT || 5001);
}

export function windowMinutes(db = getDb()) {
  const n = Number(db.prepare('SELECT value FROM settings WHERE key = ?').get(WINDOW_SETTING)?.value);
  return Number.isInteger(n) && n >= WINDOW_BOUNDS.min && n <= WINDOW_BOUNDS.max ? n : WINDOW_DEFAULT;
}

export function setWindowMinutes(db, value, actorId) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < WINDOW_BOUNDS.min || n > WINDOW_BOUNDS.max) {
    throw new AppError(`window_minutes must be a whole number between ${WINDOW_BOUNDS.min} and ${WINDOW_BOUNDS.max}`, 400, 'VALIDATION');
  }
  db.prepare(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(WINDOW_SETTING, String(n), actorId ?? null);
  return n;
}

const sessionRow = (db, tokenHash) => db.prepare(
  "SELECT id, user_id, created_at, step_up_at, step_up_method, mfa_method, scope, parent_token_hash FROM identity_sessions WHERE token_hash = ?",
).get(tokenHash);

/** ms since epoch of a session row's most recent authentication. */
export function rowAuthTimeMs(row) {
  if (!row) return NaN;
  const created = parseUtc(row.created_at);
  const stepped = parseUtc(row.step_up_at);
  return Number.isFinite(stepped) ? Math.max(created, stepped) : created;
}

/**
 * { authTimeMs, mfa } for the session behind a token hash. An app-scope session
 * (per-app origins) answers with the platform session it came from, so a
 * step-up on the platform reaches the app.
 */
export function sessionAuth(db, tokenHash) {
  let row = tokenHash ? sessionRow(db, tokenHash) : null;
  if (row && row.scope === 'app' && row.parent_token_hash) row = sessionRow(db, row.parent_token_hash) || row;
  if (!row) return null;
  return { authTimeMs: rowAuthTimeMs(row), mfa: row.mfa_method || null, sessionId: row.id };
}

export function isFresh(db, tokenHash, nowMs = Date.now()) {
  const a = sessionAuth(db, tokenHash);
  return !!a && Number.isFinite(a.authTimeMs) && nowMs - a.authTimeMs <= windowMinutes(db) * 60_000;
}

function oidcOn(db) {
  const v = Object.fromEntries(db.prepare("SELECT key, value FROM settings WHERE key IN ('oidc_enabled','oidc_discovery_url','oidc_client_id')").all().map((r) => [r.key, r.value]));
  return v.oidc_enabled === '1' && !!v.oidc_discovery_url && !!v.oidc_client_id;
}
const samlOn = (db) => db.prepare("SELECT value FROM settings WHERE key = 'saml_enabled'").get()?.value === '1';

/**
 * The one way this person steps up, strongest first. A person with TOTP is
 * never offered something weaker; [] when they have no usable factor.
 */
export function methodsFor(db, userId) {
  const u = db.prepare('SELECT id, password_hash, sso_sub, saml_name_id FROM users WHERE id = ?').get(userId);
  if (!u) return [];
  if (isEnrolled(db, u.id)) return ['totp'];
  if (u.sso_sub && oidcOn(db)) return ['oidc'];
  if (u.saml_name_id && samlOn(db)) return ['saml'];
  if (u.password_hash && !ssoRequired(db)) return ['password'];
  return [];
}

/** Mark the session's authentication as now (a completed step-up). */
// Millisecond precision: a hosted app's return needs a step-up strictly after it asked.
export function recordStepUp(db, tokenHash, method, mfa = undefined) {
  const now = new Date().toISOString();
  const info = mfa === undefined
    ? db.prepare('UPDATE identity_sessions SET step_up_at = ?, step_up_method = ? WHERE token_hash = ?').run(now, method, tokenHash)
    : db.prepare('UPDATE identity_sessions SET step_up_at = ?, step_up_method = ?, mfa_method = ? WHERE token_hash = ?').run(now, method, mfa, tokenHash);
  return info.changes > 0;
}

/** The second factor behind a freshly issued session (sign-in, not step-up). */
export function markSessionMfa(db, token, mfa) {
  if (!token || !mfa) return;
  db.prepare('UPDATE identity_sessions SET mfa_method = ? WHERE token_hash = ?').run(mfa, hashApiKey(token));
}

// ── grants for credentials that cannot step up ──────────────────────────────

export function createGrant(db, userId, action, appId = null) {
  const minutes = windowMinutes(db);
  const expires = sqlUtc(Date.now() + minutes * 60_000);
  const id = db.prepare('INSERT INTO step_up_grants (user_id, action, app_id, expires_at) VALUES (?, ?, ?, ?)')
    .run(userId, action, appId, expires).lastInsertRowid;
  return { id: Number(id), action, app_id: appId, expires_at: expires, minutes };
}

export function hasGrant(db, userId, action, appId = null) {
  return !!db.prepare(`SELECT 1 FROM step_up_grants WHERE user_id = ? AND action = ? AND app_id IS ?
    AND revoked_at IS NULL AND datetime(expires_at) > datetime('now')`).get(userId, action, appId ?? null);
}

export function listGrants(db, userId) {
  return db.prepare(`SELECT g.id, g.action, g.granted_at, g.expires_at, a.slug AS app
    FROM step_up_grants g LEFT JOIN apps a ON a.id = g.app_id
    WHERE g.user_id = ? AND g.revoked_at IS NULL AND datetime(g.expires_at) > datetime('now') ORDER BY g.id DESC`).all(userId);
}

export function revokeGrant(db, userId, id) {
  return db.prepare("UPDATE step_up_grants SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL")
    .run(Number(id), userId).changes > 0;
}

// ── the gate ────────────────────────────────────────────────────────────────

function grantUrl(action, slug) {
  const p = new URLSearchParams({ grant: action, ...(slug && { app: slug }) });
  return `${craneBaseUrl()}/step-up?${p}`;
}

/**
 * null when the caller may go ahead, else the AppError to throw.
 * ctx: { kind, credentialHash, userId } (from requireAuth); app: the app row
 * for a per-app action.
 */
export function stepUpRefusal(db, ctx, action, app = null) {
  const def = ACTIONS[action];
  if (!def) throw new Error(`stepUp: unknown action '${action}'`);
  const minutes = windowMinutes(db);
  if (ctx.kind === 'session') {
    if (isFresh(db, ctx.credentialHash)) return null;
    const a = sessionAuth(db, ctx.credentialHash);
    const err = new AppError(`Confirm it's you: to ${def.label} you need to have signed in within the last ${minutes} minutes.`, 401, 'STEP_UP_REQUIRED');
    err.publicDetails = {
      step_up: {
        action, mode: 'reauth', methods: methodsFor(db, ctx.userId), window_minutes: minutes,
        auth_time: a && Number.isFinite(a.authTimeMs) ? Math.floor(a.authTimeMs / 1000) : null,
        endpoint: '/api/identity/step-up',
      },
    };
    return err;
  }
  if ((ctx.kind === 'api_key' ? def.apiKey || def.keys : def.keys) === 'allow') return null;
  const appId = def.perApp ? (app?.id ?? null) : null;
  if (ctx.userId && hasGrant(db, ctx.userId, action, appId)) return null;
  const url = grantUrl(action, def.perApp ? app?.slug : null);
  const err = new AppError(
    `STEP_UP_REQUIRED: to ${def.label}${app && def.perApp ? ` on ${app.slug}` : ''} a person must confirm it in the dashboard first; an API key or agent cannot. ` +
    `Ask the user to open ${url} , confirm, and then retry within ${minutes} minutes.`,
    403, 'STEP_UP_REQUIRED');
  err.publicDetails = { step_up: { action, mode: 'grant', grant_url: url, window_minutes: minutes } };
  return err;
}

export function ctxFromReq(req) {
  return { kind: req.auth_kind || null, credentialHash: req.auth_credential_hash || null, userId: (req.real_user || req.user)?.id ?? null };
}

/** Throw unless the request may perform `action` (on `app`). */
export function assertStepUp(req, action, app = null) {
  const err = stepUpRefusal(getDb(), ctxFromReq(req), action, app);
  if (err) throw err;
}

/** Express middleware. A per-app action reads req.app, so mount it after requireAppAccess/requireAppUser. */
export function requireStepUp(action) {
  return (req, res, next) => {
    try {
      const err = stepUpRefusal(getDb(), ctxFromReq(req), action, ACTIONS[action]?.perApp ? req.app : null);
      return next(err || undefined);
    } catch (e) {
      return next(e);
    }
  };
}

/** For MCP tool handlers: user carries _stepUp (set by callTool). */
export function assertToolStepUp(user, action, app = null) {
  const ctx = user?._stepUp || { kind: null, credentialHash: null, userId: user?.id ?? null };
  const err = stepUpRefusal(getDb(), ctx, action, app);
  if (err) throw new Error(err.message);
}

// ── password step-up throttle ───────────────────────────────────────────────

const _passwordFails = new Map();

export function passwordLimited(userId, nowMs = Date.now()) {
  const list = (_passwordFails.get(userId) || []).filter((t) => nowMs - t < PASSWORD_FAILS.windowMs);
  _passwordFails.set(userId, list);
  return list.length >= PASSWORD_FAILS.max ? Math.ceil((PASSWORD_FAILS.windowMs - (nowMs - list[0])) / 1000) : 0;
}
export function notePasswordFailure(userId, nowMs = Date.now()) {
  const list = _passwordFails.get(userId) || [];
  list.push(nowMs);
  _passwordFails.set(userId, list);
}
export function clearPasswordFailures(userId) {
  _passwordFails.delete(userId);
}

// ── round trips (IdP re-login, hosted-app return) ───────────────────────────

const handleHash = (h) => crypto.createHash('sha256').update(String(h)).digest('base64url');
export { handleHash as stepUpHandleHash };

export function createRequest(db, { kind, userId = null, sessionHash = null, appId = null, appEnv = null, returnUrl = null }) {
  const handle = crypto.randomBytes(24).toString('base64url');
  db.prepare(`INSERT INTO step_up_requests (handle_hash, kind, user_id, session_hash, app_id, app_env, return_url, started_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(handleHash(handle), kind, userId, sessionHash, appId, appEnv, returnUrl, new Date().toISOString(), sqlUtc(Date.now() + REQUEST_TTL_MS));
  return handle;
}

/** The live (unconsumed, unexpired) request for a handle hash, or null. */
export function liveRequestByHash(db, hash, kinds) {
  const row = db.prepare('SELECT * FROM step_up_requests WHERE handle_hash = ?').get(String(hash || ''));
  if (!row || row.consumed_at || !kinds.includes(row.kind)) return null;
  if (parseUtc(row.expires_at) < Date.now()) return null;
  return row;
}

export function liveRequest(db, handle, kinds) {
  return typeof handle === 'string' && handle ? liveRequestByHash(db, handleHash(handle), kinds) : null;
}

export function consumeRequest(db, id) {
  return db.prepare("UPDATE step_up_requests SET consumed_at = datetime('now') WHERE id = ? AND consumed_at IS NULL").run(id).changes > 0;
}

/**
 * Finish an IdP step-up. The IdP must say the SAME subject this user is linked
 * to, and that it authenticated them AFTER we asked (auth_time / AuthnInstant),
 * which is what prompt=login / max_age=0 / ForceAuthn require of it: an IdP
 * that silently reused an old login is refused.
 */
/**
 * Whether this browser holds the platform session that asked for the step-up
 * (its session cookie hashes to request.session_hash). Checked when the IdP
 * round starts and again on the OIDC callback, so a step-up link opened in
 * another browser, or under another session, cannot freshen this one.
 */
export function browserHoldsRequestSession(sessionToken, request) {
  if (!sessionToken || !request?.session_hash) return false;
  const a = Buffer.from(hashApiKey(sessionToken));
  const b = Buffer.from(String(request.session_hash));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function finishIdpStepUp(db, request, { subjectColumn, subject, authInstantMs, mfa = null }) {
  const user = db.prepare(`SELECT id, ${subjectColumn === 'sso_sub' ? 'sso_sub' : 'saml_name_id'} AS subject FROM users WHERE id = ?`).get(request.user_id);
  if (!user || !subject || user.subject !== subject) return { ok: false, code: 'step_up_wrong_account' };
  if (!Number.isFinite(authInstantMs) || authInstantMs + IDP_SKEW_MS < parseUtc(request.started_at)) {
    return { ok: false, code: 'step_up_not_fresh' };
  }
  if (!consumeRequest(db, request.id)) return { ok: false, code: 'step_up_expired' };
  if (!recordStepUp(db, request.session_hash, request.kind, mfa)) return { ok: false, code: 'step_up_expired' };
  return { ok: true };
}

// ── hosted apps: where a step-up may send the person back ───────────────────

function sameAppPath(pathname, slug) {
  for (const [mount, env] of [[`/${slug}-sandbox`, 'sandbox'], [`/${slug}`, 'production']]) {
    if (pathname === mount || pathname.startsWith(`${mount}/`)) return env;
  }
  return null;
}

/**
 * { app, env, url } when `raw` is a URL on the app's own host (per-app origins
 * or its custom domain) or, without per-app origins, a path under the app's
 * mount on the platform host. Anything else is null: the step-up endpoint must
 * not become an open redirect.
 */
export function validateAppReturn(db, slug, raw) {
  if (typeof slug !== 'string' || typeof raw !== 'string' || !raw || raw.length > 2048 || /[\x00-\x1f\x7f\\]/.test(raw)) return null;
  const app = db.prepare('SELECT * FROM apps WHERE slug = ?').get(slug);
  if (!app) return null;
  const base = craneBaseUrl();
  let u;
  try { u = new URL(raw, base); } catch (_) { return null; }
  if (u.username || u.password) return null;
  const relative = raw.startsWith('/');
  if (relative && !isSafeRedirect(raw)) return null;
  if (!relative && !/^https?:\/\//i.test(raw)) return null;
  if (isolationEnabled(db)) {
    for (const env of ['production', 'sandbox']) {
      if (!relative && u.origin === appOrigin(db, slug, env)) return { app, env, url: u.href };
    }
  } else if (u.origin === new URL(base).origin) {
    const env = sameAppPath(u.pathname, slug);
    if (env) return { app, env, url: u.pathname + u.search + u.hash };
  }
  const domain = normalizeDomain(app.domain);
  if (!relative && domain && app.custom_domain_auth === 1 && u.protocol === 'https:' && u.host === domain) {
    return { app, env: 'production', url: u.href };
  }
  return null;
}
