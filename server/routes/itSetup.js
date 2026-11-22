import { Router } from 'express';
import { requireStepUp } from '../services/stepUp.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { logAudit } from '../middleware/audit.js';
import { AppError } from '../utils/errors.js';
import { readCookie } from '../utils/sessionCookie.js';
import { clientIp } from '../utils/clientIp.js';
import log from '../utils/logger.js';
import { createOAuthLimiter } from '../services/oauthRateLimit.js';
import {
  COOKIE, COOKIE_PATH, SCOPES, createLink, getLink, linkView, listLinks, revokeLink,
  openSession, resolveSession, csrfFor, csrfOk, endSessions,
} from '../services/itSetup/links.js';
import {
  stageChange, getChange, testChange, applyChange, discardChange, rollbackChange, lastApplied,
  changeView, listChanges, currentSection,
} from '../services/itSetup/changes.js';
import { addDomain, getDomain, listDomains, checkDomain, domainView } from '../services/domainVerification.js';
import { recentScimRequests } from '../services/scimRequestLog.js';

// Two routers:
//  - adminRouter (mounted at /api): platform admins create, list, revoke and
//    roll back IT setup links, and manage SSO domains.
//  - itRouter (mounted at /api/it-setup): the setup page's API. Its only
//    credential is the cc_itsetup cookie, path-scoped to /api/it-setup, so the
//    browser never sends it anywhere else, and no other route reads it.
//    Writes also need the X-IT-Setup-CSRF header (an HMAC of the session).
//  - pageRouter (mounted at /): the page itself, /it-setup.

const toAppError = (e) => (e?.status && e.status < 500 ? new AppError(e.message, e.status, e.code || 'VALIDATION') : e);
const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) { throw toAppError(e); } };

function craneBase() {
  return process.env.CRANE_DOMAIN ? 'https://' + process.env.CRANE_DOMAIN : 'http://localhost:' + (process.env.PORT || 5001);
}

function itAudit(linkId, action, detail = {}) {
  logAudit(null, null, `it-setup.${action}`, { link_id: linkId, ...detail }, 'it-setup');
}

// ---------------------------------------------------------------------------
// Platform admin
// ---------------------------------------------------------------------------
export const adminRouter = Router();
adminRouter.use('/it-setup-links', requireAuth, requirePlatformAdmin);
adminRouter.use('/sso-domains', requireAuth, requirePlatformAdmin);

function linkOr404(id) {
  const link = getLink(id);
  if (!link) throw new AppError('Setup link not found', 404, 'NOT_FOUND');
  return link;
}

adminRouter.get('/it-setup-links', (req, res) => {
  res.json({ links: listLinks(), scopes: SCOPES });
});

adminRouter.post('/it-setup-links', requireStepUp('security_settings'), wrap((req, res) => {
  const { label, scopes, expires_in_days } = req.body || {};
  const { id, token } = createLink({ label, scopes, expiresInDays: expires_in_days ?? undefined, userId: req.user.id });
  const link = getLink(id);
  logAudit(req.user.id, null, 'it-setup.link-create', { link_id: id, label: link.label, scopes: JSON.parse(link.scopes), expires_at: link.expires_at });
  // The value goes after '#': a browser does not send the fragment, so it is
  // not in any request line, access log or Referer.
  res.status(201).json({ link: linkView(link), url: `${craneBase()}/it-setup#t=${token}`, message: 'Copy this link now; it is not shown again.' });
}));

adminRouter.get('/it-setup-links/:id', (req, res) => {
  const link = linkOr404(req.params.id);
  res.json({ link: linkView(link), changes: listChanges(link.id) });
});

adminRouter.post('/it-setup-links/:id/revoke', (req, res) => {
  const link = linkOr404(req.params.id);
  revokeLink(link, req.user.id);
  logAudit(req.user.id, null, 'it-setup.link-revoke', { link_id: link.id });
  res.json({ link: linkView(getLink(link.id)) });
});

adminRouter.post('/it-setup-links/:id/rollback', requireStepUp('security_settings'), wrap((req, res) => {
  const link = linkOr404(req.params.id);
  const change = lastApplied(link.id);
  if (!change) throw new AppError('This link has no applied change to roll back', 404, 'NOTHING_TO_ROLL_BACK');
  const force = req.body?.force === true;
  const done = rollbackChange(change, req.user.id, { force });
  logAudit(req.user.id, null, 'it-setup.rollback', { link_id: link.id, change_id: change.id, scope: change.scope, force });
  res.json({ change: changeView(done) });
}));

adminRouter.get('/sso-domains', (req, res) => {
  res.json({ domains: listDomains().map(domainView) });
});

adminRouter.post('/sso-domains', requireStepUp('security_settings'), wrap((req, res) => {
  const { row, created } = addDomain(req.body?.domain, { userId: req.user.id });
  if (created) logAudit(req.user.id, null, 'sso-domain.add', { domain: row.domain });
  res.status(created ? 201 : 200).json({ domain: domainView(row) });
}));

adminRouter.post('/sso-domains/:id/verify', requireStepUp('security_settings'), wrap(async (req, res) => {
  const row = getDomain(req.params.id);
  if (!row) throw new AppError('Domain not found', 404, 'NOT_FOUND');
  const r = await checkDomain(row);
  logAudit(req.user.id, null, 'sso-domain.check', { domain: row.domain, result: r.result, status: r.row.status });
  res.json({ result: r.result, domain: domainView(r.row) });
}));

adminRouter.delete('/sso-domains/:id', requireStepUp('security_settings'), (req, res) => {
  const row = getDomain(req.params.id);
  if (!row) throw new AppError('Domain not found', 404, 'NOT_FOUND');
  getDb().prepare('DELETE FROM sso_domains WHERE id = ?').run(row.id);
  logAudit(req.user.id, null, 'sso-domain.delete', { domain: row.domain });
  res.json({ deleted: true });
});

// ---------------------------------------------------------------------------
// The setup page's API
// ---------------------------------------------------------------------------
export const itRouter = Router();
const openLimiter = createOAuthLimiter('it-setup-open', { max: 10, windowMs: 15 * 60_000 });
const actionLimiter = createOAuthLimiter('it-setup', { max: 120, windowMs: 60_000 });
itRouter.use(actionLimiter);
export function _resetItSetupLimitsForTests() { openLimiter.buckets.clear(); actionLimiter.buckets.clear(); }
itRouter.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

function isHttps(req) {
  return req.secure || req.headers['x-forwarded-proto'] === 'https';
}

const REFUSED = {
  invalid: [401, 'LINK_INVALID', 'This setup link is not valid. Ask your AppCrane administrator for a new one.'],
  expired: [410, 'LINK_EXPIRED', 'This setup link has expired. Ask your AppCrane administrator for a new one.'],
  revoked: [410, 'LINK_REVOKED', 'This setup link was revoked. Ask your AppCrane administrator for a new one.'],
  completed: [410, 'LINK_COMPLETED', 'Setup was already completed with this link.'],
};

itRouter.post('/session', openLimiter, (req, res) => {
  const ip = clientIp(req);
  const r = openSession(req.body?.token, ip);
  if (r.refused) {
    if (r.link) itAudit(r.link.id, 'open-refused', { reason: r.refused, ip });
    const [status, code, message] = REFUSED[r.refused];
    return res.status(status).json({ error: { code, message } });
  }
  res.cookie(COOKIE, r.session, {
    httpOnly: true, secure: isHttps(req), sameSite: 'strict', path: COOKIE_PATH,
    maxAge: Math.max(0, r.expiresAt - Date.now()),
  });
  itAudit(r.link.id, 'open', { ip, first: r.firstOpen });
  const s = resolveSession(r.session);
  res.json({ csrf: csrfFor(s.sessionHash), label: r.link.label, scopes: s.scopes, expires_at: r.link.expires_at });
});

function requireItSession(req, res, next) {
  const s = resolveSession(readCookie(req, COOKIE));
  if (!s) return res.status(401).json({ error: { code: 'IT_SETUP_SESSION', message: 'Open the setup link again to continue.' } });
  if (!['GET', 'HEAD'].includes(req.method)) {
    const site = req.headers['sec-fetch-site'];
    if ((site && site !== 'same-origin') || !csrfOk(s.sessionHash, req.headers['x-it-setup-csrf'])) {
      return res.status(403).json({ error: { code: 'CSRF', message: 'Request refused: reload the setup page and try again.' } });
    }
  }
  getDb().prepare("UPDATE it_setup_links SET last_used_at = datetime('now') WHERE id = ?").run(s.link.id);
  req.itSetup = s;
  next();
}

const requireScope = (scope) => (req, res, next) => {
  if (!req.itSetup.scopes.includes(scope)) {
    itAudit(req.itSetup.link.id, 'scope-refused', { scope, path: req.path });
    return res.status(403).json({ error: { code: 'SCOPE', message: `This setup link does not cover ${scope}.` } });
  }
  next();
};

itRouter.get('/state', requireItSession, (req, res) => {
  const { link, scopes, sessionHash } = req.itSetup;
  const sections = Object.fromEntries(scopes.filter((s) => s !== 'domains').map((s) => [s, currentSection(s, link.id)]));
  res.json({
    csrf: csrfFor(sessionHash), label: link.label, scopes, expires_at: link.expires_at,
    sections,
    domains: scopes.includes('domains') ? listDomains().map(domainView) : undefined,
    changes: listChanges(link.id),
  });
});

for (const scope of ['oidc', 'saml', 'scim', 'siem']) {
  itRouter.post(`/${scope}`, requireItSession, requireScope(scope), wrap((req, res) => {
    const id = stageChange(req.itSetup.link.id, scope, req.body || {});
    const change = getChange(req.itSetup.link.id, id);
    itAudit(req.itSetup.link.id, 'stage', { scope, change_id: id });
    res.status(201).json({ change: changeView(change) });
  }));
}

function changeOr404(req) {
  const change = getChange(req.itSetup.link.id, req.params.id);
  if (!change) throw new AppError('Change not found', 404, 'NOT_FOUND');
  if (!req.itSetup.scopes.includes(change.scope)) throw new AppError(`This setup link does not cover ${change.scope}.`, 403, 'SCOPE');
  return change;
}

itRouter.post('/changes/:id/test', requireItSession, wrap(async (req, res) => {
  const change = changeOr404(req);
  const result = await testChange(change);
  itAudit(req.itSetup.link.id, 'test', { scope: change.scope, change_id: change.id, ok: result.ok });
  res.json({ ...result, change: changeView(getChange(req.itSetup.link.id, change.id)) });
}));

itRouter.post('/changes/:id/confirm', requireItSession, wrap((req, res) => {
  const change = changeOr404(req);
  const r = applyChange(change);
  itAudit(req.itSetup.link.id, 'apply', { scope: change.scope, change_id: change.id, sso_only_turned_off: r.sso_only_turned_off, scim_token_rotated: !!r.token });
  if (r.sso_only_turned_off) logAudit(null, null, 'sso-enforce-set', { value: 'false', reason: 'it-setup', link_id: req.itSetup.link.id }, 'it-setup');
  res.json({ change: changeView(r.change), ...(r.token && { scim_token: r.token, message: 'Copy this SCIM token now; it is not shown again.' }) });
}));

itRouter.post('/changes/:id/discard', requireItSession, wrap((req, res) => {
  const change = changeOr404(req);
  discardChange(change);
  itAudit(req.itSetup.link.id, 'discard', { scope: change.scope, change_id: change.id });
  res.json({ change: changeView(getChange(req.itSetup.link.id, change.id)) });
}));

itRouter.get('/scim/requests', requireItSession, requireScope('scim'), (req, res) => {
  res.json({ requests: recentScimRequests(req.query.limit) });
});

itRouter.get('/domains', requireItSession, requireScope('domains'), (req, res) => {
  res.json({ domains: listDomains().map(domainView) });
});

itRouter.post('/domains', requireItSession, requireScope('domains'), wrap((req, res) => {
  const { row, created } = addDomain(req.body?.domain, { linkId: req.itSetup.link.id });
  // Verifying proves control of the domain; whether it lets people join
  // without approval stays a platform admin's choice (the OIDC allowed list).
  if (created) itAudit(req.itSetup.link.id, 'domain-add', { domain: row.domain });
  res.status(created ? 201 : 200).json({ domain: domainView(row) });
}));

itRouter.post('/domains/:id/verify', requireItSession, requireScope('domains'), wrap(async (req, res) => {
  const row = getDomain(req.params.id);
  if (!row) throw new AppError('Domain not found', 404, 'NOT_FOUND');
  const r = await checkDomain(row);
  itAudit(req.itSetup.link.id, 'domain-check', { domain: row.domain, result: r.result, status: r.row.status });
  res.json({ result: r.result, domain: domainView(r.row) });
}));

itRouter.post('/complete', requireItSession, (req, res) => {
  const { link } = req.itSetup;
  const db = getDb();
  db.prepare("UPDATE it_setup_changes SET status = 'discarded' WHERE link_id = ? AND status = 'staged'").run(link.id);
  db.prepare("UPDATE it_setup_links SET completed_at = datetime('now') WHERE id = ?").run(link.id);
  endSessions(link.id);
  res.clearCookie(COOKIE, { path: COOKIE_PATH });
  const applied = listChanges(link.id).filter((c) => c.status === 'applied');
  itAudit(link.id, 'complete', { applied: applied.map((c) => ({ change_id: c.id, scope: c.scope })) });
  notifyAdmins(link, applied);
  res.json({ completed: true, applied: applied.length });
});

itRouter.post('/logout', requireItSession, (req, res) => {
  getDb().prepare('DELETE FROM it_setup_sessions WHERE id = ?').run(req.itSetup.sessionId);
  res.clearCookie(COOKIE, { path: COOKIE_PATH });
  res.json({ ok: true });
});

function notifyAdmins(link, applied) {
  import('../services/emailQueue.js').then(({ enqueueEmail }) => {
    const db = getDb();
    const lines = applied.length
      ? applied.map((c) => `- ${c.scope.toUpperCase()} (change ${c.id}, applied ${c.applied_at})${c.sso_only_turned_off ? ': "Require SSO sign-in" was left off; turn it on in Settings once SSO sign-in works.' : ''}`)
      : ['- No change was applied.'];
    const text = `The IT setup link "${link.label}" (id ${link.id}) was marked complete.\n\nApplied changes:\n${lines.join('\n')}\n\n`
      + 'Review them, or roll the last one back, in Settings > IT setup links. The link no longer works.';
    for (const { email } of db.prepare("SELECT email FROM users WHERE role = 'platform_admin' AND active = 1 AND email IS NOT NULL").all()) {
      try { enqueueEmail({ to: email, subject: `[AppCrane] IT setup completed: ${link.label}`, text, appId: null, source: 'it-setup' }); }
      catch (e) { log.warn(`[it-setup] completion mail to an admin skipped: ${e.message}`); }
    }
  }).catch((e) => log.warn(`[it-setup] completion mail failed: ${e.message}`));
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------
export const pageRouter = Router();
const ASSETS = join(dirname(fileURLToPath(import.meta.url)), '..', 'assets', 'itSetup');
const PAGE_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function sendAsset(res, file, type) {
  res.setHeader('Content-Type', type);
  res.setHeader('Content-Security-Policy', PAGE_CSP);
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Frame-Options', 'DENY');
  res.send(readFileSync(join(ASSETS, file)));
}

pageRouter.get('/it-setup', (req, res) => sendAsset(res, 'page.html', 'text/html; charset=utf-8'));
pageRouter.get('/it-setup/app.js', (req, res) => sendAsset(res, 'app.js', 'text/javascript; charset=utf-8'));
pageRouter.get('/it-setup/style.css', (req, res) => sendAsset(res, 'style.css', 'text/css; charset=utf-8'));
