import express, { Router } from 'express';
import { requireStepUp } from '../services/stepUp.js';
import { getDb } from '../db.js';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { AppError } from '../utils/errors.js';
import { hashApiKey } from '../services/encryption.js';
import { revokeAllDevices } from '../services/trustedDevices.js';
import { revokeAllGrantsForUser } from '../services/oauthStore.js';
import { readPolicy, writePolicy, FIELDS } from '../services/signinRisk/config.js';
import { listLocked, unlockUser } from '../services/signinRisk/lockout.js';
import { clearFlag, listFlagged } from '../services/signinRisk/stuffing.js';
import { listStale, runStaleSweep } from '../services/signinRisk/stale.js';
import { forgetUserDevices } from '../services/signinRisk/devices.js';
import { KINDS, signal } from '../services/signinRisk/signals.js';

// Mounted at /api/signin-security.
//  - platform admin: the "Sign-in security" panel (signals, locks, flagged
//    networks, stale accounts, policy) and the unlock action
//  - public, token-authorised: the "not you?" link from a new-device e-mail.
//    GET only shows a confirmation page (mail scanners prefetch links); the
//    POST from that page does the revoking.

const router = Router();
const admin = [requireAuth, requirePlatformAdmin];

router.get('/', ...admin, (req, res) => {
  const db = getDb();
  const signals = db.prepare(`SELECT e.id, e.ts, e.kind, e.severity, e.subject_user_id, e.summary, e.data,
      u.name AS subject_name, u.username AS subject_username
    FROM events e LEFT JOIN users u ON u.id = e.subject_user_id
    WHERE e.kind LIKE 'login.risk.%' ORDER BY e.id DESC LIMIT 100`).all()
    .map((r) => { let data = null; try { data = r.data ? JSON.parse(r.data) : null; } catch (_) {} return { ...r, data }; });
  const policy = readPolicy(db);
  res.json({
    policy,
    policy_fields: Object.fromEntries(Object.entries(FIELDS).map(([k, f]) => [k, { type: f.type, min: f.min, max: f.max, default: f.def }])),
    locked: listLocked(db),
    flagged_networks: listFlagged(),
    stale: listStale(db, policy.stale_days),
    signals,
    geo: { available: false, reason: 'Country and impossible-travel rules are not built: no GeoIP database is read.' },
  });
});

router.put('/policy', ...admin, requireStepUp('security_settings'), (req, res) => {
  const db = getDb();
  try {
    const policy = writePolicy(db, req.body || {}, req.user.id);
    signal({
      kind: 'login.risk.policy', userId: req.user.id, summary: 'Sign-in security policy changed',
      data: { policy }, audit: { actorId: req.user.id, action: 'signin-risk-policy-change' },
    });
    res.json({ policy });
  } catch (e) {
    if (e.field) throw new AppError(e.message, 400, 'VALIDATION');
    throw e;
  }
});

router.post('/users/:id/unlock', ...admin, requireStepUp('security_settings'), (req, res) => {
  const db = getDb();
  const id = Number(req.params.id);
  const user = Number.isInteger(id) && id > 0 ? db.prepare('SELECT id FROM users WHERE id = ?').get(id) : null;
  if (!user) throw new AppError('User not found', 404, 'NOT_FOUND');
  res.json({ cleared: unlockUser(db, user.id, { actorId: req.user.id, ip: req.ip }) });
});

router.post('/networks/clear', ...admin, (req, res) => {
  const network = String(req.body?.network || '');
  const cleared = clearFlag(network);
  if (cleared) {
    signal({
      kind: 'login.risk.network_cleared', userId: req.user.id, summary: `Stuffing flag cleared for ${network}`,
      data: { network }, audit: { actorId: req.user.id, action: 'signin-network-cleared' },
    });
  }
  res.json({ cleared });
});

router.post('/stale/sweep', ...admin, (req, res) => {
  res.json(runStaleSweep(getDb()));
});

// ── "not you?" ─────────────────────────────────────────────────────────────

const escapeHtml = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const TOKEN_RE = /^[A-Za-z0-9_-]{32,64}$/;

function page(res, status, title, body) {
  res.set('Cache-Control', 'no-store');
  res.set('Referrer-Policy', 'no-referrer');
  res.status(status).type('html').send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>${escapeHtml(title)}</title><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem">`
    + `<h1>${escapeHtml(title)}</h1>${body}</body>`);
}

function liveLink(db, token) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return null;
  return db.prepare("SELECT * FROM signin_report_links WHERE token_hash = ? AND used_at IS NULL AND expires_at > datetime('now')").get(hashApiKey(token)) || null;
}

const DEAD = '<p>This link has expired or was already used. If you still think someone else signed in to your account, contact your platform admin.</p>';

router.get('/not-me', (req, res) => {
  const token = typeof req.query.t === 'string' ? req.query.t : '';
  if (!liveLink(getDb(), token)) return page(res, 410, 'Link not valid', DEAD);
  page(res, 200, 'Was this not you?',
    '<p>This signs out every session on your AppCrane account, forgets every remembered browser, disconnects every MCP client you approved, and revokes your MCP keys and app keys. '
    + 'Then change your password, or ask your platform admin to reset it.</p>'
    + `<form method="post" action="not-me"><input type="hidden" name="t" value="${escapeHtml(token)}">`
    + '<button type="submit" style="font-size:1rem;padding:.5rem 1rem">Sign out everywhere</button></form>');
});

router.post('/not-me', express.urlencoded({ extended: false, limit: '2kb' }), (req, res) => {
  const db = getDb();
  const link = liveLink(db, req.body?.t);
  if (!link) return page(res, 410, 'Link not valid', DEAD);
  const used = db.prepare("UPDATE signin_report_links SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL").run(link.id).changes;
  if (!used) return page(res, 410, 'Link not valid', DEAD);
  const sessions = db.prepare('DELETE FROM identity_sessions WHERE user_id = ?').run(link.user_id).changes;
  const devices = forgetUserDevices(db, link.user_id);
  const mfaDevices = revokeAllDevices(db, link.user_id, { actorId: link.user_id, reason: 'reported-not-me', ip: req.ip });
  let grants = 0;
  try { grants = revokeAllGrantsForUser(link.user_id) || 0; } catch (_) {}
  // Every key and step-up grant, not only those since this device's first
  // sign-in: an intruder could have made them from another browser too.
  const revoke = (table, col = 'revoked_at') => db.prepare(`UPDATE ${table} SET ${col} = datetime('now') WHERE user_id = ? AND ${col} IS NULL`).run(link.user_id).changes;
  const mcpKeys = revoke('user_mcp_keys');
  const appKeys = revoke('user_app_keys');
  const stepUpGrants = revoke('step_up_grants');
  db.prepare('UPDATE signin_report_links SET used_at = datetime(\'now\') WHERE user_id = ? AND used_at IS NULL').run(link.user_id);
  signal({
    kind: KINDS.reported, severity: 'critical', userId: link.user_id, subjectUserId: link.user_id,
    summary: 'User reported a sign-in as not theirs; all sessions revoked',
    data: { device_id: link.device_public_id, sessions, devices, mfa_devices: mfaDevices, oauth_grants: grants, mcp_keys: mcpKeys, app_keys: appKeys, step_up_grants: stepUpGrants, ip: req.ip },
    audit: { actorId: link.user_id, action: 'signin-reported-not-me' },
  });
  page(res, 200, 'Signed out everywhere',
    '<p>Every session on your account has ended, remembered browsers are forgotten, and your MCP keys and app keys are revoked. Change your password now, or ask your platform admin to reset it. Your platform admins can see this report.</p>');
});

export default router;
