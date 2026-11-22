// Capability requests and grants (migration 200): the policy per capability,
// the request lifecycle, the platform admin's decision, and what a revoke does.
// Who may call what is decided here, not in the routes, so REST and MCP share
// one set of rules.

import { AppError } from '../../utils/errors.js';
import { logAudit } from '../../middleware/audit.js';
import { roleForUserOnApp } from '../permissions.js';
import { parseBypassPaths } from '../../utils/authBypassPaths.js';
import { CAPABILITIES, CAPABILITY_IDS, EXTERNAL_GATES, CONNECTION_PREFIX, capabilityOf, capabilityDef } from './registry.js';
import { mailNewRequest, mailDecision, mailEnded } from './mail.js';

const POLICY_PREFIX = 'capability_approval_required:';
const REASON_MAX = 1000;
const NOTE_MAX = 1000;
const MAX_DAYS = 365;

export const ACTIVE_SQL = "status = 'approved' AND (expires_at IS NULL OR expires_at > datetime('now'))";

const forbidden = (msg, code = 'FORBIDDEN') => new AppError(msg, 403, code);

function parse(raw) {
  try { return raw ? JSON.parse(raw) : null; } catch (_) { return null; }
}

function setting(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;
}

export function approvalRequired(db, capability) {
  if (capabilityOf(capability).alwaysRequired) return true;
  const v = setting(db, POLICY_PREFIX + capability);
  if (v === '1') return true;
  if (v === '0') return false;
  return capabilityOf(capability).defaultApprovalRequired;
}

export function getPolicy(db) {
  const out = {};
  for (const id of CAPABILITY_IDS) {
    const c = CAPABILITIES[id];
    out[id] = {
      label: c.label, description: c.description,
      approval_required: approvalRequired(db, id),
      default_approval_required: c.defaultApprovalRequired,
      always_required: !!c.alwaysRequired,
      when_off: c.whenOff, on_expiry: c.onExpiry, on_revoke: c.onRevoke,
    };
  }
  return out;
}

export function setPolicy(db, patch, user) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) throw new AppError('body must map capability ids to { approval_required }', 400, 'VALIDATION');
  const changes = {};
  for (const [id, v] of Object.entries(patch)) {
    if (capabilityOf(id).alwaysRequired) throw new AppError(`${id} always needs an approved grant; it has no approval switch`, 400, 'VALIDATION');
    const on = typeof v === 'boolean' ? v : v?.approval_required;
    if (typeof on !== 'boolean') throw new AppError(`${id}.approval_required must be true or false`, 400, 'VALIDATION');
    changes[id] = on;
  }
  for (const [id, on] of Object.entries(changes)) {
    db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
      .run(POLICY_PREFIX + id, on ? '1' : '0', user.id);
  }
  if (Object.keys(changes).length) logAudit(user.id, null, 'capability-policy', { changes });
  return getPolicy(db);
}

export function activeGrantRows(db, appId, capability) {
  return db.prepare(`SELECT * FROM capability_requests WHERE app_id = ? AND capability = ? AND ${ACTIVE_SQL} ORDER BY id`).all(appId, capability);
}

export function activeScopes(db, appId, capability) {
  return activeGrantRows(db, appId, capability).map((r) => parse(r.scope) || {});
}

export function pendingRequest(db, appId, capability) {
  return db.prepare("SELECT * FROM capability_requests WHERE app_id = ? AND capability = ? AND status = 'pending'").get(appId, capability) || null;
}

function getRow(db, id) {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) throw new AppError('invalid request id', 400, 'VALIDATION');
  return db.prepare('SELECT * FROM capability_requests WHERE id = ?').get(n) || null;
}

function userView(db, id) {
  if (id == null) return null;
  const u = db.prepare('SELECT id, name, email, kind FROM users WHERE id = ?').get(id);
  return u ? { id: u.id, name: u.name, email: u.email, kind: u.kind } : { id };
}

export function publicRow(db, row) {
  if (!row) return null;
  const app = db.prepare('SELECT slug, name FROM apps WHERE id = ?').get(row.app_id);
  const active = row.status === 'approved' && (row.expires_at == null
    || db.prepare("SELECT ? > datetime('now') AS live").get(row.expires_at).live === 1);
  return {
    id: row.id,
    app: app ? { slug: app.slug, name: app.name } : null,
    capability: row.capability,
    label: capabilityDef(row.capability)?.label || row.capability,
    origin: row.origin,
    status: row.status,
    active,
    unreviewed: row.origin === 'grandfathered' && row.reviewed_at == null && row.status === 'approved',
    requested_scope: parse(row.requested_scope) || {},
    scope: parse(row.scope),
    reason: row.reason,
    requested_by: userView(db, row.requested_by),
    requested_by_kind: row.requested_by_kind,
    requested_via: row.requested_via,
    decided_by: userView(db, row.decided_by),
    decided_at: row.decided_at,
    decision_note: row.decision_note,
    expires_at: row.expires_at,
    reviewed_at: row.reviewed_at,
    expiry_action: row.expiry_action,
    ended_by: userView(db, row.ended_by),
    ended_at: row.ended_at,
    created_at: row.created_at,
  };
}

function requestHint(slug, capability) {
  const c = capabilityDef(capability);
  const body = JSON.stringify({ capability, scope: c?.example ?? {}, reason: '<why the app needs it>' });
  return `Request it from the app's Capabilities card, with POST /api/apps/${slug}/capability-requests ${body}, `
    + `or with the MCP tool appcrane_request_capability; a platform admin approves it.`;
}

export function approvalRequiredError(app, capability, needed, pending) {
  const c = capabilityDef(capability);
  const wait = pending ? ` Request #${pending.id} is waiting for a platform admin.` : '';
  const err = new AppError(
    `${c.label} needs platform admin approval on this platform, and no approved, unexpired grant for ${app.slug} covers ${JSON.stringify(needed)}.${wait} `
      + requestHint(app.slug, capability),
    403, 'CAPABILITY_APPROVAL_REQUIRED',
  );
  err.capability = capability;
  return err;
}

function cleanText(v, max, field) {
  if (v == null) return null;
  if (typeof v !== 'string') throw new AppError(`${field} must be a string`, 400, 'VALIDATION');
  const s = v.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim();
  return s ? s.slice(0, max) : null;
}

function expiryDays(v) {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > MAX_DAYS) throw new AppError(`expires_in_days must be an integer between 1 and ${MAX_DAYS}`, 400, 'VALIDATION');
  return n;
}

export function canRequest(user, app) {
  const appRole = roleForUserOnApp(user, app);
  return appRole === 'owner' || appRole === 'admin';
}

/** An owner or app admin asks. Agents may ask; they are recorded as such. */
export function createRequest(db, { app, user, capability, scope, reason, via }) {
  const c = capabilityOf(capability);
  if (!canRequest(user, app)) throw forbidden('Only an owner or an admin of this app can request a capability for it.');
  const why = cleanText(reason, REASON_MAX, 'reason');
  if (!why) throw new AppError('reason is required: say why the app needs it', 400, 'VALIDATION');
  const normalized = c.normalizeScope(scope);
  if (c.connection && !db.prepare('SELECT 1 FROM api_connections WHERE name = ?').get(c.connection)) {
    throw new AppError(`There is no platform connection named ${c.connection}`, 404, 'NOT_FOUND');
  }
  const existing = pendingRequest(db, app.id, capability);
  if (existing) return { request: publicRow(db, existing), created: false };
  const id = db.prepare(`INSERT INTO capability_requests
    (app_id, capability, origin, status, requested_scope, reason, requested_by, requested_by_kind, requested_via)
    VALUES (?, ?, 'request', 'pending', ?, ?, ?, ?, ?)`)
    .run(app.id, capability, JSON.stringify(normalized), why, user.id, user.kind || 'human', via).lastInsertRowid;
  logAudit(user.id, app.id, 'capability-request', { id: Number(id), capability, scope: normalized, via });
  mailNewRequest(db, app, capability, Number(id), user, why, normalized);
  return { request: publicRow(db, getRow(db, id)), created: true };
}

export function cancelRequest(db, { app, user, id }) {
  const row = getRow(db, id);
  if (!row || row.app_id !== app.id) throw new AppError('Capability request not found', 404, 'NOT_FOUND');
  if (row.status !== 'pending') throw new AppError(`Request #${row.id} is ${row.status}, not pending`, 409, 'NOT_PENDING');
  if (row.requested_by !== user.id && roleForUserOnApp(user, app) !== 'owner') throw forbidden('Only the person who asked, or the app owner, can cancel this request.');
  db.prepare("UPDATE capability_requests SET status = 'cancelled', ended_by = ?, ended_at = datetime('now') WHERE id = ?").run(user.id, row.id);
  logAudit(user.id, app.id, 'capability-request-cancel', { id: row.id, capability: row.capability });
  return publicRow(db, getRow(db, row.id));
}

/**
 * The approver: a human platform admin signed in to the dashboard, never the
 * person who asked. `channel` is 'session' only for an identity-session
 * request; an API key is how a script or an agent acts as a person, and MCP
 * has no approve tool at all.
 */
export function assertApprover(user, row, { channel, viewAs = false } = {}) {
  if (!user || user.role !== 'platform_admin') throw forbidden('Only a platform admin can decide capability requests.', 'FORBIDDEN_PLATFORM_ADMIN');
  if (user.kind === 'agent') throw forbidden('An agent identity can request a capability but never approve one.', 'AGENT_CANNOT_APPROVE');
  if (channel !== 'session') throw forbidden('Capability decisions are made signed in to the dashboard, not with an API key.', 'APPROVAL_REQUIRES_SESSION');
  if (viewAs) throw forbidden('Leave View as before deciding a capability request.', 'APPROVAL_REQUIRES_SESSION');
  if (row && row.requested_by != null && row.requested_by === user.id) throw forbidden('Nobody approves their own capability request: another platform admin decides it.', 'SELF_APPROVAL');
}

export function decideRequest(db, { id, user, approve, scope, expiresInDays, note, channel, viewAs }) {
  const row = getRow(db, id);
  if (!row) throw new AppError('Capability request not found', 404, 'NOT_FOUND');
  assertApprover(user, row, { channel, viewAs });
  if (row.status !== 'pending') throw new AppError(`Request #${row.id} is ${row.status}, not pending`, 409, 'NOT_PENDING');
  const c = capabilityOf(row.capability);
  const requested = parse(row.requested_scope) || {};
  const why = cleanText(note, NOTE_MAX, 'note');
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(row.app_id);
  if (!approve) {
    db.prepare("UPDATE capability_requests SET status = 'denied', decided_by = ?, decided_at = datetime('now'), decision_note = ? WHERE id = ?").run(user.id, why, row.id);
    logAudit(user.id, row.app_id, 'capability-deny', { id: row.id, capability: row.capability, note: why });
    mailDecision(db, app, getRow(db, row.id), false);
    return publicRow(db, getRow(db, row.id));
  }
  let granted = requested;
  if (scope !== undefined && scope !== null) {
    granted = c.normalizeScope(scope);
    if (!c.covers([requested], granted)) throw new AppError('The approved scope may narrow the request but not widen it.', 400, 'SCOPE_WIDENED');
  }
  const days = expiryDays(expiresInDays);
  db.prepare(`UPDATE capability_requests SET status = 'approved', scope = ?, decided_by = ?, decided_at = datetime('now'), decision_note = ?,
    expires_at = CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', '+' || ? || ' days') END WHERE id = ?`)
    .run(JSON.stringify(granted), user.id, why, days, days, row.id);
  logAudit(user.id, row.app_id, 'capability-approve', { id: row.id, capability: row.capability, scope: granted, narrowed: JSON.stringify(granted) !== JSON.stringify(requested), expires_in_days: days, note: why });
  mailDecision(db, app, getRow(db, row.id), true);
  return publicRow(db, getRow(db, row.id));
}

/** A platform admin set the capability directly: the setting carries a grant like any other. */
export function recordImplicitGrant(db, { app, user, capability, scope, via }) {
  const id = db.prepare(`INSERT INTO capability_requests
    (app_id, capability, origin, status, requested_scope, scope, reason, requested_by, requested_by_kind, requested_via, decided_by, decided_at)
    VALUES (?, ?, 'implicit', 'approved', ?, ?, 'Set directly by a platform admin', ?, ?, ?, ?, datetime('now'))`)
    .run(app.id, capability, JSON.stringify(scope), JSON.stringify(scope), user.id, user.kind || 'human', via, user.id).lastInsertRowid;
  logAudit(user.id, app.id, 'capability-implicit-grant', { id: Number(id), capability, scope, via });
  return Number(id);
}

export function confirmGrant(db, { id, user, expiresInDays, note, channel, viewAs }) {
  const row = getRow(db, id);
  if (!row) throw new AppError('Capability grant not found', 404, 'NOT_FOUND');
  assertApprover(user, null, { channel, viewAs });
  if (row.origin !== 'grandfathered' || row.reviewed_at != null || row.status !== 'approved') {
    throw new AppError(`#${row.id} is not an unreviewed grandfathered grant`, 409, 'NOT_UNREVIEWED');
  }
  const days = expiryDays(expiresInDays);
  const why = cleanText(note, NOTE_MAX, 'note');
  db.prepare(`UPDATE capability_requests SET reviewed_at = datetime('now'), decided_by = ?, decided_at = datetime('now'), decision_note = ?,
    expires_at = CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', '+' || ? || ' days') END WHERE id = ?`)
    .run(user.id, why, days, days, row.id);
  logAudit(user.id, row.app_id, 'capability-confirm', { id: row.id, capability: row.capability, expires_in_days: days, note: why });
  return publicRow(db, getRow(db, row.id));
}

function remainingScopes(db, row) {
  return db.prepare(`SELECT scope FROM capability_requests WHERE app_id = ? AND capability = ? AND id != ? AND ${ACTIVE_SQL}`)
    .all(row.app_id, row.capability, row.id).map((r) => parse(r.scope) || {});
}

/**
 * What ending a grant does to the app. 'revoke' capabilities lose the setting
 * the grant covered unless another active grant still covers it; 'flag'
 * capabilities are left exactly as they are. Returns a sentence for the audit
 * row and whether Caddy must be reloaded.
 */
export function applyEnd(db, row, mode) {
  const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(row.app_id);
  if (!app) return { effect: 'app is gone', reload: false };
  if (mode === 'flag') return { effect: 'left in place (flag only)', reload: false };
  const others = remainingScopes(db, row);
  switch (row.capability) {
    case 'auth_bypass_paths': {
      const keep = new Set(others.flatMap((s) => s.paths || []));
      const drop = new Set((parse(row.scope)?.paths || []).filter((p) => !keep.has(p)));
      const current = parseBypassPaths(app.auth_bypass_paths, () => {});
      const next = current.filter((p) => !drop.has(p));
      if (next.length === current.length) return { effect: 'no bypass path to remove', reload: false };
      db.prepare('UPDATE apps SET auth_bypass_paths = ? WHERE id = ?').run(next.length ? JSON.stringify(next) : null, app.id);
      return { effect: `removed bypass paths ${current.filter((p) => drop.has(p)).join(', ')}`, reload: true };
    }
    case 'headless':
      if (others.length || app.auth_mode !== 'headless') return { effect: 'nothing to change', reload: false };
      db.prepare("UPDATE apps SET auth_mode = 'authenticated' WHERE id = ?").run(app.id);
      return { effect: 'auth_mode set back to authenticated', reload: true };
    case 'public_visibility':
      if (others.length || app.visibility !== 'public') return { effect: 'nothing to change', reload: false };
      db.prepare("UPDATE apps SET visibility = 'private', public_access = 0 WHERE id = ?").run(app.id);
      return { effect: 'visibility set to private', reload: false };
    case 'llm_gateway':
      if (others.length) return { effect: 'nothing to change', reload: false };
      db.prepare("UPDATE llm_gateway_apps SET enabled = 0, updated_at = datetime('now') WHERE app_id = ?").run(app.id);
      return { effect: 'LLM gateway turned off (takes effect on the next deploy)', reload: false };
    case 'outbound_email':
      return { effect: others.length ? 'other grants still cover e-mail' : 'the app e-mail API refuses this app from now on', reload: false };
    case 'egress':
      return { effect: others.length ? 'the hosts other grants name stay allowed' : 'the egress proxy refuses every host for this app from now on', reload: false };
    default:
      if (row.capability.startsWith(CONNECTION_PREFIX)) {
        return { effect: others.length ? 'other grants still cover parts of this connection' : 'the connection refuses this app from now on', reload: false };
      }
      return { effect: 'left in place', reload: false };
  }
}

export function revokeGrant(db, { id, user, note, channel, viewAs }) {
  const row = getRow(db, id);
  if (!row) throw new AppError('Capability grant not found', 404, 'NOT_FOUND');
  assertApprover(user, null, { channel, viewAs });
  if (row.status !== 'approved') throw new AppError(`#${row.id} is ${row.status}, not an active grant`, 409, 'NOT_ACTIVE');
  const why = cleanText(note, NOTE_MAX, 'note');
  const c = capabilityOf(row.capability);
  const out = db.transaction(() => {
    db.prepare("UPDATE capability_requests SET status = 'revoked', ended_by = ?, ended_at = datetime('now'), decision_note = COALESCE(?, decision_note), reviewed_at = COALESCE(reviewed_at, datetime('now')) WHERE id = ?")
      .run(user.id, why, row.id);
    return applyEnd(db, row, c.onRevoke);
  })();
  logAudit(user.id, row.app_id, 'capability-revoke', { id: row.id, capability: row.capability, effect: out.effect, note: why });
  mailEnded(db, getRow(db, row.id), 'revoked', out.effect);
  return { grant: publicRow(db, getRow(db, row.id)), effect: out.effect, reload: out.reload };
}

/** Grants past expires_at: revoked or flagged per capability. Returns what happened. */
export function expireDue(db) {
  const due = db.prepare("SELECT * FROM capability_requests WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at <= datetime('now') ORDER BY id").all();
  const results = [];
  for (const row of due) {
    const c = capabilityDef(row.capability);
    const mode = c?.onExpiry || 'flag';
    const out = db.transaction(() => {
      db.prepare("UPDATE capability_requests SET status = 'expired', expiry_action = ?, ended_at = datetime('now') WHERE id = ? AND status = 'approved'")
        .run(mode === 'revoke' ? 'revoked' : 'flagged', row.id);
      return applyEnd(db, row, mode);
    })();
    logAudit(null, row.app_id, 'capability-expire', { id: row.id, capability: row.capability, action: mode === 'revoke' ? 'revoked' : 'flagged', effect: out.effect });
    mailEnded(db, getRow(db, row.id), 'expired', out.effect);
    results.push({ id: row.id, capability: row.capability, action: mode === 'revoke' ? 'revoked' : 'flagged', effect: out.effect, reload: out.reload });
  }
  return results;
}

export function listRequests(db, { status = 'pending', capability = null, appId = null, limit = 200 } = {}) {
  const where = [];
  const args = [];
  if (status === 'unreviewed') where.push("origin = 'grandfathered' AND reviewed_at IS NULL AND status = 'approved'");
  else if (status === 'active') where.push(ACTIVE_SQL);
  else if (status === 'flagged') where.push("status = 'expired' AND expiry_action = 'flagged'");
  else if (status && status !== 'all') { where.push('status = ?'); args.push(status); }
  if (capability) { capabilityOf(capability); where.push('capability = ?'); args.push(capability); }
  if (appId != null) { where.push('app_id = ?'); args.push(appId); }
  const sql = `SELECT * FROM capability_requests ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`;
  return db.prepare(sql).all(...args, Math.min(Math.max(Number(limit) || 200, 1), 500)).map((r) => publicRow(db, r));
}

function externalStatus(db, app) {
  const ai = db.prepare('SELECT ai_use, annex_iii_category, ai_review_required FROM app_ai_profile WHERE app_id = ?').get(app.id);
  return {
    ai_annex_iii: {
      ...EXTERNAL_GATES.ai_annex_iii,
      in_use: ai?.ai_use === 'annex_iii',
      category: ai?.annex_iii_category ?? null,
      review_required: !!ai?.ai_review_required,
    },
  };
}

/** The app's view: per capability, the policy, the active grants and any open request. */
export function appCapabilities(db, app, user) {
  const policy = getPolicy(db);
  const rows = db.prepare('SELECT * FROM capability_requests WHERE app_id = ? ORDER BY id DESC').all(app.id);
  const capabilities = {};
  const connectionIds = new Set(db.prepare('SELECT name FROM api_connections WHERE enabled = 1 ORDER BY name').all().map((r) => CONNECTION_PREFIX + r.name));
  for (const r of rows) if (r.capability.startsWith(CONNECTION_PREFIX)) connectionIds.add(r.capability);
  for (const id of [...CAPABILITY_IDS, ...connectionIds]) {
    const c = capabilityDef(id);
    if (!c) continue;
    const mine = rows.filter((r) => r.capability === id).map((r) => publicRow(db, r));
    capabilities[id] = {
      ...(policy[id] || {
        label: c.label, description: c.description, approval_required: true, default_approval_required: true,
        always_required: true, when_off: c.whenOff, on_expiry: c.onExpiry, on_revoke: c.onRevoke,
      }),
      example_scope: c.example,
      grants: mine.filter((r) => r.active),
      pending: mine.find((r) => r.status === 'pending') || null,
      history: mine.filter((r) => !r.active && r.status !== 'pending').slice(0, 10),
    };
  }
  let ext = {};
  try { ext = externalStatus(db, app); } catch (_) { ext = { ai_annex_iii: { ...EXTERNAL_GATES.ai_annex_iii, in_use: null } }; }
  return { app: app.slug, can_request: canRequest(user, app), capabilities, external: ext };
}
