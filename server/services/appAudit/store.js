import { getDb } from '../../db.js';
import { validateEvent, payloadHash } from './schema.js';
import { verifyForwardedIdentity } from './identity.js';

// Writing and reading app audit events. An event is always bound to the app
// whose service token wrote it: the caller passes the app row resolved from
// the token, and nothing in the body can name another app.

const listeners = new Set();
export function onAppAuditEvent(fn) { listeners.add(fn); return () => listeners.delete(fn); }

function err(message, status, code) {
  return Object.assign(new Error(message), { status, code });
}

export function getAppAuditSettings(appId, db = getDb()) {
  const r = db.prepare('SELECT allow_unregistered FROM app_audit_settings WHERE app_id = ?').get(appId);
  return { allow_unregistered: !!r?.allow_unregistered };
}

export function setAppAuditSettings(appId, { allow_unregistered }, userId, db = getDb()) {
  db.prepare(`INSERT INTO app_audit_settings (app_id, allow_unregistered, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(app_id) DO UPDATE SET allow_unregistered = excluded.allow_unregistered, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(appId, allow_unregistered ? 1 : 0, userId ?? null);
  return getAppAuditSettings(appId, db);
}

export function listEventTypes(appId, db = getDb()) {
  return db.prepare('SELECT id, action, description, created_at FROM app_audit_event_types WHERE app_id = ? ORDER BY action').all(appId);
}

function resolveActor(db, app, ev, now) {
  if (ev.identity) {
    if (ev.actor) throw err('send either actor or identity, not both', 400, 'VALIDATION');
    const { userId, env } = verifyForwardedIdentity(db, app.id, ev.identity, now);
    const u = db.prepare('SELECT id, name FROM users WHERE id = ? AND active = 1').get(userId);
    if (!u) throw err('the signed identity names a user who is not active', 401, 'IDENTITY_INVALID');
    return { actor_type: 'user', actor_id: String(u.id), actor_name: u.name || null, actor_verified: 1, identity_env: env };
  }
  if (ev.actor) return { actor_type: ev.actor.type, actor_id: ev.actor.id, actor_name: ev.actor.name ?? null, actor_verified: 0, identity_env: null };
  return { actor_type: 'app', actor_id: app.slug, actor_name: app.name || app.slug, actor_verified: 1, identity_env: null };
}

/**
 * Record one event for `app` (the row its service token resolved to).
 * Returns { status: 201 | 200, deduped, event }. Throws errors with status/code.
 */
export function recordAppEvent(app, body, { idempotencyHeader = null, now = Date.now(), db = getDb() } = {}) {
  const ev = validateEvent(body, { now, idempotencyHeader });
  const registered = db.prepare('SELECT 1 FROM app_audit_event_types WHERE app_id = ? AND action = ?').get(app.id, ev.action);
  let unregistered = 0;
  if (!registered) {
    if (!getAppAuditSettings(app.id, db).allow_unregistered) {
      throw err(`action '${ev.action}' is not a registered event type of this app; register it first (app settings > Audit events)`, 422, 'UNREGISTERED_ACTION');
    }
    unregistered = 1;
  }
  const actor = resolveActor(db, app, ev, now);
  const row = {
    app_id: app.id, app_slug: app.slug, action: ev.action, occurred_at: ev.occurred_at, ...actor,
    targets: JSON.stringify(ev.targets), context: JSON.stringify(ev.context), metadata: ev.metadata,
    idempotency_key: ev.idempotency_key, unregistered,
  };
  row.payload_hash = payloadHash({ ...row, occurred_at_given: ev.occurred_at_given });
  const existing = () => db.prepare('SELECT * FROM app_audit_events WHERE app_id = ? AND idempotency_key = ?').get(app.id, ev.idempotency_key);
  const replay = (prev) => {
    if (prev.payload_hash !== row.payload_hash) throw err('idempotency_key was already used for a different event', 409, 'IDEMPOTENCY_CONFLICT');
    return { status: 200, deduped: true, event: viewEvent(prev) };
  };
  if (ev.idempotency_key) {
    const prev = existing();
    if (prev) return replay(prev);
  }
  let id;
  try {
    id = Number(db.prepare(`INSERT INTO app_audit_events (app_id, app_slug, action, occurred_at, actor_type, actor_id, actor_name,
        actor_verified, identity_env, targets, context, metadata, idempotency_key, payload_hash, unregistered)
      VALUES (@app_id, @app_slug, @action, @occurred_at, @actor_type, @actor_id, @actor_name, @actor_verified, @identity_env,
        @targets, @context, @metadata, @idempotency_key, @payload_hash, @unregistered)`).run(row).lastInsertRowid);
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE' && ev.idempotency_key) return replay(existing());
    throw e;
  }
  for (const fn of listeners) { try { fn(id, app.id); } catch (_) {} }
  return { status: 201, deduped: false, event: viewEvent(db.prepare('SELECT * FROM app_audit_events WHERE id = ?').get(id)) };
}

function parse(v, def) {
  try { return v ? JSON.parse(v) : def; } catch { return def; }
}

/** What the API returns for one row. source 'app' marks it as written by the app, never by AppCrane. */
export function viewEvent(r) {
  return {
    id: r.id, source: 'app', app: { id: r.app_id, slug: r.app_slug }, action: r.action,
    occurred_at: r.occurred_at, received_at: r.created_at ? `${String(r.created_at).replace(' ', 'T')}Z` : null,
    actor: { type: r.actor_type, id: r.actor_id, name: r.actor_name, verified: !!r.actor_verified, ...(r.identity_env ? { identity_env: r.identity_env } : {}) },
    targets: parse(r.targets, []), context: parse(r.context, {}), metadata: parse(r.metadata, null),
    idempotency_key: r.idempotency_key, unregistered: !!r.unregistered,
  };
}

const MAX_PAGE = 200;
export const EXPORT_MAX = 10_000;

function isoOrNull(v, field) {
  if (v == null || v === '') return null;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) throw err(`${field} must be an ISO 8601 timestamp`, 400, 'VALIDATION');
  return new Date(t).toISOString();
}

/**
 * Filtered page, newest first. appId null = every app (platform admins only;
 * the route decides). q: action (exact or prefix ending in '.'), actor_type,
 * actor_id, target_type, target_id, since, until (occurred_at), app (slug),
 * before (id cursor), limit.
 */
export function listAppEvents(appId, q = {}, { db = getDb(), max = MAX_PAGE } = {}) {
  const where = [];
  const params = [];
  if (appId != null) { where.push('app_id = ?'); params.push(appId); }
  if (appId == null && q.app) { where.push('app_slug = ?'); params.push(String(q.app)); }
  if (q.action) {
    const a = String(q.action);
    if (a.endsWith('.')) { where.push("substr(action, 1, ?) = ?"); params.push(a.length, a); }
    else { where.push('action = ?'); params.push(a); }
  }
  if (q.actor_type) { where.push('actor_type = ?'); params.push(String(q.actor_type)); }
  if (q.actor_id) { where.push('actor_id = ?'); params.push(String(q.actor_id)); }
  if (q.target_type || q.target_id) {
    where.push(`EXISTS (SELECT 1 FROM json_each(app_audit_events.targets) t
      WHERE (? IS NULL OR json_extract(t.value, '$.type') = ?) AND (? IS NULL OR json_extract(t.value, '$.id') = ?))`);
    const tt = q.target_type ? String(q.target_type) : null;
    const ti = q.target_id ? String(q.target_id) : null;
    params.push(tt, tt, ti, ti);
  }
  const since = isoOrNull(q.since, 'since');
  const until = isoOrNull(q.until, 'until');
  if (since) { where.push('occurred_at >= ?'); params.push(since); }
  if (until) { where.push('occurred_at <= ?'); params.push(until); }
  const before = Number.parseInt(q.before, 10);
  if (Number.isInteger(before) && before > 0) { where.push('id < ?'); params.push(before); }
  const n = Number.parseInt(q.limit, 10);
  const limit = Number.isInteger(n) && n > 0 ? Math.min(n, max) : Math.min(50, max);
  const rows = db.prepare(`SELECT * FROM app_audit_events ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`)
    .all(...params, limit + 1);
  const more = rows.length > limit;
  const page = more ? rows.slice(0, limit) : rows;
  return { events: page.map(viewEvent), limit, next_before: more ? page[page.length - 1].id : null };
}

const CSV_COLUMNS = ['id', 'app_slug', 'occurred_at', 'received_at', 'action', 'actor_type', 'actor_id', 'actor_name', 'actor_verified',
  'targets', 'location', 'user_agent', 'metadata', 'unregistered'];

function csvCell(v) {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(events) {
  const lines = [CSV_COLUMNS.join(',')];
  for (const e of events) {
    lines.push([e.id, e.app.slug, e.occurred_at, e.received_at, e.action, e.actor.type, e.actor.id, e.actor.name, e.actor.verified ? 1 : 0,
      JSON.stringify(e.targets), e.context.location, e.context.user_agent, e.metadata == null ? '' : JSON.stringify(e.metadata),
      e.unregistered ? 1 : 0].map(csvCell).join(','));
  }
  return lines.join('\r\n') + '\r\n';
}
