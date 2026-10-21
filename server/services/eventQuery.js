import { getDb } from '../db.js';
import { SEVERITIES } from './eventStore.js';
import { userHasAppPermission } from './permissions.js';

export const PAGE_DEFAULT = 50;
export const PAGE_MAX = 200;
export const RELATED_WINDOW_HOURS = 2;
const RELATED_LIMIT = 100;

const SELECT = `
  SELECT e.id, e.ts, e.kind, e.severity, e.app_id, e.app_slug, e.user_id, e.subject_user_id,
         e.summary, e.ref_table, e.ref_id, e.data,
         u.name AS user_name, su.name AS subject_user_name
    FROM events e
    LEFT JOIN users u  ON u.id  = e.user_id
    LEFT JOIN users su ON su.id = e.subject_user_id
`;

function shape(r) {
  let data = null;
  try { data = r.data ? JSON.parse(r.data) : null; } catch { data = null; }
  return { ...r, data };
}

function toTs(v) {
  if (typeof v !== 'string' || !v.trim()) return null;
  const ms = Date.parse(/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$/.test(v.trim()) ? v.trim().replace(' ', 'T') + 'Z' : v.trim());
  if (Number.isNaN(ms)) return null;
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
}

const posInt = (v) => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : null;
};

/**
 * Parse list filters from a query object. `scope` adds the caller's fixed
 * constraint (an app, or "about me") that no query parameter can widen.
 */
export function listEvents(query = {}, scope = {}) {
  const where = [];
  const args = [];

  if (scope.appId != null) { where.push('e.app_id = ?'); args.push(scope.appId); }
  if (scope.userId != null) { where.push('(e.user_id = ? OR e.subject_user_id = ?)'); args.push(scope.userId, scope.userId); }

  const kinds = String(query.kind || '').split(',').map(s => s.trim()).filter(Boolean).slice(0, 20);
  if (kinds.length) {
    where.push(`(${kinds.map(() => "(e.kind = ? OR e.kind LIKE ? ESCAPE '\\')").join(' OR ')})`);
    for (const k of kinds) args.push(k, k.replace(/[\\%_]/g, '\\$&') + '.%');
  }
  const sev = String(query.severity || '').split(',').map(s => s.trim()).filter(s => SEVERITIES.includes(s));
  if (sev.length) { where.push(`e.severity IN (${sev.map(() => '?').join(',')})`); args.push(...sev); }

  if (scope.appId == null && query.app) {
    const id = posInt(query.app);
    if (id) { where.push('e.app_id = ?'); args.push(id); } else { where.push('e.app_slug = ?'); args.push(String(query.app)); }
  }
  if (scope.userId == null && query.user) {
    const id = posInt(query.user);
    if (id) { where.push('(e.user_id = ? OR e.subject_user_id = ?)'); args.push(id, id); } else { where.push('0'); }
  }
  const from = toTs(query.from);
  if (from) { where.push('e.ts >= ?'); args.push(from); }
  const to = toTs(query.to);
  if (to) { where.push('e.ts <= ?'); args.push(to); }
  if (query.q && String(query.q).trim()) {
    where.push("e.summary LIKE ? ESCAPE '\\'");
    args.push('%' + String(query.q).trim().slice(0, 200).replace(/[\\%_]/g, '\\$&') + '%');
  }
  const before = posInt(query.before);
  if (before) { where.push('e.id < ?'); args.push(before); }

  const limit = Math.min(posInt(query.limit) || PAGE_DEFAULT, PAGE_MAX);
  const rows = getDb().prepare(`${SELECT} ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY e.id DESC LIMIT ?`)
    .all(...args, limit + 1);
  const more = rows.length > limit;
  const page = rows.slice(0, limit).map(shape);
  return { events: page, next_cursor: more ? page[page.length - 1].id : null };
}

export function getEvent(id) {
  const row = getDb().prepare(`${SELECT} WHERE e.id = ?`).get(id);
  return row ? shape(row) : null;
}

/** App ids on which `user` may read the app's events (same gate as its audit trail). */
export function auditableAppIds(user) {
  const db = getDb();
  const apps = db.prepare('SELECT a.* FROM apps a JOIN app_users au ON au.app_id = a.id WHERE au.user_id = ?').all(user.id);
  return new Set(apps.filter(a => userHasAppPermission(user, a, 'app.audit.view')).map(a => a.id));
}

export function canSeeEvent(user, ev, appIds = null) {
  if (!user || !ev) return false;
  if (user.role === 'platform_admin') return true;
  if (ev.user_id === user.id || ev.subject_user_id === user.id) return true;
  if (ev.app_id == null) return false;
  return (appIds || auditableAppIds(user)).has(ev.app_id);
}

/** Events for the same app or the same person within ±2h of `ev`, oldest first. */
export function relatedEvents(ev, user) {
  const people = [...new Set([ev.user_id, ev.subject_user_id].filter(v => v != null))];
  const match = [];
  const args = [ev.ts, `-${RELATED_WINDOW_HOURS} hours`, ev.ts, `+${RELATED_WINDOW_HOURS} hours`, ev.id];
  if (ev.app_id != null) { match.push('e.app_id = ?'); args.push(ev.app_id); }
  for (const p of people) { match.push('e.user_id = ? OR e.subject_user_id = ?'); args.push(p, p); }
  if (!match.length) return [];
  const rows = getDb().prepare(`
    ${SELECT}
    WHERE e.ts >= datetime(?, ?) AND e.ts <= datetime(?, ?) AND e.id != ?
      AND (${match.map(m => `(${m})`).join(' OR ')})
    ORDER BY e.ts ASC, e.id ASC LIMIT ?
  `).all(...args, RELATED_LIMIT * 2).map(shape);
  const appIds = user?.role === 'platform_admin' ? null : auditableAppIds(user);
  return rows.filter(r => canSeeEvent(user, r, appIds)).slice(0, RELATED_LIMIT);
}

export function distinctKinds() {
  return getDb().prepare('SELECT DISTINCT kind FROM events ORDER BY kind').all().map(r => r.kind);
}
