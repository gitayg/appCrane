// Tasks: hosted apps assign work to people; each person has one inbox across
// every app.
//
// Who may do what (enforced here, for both the app API and the dashboard):
//   app (its service token)  create; list/read its own tasks; comment, change
//                            status, delete its own tasks; poll its events.
//   requester                read, comment, any status change, delete.
//   assignee                 read, comment, and move open -> in_progress/done/
//                            declined or in_progress -> open/done/declined.
//                            A closed task (done/declined) is reopened only by
//                            the requester or the app.
//   anyone else              404, including other members of the app and
//                            platform admins (tasks are app data; v2.39.0 rule).
// A person sees a task only while they still have access to its app. A
// deleted task is soft-deleted and hidden from everyone, the app included.

import crypto from 'crypto';
import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { logAudit } from '../middleware/audit.js';
import log from '../utils/logger.js';
import { TASK_STATUSES, taskSummary, taskComments, taskHistory, renderEvent } from './tasksEvents.js';
import { queueTaskMail } from './tasksMail.js';
import { queueTaskWebhook } from './tasksWebhook.js';

export { TASK_STATUSES };

export const TASK_LIMITS = Object.freeze({
  SUBJECT_MAX: 200,
  BODY_MAX: 10_000,
  COMMENT_MAX: 5_000,
  EXTERNAL_REF_MAX: 200,
  URL_MAX: 2048,
  CREATES_PER_APP_PER_HOUR: 500,
  LIST_MAX: 200,
  EVENTS_MAX: 500,
});

const ASSIGNEE_MOVES = Object.freeze({
  open: ['in_progress', 'done', 'declined'],
  in_progress: ['open', 'done', 'declined'],
  done: [],
  declined: [],
});

const nowIso = () => new Date().toISOString();
const bad = (msg, code = 'INVALID_TASK') => new AppError(msg, 400, code);
const notFound = () => new AppError('Task not found', 404, 'NOT_FOUND');

function plainText(v, field, { max, required = false, multiline = false }) {
  if (v === undefined || v === null || v === '') {
    if (required) throw bad(`${field} is required`);
    return null;
  }
  if (typeof v !== 'string') throw bad(`${field} must be a string`);
  const s = v.replace(/\r\n?/g, '\n').trim();
  if (!s) {
    if (required) throw bad(`${field} is required`);
    return null;
  }
  if (s.length > max) throw bad(`${field} must be at most ${max} characters`);
  const ctrl = multiline ? /[\x00-\x08\x0b-\x1f\x7f]/ : /[\x00-\x1f\x7f]/;
  if (ctrl.test(s)) throw bad(`${field} must be plain text without control characters`);
  return s;
}

function linkUrl(v) {
  const s = plainText(v, 'url', { max: TASK_LIMITS.URL_MAX });
  if (s == null) return null;
  let u;
  try { u = new URL(s); } catch { throw bad('url must be an absolute http(s) URL'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw bad('url must be an absolute http(s) URL');
  if (u.username || u.password) throw bad('url must not carry credentials');
  return u.toString();
}

function dueDate(v) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) throw bad('due_date must be YYYY-MM-DD');
  const d = new Date(`${v}T00:00:00Z`);
  if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) throw bad('due_date must be a real date');
  return v;
}

function status(v) {
  if (!TASK_STATUSES.includes(v)) throw bad(`status must be one of: ${TASK_STATUSES.join(', ')}`);
  return v;
}

function hasAppAccess(db, appId, userId) {
  return !!db.prepare('SELECT 1 FROM app_users WHERE app_id = ? AND user_id = ?').get(appId, userId);
}

// The app names a person by id or e-mail. Not-found and no-access answer the
// same message, so the API is not a directory of who exists elsewhere.
function memberFor(db, appId, body, role) {
  const id = body[`${role}_user_id`];
  const email = body[`${role}_email`];
  let user = null;
  if (id !== undefined && id !== null && id !== '') {
    const n = Number(id);
    if (!Number.isInteger(n) || n <= 0) throw bad(`${role}_user_id must be a positive integer`);
    user = db.prepare('SELECT id, active FROM users WHERE id = ?').get(n);
  } else if (typeof email === 'string' && email.trim()) {
    user = db.prepare('SELECT id, active FROM users WHERE lower(email) = lower(?)').get(email.trim());
  } else {
    throw bad(`${role}_user_id or ${role}_email is required`);
  }
  if (!user || !user.active || !hasAppAccess(db, appId, user.id)) {
    throw bad(`${role} must be an active user with access to this app`, role === 'requester' ? 'REQUESTER_NO_ACCESS' : 'ASSIGNEE_NO_ACCESS');
  }
  return user.id;
}

function rolesOf(task, userId) {
  return { requester: task.requester_user_id === userId, assignee: task.assignee_user_id === userId };
}

export function allowedStatuses(task, actor) {
  if (actor.kind === 'app') return TASK_STATUSES.filter((s) => s !== task.status);
  const r = rolesOf(task, actor.user.id);
  if (r.requester) return TASK_STATUSES.filter((s) => s !== task.status);
  if (r.assignee) return [...ASSIGNEE_MOVES[task.status]];
  return [];
}

function canDelete(task, actor) {
  return actor.kind === 'app' || rolesOf(task, actor.user.id).requester;
}

const actorId = (actor) => (actor.kind === 'user' ? actor.user.id : null);
const actorVia = (actor) => (actor.kind === 'user' ? 'dashboard' : 'app');

function recordEvent(db, task, kind, actor, extra = {}) {
  const at = nowIso();
  const id = db.prepare(`
    INSERT INTO task_events (task_id, app_id, kind, actor_user_id, via, from_status, to_status, comment_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(task.id, task.app_id, kind, extra.actorUserId !== undefined ? extra.actorUserId : actorId(actor), actorVia(actor),
    extra.from ?? null, extra.to ?? null, extra.commentId ?? null, at).lastInsertRowid;
  db.prepare('UPDATE tasks SET last_activity_at = ?, last_actor_user_id = ?, updated_at = ? WHERE id = ?')
    .run(at, extra.actorUserId !== undefined ? extra.actorUserId : actorId(actor), at, task.id);
  return id;
}

// After the write has committed: e-mail and webhook. Neither may fail the
// request that caused it.
function notify(eventId) {
  const db = getDb();
  try { queueTaskMail(db, eventId); } catch (e) { log.warn(`[tasks] mail for event ${eventId} failed: ${e.message}`); }
  try { queueTaskWebhook(eventId); } catch (e) { log.warn(`[tasks] webhook for event ${eventId} failed: ${e.message}`); }
}

// ── Lookup ──────────────────────────────────────────────────────────────────

function liveTask(db, id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{10,64}$/.test(id)) return null;
  return db.prepare('SELECT * FROM tasks WHERE id = ? AND deleted_at IS NULL').get(id) || null;
}

function taskForApp(db, app, id) {
  const t = liveTask(db, id);
  if (!t || t.app_id !== app.id) throw notFound();
  return t;
}

function taskForUser(db, user, id) {
  const t = liveTask(db, id);
  if (!t) throw notFound();
  const r = rolesOf(t, user.id);
  if (!r.requester && !r.assignee) throw notFound();
  if (!hasAppAccess(db, t.app_id, user.id)) throw notFound();
  return t;
}

function detail(db, t, actor) {
  return {
    ...taskSummary(db, t),
    body: t.body,
    comments: taskComments(db, t.id),
    history: taskHistory(db, t.id),
    ...(actor.kind === 'user' ? {
      my_roles: rolesOf(t, actor.user.id),
      allowed_statuses: allowedStatuses(t, actor),
      can_delete: canDelete(t, actor),
    } : {}),
  };
}

// ── Writes shared by both sides ─────────────────────────────────────────────

function addComment(db, t, actor, raw) {
  const body = plainText(raw, 'body', { max: TASK_LIMITS.COMMENT_MAX, required: true, multiline: true });
  let eventId, commentId;
  db.transaction(() => {
    commentId = db.prepare('INSERT INTO task_comments (task_id, author_user_id, body, via, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(t.id, actorId(actor), body, actorVia(actor), nowIso()).lastInsertRowid;
    eventId = recordEvent(db, t, 'comment', actor, { commentId });
  })();
  notify(eventId);
  return taskComments(db, t.id).find((c) => c.id === Number(commentId));
}

function changeStatus(db, t, actor, raw) {
  const to = status(raw);
  if (to === t.status) return t;
  if (!allowedStatuses(t, actor).includes(to)) {
    throw new AppError(`You cannot move this task from ${t.status} to ${to}`, 403, 'STATUS_NOT_ALLOWED');
  }
  let eventId;
  db.transaction(() => {
    db.prepare('UPDATE tasks SET status = ? WHERE id = ?').run(to, t.id);
    eventId = recordEvent(db, t, 'status', actor, { from: t.status, to });
  })();
  notify(eventId);
  return db.prepare('SELECT * FROM tasks WHERE id = ?').get(t.id);
}

function softDelete(db, t, actor) {
  if (!canDelete(t, actor)) throw new AppError('Only the requester can delete this task', 403, 'DELETE_NOT_ALLOWED');
  let eventId;
  db.transaction(() => {
    db.prepare('UPDATE tasks SET deleted_at = ?, deleted_by_user_id = ?, deleted_via = ? WHERE id = ?')
      .run(nowIso(), actorId(actor), actorVia(actor), t.id);
    eventId = recordEvent(db, t, 'deleted', actor);
  })();
  // Ids only: never the subject or body.
  logAudit(actorId(actor), t.app_id, 'task-delete', { task_id: t.id, via: actorVia(actor) }, actor.kind === 'app' ? 'app' : null);
  notify(eventId);
}

// ── App side ────────────────────────────────────────────────────────────────

export function createTask(app, body = {}) {
  const db = getDb();
  const subject = plainText(body.subject, 'subject', { max: TASK_LIMITS.SUBJECT_MAX, required: true });
  const text = plainText(body.body, 'body', { max: TASK_LIMITS.BODY_MAX, multiline: true }) || '';
  const externalRef = plainText(body.external_ref, 'external_ref', { max: TASK_LIMITS.EXTERNAL_REF_MAX });
  const url = linkUrl(body.url);
  const due = dueDate(body.due_date);
  const requester = memberFor(db, app.id, body, 'requester');
  const assignee = memberFor(db, app.id, body, 'assignee');

  const since = new Date(Date.now() - 3600_000).toISOString();
  const recent = db.prepare('SELECT COUNT(*) AS n FROM tasks WHERE app_id = ? AND created_at > ?').get(app.id, since).n;
  if (recent >= TASK_LIMITS.CREATES_PER_APP_PER_HOUR) {
    throw new AppError(`This app created ${recent} tasks in the last hour; try again later`, 429, 'TASK_RATE_LIMITED');
  }

  const id = crypto.randomBytes(16).toString('base64url');
  const at = nowIso();
  let eventId;
  db.transaction(() => {
    db.prepare(`
      INSERT INTO tasks (id, app_id, subject, body, status, requester_user_id, assignee_user_id, due_date, external_ref, url,
                         created_at, updated_at, last_activity_at, last_actor_user_id)
      VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, app.id, subject, text, requester, assignee, due, externalRef, url, at, at, at, requester);
    const t = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
    eventId = recordEvent(db, t, 'created', { kind: 'app' }, { actorUserId: requester, to: 'open' });
  })();
  notify(eventId);
  return detail(db, db.prepare('SELECT * FROM tasks WHERE id = ?').get(id), { kind: 'app' });
}

export function listAppTasks(app, q = {}) {
  const db = getDb();
  const where = ['app_id = ?', 'deleted_at IS NULL'];
  const args = [app.id];
  if (q.status) { where.push('status = ?'); args.push(status(q.status)); }
  for (const f of ['assignee_user_id', 'requester_user_id']) {
    if (q[f] !== undefined && q[f] !== '') {
      const n = Number(q[f]);
      if (!Number.isInteger(n)) throw bad(`${f} must be an integer`);
      where.push(`${f} = ?`); args.push(n);
    }
  }
  if (q.external_ref) { where.push('external_ref = ?'); args.push(String(q.external_ref)); }
  const limit = Math.min(Math.max(parseInt(q.limit, 10) || 50, 1), TASK_LIMITS.LIST_MAX);
  const rows = db.prepare(`SELECT * FROM tasks WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT ?`).all(...args, limit);
  return rows.map((t) => taskSummary(db, t));
}

export function getAppTask(app, id) {
  const db = getDb();
  return detail(db, taskForApp(db, app, id), { kind: 'app' });
}

export function appComment(app, id, body) {
  const db = getDb();
  return addComment(db, taskForApp(db, app, id), { kind: 'app' }, body);
}

export function appSetStatus(app, id, to) {
  const db = getDb();
  const t = changeStatus(db, taskForApp(db, app, id), { kind: 'app' }, to);
  return detail(db, t, { kind: 'app' });
}

export function appDelete(app, id) {
  const db = getDb();
  softDelete(db, taskForApp(db, app, id), { kind: 'app' });
}

/** The app's change feed: every event on its tasks after `since` (a cursor from a previous call, or 0). */
export function appEvents(app, since, limit) {
  const db = getDb();
  const from = since === undefined || since === '' ? 0 : Number(since);
  if (!Number.isInteger(from) || from < 0) throw bad('since must be a cursor returned by this endpoint');
  const n = Math.min(Math.max(parseInt(limit, 10) || 100, 1), TASK_LIMITS.EVENTS_MAX);
  const rows = db.prepare('SELECT * FROM task_events WHERE app_id = ? AND id > ? ORDER BY id LIMIT ?').all(app.id, from, n);
  const events = rows.map((e) => renderEvent(db, e));
  return { events, cursor: rows.length ? String(rows[rows.length - 1].id) : String(from), has_more: rows.length === n };
}

// ── User side ───────────────────────────────────────────────────────────────

const STATUS_GROUPS = { active: ['open', 'in_progress'], closed: ['done', 'declined'] };

export function listMyTasks(user, q = {}) {
  const db = getDb();
  const where = [
    't.deleted_at IS NULL',
    'EXISTS (SELECT 1 FROM app_users m WHERE m.app_id = t.app_id AND m.user_id = ?)',
  ];
  const args = [user.id];
  const box = q.box || 'all';
  if (box === 'assigned') { where.push('t.assignee_user_id = ?'); args.push(user.id); }
  else if (box === 'requested') { where.push('t.requester_user_id = ?'); args.push(user.id); }
  else if (box === 'all') { where.push('(t.assignee_user_id = ? OR t.requester_user_id = ?)'); args.push(user.id, user.id); }
  else throw bad('box must be assigned, requested or all');
  if (q.status) {
    const set = STATUS_GROUPS[q.status] || [status(q.status)];
    where.push(`t.status IN (${set.map(() => '?').join(',')})`); args.push(...set);
  }
  if (q.app) { where.push('a.slug = ?'); args.push(String(q.app)); }
  const limit = Math.min(Math.max(parseInt(q.limit, 10) || 100, 1), TASK_LIMITS.LIST_MAX);
  const rows = db.prepare(`
    SELECT t.*, (SELECT seen_at FROM task_reads r WHERE r.task_id = t.id AND r.user_id = ?) AS seen_at
    FROM tasks t JOIN apps a ON a.id = t.app_id
    WHERE ${where.join(' AND ')}
    ORDER BY t.last_activity_at DESC LIMIT ?
  `).all(user.id, ...args, limit);
  return rows.map((t) => ({
    ...taskSummary(db, t),
    my_roles: rolesOf(t, user.id),
    unread: t.last_actor_user_id !== user.id && (!t.seen_at || t.last_activity_at > t.seen_at),
  }));
}

export function myTaskCounts(user) {
  const db = getDb();
  const row = db.prepare(`
    SELECT
      SUM(CASE WHEN t.assignee_user_id = ? AND t.status IN ('open', 'in_progress') THEN 1 ELSE 0 END) AS open_assigned,
      SUM(CASE WHEN COALESCE(t.last_actor_user_id, -1) != ?
                AND t.last_activity_at > COALESCE((SELECT seen_at FROM task_reads r WHERE r.task_id = t.id AND r.user_id = ?), '')
               THEN 1 ELSE 0 END) AS unread
    FROM tasks t
    WHERE t.deleted_at IS NULL
      AND (t.assignee_user_id = ? OR t.requester_user_id = ?)
      AND EXISTS (SELECT 1 FROM app_users m WHERE m.app_id = t.app_id AND m.user_id = ?)
  `).get(user.id, user.id, user.id, user.id, user.id, user.id);
  return { open_assigned: row.open_assigned || 0, unread: row.unread || 0 };
}

export function getMyTask(user, id) {
  const db = getDb();
  const t = taskForUser(db, user, id);
  db.prepare(`INSERT INTO task_reads (task_id, user_id, seen_at) VALUES (?, ?, ?)
              ON CONFLICT(task_id, user_id) DO UPDATE SET seen_at = excluded.seen_at`).run(t.id, user.id, nowIso());
  return detail(db, t, { kind: 'user', user });
}

export function userComment(user, id, body) {
  const db = getDb();
  return addComment(db, taskForUser(db, user, id), { kind: 'user', user }, body);
}

export function userSetStatus(user, id, to) {
  const db = getDb();
  const t = changeStatus(db, taskForUser(db, user, id), { kind: 'user', user }, to);
  return detail(db, t, { kind: 'user', user });
}

export function userDelete(user, id) {
  const db = getDb();
  softDelete(db, taskForUser(db, user, id), { kind: 'user', user });
}
