// Rendering shared by the Tasks API (app side), the inbox (user side), the
// webhook and the e-mails. Plain data only: every string here is user text and
// is escaped by whoever renders it (React, brandedLayout.esc).

export const TASK_STATUSES = Object.freeze(['open', 'in_progress', 'done', 'declined']);

export const STATUS_LABELS = Object.freeze({
  open: 'Open', in_progress: 'In progress', done: 'Done', declined: 'Declined',
});

export function userRef(db, id) {
  if (id == null) return null;
  const u = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(id);
  return u ? { id: u.id, name: u.name, email: u.email } : { id, name: 'Removed user', email: null };
}

export function taskSummary(db, t) {
  const app = db.prepare('SELECT slug, name FROM apps WHERE id = ?').get(t.app_id);
  return {
    id: t.id,
    app: app ? { slug: app.slug, name: app.name } : null,
    subject: t.subject,
    status: t.status,
    requester: userRef(db, t.requester_user_id),
    assignee: userRef(db, t.assignee_user_id),
    due_date: t.due_date,
    external_ref: t.external_ref,
    url: t.url,
    created_at: t.created_at,
    updated_at: t.updated_at,
    last_activity_at: t.last_activity_at,
  };
}

export function taskComments(db, taskId) {
  return db.prepare('SELECT * FROM task_comments WHERE task_id = ? ORDER BY id').all(taskId).map((c) => ({
    id: c.id,
    author: userRef(db, c.author_user_id),
    via: c.via,
    body: c.body,
    created_at: c.created_at,
  }));
}

export function taskHistory(db, taskId) {
  return db.prepare("SELECT * FROM task_events WHERE task_id = ? AND kind IN ('created', 'status') ORDER BY id").all(taskId)
    .map((e) => ({
      kind: e.kind,
      from_status: e.from_status,
      to_status: e.to_status,
      actor: userRef(db, e.actor_user_id),
      via: e.via,
      created_at: e.created_at,
    }));
}

/** One event as the app sees it, on the poll feed and in a webhook body. */
export function renderEvent(db, ev) {
  const out = {
    cursor: String(ev.id),
    type: `task.${ev.kind}`,
    task_id: ev.task_id,
    actor: userRef(db, ev.actor_user_id),
    via: ev.via,
    created_at: ev.created_at,
  };
  if (ev.kind === 'status' || ev.kind === 'created') {
    out.from_status = ev.from_status;
    out.to_status = ev.to_status;
  }
  if (ev.kind === 'comment' && ev.comment_id != null) {
    const c = db.prepare('SELECT id, body, created_at FROM task_comments WHERE id = ?').get(ev.comment_id);
    out.comment = c ? { id: c.id, body: c.body, created_at: c.created_at } : null;
  }
  return out;
}
