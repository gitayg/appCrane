// E-mail a person when their access to an app changes.
//
// Triggers on app_user_roles (migration 171) record every change in
// app_access_changes. Every TICK_MS this worker takes the changes for each
// (app, user) whose latest change is at least DEBOUNCE_S old, compares the
// role before the earliest of them with the role the person holds now, and
// mails only a real net change: a grant undone a few seconds later sends
// nothing. Rows are marked processed in the same transaction that queues the
// mail, so a crash can neither send twice nor drop a change.
//
// Platform mail (app_id NULL), deduped by the idempotency key, which migration
// 171 makes unique for source 'app-access-change'.

import { getDb } from '../db.js';
import { enqueueEmail } from './emailQueue.js';
import { renderAccessChange } from './appAccessMailContent.js';
import { findAccessActor } from './appAccessActor.js';
import { jobStarted, trackJob } from './jobHealth.js';
import log from '../utils/logger.js';

export const ACCESS_MAIL_SOURCE = 'app-access-change';
export const ACCESS_MAIL_SETTING = 'app_access_mail_enabled';
const TICK_MS = 15_000;
const DEBOUNCE_S = 30;
// The creator's owner row is written in the same request as the app row.
const CREATE_WINDOW_S = 120;
let timer = null;

const ROLES = new Set(['user', 'admin', 'owner']);
const norm = (r) => (ROLES.has(r) ? r : 'none');

export function accessMailEnabled(db) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(ACCESS_MAIL_SETTING)?.value !== '0';
}

function isCreatorGrantAtCreate(db, app, userId, first, from, to) {
  if (from !== 'none' || to !== 'owner' || app.created_by !== userId) return false;
  const firstForApp = db.prepare('SELECT MIN(id) AS id FROM app_access_changes WHERE app_id = ?').get(app.id).id;
  if (firstForApp !== first.id) return false;
  const gap = db.prepare('SELECT abs(julianday(?) - julianday(?)) * 86400 AS s').get(first.created_at, app.created_at).s;
  return gap != null && gap <= CREATE_WINDOW_S;
}

function recipient(db, userId) {
  return db.prepare(`SELECT id, name, username, email FROM users WHERE id = ? AND active = 1
                     AND email IS NOT NULL AND trim(email) != '' AND COALESCE(kind, 'human') = 'human'`).get(userId) || null;
}

/** Decide one (app, user) group. Returns 'sent', 'skipped' or 'failed'; 'failed' leaves the rows for the next tick. */
function processGroup(db, rows, { enabled, markProcessed }) {
  const first = rows[0];
  const last = rows[rows.length - 1];
  const { app_id: appId, user_id: userId } = first;
  const ids = rows.map((r) => r.id);
  const skip = () => { markProcessed(ids); return 'skipped'; };

  if (!enabled) return skip();
  const from = norm(first.old_role);
  const to = norm(db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(appId, userId)?.app_role);
  if (from === to) return skip();
  const app = db.prepare('SELECT id, name, slug, created_by, created_at FROM apps WHERE id = ?').get(appId);
  if (!app) return skip();
  const user = recipient(db, userId);
  if (!user) return skip();
  if (isCreatorGrantAtCreate(db, app, userId, first, from, to)) return skip();

  const actor = findAccessActor(db, { appId, target: user, firstAt: first.created_at, lastAt: last.created_at });
  const mail = renderAccessChange({ app, user, from, to, actor });
  const key = `${ACCESS_MAIL_SOURCE}:${appId}:${userId}:${ids[0]}-${ids[ids.length - 1]}:${ids.length}`;
  try {
    db.transaction(() => {
      enqueueEmail({ ...mail, to: user.email, appId: null, source: ACCESS_MAIL_SOURCE, idempotencyKey: key });
      markProcessed(ids);
    })();
    return 'sent';
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') { markProcessed(ids); return 'skipped'; }
    log.warn(`[app-access-mail] mail for app ${appId} user ${userId} not queued, will retry: ${e.message}`);
    return 'failed';
  }
}

/** One pass. debounceSeconds is how long a person's latest change must have settled. */
export function processAppAccessChanges(db = getDb(), { debounceSeconds = DEBOUNCE_S } = {}) {
  const out = { sent: 0, skipped: 0, failed: 0, waiting: 0 };
  db.transaction(() => {
    const cutoff = db.prepare('SELECT datetime(\'now\', ?) AS t').get(`-${Math.max(0, Number(debounceSeconds) || 0)} seconds`).t;
    const rows = db.prepare('SELECT * FROM app_access_changes WHERE processed_at IS NULL ORDER BY id').all();
    const groups = new Map();
    for (const r of rows) {
      const k = `${r.app_id}:${r.user_id}`;
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(r);
    }
    const enabled = accessMailEnabled(db);
    const mark = db.prepare("UPDATE app_access_changes SET processed_at = datetime('now') WHERE id = ?");
    const markProcessed = (ids) => { for (const id of ids) mark.run(id); };
    for (const group of groups.values()) {
      if (group[group.length - 1].created_at > cutoff) { out.waiting++; continue; }
      out[processGroup(db, group, { enabled, markProcessed })]++;
    }
  })();
  return out;
}

export function startAppAccessMailWorker() {
  if (timer) return;
  log.info(`[app-access-mail] worker started (tick every ${TICK_MS / 1000}s)`);
  jobStarted('app-access-mail');
  timer = setInterval(() => {
    trackJob('app-access-mail', () => processAppAccessChanges()).catch((e) => log.warn(`[app-access-mail] tick failed: ${e.message}`));
  }, TICK_MS);
}

export function stopAppAccessMailWorker() {
  if (timer) { clearInterval(timer); timer = null; }
}
