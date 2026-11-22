// Required owner: every app must have at least one ACTIVE owner. An owner row
// whose user is deactivated counts as none; a deleted user's row is already
// gone (app_user_roles cascades).
//
// checkAppOwnership() is the one place that decides. It compares every app
// with the open rows in app_owner_orphans (migration 176): a newly ownerless
// app gets a row, an audit entry and one e-mail per recipient; an app that has
// an owner again gets its row resolved. It is a full sweep and idempotent, so
// the write paths that can orphan an app (SCIM user deprovision and group
// reconcile, user deletion, role changes, access-review decisions) call it
// right after their write for an immediate, attributed result, and the
// 'app-owner-orphans' job runs it every few minutes for any path without a
// hook (MCP tools, direct database changes, future code).

import { getDb } from '../db.js';
import { AppError } from '../utils/errors.js';
import { enqueueEmail } from './emailQueue.js';
import { logAudit } from '../middleware/audit.js';
import { jobStarted, trackJobSync } from './jobHealth.js';
import { renderOrphaned } from './appOwnershipMail.js';
import log from '../utils/logger.js';

export const OWNER_MAIL_SOURCE = 'app-owner';
const TICK_MS = 5 * 60_000;
let timer = null;

const ACTIVE_OWNER_EXISTS = `EXISTS (
  SELECT 1 FROM app_user_roles r JOIN users u ON u.id = r.user_id
  WHERE r.app_id = a.id AND r.app_role = 'owner' AND u.active = 1)`;

export function activeOwners(db, appId) {
  return db.prepare(`SELECT u.id, u.name, u.email FROM app_user_roles r JOIN users u ON u.id = r.user_id
                     WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 1 ORDER BY u.id`).all(appId);
}

/**
 * The last-owner guard, counted over ACTIVE owners: removing or demoting the
 * one active owner is refused, while an inactive owner's row never kept an app
 * owned and may go.
 */
export function assertNotLastActiveOwner(db, appId, userId) {
  const target = db.prepare(`SELECT r.app_role, u.active FROM app_user_roles r JOIN users u ON u.id = r.user_id
                             WHERE r.app_id = ? AND r.user_id = ?`).get(appId, userId);
  if (target?.app_role !== 'owner' || !target.active) return;
  if (activeOwners(db, appId).length <= 1) {
    throw new AppError('Cannot remove the last owner of the app. Assign another owner first.', 400, 'LAST_OWNER');
  }
}

export function openOrphan(db, appId) {
  return db.prepare('SELECT * FROM app_owner_orphans WHERE app_id = ? AND resolved_at IS NULL').get(appId) || null;
}

function diagnose(db, appId) {
  const inactive = db.prepare(`SELECT u.id FROM app_user_roles r JOIN users u ON u.id = r.user_id
                               WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 0`).all(appId).map((r) => r.id);
  if (inactive.length) return { reason: 'owner-deactivated', former_owner_ids: inactive };
  const last = db.prepare(`SELECT user_id FROM app_access_changes WHERE app_id = ? AND old_role = 'owner'
                           ORDER BY id DESC LIMIT 1`).get(appId);
  if (!last) return { reason: 'no-owner', former_owner_ids: [] };
  const exists = db.prepare('SELECT 1 FROM users WHERE id = ?').get(last.user_id);
  return { reason: exists ? 'owner-removed' : 'owner-deleted', former_owner_ids: [last.user_id] };
}

function recipients(db, appId) {
  const rows = db.prepare(`
    SELECT u.id, u.name, u.email, CASE WHEN u.role = 'platform_admin' THEN 'platform_admin' ELSE 'app_admin' END AS recipient_role
      FROM users u
     WHERE u.active = 1 AND u.email IS NOT NULL AND trim(u.email) != '' AND COALESCE(u.kind, 'human') = 'human'
       AND (u.role = 'platform_admin'
            OR EXISTS (SELECT 1 FROM app_user_roles r WHERE r.app_id = ? AND r.user_id = u.id AND r.app_role = 'admin'))
     ORDER BY u.id`).all(appId);
  return rows;
}

function notify(db, orphan, app, cause, reason) {
  let sent = 0;
  for (const user of recipients(db, app.id)) {
    const mail = renderOrphaned({ app, user, reason, cause, recipientRole: user.recipient_role });
    try {
      enqueueEmail({ ...mail, to: user.email, appId: null, source: OWNER_MAIL_SOURCE, idempotencyKey: `${OWNER_MAIL_SOURCE}:orphan:${orphan}:${user.id}` });
      sent++;
    } catch (e) {
      if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[app-owner] orphan mail for app ${app.id} to user ${user.id} not queued: ${e.message}`);
    }
  }
  db.prepare("UPDATE app_owner_orphans SET notified_at = datetime('now'), notify_note = ? WHERE id = ?")
    .run(sent ? `mailed ${sent}` : 'no recipient with an e-mail address', orphan);
  return sent;
}

/** Resolve the open orphan row of an app, if any. Returns true when one was resolved. */
export function resolveOrphan(db, appId, { by = null, resolution }) {
  const row = openOrphan(db, appId);
  if (!row) return false;
  db.prepare("UPDATE app_owner_orphans SET resolved_at = datetime('now'), resolved_by = ?, resolution = ? WHERE id = ?")
    .run(by, resolution, row.id);
  db.prepare(`UPDATE app_owner_transfers SET status = 'superseded', decided_at = datetime('now')
              WHERE app_id = ? AND status = 'pending' AND kind = 'orphan'`).run(appId);
  logAudit(by, db.prepare('SELECT 1 FROM apps WHERE id = ?').get(appId) ? appId : null, 'app-owner-restored',
    { orphan_id: row.id, resolution });
  return true;
}

/**
 * One sweep. cause names the write that prompted it ('sweep' for the job);
 * actorId is who made that write, when known. Returns the app ids it orphaned
 * and resolved.
 */
export function checkAppOwnership(db = getDb(), { cause = 'sweep', actorId = null } = {}) {
  const out = { orphaned: [], resolved: [], expired: 0 };
  db.transaction(() => {
    const ownerless = db.prepare(`SELECT a.id, a.name, a.slug FROM apps a WHERE NOT ${ACTIVE_OWNER_EXISTS}`).all();
    const open = new Map(db.prepare('SELECT * FROM app_owner_orphans WHERE resolved_at IS NULL').all().map((r) => [r.app_id, r]));
    const ownerlessIds = new Set(ownerless.map((a) => a.id));

    for (const app of ownerless) {
      if (open.has(app.id)) continue;
      const d = diagnose(db, app.id);
      const id = db.prepare('INSERT INTO app_owner_orphans (app_id, cause, detail) VALUES (?, ?, ?)')
        .run(app.id, cause, JSON.stringify(d)).lastInsertRowid;
      logAudit(actorId, app.id, 'app-owner-orphaned', { orphan_id: id, cause, ...d }, actorId ? null : 'system');
      notify(db, id, app, cause, d.reason);
      out.orphaned.push(app.id);
    }

    for (const [appId] of open) {
      if (ownerlessIds.has(appId)) continue;
      const exists = db.prepare('SELECT 1 FROM apps WHERE id = ?').get(appId);
      const newest = exists && db.prepare(`SELECT r.user_id FROM app_user_roles r JOIN users u ON u.id = r.user_id
        WHERE r.app_id = ? AND r.app_role = 'owner' AND u.active = 1 ORDER BY r.rowid DESC LIMIT 1`).get(appId);
      resolveOrphan(db, appId, { by: actorId ?? newest?.user_id ?? null, resolution: exists ? 'owner-restored' : 'app-deleted' });
      out.resolved.push(appId);
    }

    out.expired = db.prepare(`UPDATE app_owner_transfers SET status = 'expired', decided_at = datetime('now')
                              WHERE status = 'pending' AND expires_at <= datetime('now')`).run().changes;
  })();
  if (out.orphaned.length) log.warn(`[app-owner] ${out.orphaned.length} app(s) lost their last owner (${cause})`);
  return out;
}

/** checkAppOwnership for a write path: never lets a failure here fail the write that called it. */
export function afterOwnershipWrite(db, cause, actorId = null) {
  try {
    return checkAppOwnership(db, { cause, actorId });
  } catch (e) {
    log.warn(`[app-owner] ownership check after ${cause} failed, the sweep will retry: ${e.message}`);
    return null;
  }
}

export function listOrphanedApps(db = getDb()) {
  return db.prepare(`
    SELECT o.id AS orphan_id, o.app_id, a.slug, a.name, o.orphaned_at, o.cause, o.detail, o.notified_at, o.notify_note,
           CAST((julianday('now') - julianday(o.orphaned_at)) AS INTEGER) AS age_days,
           (julianday('now') - julianday(o.orphaned_at)) * 86400 AS age_seconds,
           t.id AS transfer_id, t.nominee_user_id, nu.name AS nominee_name, nu.email AS nominee_email, t.created_at AS transfer_created_at, t.expires_at AS transfer_expires_at
      FROM app_owner_orphans o
      JOIN apps a ON a.id = o.app_id
      LEFT JOIN app_owner_transfers t ON t.app_id = o.app_id AND t.status = 'pending'
      LEFT JOIN users nu ON nu.id = t.nominee_user_id
     WHERE o.resolved_at IS NULL
     ORDER BY o.orphaned_at, o.id`).all().map((r) => ({
    ...r,
    age_seconds: Math.max(0, Math.round(r.age_seconds)),
    detail: r.detail ? JSON.parse(r.detail) : null,
  }));
}

export function startAppOwnershipWorker() {
  if (timer) return;
  jobStarted('app-owner-orphans');
  const run = () => {
    try { trackJobSync('app-owner-orphans', () => checkAppOwnership()); } catch (e) { log.warn(`[app-owner] sweep failed: ${e.message}`); }
  };
  run();
  timer = setInterval(run, TICK_MS);
  timer.unref?.();
}

export function stopAppOwnershipWorker() {
  if (timer) { clearInterval(timer); timer = null; }
}
