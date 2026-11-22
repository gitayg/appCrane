// Ownership transfer: someone is nominated as an app's owner, gets an e-mail,
// and accepts or declines in the dashboard. Acceptance makes them owner and
// resolves the app's orphan record. A platform admin can also assign an owner
// directly.
//
// Who may nominate:
//   - a platform admin, on any app;
//   - an owner of the app (a handover), who may also step down to admin when
//     the nominee accepts. An owner can already make anyone a co-owner through
//     PUT /api/apps/:slug/roles, so this gives them no new power;
//   - an app admin, only while the app is orphaned, and never themselves. The
//     nominee still has to accept, and platform admins see every pending
//     transfer on the orphaned-apps list.
// Only the nominee can accept or decline; nobody accepts on someone's behalf.

import { AppError } from '../utils/errors.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from './permissions.js';
import { logAudit } from '../middleware/audit.js';
import { enqueueEmail } from './emailQueue.js';
import { renderNomination, renderDecision } from './appOwnershipMail.js';
import { OWNER_MAIL_SOURCE, openOrphan, activeOwners, resolveOrphan, afterOwnershipWrite } from './appOwnership.js';
import log from '../utils/logger.js';

const NOTE_MAX = 500;

function mail(db, to, rendered, key) {
  if (!to?.email || !String(to.email).trim()) return false;
  try {
    enqueueEmail({ ...rendered, to: to.email, appId: null, source: OWNER_MAIL_SOURCE, idempotencyKey: key });
    return true;
  } catch (e) {
    if (e.code !== 'SQLITE_CONSTRAINT_UNIQUE') log.warn(`[app-owner] mail ${key} not queued: ${e.message}`);
    return false;
  }
}

function pendingTransfer(db, appId) {
  return db.prepare("SELECT * FROM app_owner_transfers WHERE app_id = ? AND status = 'pending' AND expires_at > datetime('now')").get(appId) || null;
}

function activeHuman(db, { user_id, email }) {
  if (!user_id && !email) throw new AppError('user_id or email is required', 400, 'VALIDATION');
  const u = user_id
    ? db.prepare("SELECT id, name, email, active, COALESCE(kind, 'human') AS kind FROM users WHERE id = ?").get(Number(user_id))
    : db.prepare("SELECT id, name, email, active, COALESCE(kind, 'human') AS kind FROM users WHERE lower(email) = lower(?)").get(String(email).trim());
  if (!u || !u.active) throw new AppError('That user does not exist or is not active.', 404, 'NOT_FOUND');
  if (u.kind !== 'human') throw new AppError('Only a person can own an app, not an agent identity.', 400, 'NOMINEE_NOT_HUMAN');
  return u;
}

function setOwner(db, appId, userId) {
  db.prepare(`INSERT INTO app_user_roles (app_id, user_id, app_role) VALUES (?, ?, 'owner')
              ON CONFLICT(app_id, user_id) DO UPDATE SET app_role = 'owner'`).run(appId, userId);
}

function publicTransfer(db, t) {
  if (!t) return null;
  const who = db.prepare('SELECT id, name, email FROM users WHERE id = ?');
  const app = db.prepare('SELECT slug, name FROM apps WHERE id = ?').get(t.app_id);
  return {
    id: t.id, app_id: t.app_id, app_slug: app?.slug ?? null, app_name: app?.name ?? null,
    kind: t.kind, step_down: !!t.step_down, note: t.note, status: t.status,
    created_at: t.created_at, expires_at: t.expires_at, decided_at: t.decided_at,
    nominee: who.get(t.nominee_user_id) || null,
    nominated_by: t.nominated_by ? who.get(t.nominated_by) || null : null,
  };
}

/** The ownership state of one app, as its members see it. */
export function ownershipOf(db, app, viewer) {
  const orphan = openOrphan(db, app.id);
  const appRole = isPlatformAdmin(viewer) ? 'platform_admin' : roleForUserOnApp(viewer, app);
  const pending = pendingTransfer(db, app.id);
  return {
    app: app.slug,
    owners: activeOwners(db, app.id),
    orphaned: !!orphan,
    orphan: orphan ? { orphaned_at: orphan.orphaned_at, cause: orphan.cause, detail: orphan.detail ? JSON.parse(orphan.detail) : null } : null,
    pending_transfer: publicTransfer(db, pending),
    can_nominate: appRole === 'platform_admin' || appRole === 'owner' || (appRole === 'admin' && !!orphan),
    can_assign: appRole === 'platform_admin',
    viewer_role: appRole,
  };
}

export function nominateOwner(db, actor, app, { user_id, email, step_down = false, note = null } = {}) {
  const orphan = openOrphan(db, app.id);
  const pa = isPlatformAdmin(actor);
  const appRole = roleForUserOnApp(actor, app);
  const isOwner = appRole === 'owner';
  if (!pa && !isOwner) {
    if (appRole !== 'admin') throw new AppError('Only a platform admin or an owner of this app can nominate a new owner.', 403, 'FORBIDDEN');
    if (!orphan) throw new AppError('App admins can nominate an owner only while the app has none.', 403, 'FORBIDDEN');
  }
  const nominee = activeHuman(db, { user_id, email });
  if (!pa && !isOwner) {
    if (nominee.id === actor.id) throw new AppError('You cannot nominate yourself. Nominate someone else, or ask a platform admin.', 403, 'SELF_NOMINATION');
  }
  if (step_down && !isOwner) throw new AppError('Only an owner can step down as part of a handover.', 400, 'VALIDATION');
  if (activeOwners(db, app.id).some((o) => o.id === nominee.id)) throw new AppError('That person already owns this app.', 409, 'ALREADY_OWNER');
  if (step_down && nominee.id === actor.id) throw new AppError('You cannot hand the app over to yourself.', 400, 'VALIDATION');
  if (pendingTransfer(db, app.id)) throw new AppError('This app already has a pending owner nomination. Cancel it first.', 409, 'TRANSFER_PENDING');
  const cleanNote = note == null ? null : String(note).trim().slice(0, NOTE_MAX) || null;

  const kind = orphan ? 'orphan' : 'handover';
  const t = db.transaction(() => {
    db.prepare("UPDATE app_owner_transfers SET status = 'expired', decided_at = datetime('now') WHERE app_id = ? AND status = 'pending'").run(app.id);
    const id = db.prepare(`INSERT INTO app_owner_transfers (app_id, nominee_user_id, nominated_by, kind, step_down, note)
                           VALUES (?, ?, ?, ?, ?, ?)`).run(app.id, nominee.id, actor.id, kind, step_down ? 1 : 0, cleanNote).lastInsertRowid;
    logAudit(actor.id, app.id, 'app-owner-nominate', { transfer_id: id, nominee_user_id: nominee.id, kind, step_down: !!step_down });
    return db.prepare('SELECT * FROM app_owner_transfers WHERE id = ?').get(id);
  })();
  mail(db, nominee, renderNomination({ app, nominee, nominator: actor, kind, note: cleanNote, expiresAt: t.expires_at }),
    `${OWNER_MAIL_SOURCE}:transfer:${t.id}`);
  return publicTransfer(db, t);
}

function loadForNominee(db, actor, id) {
  const t = db.prepare('SELECT * FROM app_owner_transfers WHERE id = ?').get(Number(id));
  // The same answer for "not yours" and "does not exist": a transfer id says nothing to anyone else.
  if (!t || t.nominee_user_id !== actor.id) throw new AppError('Owner nomination not found', 404, 'NOT_FOUND');
  if (t.status !== 'pending') throw new AppError(`This nomination is already ${t.status}.`, 409, 'NOT_PENDING');
  if (db.prepare("SELECT datetime('now') >= ? AS late").get(t.expires_at).late) {
    db.prepare("UPDATE app_owner_transfers SET status = 'expired', decided_at = datetime('now') WHERE id = ?").run(t.id);
    throw new AppError('This nomination has expired. Ask for a new one.', 409, 'EXPIRED');
  }
  return t;
}

/**
 * Why a pending nomination can no longer be accepted, or null when it still
 * stands: the authority it was made under must still exist at acceptance.
 */
export function staleReason(db, t, nominee) {
  if (t.kind === 'orphan' && !openOrphan(db, t.app_id)) return 'the app has an owner again';
  const by = t.nominated_by
    ? db.prepare('SELECT id, role, active FROM users WHERE id = ?').get(t.nominated_by)
    : null;
  if (!by || !by.active) return 'the person who nominated you is no longer active';
  if (by.role !== 'platform_admin') {
    const r = db.prepare('SELECT app_role FROM app_user_roles WHERE app_id = ? AND user_id = ?').get(t.app_id, by.id)?.app_role;
    const ok = t.kind === 'handover' ? r === 'owner' : (r === 'owner' || r === 'admin');
    if (!ok) return 'the person who nominated you no longer has the role needed to nominate an owner';
  }
  const u = db.prepare("SELECT active, COALESCE(kind, 'human') AS kind FROM users WHERE id = ?").get(nominee.id);
  if (!u || !u.active || u.kind !== 'human') return 'you can no longer own an app';
  return null;
}

export function decideTransfer(db, actor, id, accept) {
  if (actor.view_as) throw new AppError('Stop previewing a role before answering an owner nomination.', 403, 'FORBIDDEN');
  const t = loadForNominee(db, actor, id);
  const app = db.prepare('SELECT id, slug, name FROM apps WHERE id = ?').get(t.app_id);
  if (!app) throw new AppError('Owner nomination not found', 404, 'NOT_FOUND');
  const stale = db.transaction(() => {
    const why = accept ? staleReason(db, t, actor) : null;
    if (why) {
      db.prepare("UPDATE app_owner_transfers SET status = 'superseded', decided_at = datetime('now') WHERE id = ? AND status = 'pending'").run(t.id);
      logAudit(actor.id, app.id, 'app-owner-nomination-superseded', { transfer_id: t.id, kind: t.kind, reason: why });
      return why;
    }
    db.prepare("UPDATE app_owner_transfers SET status = ?, decided_at = datetime('now'), decided_by = ? WHERE id = ?")
      .run(accept ? 'accepted' : 'declined', actor.id, t.id);
    if (accept) {
      setOwner(db, app.id, actor.id);
      if (t.step_down && t.nominated_by && t.nominated_by !== actor.id) {
        db.prepare("UPDATE app_user_roles SET app_role = 'admin' WHERE app_id = ? AND user_id = ? AND app_role = 'owner'").run(app.id, t.nominated_by);
      }
      resolveOrphan(db, app.id, { by: actor.id, resolution: 'transfer-accepted' });
    }
    logAudit(actor.id, app.id, accept ? 'app-owner-accept' : 'app-owner-decline', { transfer_id: t.id, kind: t.kind });
    return null;
  })();
  if (stale) throw new AppError(`This nomination no longer stands: ${stale}. Ask a platform admin for a new one.`, 409, 'TRANSFER_STALE');
  afterOwnershipWrite(db, accept ? 'owner-transfer' : 'owner-transfer-declined', actor.id);
  const nominator = t.nominated_by
    ? db.prepare('SELECT id, name, email FROM users WHERE id = ? AND active = 1').get(t.nominated_by)
    : null;
  if (nominator && nominator.id !== actor.id) {
    mail(db, nominator, renderDecision({ app, nominator, nominee: actor, accepted: accept }), `${OWNER_MAIL_SOURCE}:decision:${t.id}`);
  }
  return publicTransfer(db, db.prepare('SELECT * FROM app_owner_transfers WHERE id = ?').get(t.id));
}

export function cancelTransfer(db, actor, app, id) {
  const t = db.prepare("SELECT * FROM app_owner_transfers WHERE id = ? AND app_id = ?").get(Number(id), app.id);
  if (!t) throw new AppError('Owner nomination not found', 404, 'NOT_FOUND');
  if (t.status !== 'pending') throw new AppError(`This nomination is already ${t.status}.`, 409, 'NOT_PENDING');
  const allowed = isPlatformAdmin(actor) || t.nominated_by === actor.id || roleForUserOnApp(actor, app) === 'owner';
  if (!allowed) throw new AppError('Only the person who nominated, an owner of the app or a platform admin can cancel this.', 403, 'FORBIDDEN');
  db.prepare("UPDATE app_owner_transfers SET status = 'cancelled', decided_at = datetime('now'), decided_by = ? WHERE id = ?").run(actor.id, t.id);
  logAudit(actor.id, app.id, 'app-owner-nomination-cancel', { transfer_id: t.id });
  return publicTransfer(db, db.prepare('SELECT * FROM app_owner_transfers WHERE id = ?').get(t.id));
}

export function assignOwner(db, actor, app, { user_id, email } = {}) {
  if (!isPlatformAdmin(actor)) throw new AppError('Only a platform admin can assign an owner directly.', 403, 'FORBIDDEN_PLATFORM_ADMIN');
  const user = activeHuman(db, { user_id, email });
  db.transaction(() => {
    setOwner(db, app.id, user.id);
    db.prepare("UPDATE app_owner_transfers SET status = 'superseded', decided_at = datetime('now'), decided_by = ? WHERE app_id = ? AND status = 'pending'")
      .run(actor.id, app.id);
    resolveOrphan(db, app.id, { by: actor.id, resolution: 'assigned' });
    logAudit(actor.id, app.id, 'app-owner-assign', { user_id: user.id });
  })();
  afterOwnershipWrite(db, 'owner-assign', actor.id);
  return { app: app.slug, owners: activeOwners(db, app.id) };
}

export function transfersForNominee(db, userId) {
  return db.prepare(`SELECT * FROM app_owner_transfers WHERE nominee_user_id = ? AND status = 'pending' AND expires_at > datetime('now')
                     ORDER BY id`).all(userId).map((t) => publicTransfer(db, t));
}
