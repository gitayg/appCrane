import { logAudit } from '../../middleware/audit.js';
import { recordEvent } from '../eventStore.js';

// Every sign-in risk signal is one event (kind login.risk.*, so the SIEM
// mapping files it under authentication and a "login" kind filter keeps it)
// plus, when it is an action on an account, one audit row.

export const KINDS = Object.freeze({
  newDevice: 'login.risk.new_device',
  locked: 'login.risk.locked',
  lockedRefused: 'login.risk.locked_refused',
  unlocked: 'login.risk.unlocked',
  stuffing: 'login.risk.stuffing',
  reported: 'login.risk.reported',
  staleDeactivated: 'login.risk.stale_deactivated',
});

export function signal({ kind, severity = 'info', userId = null, subjectUserId = null, summary, data = {}, audit = null, dedupeKey, dedupeMs }) {
  if (audit) {
    try { logAudit(audit.actorId ?? null, null, audit.action, { ...data, ...(subjectUserId && { target_user_id: subjectUserId }) }); } catch (_) {}
  }
  return recordEvent({ kind, severity, userId, subjectUserId, summary, data, dedupeKey, dedupeMs });
}
