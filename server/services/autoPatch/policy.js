// The written policy behind RCE auto-patch, and who may change it.
//
// Platform setting `auto_approve_rce_fixes`: ON unless a platform admin has
// stored 'false'. A missing row is ON, so a fresh install and an upgraded one
// both start with the policy in force.
//
// Per app: the owner or a platform admin may opt an app out. Opting back in
// follows who opted out: an owner's opt-out may be reversed by the owner or a
// platform admin; a platform admin's opt-out only by a platform admin, so an
// owner cannot undo a decision taken above them.
//
// `auto_patch_cooldown_hours` (default 24, 0 to 168): how long a fixed version
// must have been on the registry before it is applied without a person. A day
// is long enough for most hijacked or broken releases to be noticed and
// unpublished (npm allows unpublish within 72 hours) and short enough that an
// RCE fix does not wait a working week.

import { AppError } from '../../utils/errors.js';
import { isPlatformAdmin } from '../../utils/roles.js';
import { roleForUserOnApp } from '../permissions.js';
import { logAudit } from '../../middleware/audit.js';

export const POLICY_NAME = 'AppCrane RCE auto-patch policy v1';
export const ENABLED_KEY = 'auto_approve_rce_fixes';
export const COOLDOWN_KEY = 'auto_patch_cooldown_hours';
export const DEFAULT_COOLDOWN_HOURS = 24;
export const MAX_COOLDOWN_HOURS = 168;

function setting(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? null;
}

function putSetting(db, key, value, userId) {
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(key, String(value), userId ?? null);
}

export function getPolicy(db) {
  const raw = setting(db, ENABLED_KEY);
  const enabled = raw === null ? true : String(raw).trim().toLowerCase() !== 'false';
  const c = Number(setting(db, COOLDOWN_KEY));
  const cooldownHours = setting(db, COOLDOWN_KEY) !== null && Number.isFinite(c) && c >= 0 && c <= MAX_COOLDOWN_HOURS
    ? c : DEFAULT_COOLDOWN_HOURS;
  return { name: POLICY_NAME, enabled, cooldown_hours: cooldownHours, default_enabled: true };
}

export function setPolicy(db, patch, user) {
  if (!isPlatformAdmin(user)) throw new AppError('Only a platform admin can change the auto-patch policy', 403, 'FORBIDDEN');
  const before = getPolicy(db);
  if (patch.enabled !== undefined) {
    if (typeof patch.enabled !== 'boolean') throw new AppError('enabled must be true or false', 400, 'VALIDATION');
    putSetting(db, ENABLED_KEY, patch.enabled ? 'true' : 'false', user.id);
  }
  if (patch.cooldown_hours !== undefined) {
    const n = Number(patch.cooldown_hours);
    if (!Number.isFinite(n) || n < 0 || n > MAX_COOLDOWN_HOURS) {
      throw new AppError(`cooldown_hours must be between 0 and ${MAX_COOLDOWN_HOURS}`, 400, 'VALIDATION');
    }
    putSetting(db, COOLDOWN_KEY, n, user.id);
  }
  const after = getPolicy(db);
  logAudit(user.id, null, 'auto-patch-policy-change', { before, after });
  return after;
}

export function getAppOverride(db, appId) {
  return db.prepare('SELECT * FROM app_auto_patch WHERE app_id = ?').get(appId) || null;
}

/** { enabled, reason } for this app: the platform setting, then the app's opt-out. */
export function effectiveForApp(db, app) {
  const policy = getPolicy(db);
  if (!policy.enabled) return { enabled: false, reason: 'the platform setting is off', policy, override: getAppOverride(db, app.id) };
  const o = getAppOverride(db, app.id);
  if (o?.opted_out) return { enabled: false, reason: `opted out by ${o.set_by_role === 'platform_admin' ? 'a platform admin' : 'the app owner'}`, policy, override: o };
  return { enabled: true, reason: 'on (platform default)', policy, override: o };
}

function callerRole(user, app) {
  if (isPlatformAdmin(user)) return 'platform_admin';
  return roleForUserOnApp(user, app) === 'owner' ? 'owner' : null;
}

/** Opt an app out (optedOut = true) or back in. */
export function setAppOptOut(db, app, { opted_out, reason }, user) {
  if (typeof opted_out !== 'boolean') throw new AppError('opted_out must be true or false', 400, 'VALIDATION');
  const role = callerRole(user, app);
  if (!role) throw new AppError('Only the app owner or a platform admin can change auto-patch for this app', 403, 'FORBIDDEN');
  const current = getAppOverride(db, app.id);
  if (!opted_out && current?.opted_out && current.set_by_role === 'platform_admin' && role !== 'platform_admin') {
    throw new AppError('A platform admin opted this app out of auto-patch, so only a platform admin can opt it back in', 403, 'FORBIDDEN');
  }
  const why = typeof reason === 'string' ? reason.trim().slice(0, 500) : null;
  db.prepare(`INSERT INTO app_auto_patch (app_id, opted_out, set_by, set_by_role, reason, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(app_id) DO UPDATE SET opted_out = excluded.opted_out, set_by = excluded.set_by,
      set_by_role = excluded.set_by_role, reason = excluded.reason, updated_at = datetime('now')`)
    .run(app.id, opted_out ? 1 : 0, user.id, role, why || null);
  logAudit(user.id, app.id, opted_out ? 'auto-patch-opt-out' : 'auto-patch-opt-in', { role, reason: why || null });
  return effectiveForApp(db, app);
}
