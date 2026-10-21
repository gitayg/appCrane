// Data classification per app, and the policy each level carries.
//
// The level lives on the app's intake row (migration 139). The policy table is
// one settings row ('classification_policy', JSON) holding only what a platform
// admin changed; everything else reads from DEFAULT_POLICY, so an upgrade with
// no row behaves exactly as documented below.

import { AppError } from '../utils/errors.js';
import { isPlatformAdmin } from '../utils/roles.js';
import { roleForUserOnApp } from './permissions.js';
import { logAudit } from '../middleware/audit.js';
import { recordEvent } from './eventStore.js';

export const LEVELS = Object.freeze(['public', 'internal', 'confidential', 'restricted']);
export const DEFAULT_LEVEL = 'internal';
export const MODES = Object.freeze(['enforce', 'warn', 'off']);
export const GLOBAL_MODES = Object.freeze(['by_classification', ...MODES]);
const POLICY_KEY = 'classification_policy';

export const DEFAULT_POLICY = Object.freeze({
  release_check_mode: 'by_classification',
  block_vulnerable_dependencies: true,
  levels: Object.freeze({
    public:       Object.freeze({ intake_approval: false, release_check: 'warn',    require_access_rules: false, allow_sso_bypass: true,  allow_public_visibility: true,  exceptions_by: 'owner' }),
    internal:     Object.freeze({ intake_approval: false, release_check: 'warn',    require_access_rules: false, allow_sso_bypass: true,  allow_public_visibility: true,  exceptions_by: 'owner' }),
    confidential: Object.freeze({ intake_approval: true,  release_check: 'enforce', require_access_rules: false, allow_sso_bypass: false, allow_public_visibility: false, exceptions_by: 'owner' }),
    restricted:   Object.freeze({ intake_approval: true,  release_check: 'enforce', require_access_rules: true,  allow_sso_bypass: false, allow_public_visibility: false, exceptions_by: 'platform_admin' }),
  }),
});

const BOOL_FIELDS = ['intake_approval', 'require_access_rules', 'allow_sso_bypass', 'allow_public_visibility'];

export function rank(level) { return LEVELS.indexOf(level); }

function readStored(db) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(POLICY_KEY);
  if (!row?.value) return {};
  try { return JSON.parse(row.value) || {}; } catch { return {}; }
}

/** The effective policy: defaults with the stored overrides applied. */
export function getClassificationPolicy(db) {
  const stored = readStored(db);
  const levels = {};
  for (const l of LEVELS) levels[l] = { ...DEFAULT_POLICY.levels[l], ...(stored.levels?.[l] || {}) };
  const mode = GLOBAL_MODES.includes(stored.release_check_mode) ? stored.release_check_mode : DEFAULT_POLICY.release_check_mode;
  const blockVuln = typeof stored.block_vulnerable_dependencies === 'boolean' ? stored.block_vulnerable_dependencies : DEFAULT_POLICY.block_vulnerable_dependencies;
  return { release_check_mode: mode, block_vulnerable_dependencies: blockVuln, levels };
}

function validatePatch(patch) {
  const bad = (m) => { throw new AppError(m, 400, 'VALIDATION'); };
  if (!patch || typeof patch !== 'object') bad('policy must be an object');
  const out = {};
  if (patch.release_check_mode !== undefined) {
    if (!GLOBAL_MODES.includes(patch.release_check_mode)) bad(`release_check_mode must be one of ${GLOBAL_MODES.join(', ')}`);
    out.release_check_mode = patch.release_check_mode;
  }
  if (patch.block_vulnerable_dependencies !== undefined) {
    if (typeof patch.block_vulnerable_dependencies !== 'boolean') bad('block_vulnerable_dependencies must be true or false');
    out.block_vulnerable_dependencies = patch.block_vulnerable_dependencies;
  }
  if (patch.levels !== undefined) {
    if (!patch.levels || typeof patch.levels !== 'object') bad('levels must be an object');
    out.levels = {};
    for (const [level, fields] of Object.entries(patch.levels)) {
      if (!LEVELS.includes(level)) bad(`unknown classification '${level}'`);
      if (!fields || typeof fields !== 'object') bad(`levels.${level} must be an object`);
      const f = {};
      for (const [k, v] of Object.entries(fields)) {
        if (BOOL_FIELDS.includes(k)) {
          if (typeof v !== 'boolean') bad(`levels.${level}.${k} must be true or false`);
          f[k] = v;
        } else if (k === 'release_check') {
          if (!MODES.includes(v)) bad(`levels.${level}.release_check must be one of ${MODES.join(', ')}`);
          f[k] = v;
        } else if (k === 'exceptions_by') {
          if (!['owner', 'platform_admin'].includes(v)) bad(`levels.${level}.exceptions_by must be owner or platform_admin`);
          f[k] = v;
        } else {
          bad(`unknown policy field '${k}'`);
        }
      }
      out.levels[level] = f;
    }
  }
  return out;
}

/** Partial update by a platform admin. Returns the effective policy. */
export function setClassificationPolicy(db, patch, user) {
  if (!isPlatformAdmin(user)) throw new AppError('Only platform admins can change the classification policy', 403, 'FORBIDDEN');
  const clean = validatePatch(patch);
  const stored = readStored(db);
  const next = { ...stored };
  if (clean.release_check_mode) next.release_check_mode = clean.release_check_mode;
  if (clean.block_vulnerable_dependencies !== undefined) next.block_vulnerable_dependencies = clean.block_vulnerable_dependencies;
  if (clean.levels) {
    next.levels = { ...(stored.levels || {}) };
    for (const [l, f] of Object.entries(clean.levels)) next.levels[l] = { ...(next.levels[l] || {}), ...f };
  }
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(POLICY_KEY, JSON.stringify(next), user.id);
  logAudit(user.id, null, 'classification-policy-change', { patch: clean });
  return getClassificationPolicy(db);
}

export function levelPolicy(db, level) {
  return getClassificationPolicy(db).levels[LEVELS.includes(level) ? level : DEFAULT_LEVEL];
}

/** The app's level, or the default when it has no intake row. */
export function getClassification(db, appId) {
  const row = db.prepare('SELECT data_classification, classification_locked FROM app_intake WHERE app_id = ?').get(appId);
  return { level: row?.data_classification || DEFAULT_LEVEL, locked: !!row?.classification_locked, has_intake: !!row };
}

export function assertLevel(level) {
  if (!LEVELS.includes(level)) throw new AppError(`data_classification must be one of ${LEVELS.join(', ')}`, 400, 'VALIDATION');
  return level;
}

/**
 * Change an app's classification.
 * Platform admins: any level, and their choice locks it against owners.
 * Owners: only while not locked; once intake is approved they may only raise it.
 */
export function setClassification(db, app, level, user) {
  assertLevel(level);
  const admin = isPlatformAdmin(user);
  if (!admin && roleForUserOnApp(user, app) !== 'owner') {
    throw new AppError('Only the app owner or a platform admin can set the data classification', 403, 'FORBIDDEN');
  }
  const intake = db.prepare('SELECT data_classification, classification_locked, status FROM app_intake WHERE app_id = ?').get(app.id);
  const current = intake?.data_classification || DEFAULT_LEVEL;
  if (!admin) {
    if (intake?.classification_locked) {
      throw new AppError('A platform admin set this classification; ask a platform admin to change it', 403, 'CLASSIFICATION_LOCKED');
    }
    if ((intake?.status ?? 'approved') === 'approved' && rank(level) < rank(current)) {
      throw new AppError(`Lowering an approved app's classification (${current} to ${level}) needs a platform admin`, 403, 'CLASSIFICATION_LOWER_NEEDS_ADMIN');
    }
  }
  // An approval given at a level that needed none does not cover a level that
  // does: an owner raising the app into one sends it back for review.
  const reReview = !admin && intake?.status === 'approved'
    && levelPolicy(db, level).intake_approval && !levelPolicy(db, current).intake_approval;
  if (intake) {
    db.prepare(`UPDATE app_intake SET data_classification = ?, classification_locked = ?,
      status = CASE WHEN ? THEN 'pending' ELSE status END, updated_at = datetime('now') WHERE app_id = ?`)
      .run(level, admin ? 1 : intake.classification_locked, reReview ? 1 : 0, app.id);
  } else {
    const pending = !admin && levelPolicy(db, level).intake_approval;
    db.prepare(`INSERT INTO app_intake (app_id, data_classification, classification_locked, status, grandfathered)
      VALUES (?, ?, ?, ?, ?)`).run(app.id, level, admin ? 1 : 0, pending ? 'pending' : 'approved', pending ? 0 : 1);
  }
  if (current !== level) {
    logAudit(user.id, app.id, 'app-classification-change', { from: current, to: level, by_platform_admin: admin });
    recordEvent({
      kind: 'classification.changed', severity: rank(level) < rank(current) ? 'warning' : 'info',
      appId: app.id, userId: user.id, summary: `Data classification changed from ${current} to ${level}`,
      data: { from: current, to: level },
    });
  }
  return { ...getClassification(db, app.id), previous: current, intake_status: db.prepare('SELECT status FROM app_intake WHERE app_id = ?').get(app.id).status };
}
