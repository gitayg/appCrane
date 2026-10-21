import { AppError } from '../../utils/errors.js';

// The platform's access-review policy, one JSON setting. by_classification
// gives a data classification level its own cadence; apps at such a level are
// reviewed in their own campaign instead of the default one.

export const POLICY_KEY = 'access_review_policy';
export const LEVELS = Object.freeze(['public', 'internal', 'confidential', 'restricted']);
export const DEFAULT_LEVEL = 'internal';
export const OVERDUE_ACTIONS = Object.freeze(['none', 'report']);

export const DEFAULT_POLICY = Object.freeze({
  enabled: false,
  cadence_days: 90,
  due_days: 14,
  reminder_days: 3,
  grace_days: 7,
  overdue_action: 'none',
  by_classification: {},
});

const LIMITS = {
  cadence_days: [7, 730],
  due_days: [1, 90],
  reminder_days: [0, 30],
  grace_days: [0, 90],
};

function intIn(v, [lo, hi]) {
  const n = Number(v);
  return Number.isInteger(n) && n >= lo && n <= hi ? n : null;
}

export function getPolicy(db) {
  let stored = {};
  try { stored = JSON.parse(db.prepare('SELECT value FROM settings WHERE key = ?').get(POLICY_KEY)?.value || '{}') || {}; } catch (_) {}
  const out = { ...DEFAULT_POLICY, by_classification: {} };
  if (typeof stored.enabled === 'boolean') out.enabled = stored.enabled;
  for (const k of Object.keys(LIMITS)) {
    const n = intIn(stored[k], LIMITS[k]);
    if (n != null) out[k] = n;
  }
  if (OVERDUE_ACTIONS.includes(stored.overdue_action)) out.overdue_action = stored.overdue_action;
  for (const [lvl, d] of Object.entries(stored.by_classification || {})) {
    const n = intIn(d, LIMITS.cadence_days);
    if (LEVELS.includes(lvl) && n != null) out.by_classification[lvl] = n;
  }
  return out;
}

/** Validate a partial policy and store the merged result. Throws AppError 400 on a bad field. */
export function setPolicy(db, patch, userId) {
  const cur = getPolicy(db);
  const next = { ...cur, by_classification: { ...cur.by_classification } };
  const p = patch || {};
  if (p.enabled !== undefined) {
    if (typeof p.enabled !== 'boolean') throw new AppError('enabled must be true or false', 400, 'VALIDATION');
    next.enabled = p.enabled;
  }
  for (const [k, range] of Object.entries(LIMITS)) {
    if (p[k] === undefined) continue;
    const n = intIn(p[k], range);
    if (n == null) throw new AppError(`${k} must be a whole number from ${range[0]} to ${range[1]}`, 400, 'VALIDATION');
    next[k] = n;
  }
  if (p.overdue_action !== undefined) {
    if (!OVERDUE_ACTIONS.includes(p.overdue_action)) throw new AppError(`overdue_action must be one of ${OVERDUE_ACTIONS.join(', ')}`, 400, 'VALIDATION');
    next.overdue_action = p.overdue_action;
  }
  if (p.by_classification !== undefined) {
    if (!p.by_classification || typeof p.by_classification !== 'object' || Array.isArray(p.by_classification)) {
      throw new AppError('by_classification must be an object of level: days', 400, 'VALIDATION');
    }
    next.by_classification = {};
    for (const [lvl, d] of Object.entries(p.by_classification)) {
      if (!LEVELS.includes(lvl)) throw new AppError(`Unknown classification level '${lvl}'`, 400, 'VALIDATION');
      if (d === null || d === '') continue;
      const n = intIn(d, LIMITS.cadence_days);
      if (n == null) throw new AppError(`${lvl} cadence must be a whole number from 7 to 730`, 400, 'VALIDATION');
      next.by_classification[lvl] = n;
    }
  }
  db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
              ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`)
    .run(POLICY_KEY, JSON.stringify(next), userId ?? null);
  return next;
}

/**
 * An app's data classification. Read defensively: the level lives in
 * app_intake (migration 139) and may also appear as apps.data_classification;
 * neither is required.
 */
export function classificationOf(db, appId) {
  for (const sql of [
    'SELECT data_classification AS c FROM app_intake WHERE app_id = ?',
    'SELECT data_classification AS c FROM apps WHERE id = ?',
  ]) {
    try {
      const c = db.prepare(sql).get(appId)?.c;
      if (LEVELS.includes(c)) return c;
    } catch (_) { /* table or column not there */ }
  }
  return DEFAULT_LEVEL;
}

/** The campaign scopes the policy implies: 'default' plus each level with its own cadence. */
export function scopesOf(policy) {
  return [
    { scope: 'default', cadence_days: policy.cadence_days },
    ...Object.entries(policy.by_classification).map(([lvl, d]) => ({ scope: lvl, cadence_days: d })),
  ];
}

export function inScope(policy, scope, level) {
  if (scope === 'default') return policy.by_classification[level] == null;
  return level === scope;
}
