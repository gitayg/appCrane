import { getDb } from '../../db.js';

// One JSON setting for every sign-in risk knob. A missing or out-of-range
// field falls back to its default, so a hand-edited row can never turn a
// limit into "unlimited".

export const POLICY_KEY = 'signin_risk_policy';

export const FIELDS = Object.freeze({
  new_device_mail:        { type: 'bool', def: true },
  lockout_threshold:      { type: 'int', def: 10, min: 3, max: 100 },
  lockout_window_minutes: { type: 'int', def: 15, min: 1, max: 1440 },
  lockout_base_minutes:   { type: 'int', def: 5, min: 1, max: 1440 },
  lockout_max_minutes:    { type: 'int', def: 1440, min: 1, max: 10080 },
  stuffing_accounts:      { type: 'int', def: 10, min: 3, max: 1000 },
  stuffing_window_minutes: { type: 'int', def: 10, min: 1, max: 1440 },
  stuffing_penalty_minutes: { type: 'int', def: 60, min: 1, max: 1440 },
  stuffing_logins_per_minute: { type: 'int', def: 1, min: 1, max: 5 },
  stale_days:             { type: 'int', def: 90, min: 7, max: 3650 },
  // 0 = off (the default). When on it must be later than stale_days.
  stale_deactivate_days:  { type: 'int', def: 0, min: 0, max: 3650 },
});

function coerce(spec, v) {
  if (spec.type === 'bool') return typeof v === 'boolean' ? v : spec.def;
  const n = Number(v);
  return Number.isInteger(n) && n >= spec.min && n <= spec.max ? n : spec.def;
}

export function readPolicy(db = getDb()) {
  let raw = {};
  try { raw = JSON.parse(db.prepare('SELECT value FROM settings WHERE key = ?').get(POLICY_KEY)?.value || '{}') || {}; } catch (_) { raw = {}; }
  const out = {};
  for (const [k, spec] of Object.entries(FIELDS)) out[k] = coerce(spec, raw[k]);
  if (out.lockout_max_minutes < out.lockout_base_minutes) out.lockout_max_minutes = out.lockout_base_minutes;
  if (out.stale_deactivate_days && out.stale_deactivate_days <= out.stale_days) out.stale_deactivate_days = 0;
  return out;
}

/** Validate a partial update and store the merged policy. Throws { field } on a bad value. */
export function writePolicy(db, patch, actorId) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    const e = new Error('policy must be an object'); e.field = 'policy'; throw e;
  }
  const next = { ...readPolicy(db) };
  for (const [k, v] of Object.entries(patch)) {
    const spec = FIELDS[k];
    if (!spec) { const e = new Error(`unknown field ${k}`); e.field = k; throw e; }
    if (spec.type === 'bool') {
      if (typeof v !== 'boolean') { const e = new Error(`${k} must be true or false`); e.field = k; throw e; }
    } else {
      const n = Number(v);
      if (!Number.isInteger(n) || n < spec.min || n > spec.max) {
        const e = new Error(`${k} must be a whole number from ${spec.min} to ${spec.max}`); e.field = k; throw e;
      }
    }
    next[k] = spec.type === 'bool' ? v : Number(v);
  }
  if (next.lockout_max_minutes < next.lockout_base_minutes) {
    const e = new Error('lockout_max_minutes must be at least lockout_base_minutes'); e.field = 'lockout_max_minutes'; throw e;
  }
  if (next.stale_deactivate_days && next.stale_deactivate_days <= next.stale_days) {
    const e = new Error('stale_deactivate_days must be 0 (off) or more than stale_days'); e.field = 'stale_deactivate_days'; throw e;
  }
  db.prepare(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .run(POLICY_KEY, JSON.stringify(next), actorId ?? null);
  return next;
}
