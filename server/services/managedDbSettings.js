// Platform-wide limits for the managed databases, set by a platform admin.
//
// Stored in the generic `settings` table (migration 005) like platformPolicy.js,
// but read through this module only, because every value is interpolated into
// engine DDL (ALTER ROLE ... CONNECTION LIMIT n) or a server flag
// (-c max_connections=n). A value that is not a validated integer never leaves
// this file: get() falls back to the default for anything stored out of range,
// so a hand-edited row cannot turn into SQL.
//
// Kept free of managedDb.js imports so routes can read and write the settings
// without loading the engine module (the same reason sandboxDb.js gives).

export const SETTING_KEYS = {
  connLimit: 'managed_db_conn_limit',
  pgMaxConnections: 'managed_db_pg_max_connections',
  statementTimeoutS: 'managed_db_statement_timeout_s',
  authAlertThreshold: 'managed_db_auth_alert_threshold',
};

// [default, min, max]. Bounds are what each engine accepts and what is sane on
// the default container sizes, not arbitrary tidiness:
//   conn_limit          per LOGIN. 25 is a typical pool (10-20) plus migrations
//                       and a console; -1 (Postgres "no limit") is not offered,
//                       because the whole point is that one app cannot take
//                       every connection slot from the others.
//   pg_max_connections  per SERVER. Postgres' default is 100, which 5 apps at
//                       the 25 cap already exceed. Changing it needs a server
//                       restart, so a new value takes effect when ensureServer()
//                       next recreates the container (see managedDb.js).
//   statement_timeout_s per LOGIN, seconds. 0 = no timeout. A runaway query
//                       holds locks and a connection slot until it finishes.
//   auth_alert_threshold failures per login per 10 minutes BEFORE an alert;
//                       the alert fires on the next one past it.
const SPEC = {
  conn_limit: [SETTING_KEYS.connLimit, 25, 1, 1000],
  pg_max_connections: [SETTING_KEYS.pgMaxConnections, 300, 100, 5000],
  statement_timeout_s: [SETTING_KEYS.statementTimeoutS, 300, 0, 86400],
  auth_alert_threshold: [SETTING_KEYS.authAlertThreshold, 5, 1, 1000],
};

export const DEFAULTS = Object.fromEntries(Object.entries(SPEC).map(([k, [, d]]) => [k, d]));

function readRaw(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value;
}

function valid(v, min, max) {
  const n = Number(v);
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
}

/** Every setting, defaults filled in. Always integers inside their bounds. */
export function getManagedDbSettings(db) {
  const out = {};
  for (const [field, [key, def, min, max]] of Object.entries(SPEC)) {
    const raw = readRaw(db, key);
    out[field] = raw === undefined || raw === null || raw === '' ? def : (valid(raw, min, max) ?? def);
  }
  return out;
}

/**
 * Partial update. Throws an Error naming the field for an out-of-range value,
 * and writes nothing in that case (validation runs before any write).
 */
export function setManagedDbSettings(db, patch, userId = null) {
  const p = patch || {};
  const writes = [];
  for (const [field, value] of Object.entries(p)) {
    const spec = SPEC[field];
    if (!spec) throw new Error(`unknown managed database setting '${field}' (allowed: ${Object.keys(SPEC).join(', ')})`);
    const [key, , min, max] = spec;
    const n = valid(value, min, max);
    if (n === null) throw new Error(`${field} must be an integer from ${min} to ${max}`);
    writes.push([key, n]);
  }
  const stmt = db.prepare(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`);
  for (const [key, n] of writes) stmt.run(key, String(n), userId);
  return getManagedDbSettings(db);
}

export const SETTINGS_SPEC = Object.fromEntries(
  Object.entries(SPEC).map(([k, [, def, min, max]]) => [k, { default: def, min, max }]),
);
