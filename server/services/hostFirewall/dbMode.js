// How APPCRANE-DB treats a source that is not on a port's allowlist:
//   off      the chain is kept empty: every container reaches every port
//   observe  allowed sources RETURN; any other is counted and logged
//            (rate-limited, prefix APPCRANE-DB-WOULD-DROP) and falls through
//   enforce  allowed sources RETURN; any other is dropped
// observe is the default, so a host sees what enforce would refuse before it
// refuses anything. Moving towards off weakens the protection.

export const DB_ALLOWLIST_MODE_SETTING = 'db_allowlist_mode';
export const DB_ALLOWLIST_MODES = Object.freeze(['off', 'observe', 'enforce']);
export const DEFAULT_DB_ALLOWLIST_MODE = 'observe';

export function parseDbAllowlistMode(raw) {
  const v = String(raw ?? '').trim().toLowerCase();
  return DB_ALLOWLIST_MODES.includes(v) ? v : DEFAULT_DB_ALLOWLIST_MODE;
}

export function dbAllowlistMode(db) {
  return parseDbAllowlistMode(db.prepare('SELECT value FROM settings WHERE key = ?').get(DB_ALLOWLIST_MODE_SETTING)?.value);
}

/** True when going from `from` to `to` lets more through (enforce -> observe or off, observe -> off). */
export function dbModeWeakens(from, to) {
  return DB_ALLOWLIST_MODES.indexOf(parseDbAllowlistMode(to)) < DB_ALLOWLIST_MODES.indexOf(parseDbAllowlistMode(from));
}
