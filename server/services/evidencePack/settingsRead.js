export function allSettings(db) {
  return db.prepare('SELECT key, value, updated_at FROM settings ORDER BY key').all();
}

export function settingValue(db, key) {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value;
}
