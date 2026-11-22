// Per-app opt-in for the widget scopes that carry an owner's power
// (migration 216): off unless an owner or platform admin turns them on.

export const OPT_IN_SCOPES = { members: 'widget_members', 'app-keys': 'widget_app_keys' };

export function widgetOptIns(db, appId) {
  const row = db.prepare('SELECT widget_members, widget_app_keys FROM app_settings WHERE app_id = ?').get(appId);
  return { members: row?.widget_members === 1, 'app-keys': row?.widget_app_keys === 1 };
}

export function scopeEnabled(db, appId, scope) {
  return !(scope in OPT_IN_SCOPES) || widgetOptIns(db, appId)[scope];
}

/** changes: { members?: boolean, 'app-keys'?: boolean } */
export function setWidgetOptIns(db, appId, changes) {
  const next = { ...widgetOptIns(db, appId), ...changes };
  db.prepare(`
    INSERT INTO app_settings (app_id, widget_members, widget_app_keys) VALUES (?, ?, ?)
    ON CONFLICT(app_id) DO UPDATE SET widget_members = excluded.widget_members,
      widget_app_keys = excluded.widget_app_keys, updated_at = datetime('now')
  `).run(appId, next.members ? 1 : 0, next['app-keys'] ? 1 : 0);
  return next;
}
