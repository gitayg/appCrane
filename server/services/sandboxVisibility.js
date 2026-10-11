/**
 * Per-app "Show Sandbox to users" (migration 104).
 *
 * A visibility setting for the launch surfaces, not an access control: sandbox
 * keeps deploying and /<slug>-sandbox keeps routing for anyone with access. The
 * server computes `sandbox_visible` per caller so the SPA is told the answer
 * rather than re-deriving it from a role string it might read differently.
 */
import { isAdmin } from '../utils/roles.js';

/** No row means shown: that is the behaviour every app had before 104. */
export function getShowSandbox(db, appId) {
  const row = db.prepare('SELECT show_sandbox FROM app_settings WHERE app_id = ?').get(appId);
  return row ? row.show_sandbox === 1 : true;
}

/** One query for the whole catalogue; the list endpoint is the hottest one. */
export function showSandboxByAppId(db) {
  const map = new Map();
  for (const r of db.prepare('SELECT app_id, show_sandbox FROM app_settings').all()) {
    map.set(r.app_id, r.show_sandbox === 1);
  }
  return map;
}

export function setShowSandbox(db, appId, show) {
  db.prepare(`
    INSERT INTO app_settings (app_id, show_sandbox) VALUES (?, ?)
    ON CONFLICT(app_id) DO UPDATE SET show_sandbox = excluded.show_sandbox, updated_at = datetime('now')
  `).run(appId, show ? 1 : 0);
}

/**
 * Whether THIS caller is offered Sandbox. The people who build and release the
 * app (owner, app admin) and global admins, who administer every app, always
 * are; everyone else only while the setting is on.
 */
export function sandboxVisibleFor(user, appRole, show) {
  if (show) return true;
  if (isAdmin(user)) return true;
  return appRole === 'owner' || appRole === 'admin';
}

/** Accepts a real boolean, or 0/1 from form-ish callers; anything else is refused. */
export function parseShowSandbox(v) {
  if (v === true || v === 1) return true;
  if (v === false || v === 0) return false;
  return undefined;
}
