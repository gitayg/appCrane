import { getDb } from '../db.js';

// users.api_key_last_used_at is what tells a used personal key from a never-used
// one, so every route that accepts a personal key records it here: requireAuth
// and each route with its own key fallback (Ask, Plan, coder, enhancements,
// /api/me, set-password, the forward_auth verify). Stamped at most once an hour
// per user to keep it off the hot path.
export function recordUserKeyUse(userId, db = getDb()) {
  try {
    db.prepare("UPDATE users SET api_key_last_used_at = datetime('now') WHERE id = ? AND (api_key_last_used_at IS NULL OR api_key_last_used_at < datetime('now', '-1 hour'))").run(userId);
  } catch (_) {}
}
