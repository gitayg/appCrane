-- View as role: a read-only preview of AppCrane as a lower role.
--
-- Keyed to the SHA-256 of the credential that started it (an identity session
-- token or a user API key), so it travels with that one sign-in and nothing
-- the browser sends can create or widen it. requireAuth re-checks on every
-- request that the target is still below the real user's standing; a row that
-- no longer is gets ignored and deleted.
CREATE TABLE IF NOT EXISTS view_as_sessions (
  credential_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_role TEXT NOT NULL CHECK (target_role IN ('user', 'owner', 'admin', 'none')),
  app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);
