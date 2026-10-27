-- v2.124.0: personal app sign-in keys (dhk_uak_*).
--
-- A key a user issues for themselves that does exactly one thing: sign them in
-- to ONE app through that app's forward_auth gate (/api/identity/verify?app=
-- <slug>). It is refused by every other AppCrane endpoint — the REST API, MCP,
-- the dashboard — so a key sitting in a CLI's config file on a laptop is worth
-- one app's front door, not the user's whole account. The first consumer is an
-- uploader that posts to an app from a cron job or a hook, where a browser SSO
-- session is not available and a full dhk_user_* key was the only option.
--
-- This is NOT the dhk_app_* model removed in v2.2.12. Those keys belonged to an
-- app and carried their own grants. This one belongs to a user and grants
-- nothing of its own: at every request the user's CURRENT role on the app is
-- resolved as for a browser session, so removing their role, deactivating them
-- or deleting them shuts the key with no revoke step.
--
-- Format: dhk_uak_<random>. Plaintext shown once; only the SHA-256 hash stored.
CREATE TABLE IF NOT EXISTS user_app_keys (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id       INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  key_hash     TEXT    NOT NULL UNIQUE,
  label        TEXT,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  expires_at   TEXT,
  revoked_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_user_app_keys_user_id ON user_app_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_user_app_keys_app_id  ON user_app_keys(app_id);
