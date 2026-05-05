-- v1.29.x: Personal MCP keys, self-issued by users.
--
-- A personal MCP key authenticates AS the user, but is scoped to MCP only
-- (not the dashboard). At call time, accessibility is resolved dynamically:
-- the key grants access to every app where the issuing user is currently
-- an Owner. Role changes take effect immediately — no key reissue needed.
--
-- Format: dhk_mcp_<random>. Plaintext shown once; only SHA-256 hash stored.
-- Users can create multiple (one per device, etc.). Admins keep their full
-- dhk_admin_/dhk_user_ keys for everything else; this is purely additive.
CREATE TABLE IF NOT EXISTS user_mcp_keys (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash     TEXT    NOT NULL UNIQUE,
  label        TEXT,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  expires_at   TEXT,
  revoked_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_user_mcp_keys_user_id  ON user_mcp_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_user_mcp_keys_key_hash ON user_mcp_keys(key_hash);
