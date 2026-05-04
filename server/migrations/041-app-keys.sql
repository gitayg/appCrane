-- v1.29: Owner-issued app-scoped API keys.
--
-- Each key authenticates as a specific app. Format: dhk_app_<slug>_<random>.
-- The key is created by an Owner of the app (or AppCrane global admin); the
-- issuer's user_id is preserved on `created_by` for audit attribution.
--
-- Scope determines which AppCrane operations the key can perform:
--   'read'   — discovery + read-only (logs, requests, app info)
--   'deploy' — read + trigger deploys + claim/ship requests
--   'full'   — deploy + read/write env vars (mirrors Owner power on this app)
--
-- The plaintext key is shown ONCE on creation; only the SHA-256 hash is stored.
-- Revoking a key sets revoked_at; expired/revoked keys never authenticate.
CREATE TABLE IF NOT EXISTS app_keys (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id       INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  key_hash     TEXT    NOT NULL UNIQUE,
  label        TEXT,
  scope        TEXT    NOT NULL DEFAULT 'full',
  created_by   INTEGER NOT NULL REFERENCES users(id),
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  expires_at   TEXT,
  revoked_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_app_keys_app_id   ON app_keys(app_id);
CREATE INDEX IF NOT EXISTS idx_app_keys_key_hash ON app_keys(key_hash);
