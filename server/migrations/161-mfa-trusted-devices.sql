-- "Remember this device" for local (password) MFA. See server/services/trustedDevices.js.
-- Only the SHA-256 of the cookie token is stored; public_id is the opaque
-- handle the UI uses to revoke one row, so row ids never leave the server.

CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT,
  ip TEXT,
  mfa_enabled_at TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_user ON mfa_trusted_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_expires ON mfa_trusted_devices(expires_at);
