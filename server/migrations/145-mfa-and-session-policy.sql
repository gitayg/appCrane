-- Local MFA for password sign-in (TOTP + recovery codes) and session lifetime
-- policy (absolute + idle). See server/services/mfa.js and sessionPolicy.js.

CREATE TABLE IF NOT EXISTS user_mfa (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  totp_secret_enc TEXT,
  algorithm TEXT NOT NULL DEFAULT 'SHA1' CHECK (algorithm IN ('SHA1', 'SHA256')),
  enabled_at TEXT,
  last_used_step INTEGER,
  pending_secret_enc TEXT,
  pending_algorithm TEXT CHECK (pending_algorithm IS NULL OR pending_algorithm IN ('SHA1', 'SHA256')),
  pending_created_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON user_mfa_recovery_codes(user_id);

-- Second-step tickets between a correct password and an issued session.
CREATE TABLE IF NOT EXISTS mfa_challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'enroll')),
  app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);

ALTER TABLE identity_sessions ADD COLUMN last_seen_at TEXT;
ALTER TABLE identity_sessions ADD COLUMN absolute_expires_at TEXT;

-- Every session, whichever route issues it (password, MFA step, OIDC, SAML,
-- set-password), gets the role's absolute lifetime and idle timeout here, so a
-- new issuer cannot forget the policy. expires_at becomes the earlier of the
-- absolute deadline and now + idle (never later than what the issuer asked
-- for); requests slide it forward (sessionPolicy.touchSession). Timestamps are
-- written 'YYYY-MM-DD HH:MM:SSZ', which compares correctly against
-- datetime('now') as text and parses as UTC in JavaScript.
-- Defaults (minutes) must match DEFAULTS in server/services/sessionPolicy.js:
-- platform_admin 480 absolute / 30 idle, everyone else 1440 / 480.
CREATE TRIGGER IF NOT EXISTS identity_sessions_apply_policy
AFTER INSERT ON identity_sessions
BEGIN
  UPDATE identity_sessions SET
    last_seen_at = strftime('%Y-%m-%d %H:%M:%SZ', 'now'),
    absolute_expires_at = strftime('%Y-%m-%d %H:%M:%SZ', COALESCE(
      min(datetime(NEW.expires_at), datetime('now', '+' || (
        SELECT CASE WHEN u.role = 'platform_admin'
          THEN COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'session_admin_absolute_minutes' AND CAST(value AS INTEGER) BETWEEN 15 AND 43200), 480)
          ELSE COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'session_user_absolute_minutes' AND CAST(value AS INTEGER) BETWEEN 15 AND 43200), 1440)
        END FROM users u WHERE u.id = NEW.user_id) || ' minutes')),
      datetime('now', '+' || (
        SELECT CASE WHEN u.role = 'platform_admin'
          THEN COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'session_admin_absolute_minutes' AND CAST(value AS INTEGER) BETWEEN 15 AND 43200), 480)
          ELSE COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'session_user_absolute_minutes' AND CAST(value AS INTEGER) BETWEEN 15 AND 43200), 1440)
        END FROM users u WHERE u.id = NEW.user_id) || ' minutes')))
  WHERE id = NEW.id;
  UPDATE identity_sessions SET
    expires_at = strftime('%Y-%m-%d %H:%M:%SZ', min(datetime(absolute_expires_at), datetime('now', '+' || (
      SELECT CASE WHEN u.role = 'platform_admin'
        THEN COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'session_admin_idle_minutes' AND CAST(value AS INTEGER) BETWEEN 5 AND 1440), 30)
        ELSE COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'session_user_idle_minutes' AND CAST(value AS INTEGER) BETWEEN 5 AND 1440), 480)
      END FROM users u WHERE u.id = NEW.user_id) || ' minutes')))
  WHERE id = NEW.id AND absolute_expires_at IS NOT NULL;
END;
