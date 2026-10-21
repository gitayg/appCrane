-- API key expiry (services/apiKeyExpiry.js).
--
-- Every personal credential a person or their agent holds expires a fixed
-- number of days after it was issued or last rotated: user API keys
-- (dhk_user_* / dhk_admin_*, users.api_key_hash), personal MCP keys
-- (dhk_mcp_*, user_mcp_keys, coder per-turn keys excluded: they live for one
-- turn) and Crew agent tokens (dhk_crew_*). The window is the platform setting
-- api_key_max_age_days, default 90, clamped to 7..365.
--
-- Triggers stamp the expiry on every issue and rotation, so every place that
-- writes a key (users.js, SSO and SCIM provisioning, crane regenerate-key, the
-- MCP key routes, Crew rotation) gets it without having to remember.
--
-- Existing keys are NOT all expired at once: each live key gets upgrade time +
-- the window (an existing shorter MCP key expiry is kept).

ALTER TABLE users ADD COLUMN api_key_issued_at TEXT;
ALTER TABLE users ADD COLUMN api_key_expires_at TEXT;
ALTER TABLE users ADD COLUMN api_key_last_used_at TEXT;
-- Where the sweep moves an expired key's hash. api_key_hash is UNIQUE NOT NULL,
-- so it becomes 'expired:' || <old hash>, which no presented key hashes to:
-- every lookup by api_key_hash stops matching, while requireAuth can still
-- find the key here and say "expired".
ALTER TABLE users ADD COLUMN api_key_expired_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_users_api_key_expired_hash ON users(api_key_expired_hash);

ALTER TABLE user_mcp_keys ADD COLUMN issued_at TEXT;
ALTER TABLE crew_agent_tokens ADD COLUMN expires_at TEXT;

UPDATE users
   SET api_key_issued_at = datetime('now'),
       api_key_expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
 WHERE api_key_hash IS NOT NULL;

UPDATE user_mcp_keys
   SET issued_at = COALESCE(created_at, datetime('now')),
       expires_at = CASE
         WHEN expires_at IS NOT NULL AND datetime(expires_at) IS NOT NULL
              AND datetime(expires_at) < datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
           THEN datetime(expires_at)
         ELSE datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
       END
 WHERE coder_session_id IS NULL AND revoked_at IS NULL;

UPDATE crew_agent_tokens
   SET expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
 WHERE revoked_at IS NULL;

CREATE TRIGGER IF NOT EXISTS trg_users_api_key_issue
AFTER INSERT ON users
WHEN NEW.api_key_hash IS NOT NULL AND NEW.api_key_hash NOT LIKE 'expired:%'
BEGIN
  UPDATE users
     SET api_key_issued_at = datetime('now'),
         api_key_expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days'),
         api_key_last_used_at = NULL,
         api_key_expired_hash = NULL
   WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_users_api_key_rotate
AFTER UPDATE OF api_key_hash ON users
WHEN NEW.api_key_hash IS NOT NULL AND NEW.api_key_hash IS NOT OLD.api_key_hash AND NEW.api_key_hash NOT LIKE 'expired:%'
BEGIN
  UPDATE users
     SET api_key_issued_at = datetime('now'),
         api_key_expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days'),
         api_key_last_used_at = NULL,
         api_key_expired_hash = NULL
   WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_user_mcp_keys_issue
AFTER INSERT ON user_mcp_keys
WHEN NEW.coder_session_id IS NULL
BEGIN
  UPDATE user_mcp_keys
     SET issued_at = datetime('now'),
         expires_at = CASE
           WHEN NEW.expires_at IS NOT NULL AND datetime(NEW.expires_at) IS NOT NULL
                AND datetime(NEW.expires_at) < datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
             THEN datetime(NEW.expires_at)
           ELSE datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
         END
   WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_user_mcp_keys_rotate
AFTER UPDATE OF key_hash ON user_mcp_keys
WHEN NEW.coder_session_id IS NULL AND NEW.key_hash IS NOT OLD.key_hash
BEGIN
  UPDATE user_mcp_keys
     SET issued_at = datetime('now'),
         expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
   WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_crew_agent_tokens_issue
AFTER INSERT ON crew_agent_tokens
BEGIN
  UPDATE crew_agent_tokens
     SET expires_at = datetime('now', '+' || MAX(7, MIN(365, COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'api_key_max_age_days' AND CAST(value AS INTEGER) > 0), 90))) || ' days')
   WHERE id = NEW.id;
END;

-- Expiry warnings are platform mail (app_id NULL), which idx_email_queue_idem
-- cannot dedupe; the key names the credential, its expiry and the stage
-- (14 or 3 days), so each warning goes out once per key per expiry.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_queue_api_key_expiry
  ON email_queue(idempotency_key)
  WHERE source = 'api-key-expiry' AND idempotency_key IS NOT NULL;
