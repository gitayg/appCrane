-- MCP OAuth client policy (services/oauthClientPolicy.js): a platform admin can
-- approve a dynamically registered client. Approval is required in the
-- 'approval' registration mode and lets a client past the redirect-host
-- allowlist in 'allowlist' mode. The grant's absolute lifetime is not stored:
-- it is created_at plus the API key window (api_key_max_age_days), read at use,
-- so shortening the window also shortens connections already approved.
ALTER TABLE oauth_clients ADD COLUMN approved_at TEXT;
ALTER TABLE oauth_clients ADD COLUMN approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL;
