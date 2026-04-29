-- OIDC: add sso_sub to link users to their IdP identity
ALTER TABLE users ADD COLUMN sso_sub TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_sub ON users(sso_sub) WHERE sso_sub IS NOT NULL;
