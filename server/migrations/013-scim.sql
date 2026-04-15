-- SCIM: user active state + Okta externalId
ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN scim_external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_ext ON users(scim_external_id) WHERE scim_external_id IS NOT NULL;
