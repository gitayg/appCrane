-- SAML: add saml_name_id to link users to their Okta identity
ALTER TABLE users ADD COLUMN saml_name_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_saml_name_id ON users(saml_name_id) WHERE saml_name_id IS NOT NULL;
