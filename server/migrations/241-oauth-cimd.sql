-- OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-03,
-- services/oauthCimd.js): a client_id that is an https URL is fetched and cached
-- here as an oauth_clients row keyed by that URL, so codes, grants and tokens
-- reference it exactly like a dynamically registered client.
ALTER TABLE oauth_clients ADD COLUMN is_cimd INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oauth_clients ADD COLUMN client_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN logo_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN metadata_fetched_at TEXT;
ALTER TABLE oauth_clients ADD COLUMN metadata_expires_at TEXT;
