-- Identity Assertion JWT Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant-06,
-- services/oauthIdJag.js): every accepted ID-JAG's jti is kept until it expires,
-- so an assertion is redeemed at most once. oauth_grants.via records how a grant
-- was made ('consent' when NULL, 'id-jag' for an assertion).
CREATE TABLE IF NOT EXISTS oauth_id_jag_jti (
  iss TEXT NOT NULL,
  jti TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (iss, jti)
);
ALTER TABLE oauth_grants ADD COLUMN via TEXT;
