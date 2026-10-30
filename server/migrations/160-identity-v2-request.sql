-- One "verify the v2 identity signature" request per app, filed by the
-- 2.125.14 upgrade (services/identityUpgradeRequests.js). The startup scan runs
-- on every boot; this index is what makes it file once: the insert uses
-- ON CONFLICT DO NOTHING, and a request the owner closed is never reopened.
CREATE UNIQUE INDEX IF NOT EXISTS idx_enhancement_requests_identity_v2
  ON enhancement_requests(app_slug) WHERE kind = 'identity-v2';
