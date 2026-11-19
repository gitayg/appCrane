-- People who signed in through an SSO provider with auto-provisioning on, but
-- whose email is not on the allowed list. A platform admin approves (creates
-- the account) or denies each one. One row per provider identity.
CREATE TABLE IF NOT EXISTS sso_signup_requests (
  id            INTEGER PRIMARY KEY,
  provider      TEXT NOT NULL DEFAULT 'oidc',
  subject       TEXT NOT NULL,
  email         TEXT NOT NULL,
  name          TEXT,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
  requested_at  TEXT DEFAULT (datetime('now')),
  last_seen_at  TEXT DEFAULT (datetime('now')),
  decided_by    INTEGER,
  decided_at    TEXT,
  user_id       INTEGER,
  UNIQUE (provider, subject)
);
CREATE INDEX IF NOT EXISTS idx_sso_signup_requests_status ON sso_signup_requests(status);
