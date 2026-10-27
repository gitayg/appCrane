-- Per-app origins (services/appOrigin.js). When the platform setting
-- app_isolation_domain is set, every app is served on its own host
-- (<slug>.<domain>, <slug>-sandbox.<domain>) instead of /<slug> on the
-- platform host, so one app's script can no longer act as the visitor in
-- another app or read the dashboard's session.
--
-- scope: 'platform' is the dashboard/API session (cc_token). 'app' is a
-- session issued by the sign-in handoff for ONE app and environment
-- (app_id + app_env), held in a host-only cookie on that app's host; the
-- platform API never accepts it. parent_token_hash ties it to the platform
-- session it came from, so signing out of AppCrane ends it too.
ALTER TABLE identity_sessions ADD COLUMN scope TEXT NOT NULL DEFAULT 'platform';
ALTER TABLE identity_sessions ADD COLUMN app_env TEXT;
ALTER TABLE identity_sessions ADD COLUMN parent_token_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_identity_sessions_parent ON identity_sessions(parent_token_hash);

-- One-time sign-in codes carried from the platform host to an app host.
-- Stored hashed, single use, short lived.
CREATE TABLE IF NOT EXISTS app_handoff_codes (
  code_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  app_env TEXT NOT NULL CHECK (app_env IN ('sandbox', 'production')),
  parent_token_hash TEXT NOT NULL,
  -- sha256 of the value in the app host's __Host-cc_handoff cookie: only the
  -- browser that started the sign-in can use the code.
  state_hash TEXT NOT NULL,
  return_path TEXT NOT NULL DEFAULT '/',
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_app_handoff_codes_expires ON app_handoff_codes(expires_at);
