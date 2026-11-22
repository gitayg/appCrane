-- Step-up authentication (services/stepUp.js). A dangerous action needs the
-- person to have authenticated recently (default 10 minutes, setting
-- step_up_window_minutes): a session's authentication time is the later of its
-- sign-in (created_at) and its last step-up (step_up_at).
--
-- mfa_method: the second factor behind the session's most recent
-- authentication ('totp', 'recovery_code', 'idp'), NULL for none. Sent to
-- hosted apps as X-AppCrane-Auth-Mfa.
ALTER TABLE identity_sessions ADD COLUMN step_up_at TEXT;
ALTER TABLE identity_sessions ADD COLUMN step_up_method TEXT;
ALTER TABLE identity_sessions ADD COLUMN mfa_method TEXT;

-- A step-up that leaves AppCrane and comes back: an OIDC or SAML re-login, or
-- a hosted app sending its user here with a return URL. The handle is opaque
-- (random, stored hashed), bound to the platform session that started it
-- (session_hash) where there is one, and single-use.
CREATE TABLE IF NOT EXISTS step_up_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  handle_hash TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('oidc', 'saml', 'app_return')),
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT,
  app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
  app_env TEXT,
  return_url TEXT,
  idp_request_id TEXT,
  started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%SZ', 'now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_step_up_requests_idp ON step_up_requests(idp_request_id);

-- A credential that cannot step up interactively (a user API key, a personal
-- MCP key, an MCP OAuth token) may perform an action that needs one only while
-- its person holds a grant they made from a freshly stepped-up dashboard
-- session: one action, one app (NULL = platform-wide action), time-boxed.
CREATE TABLE IF NOT EXISTS step_up_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
  granted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%SZ', 'now')),
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_step_up_grants_user ON step_up_grants(user_id, action);
