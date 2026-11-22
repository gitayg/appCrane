-- Sign-in risk signals (services/signinRisk/*).
--
-- signin_devices: one row per (user, browser). The browser holds a random
-- device cookie; only its SHA-256 is stored. notified_at is set when the
-- "new sign-in" e-mail for that device was queued, so it is sent at most once.
CREATE TABLE IF NOT EXISTS signin_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  ua_family TEXT,
  first_ip TEXT,
  last_ip TEXT,
  first_method TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  notified_at TEXT,
  UNIQUE (user_id, token_hash)
);
CREATE INDEX IF NOT EXISTS idx_signin_devices_token ON signin_devices(token_hash);

-- signin_lockouts: per-account (not per-IP) password failure state.
-- subject_key is 'u:<user id>' for a real account, 'l:<sha256 of the login>'
-- for a name that matches no account (so a locked answer does not reveal
-- which names exist), or 'd:<device row id>' for a recognised device's own
-- counter. locked_until NULL or in the past means not locked.
CREATE TABLE IF NOT EXISTS signin_lockouts (
  subject_key TEXT PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  failures INTEGER NOT NULL DEFAULT 0,
  window_started_at TEXT,
  locked_until TEXT,
  lock_count INTEGER NOT NULL DEFAULT 0,
  last_locked_at TEXT,
  last_failure_at TEXT,
  last_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_signin_lockouts_user ON signin_lockouts(user_id);

-- signin_report_links: the "not you?" link in a new-device e-mail. Opaque
-- token, stored hashed, single use, bound to one user.
CREATE TABLE IF NOT EXISTS signin_report_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_public_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  used_at TEXT
);
