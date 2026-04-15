-- Identity Manager: password auth, user profiles, per-app roles

ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN username TEXT;
ALTER TABLE users ADD COLUMN avatar_url TEXT;
ALTER TABLE users ADD COLUMN phone TEXT;
ALTER TABLE users ADD COLUMN year_of_birth INTEGER;
ALTER TABLE users ADD COLUMN preferences TEXT DEFAULT '{}';
ALTER TABLE users ADD COLUMN last_login_at TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE username IS NOT NULL;

-- Per-app roles (admin/user/viewer per app, separate from AppCrane admin role)
CREATE TABLE IF NOT EXISTS app_user_roles (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_role TEXT NOT NULL DEFAULT 'user' CHECK(app_role IN ('admin', 'user', 'viewer')),
  PRIMARY KEY (app_id, user_id)
);

-- Session tokens for identity login (used by apps, not CLI)
CREATE TABLE IF NOT EXISTS identity_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_identity_sessions_token ON identity_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_identity_sessions_expires ON identity_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_app_user_roles_app ON app_user_roles(app_id);
