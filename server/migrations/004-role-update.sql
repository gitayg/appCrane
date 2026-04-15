-- Update app_user_roles to support none/user/admin
-- SQLite doesn't support ALTER CHECK, so we recreate the table

CREATE TABLE IF NOT EXISTS app_user_roles_new (
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_role TEXT NOT NULL DEFAULT 'none' CHECK(app_role IN ('none', 'user', 'admin')),
  PRIMARY KEY (app_id, user_id)
);

INSERT OR IGNORE INTO app_user_roles_new (app_id, user_id, app_role)
  SELECT app_id, user_id, CASE WHEN app_role = 'viewer' THEN 'none' ELSE app_role END
  FROM app_user_roles;

DROP TABLE IF EXISTS app_user_roles;
ALTER TABLE app_user_roles_new RENAME TO app_user_roles;

CREATE INDEX IF NOT EXISTS idx_app_user_roles_app ON app_user_roles(app_id);
