-- App-defined roles: vocabulary an app owner invents for their OWN app, which
-- AppCrane stores and hands to the app (via /api/me and X-AppCrane-App-Roles)
-- but never interprets.
--
-- SEPARATE TABLES ON PURPOSE. These do NOT extend app_user_roles, whose
-- app_role column ('none'|'user'|'admin'|'owner') is AppCrane's own tier and
-- decides who may deploy, read env vars or delete the app. If the two shared a
-- table or a lookup, an app owner could type 'admin' into a settings form and
-- have it read back by a platform authz check — privilege escalation authored
-- through the UI. Nothing in AppCrane may ever consult these tables when
-- deciding something about AppCrane.
--
-- A user may hold SEVERAL app-defined roles on one app (hence a grants table
-- with a composite PK), unlike app_user_roles which is one row per user per app.
CREATE TABLE IF NOT EXISTS app_defined_roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  label TEXT NOT NULL,
  description TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(app_id, key)
);

-- Deleting a role cascades its grants: the role stops existing, so holding it
-- must stop existing too. The API reports how many people that affects before
-- and after, because it is a silent de-authorization inside the app otherwise.
CREATE TABLE IF NOT EXISTS app_role_grants (
  role_id INTEGER NOT NULL REFERENCES app_defined_roles(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app_id  INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  granted_by INTEGER REFERENCES users(id),
  granted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (role_id, user_id)
);

-- app_id is denormalized onto the grant so the hot path — "which keys does this
-- user hold on this app", run on every identity verification — is one indexed
-- lookup that never has to trust a role_id to name the right app.
CREATE INDEX IF NOT EXISTS idx_app_role_grants_lookup ON app_role_grants(app_id, user_id);
CREATE INDEX IF NOT EXISTS idx_app_defined_roles_app ON app_defined_roles(app_id);
