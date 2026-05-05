-- v1.29.x: Configurable RBAC matrix for the per-app role tiers.
--
-- Most authz checks in AppCrane are hardcoded by design — the things that
-- change between installs are a small set of "high-stakes" permissions where
-- some orgs want Admin to do them and others want Owner-only. Those are the
-- ones in this table. Anything not in role_permissions stays gated by the
-- existing requireAdmin / requireAppAccess / requireAppUser middleware.
--
-- Schema: (permission, role) → granted (0 or 1). Roles are 'user' | 'admin'
-- | 'owner'. Permissions are atomic strings checked by code via
-- userHasAppPermission(). AppCrane global admins (users.role='admin') always
-- have every permission; this table only governs the per-app role tiers.
--
-- Defaults (also the "Reset to defaults" behavior in the UI):
--   deploy.production         — Admin and Owner
--   request.ship              — Owner only (the one who wrote the code marks shipped)
--   env.write.production      — Admin and Owner
--   code.modify_repo_settings — Owner only (github_url, branch, repo settings)
--   app.delete                — Owner only

CREATE TABLE IF NOT EXISTS role_permissions (
  permission TEXT NOT NULL,
  role       TEXT NOT NULL,
  granted    INTEGER NOT NULL,
  PRIMARY KEY (permission, role)
);

INSERT OR IGNORE INTO role_permissions (permission, role, granted) VALUES
  ('deploy.production',         'user',  0),
  ('deploy.production',         'admin', 1),
  ('deploy.production',         'owner', 1),
  ('request.ship',              'user',  0),
  ('request.ship',              'admin', 0),
  ('request.ship',              'owner', 1),
  ('env.write.production',      'user',  0),
  ('env.write.production',      'admin', 1),
  ('env.write.production',      'owner', 1),
  ('code.modify_repo_settings', 'user',  0),
  ('code.modify_repo_settings', 'admin', 0),
  ('code.modify_repo_settings', 'owner', 1),
  ('app.delete',                'user',  0),
  ('app.delete',                'admin', 0),
  ('app.delete',                'owner', 1);
