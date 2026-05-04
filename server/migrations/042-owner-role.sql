-- v1.29: Add 'owner' tier to per-app roles. Hierarchy: owner > admin > user.
--
-- Owner is the role that can manage app source / repo settings / app-scoped
-- keys / mark requests "shipped". Admin can operate the app (env vars,
-- deploys, claim requests) but not write code. User has read-only access
-- plus the ability to submit requests.
--
-- Auto-promote existing app creators to 'owner' so apps already in flight
-- don't lose code-management ability when the new tier lands. If a creator
-- already has an 'admin' row, upgrade it to 'owner'.

INSERT OR IGNORE INTO app_user_roles (app_id, user_id, app_role)
  SELECT id, created_by, 'owner'
  FROM apps
  WHERE created_by IS NOT NULL;

UPDATE app_user_roles
  SET app_role = 'owner'
  WHERE app_role = 'admin'
    AND (app_id, user_id) IN (
      SELECT id, created_by FROM apps WHERE created_by IS NOT NULL
    );
