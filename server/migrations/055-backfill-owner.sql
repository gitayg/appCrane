-- v2.5.12: backfill app_user_roles.app_role='owner' for apps that have
-- no owner row.
--
-- The bug: every app-creation path (POST /api/apps,
-- appcrane_create_app, appcrane_create_managed_app) inserted the
-- creator into app_users (membership) but never into app_user_roles
-- with role='owner'. Apps therefore showed up with the "⚠ No owner"
-- badge in the dashboard and lost meaningful per-app authz boundaries
-- (only global admins could administer them).
--
-- Backfill rule: for every app that currently has no owner in
-- app_user_roles, grant 'owner' to apps.created_by — provided that
-- user still exists and is active. Apps whose creator was deleted
-- stay ownerless; an admin can promote a successor explicitly.
--
-- Safe to re-run: INSERT OR IGNORE skips rows that already exist.

INSERT OR IGNORE INTO app_user_roles (app_id, user_id, app_role)
SELECT a.id, a.created_by, 'owner'
FROM apps a
JOIN users u ON u.id = a.created_by AND u.active = 1
WHERE a.created_by IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM app_user_roles aur
    WHERE aur.app_id = a.id AND aur.app_role = 'owner'
  );
