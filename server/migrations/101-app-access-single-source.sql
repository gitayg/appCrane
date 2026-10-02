-- v2.94.0 — access to an app is recorded in one place: app_user_roles.
--
-- app_users (is a member) and app_user_roles (at which tier) said the same
-- thing twice and drifted. Migrations 042/048 and services/ownerBackfill.js
-- made app creators owners without a membership row, so an owner was refused
-- their own app's env vars by requireAppUser, which read app_users. Since
-- v2.42.1 "no role" is already the absence of a row, so a role row carries
-- everything a membership row did.
--
-- 1. Every member keeps access: a membership with no role becomes 'user', and
--    a leftover 'none' row next to a membership becomes 'user' too (that member
--    could open the app before, so they still can).
-- 2. 'none' rows with no membership are dropped: they granted nothing.
-- 3. app_users becomes a read-only view of app_user_roles. Every reader keeps
--    working; a write to it fails, so no code path can create a second copy.

UPDATE app_user_roles SET app_role = 'user'
  WHERE app_role = 'none'
    AND EXISTS (SELECT 1 FROM app_users au
                WHERE au.app_id = app_user_roles.app_id AND au.user_id = app_user_roles.user_id);

INSERT OR IGNORE INTO app_user_roles (app_id, user_id, app_role)
  SELECT au.app_id, au.user_id, 'user'
  FROM app_users au
  JOIN apps  a ON a.id = au.app_id
  JOIN users u ON u.id = au.user_id;

DELETE FROM app_user_roles WHERE app_role = 'none';

DROP TABLE app_users;

CREATE VIEW app_users AS
  SELECT app_id, user_id FROM app_user_roles WHERE app_role <> 'none';
