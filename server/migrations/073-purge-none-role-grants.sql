-- v2.42.1: retire app_role='none' as a stored value, and revoke the access it
-- silently granted.
--
-- PUT /api/apps/:slug/roles with app_role='none' — the admin UI's "remove" —
-- wrote a 'none' row AND inserted an app_users membership row. requireAppUser
-- checks app_users, so a person the dashboard displayed as having no role could
-- read DECRYPTED production env vars through GET /:slug/env/:env?reveal=true,
-- and run backup/restore/copy-data. /api/me reported 'none' and Caddy's
-- forward_auth denied them at /<slug>, so every human-visible signal said the
-- removal had worked.
--
-- The route now deletes instead of writing. This clears what it already made.
-- Order matters: read the 'none' rows to pick the memberships, THEN drop them.

DELETE FROM app_users
WHERE (app_id, user_id) IN (
  SELECT app_id, user_id FROM app_user_roles WHERE app_role = 'none'
);

-- Any app-defined roles those people held come with it. Left behind they would
-- be restored silently the moment someone re-added the person at any tier.
DELETE FROM app_role_grants
WHERE (app_id, user_id) IN (
  SELECT app_id, user_id FROM app_user_roles WHERE app_role = 'none'
);

DELETE FROM app_user_roles WHERE app_role = 'none';
