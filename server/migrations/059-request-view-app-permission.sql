-- v2.7.29: configurable "who can view app enhancement requests" permission.
--
-- /api/enhancements/owned returns requests filed against apps the caller
-- holds the `request.view_app` permission on (resolved via per-app role +
-- matrix). Default: owner-only — owners triage their own app's requests.
-- Operators flip `admin` (or `user`) on at /settings#roles to widen.
-- platform_admin is granted by default — they already see everything via
-- the admin endpoint, this just makes the fallback path consistent.

INSERT OR IGNORE INTO role_permissions (permission, role, granted) VALUES
  ('request.view_app', 'user',           0),
  ('request.view_app', 'admin',          0),
  ('request.view_app', 'owner',          1),
  ('request.view_app', 'platform_admin', 1);
