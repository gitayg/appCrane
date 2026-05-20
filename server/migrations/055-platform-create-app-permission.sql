-- v2.7.0: configurable "who can create apps" permission.
--
-- Previously app creation was gated only by requireAuth on POST /api/apps
-- (any authenticated user could create via the API) while the dashboard
-- button was admin-only — an inconsistent split. This adds a platform-scoped
-- permission so a platform admin can grant plain users (users.role='user')
-- the ability to onboard apps without promoting them to admin.
--
-- Platform-scoped: checked against the caller's GLOBAL role via
-- userHasPlatformPermission(), not a per-app role (no app exists yet).
-- Global admins always have it regardless of these rows. The per-app
-- owner/admin columns are seeded for matrix completeness but are inert for a
-- platform permission.
--
-- Default: only admins (user=0). Flip the `user` cell on at /settings#roles
-- to let end users create apps.

INSERT OR IGNORE INTO role_permissions (permission, role, granted) VALUES
  ('platform.create_app', 'user',           0),
  ('platform.create_app', 'admin',          1),
  ('platform.create_app', 'owner',          1),
  ('platform.create_app', 'platform_admin', 1);
