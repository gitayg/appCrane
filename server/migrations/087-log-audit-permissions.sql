-- v2.66.0: gate runtime logs and the audit trail behind the RBAC matrix.
--
-- GET /api/:slug/logs/:env and GET /api/:slug/audit were gated by
-- requireAppAccess alone, which any assigned member satisfies — including a
-- plain 'user'. Runtime logs routinely carry bearer tokens, e-mail addresses
-- and full request paths, so "assigned to the app" is the wrong bar.
--
-- These two rows MUST be seeded here, not just declared in permissions.js.
-- userHasAppPermission() reads role_permissions and returns
-- `row?.granted === 1` — there is NO fallback to the DEFAULTS map in
-- resetToDefaults(). A key that exists only in code therefore denies every
-- per-app tier, so without this seeding an upgrade would silently take logs
-- and audit away from every app owner who has them today.
--
-- Defaults (mirrored by resetToDefaults() in server/services/permissions.js):
--   app.logs.view   — Owner only. Logs are the higher-risk of the two.
--   app.audit.view  — Admin and Owner. The audit trail is "who did what",
--                     which is what a per-app admin is for.
--
-- 'platform_admin' rows are seeded for completeness so the Settings matrix
-- renders a full row; the code path short-circuits for global admins anyway.
--
-- INSERT OR IGNORE: idempotent, and it must never clobber an operator who
-- already tuned these cells (re-running a migration, or a restore).

INSERT OR IGNORE INTO role_permissions (permission, role, granted) VALUES
  ('app.logs.view',  'user',           0),
  ('app.logs.view',  'admin',          0),
  ('app.logs.view',  'owner',          1),
  ('app.logs.view',  'platform_admin', 1),
  ('app.audit.view', 'user',           0),
  ('app.audit.view', 'admin',          1),
  ('app.audit.view', 'owner',          1),
  ('app.audit.view', 'platform_admin', 1);
