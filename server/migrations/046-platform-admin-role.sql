-- v2.1.3: Introduce platform_admin role
--
-- A new global role tier above 'admin', meant for setup / role-management /
-- platform-config operations. The bootstrap key (id=1) is auto-promoted so
-- something is platform_admin on day one without a CLI step. Other users
-- can be promoted/demoted via PUT /api/users/:id/role (platform_admin only).
--
-- Per-app capabilities for platform_admin are configurable in the existing
-- role_permissions matrix at /settings#roles — same UI, new column. We
-- seed all five existing permissions to granted=1 since platform_admin is
-- the most privileged tier; operators can flip them off via the UI.
--
-- Schema change: relax users.role CHECK to include platform_admin. SQLite
-- cannot ALTER a CHECK in place; the documented writable_schema trick
-- persists the new CHECK string to sqlite_master. Statements run via the
-- migration runner are re-parsed at run time so the UPDATE below sees the
-- new constraint.

PRAGMA writable_schema = ON;
UPDATE sqlite_master
   SET sql = REPLACE(sql,
              "CHECK(role IN ('admin', 'user'))",
              "CHECK(role IN ('platform_admin', 'admin', 'user'))")
 WHERE type = 'table' AND name = 'users';
PRAGMA writable_schema = OFF;

-- Auto-promote the bootstrap admin (id=1). No-op if id=1 is missing or
-- isn't currently 'admin' (e.g. operator already changed things).
UPDATE users SET role = 'platform_admin' WHERE id = 1 AND role = 'admin';

-- Seed platform_admin grants in role_permissions. Default = granted for all
-- five existing permissions; operator can revoke via the matrix UI.
INSERT OR IGNORE INTO role_permissions (permission, role, granted) VALUES
  ('deploy.production',         'platform_admin', 1),
  ('request.ship',              'platform_admin', 1),
  ('env.write.production',      'platform_admin', 1),
  ('code.modify_repo_settings', 'platform_admin', 1),
  ('app.delete',                'platform_admin', 1);
