-- migration:no-transaction
--
-- v2.1.3 / fix v2.1.4 / fix v2.1.6 / fix v2.1.7: Introduce platform_admin role
--
-- A new global role tier above 'admin', meant for setup, role-management,
-- and platform-config operations. Bootstrap admin (id=1) is auto-promoted
-- so the role exists on day one without a CLI step. Other users can be
-- promoted/demoted via PUT /api/users/:id/role (platform_admin only).
-- Per-app capabilities configurable via the role_permissions matrix at
-- /settings#roles.
--
-- HISTORY:
--   v2.1.3 used PRAGMA writable_schema to relax the users.role CHECK.
--     Failed because the runner wrapped every migration in a transaction
--     and writable_schema is a no-op there.
--   v2.1.4 switched to a CREATE-INSERT-DROP-RENAME rebuild pattern with
--     legacy_alter_table + defer_foreign_keys. Brittle in practice — the
--     rebuild interacts badly with FK references from a half-dozen child
--     tables, and the workaround pragmas behave inconsistently across
--     SQLite versions.
--   v2.1.6 reverts to the original simple writable_schema approach, but
--     declares `migration:no-transaction` on the first line so the runner
--     skips the implicit transaction wrapper. Still failed in production.
--   v2.1.7 adds `PRAGMA defensive = OFF`. better-sqlite3 sets defensive=ON
--     by default, which blocks UPDATE sqlite_master independently of the
--     writable_schema flag — both must be cleared. Re-armed after the
--     mutation so the rest of the connection's lifetime stays defensive.
--
-- For installs that ran a broken earlier version manually: after upgrade,
-- record it as applied so this file does not run again:
--   INSERT INTO _migrations (name) VALUES ('046-platform-admin-role.sql');

PRAGMA defensive = OFF;
PRAGMA writable_schema = ON;
UPDATE sqlite_master
   SET sql = REPLACE(sql,
              "CHECK(role IN ('admin', 'user'))",
              "CHECK(role IN ('platform_admin', 'admin', 'user'))")
 WHERE type = 'table' AND name = 'users';
PRAGMA writable_schema = OFF;
PRAGMA defensive = ON;

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
