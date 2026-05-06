-- v2.1.3 (fixed in v2.1.4): Introduce platform_admin role
--
-- A new global role tier above 'admin', meant for setup / role-management /
-- platform-config operations. Bootstrap admin (id=1) is auto-promoted so the
-- role exists on day one without a CLI step. Other users can be promoted/
-- demoted via PUT /api/users/:id/role (platform_admin only). Per-app
-- capabilities configurable via the role_permissions matrix at /settings#roles.
--
-- HISTORY: the original v2.1.3 migration relaxed the users.role CHECK via
-- PRAGMA writable_schema = ON + UPDATE sqlite_master. That fails inside
-- the migration runner's db.transaction() wrapper — SQLite refuses to
-- modify sqlite_master while a transaction is open, regardless of the
-- pragma. Replaced with the documented CREATE-INSERT-DROP-RENAME rebuild
-- pattern, which works inside a transaction.
--
-- Two pragmas make the rebuild safe under the existing FK references:
--   * legacy_alter_table = ON  — keeps child-table FK references as text
--     names that resolve at check time (rather than rewriting them to
--     point at users_old after the RENAME).
--   * defer_foreign_keys = ON  — defers FK enforcement to COMMIT, so the
--     intermediate state (after DROP TABLE users_old, before COMMIT) is
--     allowed. At COMMIT, all child references say "users" and resolve
--     to the rebuilt table — same ids, same data — so checks pass.
--
-- For installs that ran the broken v2.1.3 migration manually: after upgrade,
-- record it as applied so this file does not run again:
--   INSERT INTO _migrations (name) VALUES ('046-platform-admin-role.sql');
-- (If it does run again it is still safe — the INSERT/SELECT preserves
-- data — but it is wasted work.)

PRAGMA legacy_alter_table = ON;
PRAGMA defer_foreign_keys = ON;

ALTER TABLE users RENAME TO users_old;

-- Schema mirrors the post-migration-040 state of users (in column order):
--   001-initial:       id, name, email, role, api_key_hash, created_at
--   002-identity:      password_hash, username, avatar_url, phone,
--                      year_of_birth, preferences, last_login_at
--   003-key-encrypted: api_key_encrypted
--   011-oidc:          sso_sub
--   012-saml:          saml_name_id
--   013-scim:          active, scim_external_id
--   038-user-kind:     kind
--   040-mcp-scope:     mcp_app_scope
-- Only role's CHECK changes; everything else copies forward.

CREATE TABLE users (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  name               TEXT NOT NULL,
  email              TEXT UNIQUE,
  role               TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('platform_admin', 'admin', 'user')),
  api_key_hash       TEXT UNIQUE NOT NULL,
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),
  password_hash      TEXT,
  username           TEXT,
  avatar_url         TEXT,
  phone              TEXT,
  year_of_birth      INTEGER,
  preferences        TEXT DEFAULT '{}',
  last_login_at      TEXT,
  api_key_encrypted  TEXT,
  sso_sub            TEXT,
  saml_name_id       TEXT,
  active             INTEGER NOT NULL DEFAULT 1,
  scim_external_id   TEXT,
  kind               TEXT NOT NULL DEFAULT 'human',
  mcp_app_scope      TEXT
);

INSERT INTO users (
  id, name, email, role, api_key_hash, created_at,
  password_hash, username, avatar_url, phone, year_of_birth, preferences, last_login_at,
  api_key_encrypted, sso_sub, saml_name_id, active, scim_external_id, kind, mcp_app_scope
)
SELECT
  id, name, email, role, api_key_hash, created_at,
  password_hash, username, avatar_url, phone, year_of_birth, preferences, last_login_at,
  api_key_encrypted, sso_sub, saml_name_id, active, scim_external_id, kind, mcp_app_scope
FROM users_old;

DROP TABLE users_old;

-- Recreate the explicit (non-UNIQUE-column) indexes that lived on users.
-- The implicit indexes on UNIQUE columns (email, api_key_hash) are already
-- covered by the CREATE TABLE above.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_sub        ON users(sso_sub)          WHERE sso_sub          IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_saml_name_id   ON users(saml_name_id)     WHERE saml_name_id     IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_ext       ON users(scim_external_id) WHERE scim_external_id IS NOT NULL;

PRAGMA legacy_alter_table = OFF;

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
