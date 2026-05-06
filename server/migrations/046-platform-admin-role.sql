-- migration:no-transaction
--
-- v2.1.3 / v2.1.4 / v2.1.6 / v2.1.7 / fix v2.1.9: Introduce platform_admin role
--
-- A new global role tier above 'admin', meant for setup, role-management,
-- and platform-config operations. Bootstrap admin (id=1) is auto-promoted
-- so the role exists on day one without a CLI step. Other users can be
-- promoted/demoted via PUT /api/users/:id/role (platform_admin only).
-- Per-app capabilities configurable via the role_permissions matrix at
-- /settings#roles.
--
-- HISTORY: Five iterations to relax the users.role CHECK constraint:
--   v2.1.3: writable_schema inside tx          → fails: PRAGMA blocked in tx.
--   v2.1.4: rebuild + legacy_alter_table       → fails: FK semantics.
--   v2.1.6: writable_schema + no-transaction   → fails: PRAGMA defensive=ON
--                                                 blocks UPDATE sqlite_master.
--   v2.1.7: + PRAGMA defensive=OFF             → fails: better-sqlite3 has
--                                                 its own JS-side guard that
--                                                 doesn't honor the pragma;
--                                                 needs `unsafeMode: true`
--                                                 at Database construction.
--   v2.1.9: classic table rebuild with PRAGMA foreign_keys=OFF outside a
--           transaction. The no-transaction directive (added in v2.1.6)
--           lets foreign_keys actually toggle off here. No writable_schema,
--           no defensive, no unsafeMode dependencies — sidesteps the
--           better-sqlite3 sqlite_master guard entirely.
--
-- For installs where an earlier broken version was applied manually:
--   INSERT INTO _migrations (name) VALUES ('046-platform-admin-role.sql');

PRAGMA foreign_keys = OFF;

-- Build the new users table with the relaxed CHECK. Schema mirrors the
-- post-migration-040 state of users (column order matters for the
-- INSERT below):
--   001-initial:       id, name, email, role, api_key_hash, created_at
--   002-identity:      password_hash, username, avatar_url, phone,
--                      year_of_birth, preferences, last_login_at
--   003-key-encrypted: api_key_encrypted
--   011-oidc:          sso_sub
--   012-saml:          saml_name_id
--   013-scim:          active, scim_external_id
--   038-user-kind:     kind
--   040-mcp-scope:     mcp_app_scope
CREATE TABLE users_new (
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

INSERT INTO users_new (
  id, name, email, role, api_key_hash, created_at,
  password_hash, username, avatar_url, phone, year_of_birth, preferences, last_login_at,
  api_key_encrypted, sso_sub, saml_name_id, active, scim_external_id, kind, mcp_app_scope
)
SELECT
  id, name, email, role, api_key_hash, created_at,
  password_hash, username, avatar_url, phone, year_of_birth, preferences, last_login_at,
  api_key_encrypted, sso_sub, saml_name_id, active, scim_external_id, kind, mcp_app_scope
FROM users;

-- With foreign_keys=OFF, DROP+RENAME doesn't trigger child-table FK
-- failures. Children reference "users" by name, so they resolve to the
-- new table once it's renamed.
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Recreate the explicit (non-UNIQUE-column) indexes that lived on users.
-- The implicit indexes on UNIQUE columns (email, api_key_hash) are
-- already covered by the CREATE TABLE above.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso_sub        ON users(sso_sub)          WHERE sso_sub          IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_saml_name_id   ON users(saml_name_id)     WHERE saml_name_id     IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_ext       ON users(scim_external_id) WHERE scim_external_id IS NOT NULL;

PRAGMA foreign_keys = ON;

-- Auto-promote the bootstrap admin (id=1). No-op if id=1 is missing or
-- isn't currently 'admin'.
UPDATE users SET role = 'platform_admin' WHERE id = 1 AND role = 'admin';

-- Seed platform_admin grants in role_permissions. Default = granted for
-- all five existing permissions; operator can revoke via the matrix UI.
INSERT OR IGNORE INTO role_permissions (permission, role, granted) VALUES
  ('deploy.production',         'platform_admin', 1),
  ('request.ship',              'platform_admin', 1),
  ('env.write.production',      'platform_admin', 1),
  ('code.modify_repo_settings', 'platform_admin', 1),
  ('app.delete',                'platform_admin', 1);
